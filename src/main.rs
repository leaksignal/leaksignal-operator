#![warn(clippy::dbg_macro, clippy::todo)]

mod envoy_json;
mod native;
mod pod_scan;
mod proxy_mgr;
mod webhook;

use envoy_json::OwnerInfo;
use futures::stream::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use kube::{
    api::{DeleteParams, ListParams, Patch, PatchParams, PostParams},
    client::Client,
    core::{admission::SerializePatchError, DynamicObject, GroupVersionKind},
    discovery::ApiResource,
    runtime::{controller::Action, watcher::Config, Controller},
    Api, CustomResource, Resource, ResourceExt,
};
use log::{error, info, warn};
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fmt::{Debug, Write},
    sync::Arc,
};
use tokio::time::Duration;
use url::Url;

use crate::envoy_json::create_json;

fn default_istio_name() -> String {
    "leaksignal-istio".to_string()
}

fn default_upstream_port() -> usize {
    443
}

fn default_true() -> bool {
    true
}

fn default_ca_bundle() -> String {
    "/etc/ssl/certs/ca-certificates.crt".into()
}

fn default_proxy_prefix() -> String {
    "s3/leakproxy".into()
}

fn default_upstream_location() -> String {
    "ingestion.app.leaksignal.com".into()
}

fn default_native_repo() -> String {
    "leaksignal/istio-proxy".to_string()
}

fn default_proxy_pull_location() -> String {
    "https://leakproxy.s3.us-west-2.amazonaws.com/".to_string()
}

fn default_native_proxy_memory_limit() -> String {
    "2Gi".to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Kubernetes reported error: {source}")]
    KubeError {
        #[from]
        source: kube::Error,
    },
    #[error("Invalid Leak CRD: {0}")]
    UserInputError(String),
    #[error("Failed to generate certificate: {0}")]
    CertError(#[from] rcgen::Error),
    #[error("Failed to serialize patch: {0}")]
    PatchError(#[from] SerializePatchError),
    #[error("Failed to fetch via HTTP: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcMode {
    #[default]
    Default,
    Envoy,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CRDValues {
    #[serde(alias = "proxy_version")]
    pub proxy_version: String,
    #[serde(alias = "proxy_hash")]
    pub proxy_hash: String,
    #[serde(alias = "api_key")]
    pub api_key: String,
    #[serde(default = "default_upstream_location")]
    #[serde(alias = "upstream_location")]
    pub upstream_location: String,
    #[serde(default = "default_proxy_prefix")]
    #[serde(alias = "proxy_prefix")]
    #[deprecated]
    pub proxy_prefix: String,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default = "default_upstream_port")]
    #[serde(alias = "upstream_port")]
    pub upstream_port: usize,
    #[serde(default = "default_ca_bundle")]
    #[serde(alias = "ca_bundle")]
    pub ca_bundle: String,
    #[serde(default = "default_true")]
    #[serde(alias = "refresh_pods_on_update")]
    pub refresh_pods_on_update: bool,
    #[serde(default = "default_true")]
    pub refresh_pods_on_stale: bool,
    #[serde(default)]
    pub grpc_mode: GrpcMode,
    #[serde(default = "default_true")]
    pub enable_streaming: bool,
    #[serde(default = "default_true")]
    pub native: bool,
    #[serde(default = "default_true")]
    pub fail_open: bool,
    #[serde(default)]
    pub workload_selector: WorkloadSelector,
    #[serde(default = "default_istio_name")]
    pub istio_name: String,
    #[serde(default = "default_native_repo")]
    pub native_repo: String,
    #[serde(default = "default_proxy_pull_location")]
    pub proxy_pull_location: String,
    #[serde(default = "default_native_proxy_memory_limit")]
    pub native_proxy_memory_limit: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSelector {
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

impl CRDValues {
    pub fn label_selector(&self) -> Option<String> {
        if self.workload_selector.labels.is_empty() {
            return None;
        }
        let mut out = String::new();
        for (key, value) in &self.workload_selector.labels {
            if !out.is_empty() {
                out.push(',');
            }
            write!(&mut out, "{key}={value}").unwrap();
        }
        Some(out)
    }

    pub fn list_params(&self) -> ListParams {
        let mut out = ListParams::default();
        if let Some(label_selector) = self.label_selector() {
            out = out.labels(&label_selector);
        }
        out
    }
}

#[derive(CustomResource, Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[kube(
    group = "leaksignal.com",
    version = "v1",
    kind = "LeaksignalIstio",
    singular = "leaksignal-istio",
    plural = "leaksignal-istios",
    namespaced
)]
struct LeaksignalIstioSpec {
    #[serde(flatten)]
    inner: CRDValues,
}

impl LeaksignalIstioSpec {
    async fn reconcile(
        leaksignal_istio: Arc<LeaksignalIstio>,
        context: Arc<Client>,
    ) -> Result<Action, Error> {
        // Get the client from context
        let client = context.as_ref().clone();

        // Get a reference to the namespace of this LeaksignalIstio
        let namespace = leaksignal_istio.namespace().ok_or_else(|| {
            Error::UserInputError(
                "Expected LeaksignalIstio resource to be namespaced. Can't deploy to an unknown namespace."
                    .into(),
            )
        })?;

        // Get all LeaksignalIstio objects in the namespace
        let namespaced_istios: Api<LeaksignalIstio> = Api::namespaced(client.clone(), &namespace);
        let namespaced_istio_list = namespaced_istios.list(&ListParams::default()).await?;

        if !namespaced_istio_list.items.is_empty() {
            let name = leaksignal_istio.name_any();
            info!(
                "LeaksignalIstio: applying namespace level configuration to {} in ns {}",
                name, namespace
            );
            // If a namespace-specific LeaksignalIstio exists, then apply that configuration
            apply(
                client,
                &name,
                &namespace,
                &OwnerInfo {
                    kind: "LeaksignalIstio".to_string(),
                    name: name.clone(),
                    uid: leaksignal_istio.uid().unwrap_or_default(),
                },
                &leaksignal_istio.spec.inner,
                namespaced_istios,
            )
            .await?;
        } else {
            // If no namespace-specific LeaksignalIstio exists, apply the configuration from the ClusterLeaksignalIstio
            // Get all ClusterLeaksignalIstio objects
            let cluster_istios: Api<ClusterLeaksignalIstio> = Api::all(client.clone());
            let cluster_istio_list = cluster_istios.list(&ListParams::default()).await?;

            if cluster_istio_list.items.len() > 1 {
                return Err(Error::UserInputError(format!(
                    "More than one cluster default defined: {:?}",
                    cluster_istio_list.items
                )));
            }
            // Find the first ClusterLeaksignalIstio that applies to this namespace and apply its configuration
            if let Some(cluster_istio) = cluster_istio_list.items.first() {
                let name = cluster_istio.name_any();
                info!(
                    "LeaksignalIstio: applying cluster level configuration to {} in ns {}",
                    name, namespace
                );
                apply(
                    client,
                    &name,
                    &namespace,
                    &OwnerInfo {
                        kind: "ClusterLeaksignalIstio".to_string(),
                        name: name.clone(),
                        uid: cluster_istio.uid().unwrap_or_default(),
                    },
                    &cluster_istio.spec.inner,
                    cluster_istios,
                )
                .await?;
            }
        }

        Ok(Action::await_change())
    }

    fn on_error(leak: Arc<LeaksignalIstio>, error: &Error, _context: Arc<Client>) -> Action {
        error!("Ns reconciliation error:\n{:?}.\n{:?}", error, leak);
        Action::requeue(Duration::from_secs(5))
    }
}

#[derive(CustomResource, Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[kube(
    group = "leaksignal.com",
    version = "v1",
    kind = "ClusterLeaksignalIstio",
    singular = "cluster-leaksignal-istio",
    plural = "cluster-leaksignal-istios"
)]
struct ClusterLeaksignalIstioSpec {
    #[serde(flatten)]
    inner: CRDValues,
}

impl ClusterLeaksignalIstioSpec {
    async fn reconcile(
        cluster_leaksignal_istio: Arc<ClusterLeaksignalIstio>,
        context: Arc<Client>,
    ) -> Result<Action, Error> {
        // Get the client from context
        let client = context.as_ref().clone();

        // Get a list of all namespaces or the specified ones
        let namespaces: Api<Namespace> = Api::all(client.clone());
        let ns_list =
            // If namespaces field is empty, we will get all namespaces
            namespaces
                .list(&ListParams::default().labels("istio-injection=enabled"))
                .await?
                .iter()
                .map(|ns| ns.name_any())
                .collect::<Vec<_>>();

        // Iterate over the namespaces
        for ns in ns_list {
            // Check for a LeaksignalIstio in the namespace

            let leaksignal_istio_api: Api<LeaksignalIstio> = Api::namespaced(client.clone(), &ns);
            if leaksignal_istio_api
                .list(&ListParams::default())
                .await?
                .items
                .is_empty()
            {
                let name = cluster_leaksignal_istio.name_any();
                info!(
                    "ClusterLeaksignalIstio: applying cluster level configuration to {} in ns {}",
                    name, ns
                );
                // If LeaksignalIstio does not exist, use the ClusterLeaksignalIstio configuration
                apply::<ClusterLeaksignalIstio>(
                    client.clone(),
                    &name,
                    &ns,
                    &OwnerInfo {
                        kind: "ClusterLeaksignalIstio".to_string(),
                        name: name.clone(),
                        uid: cluster_leaksignal_istio.uid().unwrap_or_default(),
                    },
                    &cluster_leaksignal_istio.spec.inner,
                    Api::all(client.clone()),
                )
                .await?;
            }
        }

        Ok(Action::await_change())
    }

    fn on_error(leak: Arc<ClusterLeaksignalIstio>, error: &Error, _context: Arc<Client>) -> Action {
        error!("Cluster reconciliation error:\n{:?}.\n{:?}", error, leak);
        Action::requeue(Duration::from_secs(5))
    }
}

/// handles creation of EnvoyFilters, refreshing of pods, and removal of deleted EnvoyFilters
async fn apply<T>(
    client: Client,
    name: &str,
    namespace: &str,
    owner: &OwnerInfo,
    values: &CRDValues,
    resource_api: Api<T>,
) -> Result<(), Error>
where
    T: Resource + Clone + DeserializeOwned + Debug,
    T::DynamicType: Default,
{
    let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
        "networking.istio.io",
        "v1alpha3",
        "EnvoyFilter",
    ));
    let filters: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &resource);

    if let Some(current_filter) = filters.get_opt(&values.istio_name).await? {
        let current_owner = current_filter
            .owner_references()
            .iter()
            .find(|current_owner| {
                current_owner.api_version == "v1"
                    && (current_owner.kind == "LeaksignalIstio"
                        || current_owner.kind == "ClusterLeaksignalIstio")
            });
        if let Some(current_owner) = current_owner {
            if current_owner.uid != owner.uid {
                return Err(Error::UserInputError("conflict detected in istioName fields -- is there more than one LeaksignalIstio with the same istioName value (or default) -- skipping reconcile".to_string()));
            }
        }
    }

    // Fetch the current state of the LeaksignalIstio or ClusterLeaksignalIstio resource
    let leaksignal_istio_resource: T = resource_api.get(name).await?;

    let has_finalizer = leaksignal_istio_resource
        .finalizers()
        .contains(&"finalizer.leaksignal.com".into());
    let is_deleted = leaksignal_istio_resource
        .meta()
        .deletion_timestamp
        .is_some();

    // If the object is being deleted and our finalizer is present we need to remove the finalizer
    if is_deleted && has_finalizer {
        info!(
            "{} deleted in ns {}, removing EnvoyFilter and finalizer",
            name, namespace
        );
        // Delete the EnvoyFilter
        if let Err(e) = filters
            .delete(&values.istio_name, &DeleteParams::default())
            .await
        {
            error!(
                "failed to delete EnvoyFilter {} in {}: {}",
                values.istio_name, namespace, e
            )
        }

        // Then remove our finalizer from the list
        let patch = json!({
            "metadata": {
                "finalizers": Vec::<String>::new(),
            }
        });
        let patch = Patch::Merge(&patch);
        resource_api
            .patch(name, &PatchParams::default(), &patch)
            .await?;
        values.deapply_native(client.clone(), namespace).await?;
        values.refresh_pods(client.clone(), namespace).await?;
    } else {
        let finalizer = json!({
            "metadata": {
                "finalizers": ["finalizer.leaksignal.com"]
            }
        });
        let patch: Patch<&Value> = Patch::Merge(&finalizer);
        resource_api
            .patch(name, &PatchParams::default(), &patch)
            .await?;
    }

    // if the object has not been deleted, apply the filter
    if !is_deleted {
        info!("patching {}", values.istio_name);

        let mut proxy_url: Url = values.proxy_pull_location.parse().map_err(|e| {
            Error::UserInputError(format!("failed to parse proxyPullLocation: {e:?}"))
        })?;
        if proxy_url.cannot_be_a_base()
            || (proxy_url.scheme() != "https" && proxy_url.scheme() != "http")
        {
            return Err(Error::UserInputError(
                "proxyPullLocation must be a http(s) URL".to_string(),
            ));
        }
        proxy_url
            .path_segments_mut()
            .unwrap()
            .push(&values.proxy_version);
        if values.native {
            proxy_url.path_segments_mut().unwrap().push("leaksignal.so");
        } else {
            proxy_url
                .path_segments_mut()
                .unwrap()
                .push("leaksignal.wasm");
        }
        let path =
            proxy_mgr::check_or_add_proxy(&values.proxy_hash, values.native, &proxy_url).await?;

        let filter = create_json(namespace, owner, values, &path)?;
        let mut new: DynamicObject = serde_json::from_value(filter)
            .map_err(|e| Error::UserInputError(format!("failed to parse new envoyfilter: {e}")))?;

        values.apply_native(client.clone(), namespace).await?;

        match filters.get_opt(&values.istio_name).await? {
            Some(current) => {
                if new.data == current.data {
                    info!("skipping patch due to no spec change");
                    return Ok(());
                }

                new.metadata.resource_version = current.metadata.resource_version;
                filters
                    .replace(&values.istio_name, &PostParams::default(), &new)
                    .await?;
            }
            None => {
                filters.create(&PostParams::default(), &new).await?;
            }
        }

        values.refresh_pods(client, namespace).await?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), kube::Error> {
    env_logger::Builder::new()
        .parse_env(env_logger::Env::default().default_filter_or("info"))
        .init();
    let client = Client::try_default().await?;

    let certificate = match webhook::load_cert(client.clone()).await {
        Ok(x) => x,
        Err(e) => {
            error!("failed to create/load webhook TLS cert: {e:?}");
            std::process::exit(1);
        }
    };

    if let Err(e) = webhook::prepare_webhook(client.clone(), &certificate).await {
        error!("failed to apply webhook config: {e:?}");
        std::process::exit(1);
    }

    tokio::spawn(async move {
        match webhook::run_webhook(&certificate).await {
            Ok(()) => {
                error!("webhook terminated successfully");
            }
            Err(e) => {
                error!("webhook failed to run: {e:?}");
            }
        }
    });
    tokio::spawn(proxy_mgr::run_nfs_server());
    tokio::spawn(pod_scan::run_pod_scan(client.clone()));

    // Configure your controllers
    let leaksignal_istio_controller = Controller::new(Api::all(client.clone()), Config::default());
    let cluster_leaksignal_istio_controller =
        Controller::new(Api::all(client.clone()), Config::default());

    // Run both controllers
    let leaksignal_istio_drainer = leaksignal_istio_controller
        .run(
            LeaksignalIstioSpec::reconcile,
            LeaksignalIstioSpec::on_error,
            Arc::new(client.clone()),
        )
        .for_each(|reconciliation_result| async move {
            match reconciliation_result {
                Ok(leak_resource) => {
                    info!(
                        "Ns reconciliation successful. Resource: {:?}",
                        leak_resource
                    );
                }
                Err(reconciliation_err) => {
                    error!("Ns reconciliation error: {:?}", reconciliation_err)
                }
            }
        });
    let cluster_leaksignal_istio_drainer = cluster_leaksignal_istio_controller
        .run(
            ClusterLeaksignalIstioSpec::reconcile,
            ClusterLeaksignalIstioSpec::on_error,
            Arc::new(client.clone()),
        )
        .for_each(|reconciliation_result| async move {
            match reconciliation_result {
                Ok(leak_resource) => {
                    info!(
                        "Cluster reconciliation successful. Resource: {:?}",
                        leak_resource
                    );
                }
                Err(reconciliation_err) => {
                    error!("Cluster reconciliation error: {:?}", reconciliation_err)
                }
            }
        });

    // Combine both drainers
    futures::future::join(leaksignal_istio_drainer, cluster_leaksignal_istio_drainer).await;
    Ok(())
}
