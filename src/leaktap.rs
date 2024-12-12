use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, DaemonSetSpec},
        core::v1::{
            Container, EnvVar, HostPathVolumeSource, PodSpec, PodTemplateSpec, SecurityContext,
            Volume, VolumeMount,
        },
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference},
};
use kube::{
    api::{ObjectMeta, PostParams},
    runtime::controller::Action,
    Api, Client, CustomResource, ResourceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Error;

fn default_repo() -> String {
    "leaksignal/leaktap:latest".to_string()
}

fn default_upstream() -> String {
    "https://ingestion.app.leaksignal.com".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(CustomResource, Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[kube(
    group = "leaksignal.com",
    version = "v1",
    kind = "LeaksignalNetworkTap",
    singular = "leaksignal-network-tap",
    plural = "leaksignal-network-taps"
)]
pub struct LeaksignalNetworkTapSpec {
    #[serde(default = "default_repo")]
    pub repo: String,
    pub api_key: String,
    #[serde(default = "default_upstream")]
    pub upstream_location: String,
    #[serde(default)]
    pub pod_selector: HashMap<String, String>,
    pub node_selector: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub namespace_selector: HashMap<String, String>,
    #[serde(default = "default_true")]
    pub enable_client_interception: bool,
}

#[derive(Serialize)]
struct OperatorParams {
    pod_selector: HashMap<String, String>,
    namespace_selector: HashMap<String, String>,
    enable_client_interception: bool,
}

impl LeaksignalNetworkTapSpec {
    pub async fn reconcile(
        tap: Arc<LeaksignalNetworkTap>,
        context: Arc<Client>,
    ) -> Result<Action, Error> {
        let client = context.as_ref().clone();

        let name = tap.name_any();

        let labels: BTreeMap<String, String> =
            [("app".to_string(), name.clone())].into_iter().collect();

        let mut daemonset = DaemonSet {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                owner_references: Some(vec![OwnerReference {
                    api_version: "v1".to_string(),
                    kind: "LeaksignalNetworkTap".to_string(),
                    name: name.clone(),
                    uid: tap.metadata.uid.clone().unwrap_or_default(),
                    ..Default::default()
                }]),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(DaemonSetSpec {
                selector: LabelSelector {
                    match_expressions: None,
                    match_labels: Some(labels.clone()),
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        name: Some(name.clone()),
                        labels: Some(labels.clone()),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        containers: vec![Container {
                            env: Some(vec![
                                EnvVar {
                                    name: "UPSTREAM".to_string(),
                                    value: Some(tap.spec.upstream_location.clone()),
                                    value_from: None,
                                },
                                EnvVar {
                                    name: "API_KEY".to_string(),
                                    value: Some(tap.spec.api_key.clone()),
                                    value_from: None,
                                },
                                EnvVar {
                                    name: "NSMGR".to_string(),
                                    value: Some("true".to_string()),
                                    value_from: None,
                                },
                                EnvVar {
                                    name: "OPERATOR_PARAMS".to_string(),
                                    value: Some(
                                        serde_json::to_string(&OperatorParams {
                                            pod_selector: tap.spec.pod_selector.clone(),
                                            namespace_selector: tap.spec.namespace_selector.clone(),
                                            enable_client_interception: tap
                                                .spec
                                                .enable_client_interception,
                                        })
                                        .unwrap(),
                                    ),
                                    value_from: None,
                                },
                            ]),
                            image: Some(tap.spec.repo.clone()),
                            image_pull_policy: Some("Always".to_string()),
                            name: "leaktap".to_string(),
                            security_context: Some(SecurityContext {
                                privileged: Some(true),
                                ..Default::default()
                            }),
                            volume_mounts: Some(vec![VolumeMount {
                                mount_path: "/host".to_string(),
                                name: "host".to_string(),
                                ..Default::default()
                            }]),
                            ..Default::default()
                        }],
                        host_network: Some(true),
                        host_pid: Some(true),
                        node_selector: tap.spec.node_selector.clone(),
                        volumes: Some(vec![Volume {
                            host_path: Some(HostPathVolumeSource {
                                path: "/".to_string(),
                                type_: Some("Directory".to_string()),
                            }),
                            name: "host".to_string(),
                            ..Default::default()
                        }]),
                        ..Default::default() // preemption_policy: todo!(),
                                             // priority: todo!(),
                                             // priority_class_name: todo!(),
                                             // service_account: todo!(),
                                             // service_account_name: todo!(),
                    }),
                },
                ..Default::default()
            }),
            status: None,
        };

        let api: Api<DaemonSet> = Api::default_namespaced(client.clone());
        match api.get_opt(&name).await? {
            Some(current) => {
                daemonset.metadata.resource_version = current.metadata.resource_version;
                api.replace(&name, &PostParams::default(), &daemonset)
                    .await?;
            }
            None => {
                api.create(&PostParams::default(), &daemonset).await?;
            }
        }

        Ok(Action::await_change())
    }

    pub fn on_error(
        tap: Arc<LeaksignalNetworkTap>,
        error: &Error,
        _context: Arc<Client>,
    ) -> Action {
        log::error!("Cluster reconciliation error:\n{:?}.\n{:?}", error, tap);
        Action::requeue(Duration::from_secs(5))
    }
}
