use std::{borrow::Cow, collections::BTreeMap, convert::Infallible, net::SocketAddr};

use base64::{prelude::BASE64_STANDARD, Engine};
use json_patch::{AddOperation, PatchOperation, ReplaceOperation};
use k8s_openapi::api::{
    admissionregistration::v1::MutatingWebhookConfiguration,
    core::v1::{Pod, Secret, Service},
};
use kube::{
    api::{ListParams, PatchParams, PostParams},
    core::{
        admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
        ObjectMeta,
    },
    Api, Client, ResourceExt,
};
use log::{error, info, warn};
use rcgen::{Certificate, CertificateParams};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use warp::{
    reply::{self, Reply},
    Filter,
};

use crate::{ClusterLeaksignalIstio, Error, LeaksignalIstio};

const WEBHOOK_SECRET_NAME: &str = "leaksignal-operator-webhook-cert";

#[derive(Serialize, Deserialize)]
pub struct SecretData {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
}

impl TryFrom<Secret> for SecretData {
    type Error = Error;

    fn try_from(mut value: Secret) -> Result<Self, Self::Error> {
        Ok(SecretData {
            key: value
                .data
                .as_mut()
                .and_then(|x| x.remove("tls.key"))
                .ok_or_else(|| Error::UserInputError("missing tls.key from secret".to_string()))?
                .0,
            cert: value
                .data
                .as_mut()
                .and_then(|x| x.remove("tls.crt"))
                .ok_or_else(|| Error::UserInputError("missing tls.crt from secret".to_string()))?
                .0,
        })
    }
}

pub async fn load_cert(client: Client) -> Result<SecretData, Error> {
    let secret_api: Api<Secret> = Api::default_namespaced(client.clone());
    if let Some(secret) = secret_api.get_opt(WEBHOOK_SECRET_NAME).await? {
        return secret.try_into();
    };

    let cert = Certificate::from_params(CertificateParams::new(vec![format!(
        "leaksignal-operator.{}.svc",
        client.default_namespace()
    )]))?;

    let mut data = BTreeMap::new();
    data.insert(
        "tls.crt".to_string(),
        k8s_openapi::ByteString(cert.serialize_pem()?.into_bytes()),
    );
    data.insert(
        "tls.key".to_string(),
        k8s_openapi::ByteString(cert.serialize_private_key_pem().into_bytes()),
    );
    let out = secret_api
        .create(
            &PostParams::default(),
            &Secret {
                data: Some(data),
                immutable: Some(true),
                metadata: ObjectMeta {
                    name: Some(WEBHOOK_SECRET_NAME.to_string()),
                    namespace: Some(client.default_namespace().to_string()),
                    ..Default::default()
                },
                type_: Some("kubernetes.io/tls".to_string()),
                ..Default::default()
            },
        )
        .await;

    match out {
        Ok(out) => out.try_into(),
        Err(e) => {
            if let Some(secret) = secret_api.get_opt(WEBHOOK_SECRET_NAME).await? {
                return secret.try_into();
            };
            Err(e.into())
        }
    }
}

pub async fn prepare_webhook(client: Client, secret: &SecretData) -> Result<(), Error> {
    let api: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    let input = api.get_opt("z-leaksignal-operator").await?;
    let target: MutatingWebhookConfiguration =
        serde_json::from_value(webhook(client.default_namespace(), secret))
            .map_err(|e| Error::UserInputError(format!("invalid webhook config: {e:?}")))?;
    if input.is_none() || input.as_ref() != Some(&target) {
        api.patch(
            "z-leaksignal-operator",
            &PatchParams::apply("leaksignal.com"),
            &kube::api::Patch::Apply(target),
        )
        .await?;
    }
    Ok(())
}

fn webhook(namespace: &str, secret: &SecretData) -> Value {
    json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "MutatingWebhookConfiguration",
        "metadata": {
            "labels": {
                "app": "leaksignal-operator",
            },
            "name": "z-leaksignal-operator",
        },
        "webhooks": [{
            "admissionReviewVersions": ["v1beta1", "v1"],
            "clientConfig": {
                "caBundle": BASE64_STANDARD.encode(&secret.cert),
                "service": {
                    "name": "leaksignal-operator",
                    "namespace": namespace,
                    "path": "/mutate",
                    "port": 8443,
                },
            },
            "name": "z-leaksignal-operator.leaksignal.com",
            "failurePolicy": "Ignore",
            "matchPolicy": "Equivalent",
            "reinvocationPolicy": "IfNeeded",
            "objectSelector": {
                "matchExpressions": [{
                    "key": "ls-native",
                    "operator": "NotIn",
                    "values": ["excluded"],
                }]
            },
            "rules": [{
                "apiGroups": [""],
                "apiVersions": ["v1"],
                "operations": ["CREATE"],
                "resources": ["pods"],
                "scope": "*",
            }],
            "sideEffects": "None",
            "timeoutSeconds": 10,
        }],
    })
}

pub async fn run_webhook(secret: &SecretData) -> Result<(), Error> {
    let routes = warp::path("mutate")
        .and(warp::body::json())
        .and_then(mutate_handler)
        .with(warp::log::log("webhook"));

    let mut bind = std::env::var("ADMISSION_BIND").unwrap_or_default();
    if bind.is_empty() {
        bind = "0.0.0.0:8443".to_string();
    }
    let bind: SocketAddr = bind
        .parse()
        .map_err(|e| Error::UserInputError(format!("invalid ADMISSION_BIND ({bind}): {e}")))?;

    info!("webhook listening on {bind}");

    warp::serve(warp::post().and(routes))
        .tls()
        .cert(&secret.cert)
        .key(&secret.key)
        .run(bind)
        .await;

    Ok(())
}

async fn mutate_handler(body: AdmissionReview<Pod>) -> Result<impl Reply, Infallible> {
    let req: AdmissionRequest<_> = match body.try_into() {
        Ok(req) => req,
        Err(err) => {
            error!("invalid request: {}", err);
            return Ok(reply::json(&AdmissionResponse::invalid(err).into_review()));
        }
    };

    let mut res = AdmissionResponse::from(&req);
    if let Some(obj) = req.object {
        let name = obj.name_any();
        res = match mutate(res.clone(), &obj).await {
            Ok(res) => {
                info!("accepted: {:?} on Pod {}", req.operation, name);
                res
            }
            Err(err) => {
                warn!("denied: {:?} on {} ({})", req.operation, name, err);
                res.deny(err.to_string())
            }
        };
    };
    // Wrap the AdmissionResponse wrapped in an AdmissionReview
    Ok(reply::json(&res.into_review()))
}

async fn mutate(mut res: AdmissionResponse, obj: &Pod) -> Result<AdmissionResponse, Error> {
    if !obj
        .metadata
        .annotations
        .as_ref()
        .map(|v| v.contains_key("sidecar.istio.io/status"))
        .unwrap_or_default()
    {
        return Ok(res);
    }

    let Some(spec) = &obj.spec else {
        return Ok(res);
    };

    let Some(istio_container_idx) = spec.containers.iter().position(|x| x.name == "istio-proxy")
    else {
        return Ok(res);
    };

    let container = &spec.containers[istio_container_idx];

    let Some((_, tag)) = container.image.as_deref().and_then(|x| x.split_once(':')) else {
        return Ok(res);
    };

    let Some(ns) = obj.namespace() else {
        return Ok(res);
    };

    let client = Client::try_default().await?;
    let ns_api: Api<LeaksignalIstio> = Api::namespaced(client.clone(), &ns);
    let cluster_api: Api<ClusterLeaksignalIstio> = Api::all(client.clone());

    let ns_apis = ns_api.list(&ListParams::default()).await?.items;

    let mut applicable_crd = ns_apis
        .iter()
        .find(|x| {
            x.spec
                .inner
                .workload_selector
                .labels
                .iter()
                .all(|(k, v)| obj.labels().get(k) == Some(v))
        })
        .or_else(|| {
            ns_apis
                .iter()
                .find(|x| x.spec.inner.workload_selector.labels.is_empty())
        })
        .map(|x| x.spec.inner.clone());
    if applicable_crd.is_none() {
        let apis = cluster_api.list(&ListParams::default()).await?.items;
        applicable_crd = apis
            .iter()
            .find(|x| {
                x.spec
                    .inner
                    .workload_selector
                    .labels
                    .iter()
                    .all(|(k, v)| obj.labels().get(k) == Some(v))
            })
            .or_else(|| {
                apis.iter()
                    .find(|x| x.spec.inner.workload_selector.labels.is_empty())
            })
            .map(|x| x.spec.inner.clone());
    }
    let Some(crd) = applicable_crd else {
        // no leaksignal deployment
        return Ok(res);
    };

    let mut patches = vec![];

    if !spec
        .volumes
        .as_ref()
        .map(|x| x.iter().any(|x| x.name == "leaksignal-proxy"))
        .unwrap_or_default()
    {
        let services: Api<Service> = Api::default_namespaced(client.clone());
        let service = services
            .get_opt("leaksignal-operator")
            .await?
            .ok_or_else(|| {
                Error::UserInputError(format!(
                    "missing leaksignal-operator service, cannot assign NFS"
                ))
            })?;
        let cluster_ip = service
            .spec
            .as_ref()
            .and_then(|x| x.cluster_ip.as_deref())
            .ok_or_else(|| {
                Error::UserInputError(format!(
                    "leaksignal-operator service has no clusterIP, cannot assign NFS"
                ))
            })?;
        patches.extend([
            PatchOperation::Add(AddOperation {
                path: format!("/spec/volumes/0"),
                value: json!({
                    "name": "leaksignal-proxy",
                    "nfs": {
                        "server": cluster_ip,
                        "path": "/",
                        "readOnly": true,
                    },
                }),
            }),
            PatchOperation::Add(AddOperation {
                path: format!("/spec/containers/{istio_container_idx}/volumeMounts/0"),
                value: json!({
                    "name": "leaksignal-proxy",
                    "mountPath": "/ls-proxy/",
                }),
            }),
        ]);
    }

    if obj
        .metadata
        .labels
        .as_ref()
        .and_then(|x| x.get("ls-deployed").map(|x| &**x))
        != Some("1")
    {
        patches.push(PatchOperation::Add(AddOperation {
            path: format!("/metadata/labels/ls-deployed"),
            value: json!("1"),
        }));
    }

    if crd.native {
        let new_image = if crd.native_repo.contains(':') {
            Cow::Borrowed(&*crd.native_repo)
        } else {
            Cow::Owned(format!("{}:{tag}", crd.native_repo))
        };

        if container.resources.is_none() {
            patches.extend([PatchOperation::Add(AddOperation {
                path: format!("/spec/containers/{istio_container_idx}/resources"),
                value: json!({"limits": {"memory": "1Gi"}}),
            })]);
        }
        if container
            .resources
            .as_ref()
            .map(|x| x.limits.is_none())
            .unwrap_or_default()
        {
            patches.extend([PatchOperation::Add(AddOperation {
                path: format!("/spec/containers/{istio_container_idx}/resources/limits"),
                value: json!({"memory": "1Gi"}),
            })]);
        }
        if container
            .resources
            .as_ref()
            .map(|x| {
                x.limits
                    .as_ref()
                    .map(|x| x.get("memory").is_none())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
        {
            patches.extend([PatchOperation::Add(AddOperation {
                path: format!("/spec/containers/{istio_container_idx}/resources/limits/memory"),
                value: json!("1Gi"),
            })]);
        }

        patches.extend([
            PatchOperation::Replace(ReplaceOperation {
                path: format!("/spec/containers/{istio_container_idx}/image"),
                value: serde_json::Value::String(new_image.into_owned()),
            }),
            PatchOperation::Replace(ReplaceOperation {
                path: format!("/spec/containers/{istio_container_idx}/resources/limits/memory"),
                value: serde_json::Value::String(crd.native_proxy_memory_limit),
            }),
        ]);
    }

    if !patches.is_empty() {
        res = res.with_patch(json_patch::Patch(patches))?;
    }

    Ok(res)
}
