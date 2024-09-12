use std::{
    borrow::Cow, collections::BTreeMap, convert::Infallible, fmt::Write, net::SocketAddr,
    path::PathBuf, time::Duration,
};

use base64::{prelude::BASE64_STANDARD, Engine};
use json_patch::{AddOperation, PatchOperation, ReplaceOperation};
use k8s_openapi::api::{
    admissionregistration::v1::MutatingWebhookConfiguration,
    core::v1::{Container, Pod, Secret},
};
use kube::{
    api::{ListParams, Patch, PatchParams, PostParams},
    core::{
        admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
        ObjectMeta,
    },
    Api, Client, ResourceExt,
};
use log::{error, info, warn};
use rcgen::{CertificateParams, KeyPair};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use warp::{
    reply::{self, Reply},
    Filter,
};

use crate::{
    intercept::GeneratedCA,
    proxy_mgr::{get_subject_hash, FILE_LOCATION},
    CRDValues, ClusterLeaksignalIstio, Error, LeaksignalIstio,
};

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

    let key_pair = KeyPair::generate()?;
    let cert = CertificateParams::new(vec![format!(
        "leaksignal-operator.{}.svc",
        client.default_namespace()
    )])?
    .self_signed(&key_pair)?;

    let mut data = BTreeMap::new();
    data.insert(
        "tls.crt".to_string(),
        k8s_openapi::ByteString(cert.pem().into_bytes()),
    );
    data.insert(
        "tls.key".to_string(),
        k8s_openapi::ByteString(key_pair.serialize_pem().into_bytes()),
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
    let cert = secret.cert.clone();
    let routes = warp::post()
        .and(
            warp::path("mutate")
                .and(warp::body::json())
                .and(warp::any().map(move || cert.clone()))
                .and_then(mutate_handler),
        )
        .or(warp::get().and(
            warp::path("proxy")
                .and(warp::path::end())
                .and(warp::header("ns"))
                .and(warp::header("name"))
                .and(warp::header::optional("hash"))
                .and_then(proxy_request),
        ))
        .or(warp::get().and(
            warp::path("proxy-confirm")
                .and(warp::path::end())
                .and(warp::header("ns"))
                .and(warp::header("name"))
                .and(warp::header("uid"))
                .and(warp::header("hash"))
                .and_then(proxy_confirm),
        ))
        .with(warp::log::log("webhook"));

    let mut bind = std::env::var("ADMISSION_BIND").unwrap_or_default();
    if bind.is_empty() {
        bind = "0.0.0.0:8443".to_string();
    }
    let bind: SocketAddr = bind
        .parse()
        .map_err(|e| Error::UserInputError(format!("invalid ADMISSION_BIND ({bind}): {e}")))?;

    info!("webhook listening on {bind}");

    warp::serve(routes)
        .tls()
        .cert(&secret.cert)
        .key(&secret.key)
        .run(bind)
        .await;

    Ok(())
}

async fn lookup_crd(
    client: &Client,
    ns: &str,
    name: &str,
) -> Result<Option<(CRDValues, Pod)>, Error> {
    let pod_api: Api<Pod> = Api::namespaced(client.clone(), &ns);
    let Some(pod) = pod_api.get_opt(&name).await? else {
        return Ok(None);
    };
    get_crd(&pod, &client).await.map(|x| x.map(|x| (x, pod)))
}

async fn get_proxy(crd: &CRDValues) -> Result<PathBuf, Error> {
    let proxy_url = crd.proxy_url()?;
    crate::proxy_mgr::check_or_add_proxy(&crd.proxy_hash, crd.native, &proxy_url).await
}

async fn proxy_confirm(
    ns: String,
    name: String,
    uid: String,
    hash: String,
) -> Result<impl Reply, Infallible> {
    let client = match Client::try_default().await {
        Ok(x) => x,
        Err(e) => {
            error!("failed to init client{e}");
            return Ok(warp::http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(b"k8s conn failed".to_vec()));
        }
    };
    let (crd, pod) = match lookup_crd(&client, &ns, &name).await {
        Ok(Some(x)) => x,
        Ok(None) => {
            return Ok(warp::http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(b"pod not found".to_vec()));
        }
        Err(e) => {
            error!("failed to fetch pod {ns}/{name}: {e}");
            return Ok(warp::http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(b"pod fetch failed".to_vec()));
        }
    };

    if pod.uid() != Some(uid) {
        return Ok(warp::http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(b"UID mismatch".to_vec()));
    }

    if crd.proxy_hash != hash {
        return Ok(warp::http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(b"Hash mismatch".to_vec()));
    }

    let api: Api<Pod> = Api::namespaced(client.clone(), &ns);
    let patch = json!({
        "metadata": {
            "labels": {
                "ls-proxy": &hash[..hash.len().min(63)],
            },
        }
    });
    let patch = Patch::Merge(&patch);
    if let Err(e) = api.patch(&name, &PatchParams::default(), &patch).await {
        error!("failed to patch pod {ns}/{name}: {e}");
        return Ok(warp::http::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(b"Pod patch failed".to_vec()));
    }

    Ok(warp::http::Response::builder()
        .status(StatusCode::OK)
        .body(vec![]))
}

async fn proxy_request(
    ns: String,
    name: String,
    hash: Option<String>,
) -> Result<impl Reply, Infallible> {
    let client = match Client::try_default().await {
        Ok(x) => x,
        Err(e) => {
            error!("failed to init client{e}");
            return Ok(warp::http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(b"k8s conn failed".to_vec()));
        }
    };
    let (mut crd, _) = match lookup_crd(&client, &ns, &name).await {
        Ok(Some(x)) => x,
        Ok(None) => {
            return Ok(warp::http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(b"pod not found".to_vec()));
        }
        Err(e) => {
            error!("failed to fetch pod {ns}/{name}: {e}");
            return Ok(warp::http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(b"pod fetch failed".to_vec()));
        }
    };
    for _ in 0..60 {
        if let Some(current) = &hash {
            if current == &crd.proxy_hash {
                tokio::time::sleep(Duration::from_secs(60)).await;
                (crd, _) = match lookup_crd(&client, &ns, &name).await {
                    Ok(Some(x)) => x,
                    Ok(None) => {
                        return Ok(warp::http::Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(b"pod not found".to_vec()));
                    }
                    Err(e) => {
                        error!("failed to fetch pod {ns}/{name}: {e}");
                        return Ok(warp::http::Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(b"pod fetch failed".to_vec()));
                    }
                };
                continue;
            }
        }
        break;
    }
    if hash.as_deref() == Some(&crd.proxy_hash) {
        return Ok(warp::http::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(vec![]));
    }
    let path = match get_proxy(&crd).await {
        Ok(x) => x,
        Err(e) => {
            error!("failed to fetch proxy: {e}");
            return Ok(warp::http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(b"proxy fetch failed".to_vec()));
        }
    };

    let file = FILE_LOCATION.join(path);
    let file = match tokio::fs::read(&file).await {
        Ok(x) => x,
        Err(e) => {
            log::warn!("failed to read proxy file '{}': {e}", file.display());
            return Ok(warp::http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(vec![]));
        }
    };
    let mut filename = crd.proxy_hash.clone();
    if crd.native {
        filename.push_str(".so");
    } else {
        filename.push_str(".wasm");
    }
    Ok(warp::http::Response::builder()
        .header("filename", filename)
        .body(file))
}

async fn mutate_handler(
    body: AdmissionReview<Pod>,
    cert: Vec<u8>,
) -> Result<impl Reply, Infallible> {
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
        res = match mutate(res.clone(), &obj, cert).await {
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

async fn mutate_native(
    istio_container: &Container,
    istio_container_idx: usize,
    crd: &CRDValues,
    patches: &mut Vec<PatchOperation>,
) -> Result<(), Error> {
    let Some((_, tag)) = istio_container
        .image
        .as_deref()
        .and_then(|x| x.split_once(':'))
    else {
        return Ok(());
    };

    let new_image = if crd.native_repo.contains(':') {
        Cow::Borrowed(&*crd.native_repo)
    } else {
        Cow::Owned(format!("{}:{tag}", crd.native_repo))
    };

    if istio_container.resources.is_none() {
        patches.extend([PatchOperation::Add(AddOperation {
            path: format!("/spec/containers/{istio_container_idx}/resources"),
            value: json!({"limits": {"memory": "1Gi"}}),
        })]);
    }
    if istio_container
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
    if istio_container
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
            value: serde_json::Value::String(crd.native_proxy_memory_limit.clone()),
        }),
    ]);
    Ok(())
}

async fn mutate_client_certs(
    client: &Client,
    obj: &Pod,
    crd: &CRDValues,
    patches: &mut Vec<PatchOperation>,
    cert: Vec<u8>,
) -> Result<(), Error> {
    if !obj
        .metadata
        .annotations
        .as_ref()
        .map(|v| v.contains_key("sidecar.istio.io/status"))
        .unwrap_or_default()
    {
        return Ok(());
    }
    let pod_ns = obj.namespace().unwrap_or_default();

    let Some(spec) = &obj.spec else {
        return Ok(());
    };

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

    let ca = if crd.enable_client_interception {
        GeneratedCA::generate()?
    } else {
        GeneratedCA::default()
    };
    let raw_ca = &ca.ca_cert;
    let hash = if crd.enable_client_interception {
        get_subject_hash(&ca.ca_cert)?
    } else {
        Default::default()
    };
    for (container_idx, container) in spec.containers.iter().enumerate() {
        let cert_volume = format!("{}-cert-dirs", container.name);

        if spec
            .volumes
            .as_ref()
            .map(|x| x.iter().any(|x| x.name == cert_volume))
            .unwrap_or_default()
        {
            continue;
        }

        if !crd.enable_client_interception && container.name != "istio-proxy" {
            continue;
        }

        let mut init_command = if crd.enable_client_interception {
            format!(
                r#"mkdir -pv /certs/etc/ssl/certs && \
mkdir -pv /certs/usr/local/share/ca-certificates/ && \
cp -frv /usr/local/share/ca-certificates/* /certs/usr/local/share/ca-certificates/ || true && \
cp -frv /etc/ssl/certs/* /certs/etc/ssl/certs/ || true && \
(cat << EOF > /certs/usr/local/share/ca-certificates/leaksignal.crt
{raw_ca}
EOF
) && \
ln -svf /usr/local/share/ca-certificates/leaksignal.crt /certs/etc/ssl/certs/ca-cert-leaksignal.crt && \
ln -svf ca-cert-leaksignal.crt /certs/etc/ssl/certs/{hash}.0 && \
cat /certs/usr/local/share/ca-certificates/leaksignal.crt >> /certs/etc/ssl/certs/ca-certificates.crt"#
            )
            //TODO: different ca-bundle for rhel?
        } else {
            String::new()
        };

        if container.name == "istio-proxy" {
            let raw_cert = &ca.ca_cert;
            let raw_key = &ca.ca_key;
            let raw_operator = String::from_utf8_lossy(&cert);
            let ns = client.default_namespace();
            let mut filename = crd.proxy_hash.clone();
            if crd.native {
                filename.push_str(".so");
            } else {
                filename.push_str(".wasm");
            }
            if crd.enable_client_interception {
                write!(
                    &mut init_command,
                    r#" && \
mkdir -pv /certs/ls-cert && \
mkdir -pv /certs/ls-proxy && \
(cat << EOF > /certs/ls-cert/global.crt
{raw_cert}
EOF
) && \
(cat << EOF > /certs/ls-cert/global.key
{raw_key}
EOF
) && \
(cat << EOF > /certs/ls-cert/operator.crt
{raw_operator}
EOF
) && \
export filename=$(curl -v --cacert /certs/ls-cert/operator.crt --max-time 180 -H 'ns: {pod_ns}' -H "name: $HOSTNAME" -o /certs/ls-proxy/temp -D - https://leaksignal-operator.{ns}.svc:8443/proxy | grep -i "filename" | awk '{{print $2}}' | tr -d '\r') && \
mv -v /certs/ls-proxy/temp /certs/ls-proxy/$filename && \
base=${{filename%.*}}
curl -v --cacert /certs/ls-cert/operator.crt --max-time 900 --connect-timeout 900 -H 'ns: {pod_ns}' -H "name: $HOSTNAME" -H "uid: $POD_UID" -H "hash: $base" https://leaksignal-operator.{ns}.svc:8443/proxy-confirm"#
                )
                .unwrap();
            } else {
                write!(
                    &mut init_command,
                    r#"mkdir -pv /certs/ls-cert && \
mkdir -pv /certs/ls-proxy && \
cat << EOF > /certs/ls-cert/operator.crt
{raw_operator}
EOF && \
export filename=$(curl --cacert /certs/ls-cert/operator.crt --max-time 180 -H 'ns: {pod_ns}' -H "name: $HOSTNAME" -o /certs/ls-proxy/temp -D - https://leaksignal-operator.{ns}.svc:8443/proxy | grep -i "filename" | awk '{{print $2}}' | tr -d '\r') && \
mv -v /certs/ls-proxy/temp /certs/ls-proxy/$filename && \
base=${{filename%.*}}
curl --cacert /certs/ls-cert/operator.crt --max-time 900 --connect-timeout 900 -H 'ns: {pod_ns}' -H "name: $HOSTNAME" -H "uid: $POD_UID" -H "hash: $base" https://leaksignal-operator.{ns}.svc:8443/proxy-confirm"#
                )
                .unwrap();
            }

            let script = format!(
                r#"#!/bin/bash
while true; do
    filename=$(basename $(ls -t /ls-proxy/*.{{so,wasm}} 2>/dev/null | head -n1))
    base=${{filename%.*}}
    echo "checking for proxy updates from $base"
    headers=$(curl -s --cacert /ls-cert/operator.crt --max-time 3600 --keepalive-time 30 --connect-timeout 60 -H 'ns: {pod_ns}' -H "name: $HOSTNAME" -H "hash: $base" -o /ls-proxy/temp -D - https://leaksignal-operator.{ns}.svc:8443/proxy | tr -d '\r')
    status=$(echo -n "$headers" | grep -i "HTTP/" | awk '{{print $2}}' | tr -d '\n')
    if [ "$status" = "200" ]; then
        new_filename=$(echo -n "$headers" | grep -i "filename" | awk '{{print $2}}' | tr -d '\n')
        echo "Proxy fetch successful for $new_filename"
        mv -vf /ls-proxy/temp /ls-proxy/$new_filename
        new_base=${{new_filename%.*}}
        curl -s --cacert /ls-cert/operator.crt --max-time 900 --connect-timeout 900 -H 'ns: {pod_ns}' -H "name: $HOSTNAME" -H "uid: $POD_UID" -H "hash: $new_base" https://leaksignal-operator.{ns}.svc:8443/proxy-confirm
    elif [ "$status" = "304" ]; then
        :
    else
        if grep -qP '[^\x00-\x7F]' /ls-proxy/temp; then
            echo "Proxy fetch failed with error: $status, body: <binary>"
        else
            echo "Proxy fetch failed with error: $status, body: $(cat /ls-proxy/temp)"
        fi
    fi
    sleep 45
done
"#
            );
            // let raw_script = script
            //     .replace('\\', "\\\\")
            //     .replace('\n', "\\n")
            //     .replace('\'', r#"'"'"'"#);
            writeln!(
                &mut init_command,
                r#" && \
(cat << 'EOFEOFEOF' > /certs/ls-cert/update_proxy.sh
{script}
EOFEOFEOF
) && \
chmod +x /certs/ls-cert/update_proxy.sh
"#
            )
            .unwrap();

            patches.extend([
                PatchOperation::Add(AddOperation {
                    path: format!("/spec/containers/{container_idx}/env/0"),
                    value: json!({
                        "name": "POD_UID",
                        "valueFrom": {
                            "fieldRef": {
                                "fieldPath": "metadata.uid"
                            }
                        }
                    }),
                }),
                PatchOperation::Add(AddOperation {
                    path: format!("/spec/containers/{container_idx}/volumeMounts/0"),
                    value: json!({
                        "name": &cert_volume,
                        "mountPath": "/ls-proxy/",
                        "subPath": "ls-proxy/",
                    }),
                }),
                PatchOperation::Add(AddOperation {
                    path: format!("/spec/containers/{container_idx}/volumeMounts/0"),
                    value: json!({
                        "name": &cert_volume,
                        "mountPath": "/ls-cert/",
                        "subPath": "ls-cert/",
                    }),
                }),
                PatchOperation::Add(AddOperation {
                    path: format!("/spec/containers/{container_idx}/command"),
                    value: json!([
                        "/bin/bash",
                        "-c",
                        "/ls-cert/update_proxy.sh & \"$@\"",
                        "_",
                        "/usr/local/bin/pilot-agent",
                    ]),
                }),
            ]);

            if crd.native {
                mutate_native(container, container_idx, crd, patches).await?;
            }
        } else {
            writeln!(&mut init_command, "").unwrap();
        }

        if crd.enable_client_interception {
            patches.extend([
                PatchOperation::Add(AddOperation {
                    path: format!("/spec/containers/{container_idx}/volumeMounts/0"),
                    value: json!({
                        "name": &cert_volume,
                        "mountPath": "/etc/ssl/certs/",
                        "subPath": "etc/ssl/certs/",
                    }),
                }),
                PatchOperation::Add(AddOperation {
                    path: format!("/spec/containers/{container_idx}/volumeMounts/0"),
                    value: json!({
                        "name": &cert_volume,
                        "mountPath": "/usr/local/share/ca-certificates/",
                        "subPath": "usr/local/share/ca-certificates/",
                    }),
                }),
            ]);
        }
        let mut new_container = json!({
            "image": container.image.as_ref(),
            "imagePullPolicy": container.image_pull_policy.as_ref(),
            "name": format!("{}-cert-init", container.name),
            "volumeMounts": [
                {
                    "name": &cert_volume,
                    "mountPath": "/certs/",
                },
            ],
            "command": [
                "/bin/sh",
                "-c",
                &init_command,
            ],
            "env": [
                {
                    "name": "POD_UID",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.uid"
                        }
                    }
                }
            ],
        });
        if container.name == "istio-proxy" {
            new_container["securityContext"] = json!({
                "runAsUser": 1337,
                "runAsGroup": 1337,
                "runAsNonRoot": true,
            });
        }
        patches.extend([
            PatchOperation::Add(AddOperation {
                path: format!("/spec/volumes/0"),
                value: json!({
                    "name": &cert_volume,
                    "emptyDir": {},
                }),
            }),
            PatchOperation::Add(AddOperation {
                path: format!("/spec/initContainers/0"),
                value: new_container,
            }),
        ]);
    }
    Ok(())
}

async fn get_crd(obj: &Pod, client: &Client) -> Result<Option<CRDValues>, Error> {
    let Some(ns) = obj.namespace() else {
        return Ok(None);
    };

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
    Ok(applicable_crd)
}

async fn mutate(
    mut res: AdmissionResponse,
    obj: &Pod,
    cert: Vec<u8>,
) -> Result<AdmissionResponse, Error> {
    let client = Client::try_default().await?;

    let Some(crd) = get_crd(obj, &client).await? else {
        return Ok(res);
    };

    let mut patches = vec![];

    mutate_client_certs(&client, obj, &crd, &mut patches, cert).await?;

    if !patches.is_empty() {
        res = res.with_patch(json_patch::Patch(patches))?;
    }

    Ok(res)
}
