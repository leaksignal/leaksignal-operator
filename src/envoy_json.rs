use std::path::Path;

use serde_json::{json, Value};

use crate::{CRDValues, Error, GrpcMode};

const PATH_PREFIX: &str = "/ls-proxy/";

fn create_plugin_config(
    is_streaming: bool,
    values: &CRDValues,
    path: &Path,
) -> Result<Value, Error> {
    let mut configuration = match values.grpc_mode {
        GrpcMode::Envoy => format!(
            r"upstream_cluster: leaksignal_infra
api_key: {}
upstream_host: {}",
            values.api_key, values.upstream_location
        ),
        GrpcMode::Default => {
            let scheme = if values.tls { "https://" } else { "http://" };
            let port = if (values.tls && values.upstream_port != 443)
                || (!values.tls && values.upstream_port != 80)
            {
                format!(":{}", values.upstream_port)
            } else {
                String::new()
            };

            format!(
                r"api_key: {}
upstream_url: {scheme}{}{port}",
                values.api_key, values.upstream_location
            )
        }
    };
    if is_streaming {
        configuration.push_str("\nstreaming: true")
    }

    let vm_id = format!(
        "leaksignal_proxy_{}",
        &values.proxy_hash[..values.proxy_hash.len().min(7)]
    );

    let path = Path::new(PATH_PREFIX).join(path);

    let vm_config = if values.native {
        json!({
          "runtime": "envoy.wasm.runtime.dyn",
          "vm_id": vm_id,
          "code": {
            "local": {
              "filename": path,
            },
          },
        })
    } else {
        json!({
          "runtime": "envoy.wasm.runtime.v8",
          "vm_id": vm_id,
          "environment_variables": {
            "host_env_keys": [
              "HOSTNAME",
              "POD_NAME",
              "INSTANCE_IP",
              "ISTIO_META_WORKLOAD_NAME",
              "ISTIO_META_MESH_ID",
              "TRUST_DOMAIN",
              "POD_NAMESPACE",
              "SERVICE_ACCOUNT"
            ]
          },
          "code": {
            "local": {
              "filename": path,
            },
          },
        })
    };

    Ok(json!({
      "name": "leaksignal",
      // "root_id": "leaksignal",
      "configuration": {
        "@type": "type.googleapis.com/google.protobuf.StringValue",
        "value": configuration,
      },
      "fail_open": values.fail_open,
      "vm_config": vm_config,
    }))
}

pub struct OwnerInfo {
    pub kind: String,
    pub name: String,
    pub uid: String,
}

impl OwnerInfo {
    pub fn owner_reference(&self) -> Value {
        json!({
          "apiVersion": "v1",
          "blockOwnerDeletion": true,
          "kind": self.kind,
          "name": self.name,
          "uid": self.uid,
        })
    }
}

fn create_transport_socket(location: &str, ca_bundle: &str) -> Value {
    json!({
      "name": "envoy.transport_sockets.tls",
      "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
        "sni": location,
        "common_tls_context": {
        "validation_context": {
          "match_typed_subject_alt_names": [
          {
            "san_type": "DNS",
            "matcher": {
            "exact": location
            }
          }
          ],
          "trusted_ca": {
            "filename": ca_bundle
          }
        }
        }
      }
    })
}

/// creates json that will be applied to EnvoyFilter
pub fn create_json(
    namespace: &str,
    owner: &OwnerInfo,
    values: &CRDValues,
    path: &Path,
) -> Result<Value, Error> {
    let mut infra_cluster = json!({
      "name": "leaksignal_infra",
      "type": "STRICT_DNS",
      "http2_protocol_options": {},
      "dns_lookup_family": "V4_PREFERRED",
      "lb_policy": "ROUND_ROBIN",
      "load_assignment": {
        "cluster_name": "leaksignal_infra0",
        "endpoints": [
          {
            "lb_endpoints": [
              {
                "endpoint": {
                  "address": {
                    "socket_address": {
                      "address": values.upstream_location,
                      "port_value": values.upstream_port
                    }
                  }
                }
              }
            ]
          }
        ]
      },
    });
    if values.tls && !values.native {
        infra_cluster.as_object_mut().unwrap().insert(
            "transport_socket".to_string(),
            create_transport_socket(&values.upstream_location, &values.ca_bundle),
        );
    }

    let mut patches = vec![
        json!({
          "applyTo": "HTTP_FILTER",
          "match": {
            "listener": {
              "filterChain": {
                "filter": {
                  "name": "envoy.filters.network.http_connection_manager",
                  "subFilter": {
                    "name": "envoy.filters.http.router"
                  }
                }
              }
            }
          },
          "patch": {
            "operation": "INSERT_BEFORE",
            "value": {
              "name": "leaksignal-proxy",
              "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
                "config": create_plugin_config(false, values, path)?,
              }
            }
          }
        }),
        json!({
          "applyTo": "CLUSTER",
          "match": {
            "context": "ANY"
          },
          "patch": {
            "operation": "ADD",
            "value": infra_cluster,
          }
        }),
    ];

    if values.enable_streaming {
        patches.push(json!({
          "applyTo": "NETWORK_FILTER",
          "match": {
            "context": "ANY",
            "listener": {
              "filterChain": {
                "filter": {
                  "name": "envoy.filters.network.tcp_proxy"
                }
              }
            }
          },
          "patch": {
            "operation": "INSERT_BEFORE",
            "value": {
              "name": "leaksignal-proxy-stream",
              "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.network.wasm.v3.Wasm",
                "config": create_plugin_config(true, values, path)?,
              }
            }
          }
        }));
    }

    let mut workload_selector = values.workload_selector.clone();
    workload_selector
        .labels
        .insert("ls-deployed".to_string(), "1".to_string());
    workload_selector.labels.insert(
        "ls-proxy".to_string(),
        values.proxy_hash[..values.proxy_hash.len().min(63)].to_string(),
    );

    Ok(json!({
      "apiVersion": "networking.istio.io/v1alpha3",
      "kind": "EnvoyFilter",
      "metadata": {
        "name": &values.istio_name,
        "namespace": namespace,
        "ownerReferences": [
          owner.owner_reference(),
        ],
      },
      "spec": {
        "configPatches": patches,
        "workloadSelector": workload_selector,
      }
    }))
}
