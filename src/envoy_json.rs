use serde_json::{json, Value};
use url::Url;

use crate::{CRDValues, Error, GrpcMode};

fn create_plugin_config(
    is_streaming: bool,
    values: &CRDValues,
    proxy_url: &Url,
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

    let mut proxy_url = proxy_url.clone();
    let vm_config = if values.native {
        proxy_url.path_segments_mut().unwrap().push("leaksignal.so");

        json!({
          "runtime": "envoy.wasm.runtime.dyn",
          "vm_id": vm_id,
          "code": {
            "remote": {
              "http_uri": {
                "uri": proxy_url,
                "timeout": "120s",
                "cluster": "leaksignal_pull"
              },
              "sha256": values.proxy_hash,
              "retry_policy": {
                "num_retries": 30
              }
            }
          }
        })
    } else {
        proxy_url
            .path_segments_mut()
            .unwrap()
            .push("leaksignal.wasm");
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
            "remote": {
              "http_uri": {
                "uri": proxy_url,
                "timeout": "120s",
                "cluster": "leaksignal_pull"
              },
              "sha256": values.proxy_hash,
              "retry_policy": {
                "num_retries": 30
              }
            }
          }
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
pub fn create_json(namespace: &str, owner: &OwnerInfo, values: &CRDValues) -> Result<Value, Error> {
    let mut proxy_url: Url = values
        .proxy_pull_location
        .parse()
        .map_err(|e| Error::UserInputError(format!("failed to parse proxyPullLocation: {e:?}")))?;
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
    if values.tls {
        infra_cluster.as_object_mut().unwrap().insert(
            "transport_socket".to_string(),
            create_transport_socket(&values.upstream_location, &values.ca_bundle),
        );
    }

    let mut pull_cluster = json!({
      "name": "leaksignal_pull",
      "type": "STRICT_DNS",
      "dns_lookup_family": "V4_PREFERRED",
      "lb_policy": "ROUND_ROBIN",
      "load_assignment": {
        "cluster_name": "leaksignal_pull0",
        "endpoints": [
          {
            "lb_endpoints": [
              {
                "endpoint": {
                  "address": {
                    "socket_address": {
                      "address": proxy_url.host_str(),
                      "port_value": proxy_url.port_or_known_default(),
                    }
                  }
                }
              }
            ]
          }
        ]
      },
    });
    if proxy_url.scheme() == "https" {
        pull_cluster.as_object_mut().unwrap().insert(
            "transport_socket".to_string(),
            create_transport_socket(proxy_url.host_str().unwrap_or_default(), &values.ca_bundle),
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
                "config": create_plugin_config(false, values, &proxy_url)?,
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
        json!({
          "applyTo": "CLUSTER",
          "match": {
            "context": "ANY"
          },
          "patch": {
            "operation": "ADD",
            "value": pull_cluster,
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
                "config": create_plugin_config(true, values, &proxy_url)?,
              }
            }
          }
        }));
    }

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
        "workloadSelector": values.workload_selector,
      }
    }))
}
