use crate::{CRDValues, Error};
use chrono::Utc;
use k8s_openapi::api::{
    apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet},
    core::v1::Pod,
};
use kube::{
    api::{ListParams, Patch, PatchParams},
    client::Client,
    core::{DynamicObject, GroupVersionKind},
    discovery::ApiResource,
    Api, ResourceExt,
};
use log::{debug, info};
use serde_json::{json, Value};
use std::collections::HashMap;

struct DeployInfo {
    pub proxy_image: Option<String>,
    pub image: Option<(String, String)>,
    pub pod_name: String,
}

struct NativeState {
    deployment_api: Api<Deployment>,
    statefulset_api: Api<StatefulSet>,
    daemonset_api: Api<DaemonSet>,
    rollout_api: Api<DynamicObject>,
    statefulsets: Vec<(DeployInfo, StatefulSet)>,
    daemonsets: Vec<(DeployInfo, DaemonSet)>,
    deployments: Vec<(DeployInfo, Deployment)>,
    rollouts: Vec<(DeployInfo, DynamicObject)>,
}

const PROXY_IMAGE_KEY: &str = "sidecar.istio.io/proxyImage";

fn restart_patch() -> Value {
    json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": Utc::now().to_rfc3339(),
                    }
                }
            }
        }
    })
}

impl CRDValues {
    async fn prepare_native(&self, client: Client, namespace: &str) -> Result<NativeState, Error> {
        let rollout_resource =
            ApiResource::from_gvk(&GroupVersionKind::gvk("argoproj.io", "v1alpha1", "Rollout"));

        // todo: handle no such resource?
        let rollout_api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), namespace, &rollout_resource);
        let mut rollouts: HashMap<String, DynamicObject> =
            match rollout_api.list(&ListParams::default()).await.map(|x| {
                x.items
                    .into_iter()
                    .filter_map(|x| Some((x.metadata.uid.clone()?, x)))
                    .collect()
            }) {
                Ok(x) => x,
                Err(e) => {
                    debug!("failed to list rollouts: {e:?}");
                    Default::default()
                }
            };

        let deployment_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        let mut deployments: HashMap<String, Deployment> = deployment_api
            .list(&ListParams::default())
            .await?
            .items
            .into_iter()
            .filter_map(|x| Some((x.metadata.uid.clone()?, x)))
            .collect();
        let statefulset_api: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
        let mut statefulsets: HashMap<String, StatefulSet> = statefulset_api
            .list(&ListParams::default())
            .await?
            .items
            .into_iter()
            .filter_map(|x| Some((x.metadata.uid.clone()?, x)))
            .collect();
        let replicaset_api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);
        let replicasets: HashMap<String, ReplicaSet> = replicaset_api
            .list(&ListParams::default())
            .await?
            .items
            .into_iter()
            .filter_map(|x| Some((x.metadata.uid.clone()?, x)))
            .collect();
        let daemonset_api: Api<DaemonSet> = Api::namespaced(client.clone(), namespace);
        let mut daemonsets: HashMap<String, DaemonSet> = daemonset_api
            .list(&ListParams::default())
            .await?
            .items
            .into_iter()
            .filter_map(|x| Some((x.metadata.uid.clone()?, x)))
            .collect();

        let pod_api: Api<Pod> = Api::namespaced(client, namespace);
        let mut pods = pod_api.list(&self.list_params()).await?.items;
        pods.retain(|pod| {
            pod.metadata
                .annotations
                .as_ref()
                .map(|v| v.contains_key("sidecar.istio.io/status"))
                .unwrap_or_default()
        });

        let mut state = NativeState {
            deployment_api,
            statefulset_api,
            rollout_api,
            daemonset_api,
            statefulsets: vec![],
            daemonsets: vec![],
            deployments: vec![],
            rollouts: vec![],
        };

        fn current_proxy_image(pod: &Pod) -> Option<(String, String)> {
            pod.spec
                .as_ref()
                .and_then(|x| x.containers.iter().find(|x| x.name == "istio-proxy"))
                .and_then(|x| x.image.as_deref())
                .and_then(|x| x.split_once(':'))
                .map(|(x, y)| (x.to_string(), y.to_string()))
        }

        for pod in pods {
            let Some(owner) = pod.metadata.owner_references.as_ref().and_then(|v| {
                v.iter().find(|v| {
                    (v.kind == "ReplicaSet" || v.kind == "StatefulSet" || v.kind == "DaemonSet")
                        && v.api_version == "apps/v1"
                })
            }) else {
                debug!("pod {}: missing owner for pod", pod.name_any());
                continue;
            };

            if owner.kind == "ReplicaSet" && owner.api_version == "apps/v1" {
                let Some(replicaset) = replicasets.get(&owner.uid) else {
                    debug!(
                        "pod {}: missing replicaset for uid: {}",
                        pod.name_any(),
                        owner.uid
                    );
                    continue;
                };
                let Some(replica_owner) =
                    replicaset.metadata.owner_references.as_ref().and_then(|v| {
                        v.iter().find(|v| {
                            (v.kind == "Deployment" && v.api_version == "apps/v1")
                                || (v.kind == "Rollout" && v.api_version == "argoproj.io/v1alpha1")
                        })
                    })
                else {
                    continue;
                };

                if replica_owner.kind == "Deployment" {
                    if let Some(deployment) = deployments.remove(&replica_owner.uid) {
                        let proxy_image = deployment
                            .spec
                            .as_ref()
                            .and_then(|x| x.template.metadata.as_ref())
                            .and_then(|x| x.annotations.as_ref())
                            .and_then(|x| x.get(PROXY_IMAGE_KEY))
                            .cloned();

                        state.deployments.push((
                            DeployInfo {
                                proxy_image,
                                image: current_proxy_image(&pod),
                                pod_name: pod.name_any(),
                            },
                            deployment,
                        ));
                    } else {
                        debug!(
                            "pod {}: missing deployment for uid: {}",
                            pod.name_any(),
                            replica_owner.uid
                        );
                    }
                } else if replica_owner.kind == "Rollout" {
                    if let Some(rollout) = rollouts.remove(&replica_owner.uid) {
                        let proxy_image = rollout
                            .data
                            .as_object()
                            .and_then(|x| x.get("spec"))
                            .and_then(|x| x.get("template"))
                            .and_then(|x| x.get("metadata"))
                            .and_then(|x| x.get("annotations"))
                            .and_then(|x| x.get(PROXY_IMAGE_KEY))
                            .and_then(|x| x.as_str())
                            .map(|x| x.to_string());

                        state.rollouts.push((
                            DeployInfo {
                                proxy_image,
                                image: current_proxy_image(&pod),
                                pod_name: pod.name_any(),
                            },
                            rollout,
                        ));
                    } else {
                        debug!(
                            "pod {}: missing rollout for uid: {}",
                            pod.name_any(),
                            replica_owner.uid
                        );
                    }
                }
            } else if owner.kind == "StatefulSet" && owner.api_version == "apps/v1" {
                if let Some(statefulset) = statefulsets.remove(&owner.uid) {
                    let proxy_image = statefulset
                        .spec
                        .as_ref()
                        .and_then(|x| x.template.metadata.as_ref())
                        .and_then(|x| x.annotations.as_ref())
                        .and_then(|x| x.get(PROXY_IMAGE_KEY))
                        .cloned();

                    state.statefulsets.push((
                        DeployInfo {
                            proxy_image,
                            image: current_proxy_image(&pod),
                            pod_name: pod.name_any(),
                        },
                        statefulset,
                    ));
                } else {
                    debug!(
                        "pod {}: missing statefulset for uid: {}",
                        pod.name_any(),
                        owner.uid
                    );
                }
            } else if owner.kind == "DaemonSet" && owner.api_version == "apps/v1" {
                if let Some(daemonset) = daemonsets.remove(&owner.uid) {
                    let proxy_image = daemonset
                        .spec
                        .as_ref()
                        .and_then(|x| x.template.metadata.as_ref())
                        .and_then(|x| x.annotations.as_ref())
                        .and_then(|x| x.get(PROXY_IMAGE_KEY))
                        .cloned();

                    state.daemonsets.push((
                        DeployInfo {
                            proxy_image,
                            image: current_proxy_image(&pod),
                            pod_name: pod.name_any(),
                        },
                        daemonset,
                    ));
                } else {
                    debug!(
                        "pod {}: missing daemonset for uid: {}",
                        pod.name_any(),
                        owner.uid
                    );
                }
            } else {
                unreachable!();
            }
        }

        Ok(state)
    }

    fn native_repo<'a>(&'a self, tag: &'a str) -> (&'a str, &'a str) {
        self.native_repo
            .split_once(':')
            .map(|x| (x.0, x.1))
            .unwrap_or((&self.native_repo, tag))
    }

    pub async fn apply_native(&self, client: Client, namespace: &str) -> Result<(), Error> {
        if !self.native || !self.refresh_pods_on_update {
            return Ok(());
        }

        let NativeState {
            deployment_api,
            statefulset_api,
            rollout_api,
            statefulsets,
            deployments,
            rollouts,
            daemonset_api,
            daemonsets,
        } = self.prepare_native(client.clone(), namespace).await?;

        for (
            DeployInfo {
                image,
                pod_name,
                proxy_image: _,
            },
            deployment,
        ) in deployments
        {
            let Some((repo, tag)) = image else {
                debug!("pod {pod_name}: missing sidecar image",);
                continue;
            };
            let (target_repo, target_tag) = self.native_repo(&tag);
            if repo == target_repo && tag == target_tag {
                debug!("pod {pod_name}: skipping because image already correct",);
                continue;
            }
            if deployment
                .spec
                .as_ref()
                .map(|x| x.paused == Some(true))
                .unwrap_or_default()
            {
                debug!("pod {pod_name}: skipping redeploy due to paused deployment");
                continue;
            }
            info!(
                "restarting deployment {}/{} for native rollout",
                deployment.metadata.namespace.as_deref().unwrap_or_default(),
                deployment.metadata.name.as_deref().unwrap_or_default()
            );
            deployment_api
                .patch(
                    deployment.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::default(),
                    &Patch::Merge(restart_patch()),
                )
                .await?;
        }

        for (
            DeployInfo {
                image,
                pod_name,
                proxy_image: _,
            },
            statefulset,
        ) in statefulsets
        {
            let Some((repo, tag)) = image else {
                debug!("pod {pod_name}: missing sidecar image",);
                continue;
            };
            let (target_repo, target_tag) = self.native_repo(&tag);
            if repo == target_repo && tag == target_tag {
                debug!("pod {pod_name}: skipping because image already correct",);
                continue;
            }
            info!(
                "restarting statefulset {}/{} for native rollout",
                statefulset
                    .metadata
                    .namespace
                    .as_deref()
                    .unwrap_or_default(),
                statefulset.metadata.name.as_deref().unwrap_or_default()
            );
            statefulset_api
                .patch(
                    statefulset.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::default(),
                    &Patch::Merge(restart_patch()),
                )
                .await?;
        }

        for (
            DeployInfo {
                image,
                pod_name,
                proxy_image: _,
            },
            rollout,
        ) in rollouts
        {
            let Some((repo, tag)) = image else {
                debug!("pod {pod_name}: missing sidecar image",);
                continue;
            };
            let (target_repo, target_tag) = self.native_repo(&tag);
            if repo == target_repo && tag == target_tag {
                debug!("pod {pod_name}: skipping because image already correct",);
                continue;
            }
            info!(
                "restarting rollout {}/{} for native rollout",
                rollout.metadata.namespace.as_deref().unwrap_or_default(),
                rollout.metadata.name.as_deref().unwrap_or_default()
            );
            rollout_api
                .patch(
                    rollout.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::default(),
                    &Patch::Merge(json!({
                        "spec": {
                            "restartAt": Utc::now().to_rfc3339(),
                        }
                    })),
                )
                .await?;
        }

        for (
            DeployInfo {
                image,
                pod_name,
                proxy_image: _,
            },
            daemonset,
        ) in daemonsets
        {
            let Some((repo, tag)) = image else {
                debug!("pod {pod_name}: missing sidecar image",);
                continue;
            };
            let (target_repo, target_tag) = self.native_repo(&tag);
            if repo == target_repo && tag == target_tag {
                debug!("pod {pod_name}: skipping because image already correct",);
                continue;
            }
            info!(
                "restarting daemonset {}/{} for native rollout",
                daemonset.metadata.namespace.as_deref().unwrap_or_default(),
                daemonset.metadata.name.as_deref().unwrap_or_default()
            );
            daemonset_api
                .patch(
                    daemonset.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::default(),
                    &Patch::Merge(restart_patch()),
                )
                .await?;
        }

        Ok(())
    }

    pub async fn refresh_pods(&self, client: Client, namespace: &str) -> Result<(), Error> {
        if self.native {
            return Ok(());
        }

        let NativeState {
            deployment_api,
            statefulset_api,
            rollout_api,
            statefulsets,
            deployments,
            rollouts,
            daemonset_api,
            daemonsets,
        } = self.prepare_native(client.clone(), namespace).await?;

        for (
            DeployInfo {
                image: _,
                pod_name,
                proxy_image: _,
            },
            deployment,
        ) in deployments
        {
            if deployment
                .spec
                .as_ref()
                .map(|x| x.paused == Some(true))
                .unwrap_or_default()
            {
                debug!("pod {pod_name}: skipping redeploy due to paused deployment");
                continue;
            }
            info!(
                "restarting deployment {}/{} for refresh",
                deployment.metadata.namespace.as_deref().unwrap_or_default(),
                deployment.metadata.name.as_deref().unwrap_or_default()
            );
            deployment_api
                .patch(
                    deployment.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::default(),
                    &Patch::Merge(restart_patch()),
                )
                .await?;
        }

        for (_, statefulset) in statefulsets {
            info!(
                "restarting statefulset {}/{} for refresh",
                statefulset
                    .metadata
                    .namespace
                    .as_deref()
                    .unwrap_or_default(),
                statefulset.metadata.name.as_deref().unwrap_or_default()
            );
            statefulset_api
                .patch(
                    statefulset.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::default(),
                    &Patch::Merge(restart_patch()),
                )
                .await?;
        }

        for (_, rollout) in rollouts {
            info!(
                "restarting rollout {}/{} for refresh",
                rollout.metadata.namespace.as_deref().unwrap_or_default(),
                rollout.metadata.name.as_deref().unwrap_or_default()
            );
            rollout_api
                .patch(
                    rollout.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::default(),
                    &Patch::Merge(json!({
                        "spec": {
                            "restartAt": Utc::now().to_rfc3339(),
                        }
                    })),
                )
                .await?;
        }

        for (_, daemonset) in daemonsets {
            info!(
                "restarting daemonset {}/{} for refresh",
                daemonset.metadata.namespace.as_deref().unwrap_or_default(),
                daemonset.metadata.name.as_deref().unwrap_or_default()
            );
            daemonset_api
                .patch(
                    daemonset.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::default(),
                    &Patch::Merge(restart_patch()),
                )
                .await?;
        }

        Ok(())
    }

    pub async fn deapply_native(&self, client: Client, namespace: &str) -> Result<(), Error> {
        if !self.native {
            return Ok(());
        }

        let NativeState {
            deployment_api,
            statefulset_api,
            daemonset_api,
            rollout_api,
            statefulsets,
            daemonsets,
            deployments,
            rollouts,
        } = self.prepare_native(client.clone(), namespace).await?;

        for (
            DeployInfo {
                image: _,
                pod_name,
                proxy_image,
            },
            deployment,
        ) in deployments
        {
            let Some(proxy_image) = proxy_image else {
                debug!("pod {pod_name}: no istio proxyImage annotation found, skipping removal");
                continue;
            };
            let Some((repo, tag)) = proxy_image.split_once(':') else {
                debug!("pod {pod_name}: no istio image tag found");
                continue;
            };

            let (target_repo, target_tag) = self.native_repo(&tag);
            if repo != target_repo || tag != target_tag {
                debug!("pod {pod_name}: skipping because image incorrect");
                continue;
            }
            info!(
                "unpatching deployment {}/{} for native",
                deployment.metadata.namespace.as_deref().unwrap_or_default(),
                deployment.metadata.name.as_deref().unwrap_or_default()
            );
            deployment_api
                .patch(
                    deployment.metadata.name.as_ref().unwrap(),
                    &PatchParams::apply("leaksignal.com").force(),
                    &Patch::Apply(json!({
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                    })),
                )
                .await?;
        }

        for (
            DeployInfo {
                proxy_image,
                image: _,
                pod_name,
            },
            statefulset,
        ) in statefulsets
        {
            let Some(proxy_image) = proxy_image else {
                debug!("pod {pod_name}: no istio proxyImage annotation found, skipping removal");
                continue;
            };
            let Some((repo, tag)) = proxy_image.split_once(':') else {
                debug!("pod {pod_name}: no istio image tag found");
                continue;
            };

            let (target_repo, target_tag) = self.native_repo(&tag);
            if repo != target_repo || tag != target_tag {
                debug!("pod {pod_name}: skipping because image incorrect");
                continue;
            }

            info!(
                "unpatching statefulset {}/{} for native",
                statefulset
                    .metadata
                    .namespace
                    .as_deref()
                    .unwrap_or_default(),
                statefulset.metadata.name.as_deref().unwrap_or_default()
            );
            statefulset_api
                .patch(
                    statefulset.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::apply("leaksignal.com").force(),
                    &Patch::Apply(json!({
                        "apiVersion": "apps/v1",
                        "kind": "StatefulSet",
                    })),
                )
                .await?;
        }

        for (
            DeployInfo {
                proxy_image,
                image: _,
                pod_name,
            },
            rollout,
        ) in rollouts
        {
            let Some(proxy_image) = proxy_image else {
                debug!("pod {pod_name}: no istio proxyImage annotation found, skipping removal");
                continue;
            };
            let Some((repo, tag)) = proxy_image.split_once(':') else {
                debug!("pod {pod_name}: no istio image tag found");
                continue;
            };

            let (target_repo, target_tag) = self.native_repo(&tag);
            if repo != target_repo || tag != target_tag {
                debug!("pod {pod_name}: skipping because image incorrect");
                continue;
            }

            info!(
                "unpatching rollout {}/{} for native",
                rollout.metadata.namespace.as_deref().unwrap_or_default(),
                rollout.metadata.name.as_deref().unwrap_or_default()
            );
            rollout_api
                .patch(
                    rollout.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::apply("leaksignal.com").force(),
                    &Patch::Apply(json!({
                        "apiVersion": "argoproj.io/v1alpha1",
                        "kind": "Rollout",
                    })),
                )
                .await?;
        }

        for (
            DeployInfo {
                proxy_image,
                image: _,
                pod_name,
            },
            daemonset,
        ) in daemonsets
        {
            let Some(proxy_image) = proxy_image else {
                debug!("pod {pod_name}: no istio proxyImage annotation found, skipping removal");
                continue;
            };
            let Some((repo, tag)) = proxy_image.split_once(':') else {
                debug!("pod {pod_name}: no istio image tag found");
                continue;
            };

            let (target_repo, target_tag) = self.native_repo(&tag);
            if repo != target_repo || tag != target_tag {
                debug!("pod {pod_name}: skipping because image incorrect");
                continue;
            }

            info!(
                "unpatching daemonset {}/{} for native",
                daemonset.metadata.namespace.as_deref().unwrap_or_default(),
                daemonset.metadata.name.as_deref().unwrap_or_default()
            );
            daemonset_api
                .patch(
                    daemonset.metadata.name.as_deref().unwrap_or_default(),
                    &PatchParams::apply("leaksignal.com").force(),
                    &Patch::Apply(json!({
                        "apiVersion": "apps/v1",
                        "kind": "DaemonSet",
                    })),
                )
                .await?;
        }

        Ok(())
    }
}
