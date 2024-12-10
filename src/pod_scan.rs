use std::{collections::HashSet, time::Duration};

use chrono::Utc;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{DeleteParams, ListParams},
    Api, Client, ResourceExt,
};
use log::{error, info};

use crate::{
    istio::{CRDValues, ClusterLeaksignalIstio, LeaksignalIstio},
    Error,
};

pub async fn run_pod_scan(client: Client) {
    let mut duration_secs = 30;
    loop {
        tokio::time::sleep(Duration::from_secs(duration_secs)).await;
        if duration_secs < 300 {
            duration_secs += 5;
        }
        if let Err(e) = do_pod_scan(client.clone()).await {
            error!("failed to run pod scan: {e:?}");
        }
    }
}

async fn check_pod(
    client: Client,
    pod: Pod,
    crd: &CRDValues,
    claimed_pods: &mut HashSet<(String, String)>,
) -> Result<(), Error> {
    if !pod
        .metadata
        .annotations
        .as_ref()
        .map(|v| v.contains_key("sidecar.istio.io/status"))
        .unwrap_or_default()
    {
        return Ok(());
    }
    if let Some(time) = &pod.metadata.deletion_timestamp {
        if time.0 < Utc::now() {
            return Ok(());
        }
    }
    let ns = pod.metadata.namespace.as_deref().unwrap_or("default");
    let pod_api: Api<Pod> = Api::namespaced(client, ns);

    let key = (ns.to_string(), pod.name_any());
    if claimed_pods.contains(&key) {
        return Ok(());
    }
    claimed_pods.insert(key);

    if pod
        .metadata
        .labels
        .as_ref()
        .and_then(|x| x.get("ls-deployed").map(|x| &**x))
        != Some("1")
    {
        info!(
            "restarting pod {}/{} due to no leaksignal deployed and should be",
            pod.namespace().as_deref().unwrap_or_default(),
            pod.name_any()
        );
        pod_api
            .delete(&pod.name_any(), &DeleteParams::default())
            .await?;
        return Ok(());
    }

    if crd.native {
        let image = pod
            .spec
            .as_ref()
            .and_then(|x| x.containers.iter().find(|x| x.name == "istio-proxy"))
            .and_then(|x| x.image.as_deref());
        let repo = image.and_then(|x| x.split_once(':')).map(|x| x.0);
        let has_tag = crd.native_repo.contains(':');
        if (has_tag && image != Some(&crd.native_repo))
            || (!has_tag && Some(&*crd.native_repo) != repo)
        {
            info!(
                "restarting pod {}/{} due to image out-of-sync",
                pod.namespace().as_deref().unwrap_or_default(),
                pod.name_any()
            );
            pod_api
                .delete(&pod.name_any(), &DeleteParams::default())
                .await?;
            return Ok(());
        }
    }
    Ok(())
}

async fn do_pod_scan(client: Client) -> Result<(), Error> {
    let cluster_crd: Api<ClusterLeaksignalIstio> = Api::all(client.clone());
    let crd: Api<LeaksignalIstio> = Api::all(client.clone());

    let mut claimed_pods: HashSet<(String, String)> = HashSet::new();
    for crd in crd.list(&ListParams::default()).await? {
        if !crd.spec.inner.refresh_pods_on_stale {
            continue;
        }
        let ns = crd.metadata.namespace.as_deref().unwrap_or("default");
        let pod_api: Api<Pod> = Api::namespaced(client.clone(), ns);
        let pods = pod_api.list(&crd.spec.inner.list_params()).await?;
        for pod in pods.items {
            check_pod(client.clone(), pod, &crd.spec.inner, &mut claimed_pods).await?;
        }
    }

    let pod_api: Api<Pod> = Api::all(client.clone());
    for crd in cluster_crd.list(&ListParams::default()).await? {
        if !crd.spec.inner.refresh_pods_on_stale {
            continue;
        }
        let pods = pod_api.list(&crd.spec.inner.list_params()).await?;
        for pod in pods.items {
            check_pod(client.clone(), pod, &crd.spec.inner, &mut claimed_pods).await?;
        }
    }

    Ok(())
}
