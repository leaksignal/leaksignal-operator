#![warn(clippy::dbg_macro, clippy::todo)]

mod envoy_json;
mod intercept;
mod istio;
mod native;
mod pod_scan;
mod proxy_mgr;
mod webhook;

use futures::StreamExt;
use istio::{ClusterLeaksignalIstioSpec, LeaksignalIstioSpec};
use kube::{
    client::Client,
    core::admission::SerializePatchError,
    runtime::{watcher::Config, Controller},
    Api,
};
use log::{error, info, warn};
use std::{fmt::Debug, sync::Arc};

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
