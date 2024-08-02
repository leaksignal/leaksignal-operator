use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use bcder::{
    encode::{self, Values},
    BitString,
};
use log::info;
use reqwest::Client;
use sha1::{Digest, Sha1};
use tokio::sync::Mutex;
use url::Url;
use x509_certificate::{
    rfc3280::AttributeValue,
    rfc5280::{AlgorithmIdentifier, AlgorithmParameter, SubjectPublicKeyInfo},
    X509Certificate,
};

use crate::Error;
use sha2::Sha256;

lazy_static::lazy_static! {
    static ref FILE_LOCATION: PathBuf = {
        let base = std::env::var("PROXY_MGR_PATH").unwrap_or_default();
        if base.is_empty() {
            "/proxy".into()
        } else {
            base.into()
        }
    };
    static ref BIND_ADDR: SocketAddr = {
        let base = std::env::var("PROXY_MGR_BIND").unwrap_or_default();
        if base.is_empty() {
            "0.0.0.0:2049".parse().unwrap()
        } else {
            base.parse().expect("failed to parse PROXY_MGR_BIND env var")
        }
    };
    static ref CLIENT: Client = Client::new();
    static ref DOWNLOAD_MUTEX: Mutex<HashMap<String, Arc<Mutex<()>>>> = Default::default();
}

pub fn get_subject_hash(cert: &str) -> Result<String, Error> {
    let cert = X509Certificate::from_pem(cert)
        .map_err(|e| Error::UserInputError(format!("failed to parse ca_cert: {e}")))?;
    let mut spki: Vec<SubjectPublicKeyInfo> = vec![];
    for attribute in cert.subject_name().iter_attributes() {
        let value = attribute
            .value
            .to_string()
            .map_err(|e| Error::UserInputError(format!("failed to cacert subject: {e}")))?;
        let mut value_out = String::new();
        for c in value.trim().chars() {
            if c.is_ascii_whitespace()
                && value_out
                    .chars()
                    .last()
                    .map(|x| x.is_ascii_whitespace())
                    .unwrap_or(true)
            {
                continue;
            }
            value_out.push(c.to_ascii_lowercase());
        }
        spki.push(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: attribute.typ.clone(),
                parameters: Some(AlgorithmParameter::from_captured(
                    AttributeValue::new_utf8_string(&value_out)
                        .unwrap()
                        .to_captured(bcder::Mode::Der),
                )),
            },
            subject_public_key: BitString::new(0, bytes::Bytes::default()),
        });
    }

    let mut out: Vec<u8> = vec![];
    for item in spki {
        encode::set((&item.algorithm,))
            .write_encoded(bcder::Mode::Der, &mut out)
            .map_err(|e| {
                Error::UserInputError(format!("failed to encode subject canonically: {e}"))
            })?;
    }

    let mut hasher = Sha1::new();
    hasher.update(&out);
    let hash_out = hasher.finalize();
    let raw = &hash_out[0..4];
    let swapped = [raw[3], raw[2], raw[1], raw[0]];
    Ok(hex::encode(&swapped))
}

/// Downloads a proxy or blocks until download is complete based on hash. Also checks the hash.
pub async fn check_or_add_proxy(hash: &str, native: bool, url: &Url) -> Result<PathBuf, Error> {
    if hash.len() != 64 || hash.chars().any(|x| !x.is_ascii_hexdigit()) {
        return Err(Error::UserInputError(format!("malformed hash: {}", hash)));
    }
    let mut target = FILE_LOCATION.join(hash);
    if native {
        target.set_extension("so");
    } else {
        target.set_extension("wasm");
    }
    if tokio::fs::try_exists(&target).await? {
        return Ok(target
            .strip_prefix(&*FILE_LOCATION)
            .expect("malformed path")
            .to_path_buf());
    }

    let mutex = {
        let mut map = DOWNLOAD_MUTEX.lock().await;
        let mutex = map.entry(hash.to_string()).or_default();
        mutex.clone()
    };
    let _lock = mutex.lock().await;
    if tokio::fs::try_exists(&target).await? {
        return Ok(target
            .strip_prefix(&*FILE_LOCATION)
            .expect("malformed path")
            .to_path_buf());
    }

    info!("pulling proxy: {url}");

    let response = CLIENT.get(url.as_str()).send().await?;

    if response.status() != 200 {
        return Err(Error::UserInputError(format!(
            "invalid HTTP response when fetching proxy from '{url}': {}",
            response.status()
        )));
    }

    let body = response.bytes().await?;

    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_hash = hex::encode(hasher.finalize());
    if !computed_hash.eq_ignore_ascii_case(hash) {
        return Err(Error::UserInputError(format!(
            "Proxy file did not match provided hash '{url}': {hash}, was {computed_hash}"
        )));
    }

    tokio::fs::write(&target, &body).await?;

    {
        DOWNLOAD_MUTEX.lock().await.remove(hash);
    }

    Ok(target
        .strip_prefix(&*FILE_LOCATION)
        .expect("malformed path")
        .to_path_buf())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_cert_subject_hash() {
        let out = super::get_subject_hash(
            r#"-----BEGIN CERTIFICATE-----
        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
        -----END CERTIFICATE-----"#,
        )
        .unwrap();
        assert_eq!(out, "57bcb2da");
        let out = super::get_subject_hash(
            r#"-----BEGIN CERTIFICATE-----
        MIIBojCCAUigAwIBAgIUFz/sR4gpKC4ark97/sI0cNcaJI4wCgYIKoZIzj0EAwIw
        NjEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDETMBEGA1UECgwKTGVh
        a1NpZ25hbDAgFw03NTAxMDEwMDAwMDBaGA80MDk2MDEwMTAwMDAwMFowNjEfMB0G
        A1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDETMBEGA1UECgwKTGVha1NpZ25h
        bDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLZAYqadevTh22pBiyXSkHkDC42h
        nAlvhUvLRhX+B2B+tfBqKlky9uuL8BuaNNo7w+4T6ny3g8XfNddQ+9knIM+jMjAw
        MB0GA1UdDgQWBBT+DoCMr/WcpJhCGFiMaK9Xo1IAJTAPBgNVHRMBAf8EBTADAQH/
        MAoGCCqGSM49BAMCA0gAMEUCIBQqEwUPwsE+zsujlNouWolmojUJsOwqvuQD4nMZ
        HQvmAiEAsXc2t8kxgOkhKv/C9T7TxAlvMx193NVYDOYOYSrCj/s=
        -----END CERTIFICATE-----"#,
        )
        .unwrap();
        assert_eq!(out, "0370ebf6");
    }
}
