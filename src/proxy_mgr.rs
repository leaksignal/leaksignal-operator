use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use bcder::{
    encode::{self, Values},
    BitString,
};
use filetime::FileTime;
use log::{error, info};
use reqwest::Client;
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::Mutex,
};
use url::Url;
use x509_certificate::{
    rfc3280::AttributeValue,
    rfc5280::{AlgorithmIdentifier, AlgorithmParameter, SubjectPublicKeyInfo},
    X509Certificate,
};

use crate::{intercept::GeneratedCA, Error};
use sha2::Sha256;

use nfsserve::{
    nfs::{fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, specdata3},
    tcp::*,
    vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities},
};

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

const STATIC_FILES: &[&str] = &["ca.crt", "ca.crt.hash"];

fn get_subject_hash(cert: &str) -> Result<String, Error> {
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

pub async fn update_client_ca(ca: &GeneratedCA) -> Result<(), Error> {
    let hash = get_subject_hash(&ca.ca_cert)?;

    let temp_target = FILE_LOCATION.join("ca.crt.tmp");
    let target = FILE_LOCATION.join("ca.crt");

    tokio::fs::write(&temp_target, &ca.ca_cert).await?;
    tokio::fs::rename(temp_target, target).await?;

    let temp_target = FILE_LOCATION.join("ca.crt.hash.tmp");
    let target = FILE_LOCATION.join("ca.crt.hash");

    tokio::fs::write(&temp_target, &hash).await?;
    tokio::fs::rename(temp_target, target).await?;

    Ok(())
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

pub async fn run_nfs_server() {
    let listener = NFSTcpListener::bind(&BIND_ADDR.to_string(), NFSServer {})
        .await
        .expect("failed to bind NFS server");
    listener
        .handle_forever()
        .await
        .expect("failed to run NFS server");
}

struct NFSServer {}

fn filename_to_id(name: &str) -> u64 {
    if let Some(index) = STATIC_FILES.iter().position(|x| *x == name) {
        return index as u64 + 1;
    }
    let name = name.split_once('.').map(|x| x.0).unwrap_or(name);
    if name.len() < 16 {
        return u64::MAX;
    }
    hex::decode(&name[..16])
        .map(|x| u64::from_be_bytes(x.try_into().unwrap()))
        .unwrap_or(u64::MAX)
}

const FILE_ATTR: fattr3 = fattr3 {
    ftype: ftype3::NF3REG,
    mode: 0o444,
    nlink: 1,
    uid: 0,
    gid: 0,
    size: 0,
    used: 0,
    rdev: specdata3 {
        specdata1: 0,
        specdata2: 0,
    },
    fsid: 0,
    fileid: 0,
    atime: nfstime3 {
        seconds: 0,
        nseconds: 0,
    },
    mtime: nfstime3 {
        seconds: 0,
        nseconds: 0,
    },
    ctime: nfstime3 {
        seconds: 0,
        nseconds: 0,
    },
};

async fn get_entry_for_file_id(
    fileid: fileid3,
) -> Result<Option<(fattr3, tokio::fs::DirEntry)>, nfsstat3> {
    let mut readdir = tokio::fs::read_dir(&*FILE_LOCATION).await.map_err(|e| {
        error!("failed to read proxy dir: {e:?}");
        nfsstat3::NFS3ERR_SERVERFAULT
    })?;
    while let Some(file) = readdir.next_entry().await.map_err(|e| {
        error!("failed to read proxy dir: {e:?}");
        nfsstat3::NFS3ERR_SERVERFAULT
    })? {
        let name = file.file_name();
        let metadata = file.metadata().await.map_err(|e| {
            error!("failed to read proxy file metadata: {e:?}");
            nfsstat3::NFS3ERR_SERVERFAULT
        })?;
        if metadata.is_symlink() || metadata.is_dir() {
            continue;
        }
        let created = FileTime::from_creation_time(&metadata).unwrap_or(FileTime::zero());
        let created = nfstime3 {
            seconds: created.seconds() as u32,
            nseconds: created.nanoseconds(),
        };
        let raw = String::from_utf8_lossy(name.as_encoded_bytes());
        if !raw.ends_with(".so")
            && !raw.ends_with(".wasm")
            && !STATIC_FILES.iter().any(|x| raw == *x)
        {
            continue;
        }
        let id = filename_to_id(&raw);
        if id == fileid {
            return Ok(Some((
                fattr3 {
                    size: metadata.len(),
                    used: metadata.len(),
                    fileid: id,
                    ctime: created,
                    mtime: created,
                    atime: created,
                    ..FILE_ATTR
                },
                file,
            )));
        }
    }
    Ok(None)
}

#[async_trait::async_trait]
impl NFSFileSystem for NFSServer {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadOnly
    }

    fn root_dir(&self) -> fileid3 {
        0
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        if dirid != 0 {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }
        let filename = String::from_utf8_lossy(&filename.0);
        if !STATIC_FILES.iter().any(|x| *x == filename) {
            let Some(prefix) = filename
                .strip_suffix(".so")
                .or_else(|| filename.strip_suffix(".wasm"))
            else {
                return Err(nfsstat3::NFS3ERR_NOENT);
            };
            if prefix.len() != 64 || !prefix.chars().any(|x| x.is_ascii_hexdigit()) {
                return Err(nfsstat3::NFS3ERR_NOENT);
            }
            if (!filename.ends_with(".so") && !filename.ends_with(".wasm")) || filename.len() < 64 {
                return Err(nfsstat3::NFS3ERR_NOENT);
            }
        }

        let path = FILE_LOCATION.join(&*filename);

        if !tokio::fs::try_exists(&path).await.map_err(|e| {
            error!("failed to read proxy file exists: {e:?}");
            nfsstat3::NFS3ERR_SERVERFAULT
        })? {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }

        Ok(filename_to_id(&*filename))
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        if id == 0 {
            return Ok(fattr3 {
                ftype: ftype3::NF3DIR,
                mode: 0o444,
                nlink: 1,
                uid: 0,
                gid: 0,
                size: 0,
                used: 0,
                rdev: specdata3 {
                    specdata1: 0,
                    specdata2: 0,
                },
                fsid: 0,
                fileid: 0,
                atime: nfstime3 {
                    seconds: 0,
                    nseconds: 0,
                },
                mtime: nfstime3 {
                    seconds: 0,
                    nseconds: 0,
                },
                ctime: nfstime3 {
                    seconds: 0,
                    nseconds: 0,
                },
            });
        }
        match get_entry_for_file_id(id).await? {
            Some((attr, _)) => Ok(attr),
            None => Err(nfsstat3::NFS3ERR_NOENT),
        }
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let Some((attr, file)) = get_entry_for_file_id(id).await? else {
            return Err(nfsstat3::NFS3ERR_NOENT);
        };

        let mut file = tokio::fs::File::open(file.path()).await.map_err(|e| {
            error!("failed to open proxy file: {e:?}");
            nfsstat3::NFS3ERR_SERVERFAULT
        })?;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| {
                error!("failed to seek proxy file: {e:?}");
                nfsstat3::NFS3ERR_SERVERFAULT
            })?;
        let len = attr.size.saturating_sub(offset).min(count as u64);
        let mut out = vec![0u8; len as usize];
        let mut index = 0;
        let mut eof = false;
        while index < count as usize {
            let read_bytes = file.read(&mut out[index..]).await.map_err(|e| {
                error!("failed to read proxy file: {e:?}");
                nfsstat3::NFS3ERR_SERVERFAULT
            })?;
            if read_bytes == 0 {
                eof = true;
                out.truncate(index);
                break;
            }
            index += read_bytes;
        }
        Ok((out, eof))
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        if dirid != 0 {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }
        let mut readdir = tokio::fs::read_dir(&*FILE_LOCATION).await.map_err(|e| {
            error!("failed to read proxy dir: {e:?}");
            nfsstat3::NFS3ERR_SERVERFAULT
        })?;
        let mut out = vec![];
        let mut end = true;
        while let Some(file) = readdir.next_entry().await.map_err(|e| {
            error!("failed to read proxy dir: {e:?}");
            nfsstat3::NFS3ERR_SERVERFAULT
        })? {
            let name = file.file_name();
            let metadata = file.metadata().await.map_err(|e| {
                error!("failed to read proxy file metadata: {e:?}");
                nfsstat3::NFS3ERR_SERVERFAULT
            })?;
            if metadata.is_symlink() || metadata.is_dir() {
                continue;
            }
            let created = FileTime::from_creation_time(&metadata).unwrap_or(FileTime::zero());
            let created = nfstime3 {
                seconds: created.seconds() as u32,
                nseconds: created.nanoseconds(),
            };
            let raw = String::from_utf8_lossy(name.as_encoded_bytes());
            if !raw.ends_with(".so")
                && !raw.ends_with(".wasm")
                && !STATIC_FILES.iter().any(|x| raw == *x)
            {
                continue;
            }
            let id = filename_to_id(&raw);
            if id <= start_after {
                continue;
            }
            let attr = fattr3 {
                size: metadata.len(),
                used: metadata.len(),
                fileid: id,
                ctime: created,
                mtime: created,
                atime: created,
                ..FILE_ATTR
            };
            out.push(DirEntry {
                fileid: id,
                name: name.as_encoded_bytes().into(),
                attr,
            });
            if out.len() >= max_entries {
                end = false;
                break;
            }
        }

        Ok(ReadDirResult { entries: out, end })
    }

    async fn setattr(&self, _: fileid3, _: sattr3) -> Result<fattr3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn write(&self, _: fileid3, _: u64, _: &[u8]) -> Result<fattr3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn create(
        &self,
        _: fileid3,
        _: &filename3,
        _: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn create_exclusive(&self, _: fileid3, _: &filename3) -> Result<fileid3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn mkdir(&self, _: fileid3, _: &filename3) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn remove(&self, _: fileid3, _: &filename3) -> Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn rename(
        &self,
        _: fileid3,
        _: &filename3,
        _: fileid3,
        _: &filename3,
    ) -> Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn symlink(
        &self,
        _: fileid3,
        _: &filename3,
        _: &nfspath3,
        _: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn readlink(&self, _: fileid3) -> Result<nfspath3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_BADTYPE)
    }
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
