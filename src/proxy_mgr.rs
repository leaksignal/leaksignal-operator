use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use filetime::FileTime;
use log::{error, info};
use reqwest::Client;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::Mutex,
};
use url::Url;

use crate::Error;
use sha2::{Digest, Sha256};

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
        if !raw.ends_with(".so") && !raw.ends_with(".wasm") {
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
            if !raw.ends_with(".so") && !raw.ends_with(".wasm") {
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
