use std::collections::BTreeMap;

use k8s_openapi::{api::core::v1::Secret, ByteString};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair};

use crate::Error;

#[derive(Clone, Default)]
pub struct GeneratedCA {
    pub ca_cert: String,
    pub ca_key: String,
}

impl TryFrom<Secret> for GeneratedCA {
    type Error = crate::Error;

    fn try_from(mut value: Secret) -> Result<Self, Error> {
        Ok(GeneratedCA {
            ca_cert: String::from_utf8(
                value
                    .data
                    .as_mut()
                    .and_then(|x| x.remove("ca_cert"))
                    .ok_or_else(|| {
                        Error::UserInputError("missing ca_cert from secret".to_string())
                    })?
                    .0,
            )
            .map_err(|_| Error::UserInputError("invalid UTF-8 in secret".to_string()))?,
            ca_key: String::from_utf8(
                value
                    .data
                    .as_mut()
                    .and_then(|x| x.remove("ca_key"))
                    .ok_or_else(|| Error::UserInputError("missing ca_key from secret".to_string()))?
                    .0,
            )
            .map_err(|_| Error::UserInputError("invalid UTF-8 in secret".to_string()))?,
        })
    }
}

impl Into<BTreeMap<String, ByteString>> for GeneratedCA {
    fn into(self) -> BTreeMap<String, ByteString> {
        let mut out: BTreeMap<String, ByteString> = Default::default();
        out.insert("ca_cert".to_string(), ByteString(self.ca_cert.into_bytes()));
        out.insert("ca_key".to_string(), ByteString(self.ca_key.into_bytes()));
        out
    }
}

impl GeneratedCA {
    pub fn generate() -> Result<GeneratedCA, Error> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "LeakSignal");
        params.distinguished_name.push(DnType::CommonName, "*");

        let ca_key_pair = KeyPair::generate()?;
        let ca = params.self_signed(&ca_key_pair)?;

        Ok(GeneratedCA {
            ca_cert: ca.pem(),
            ca_key: ca_key_pair.serialize_pem(),
        })
    }
}
