use std::io::{Error as IoError, Write};
use std::io::ErrorKind;
use std::path::Path;

use isahc::config::CaCertificate;
use isahc::config::ClientCertificate;
use isahc::config::PrivateKey;
use isahc::HttpClient;
use isahc::HttpClientBuilder;
use isahc::config::Configurable;
use openssl::x509::X509;
use openssl::pkcs12::Pkcs12;
use tracing::debug;

use crate::cert::ConfigBuilder;
use crate::ClientConfigBuilder;
use crate::ClientError;
use openssl::pkey::PKey;

pub type IsahcBuilder = ClientConfigBuilder<IsahcConfigBuilder>;

fn load_pk12_certificate<P1, P2>(cert_path: P1, key_path: P2) -> Result<Vec<u8>, IoError>
    where P1: AsRef<Path>,
          P2: AsRef<Path>,
{
    let client_cert = std::fs::read(cert_path)?;
    let private_key = std::fs::read(key_path)?;

    let x509 = X509::from_pem(&client_cert)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Client Cert invalid PEM: {}", e)))?;
    let pkey = PKey::private_key_from_pem(&private_key)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Private Key invalid PEM: {}", e)))?;
    let p12 = Pkcs12::builder().build("", "kubeconfig", &pkey, &x509)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Failed to create Pkcs12: {}", e)))?;
    let p12_der = p12.to_der()
        .map_err(|e| IoError::new(ErrorKind::Other, format!("Failed to write p12 to der: {}", e)))?;

    Ok(p12_der)
}

/// load client certificate
fn load_client_certificate<P>(client_crt_path: P, client_key_path: P) -> Result<ClientCertificate, IoError>
where
    P: AsRef<Path>,
{
    let p12_der = load_pk12_certificate(&client_crt_path, &client_key_path)?;

    let p12_path = std::env::temp_dir().join("k8.p12");
    let mut p12_file = std::fs::File::create(&p12_path)?;
    p12_file.write_all(&p12_der)?;
    p12_file.flush()?;

    Ok(ClientCertificate::p12_file(&p12_path, "".to_string()))
}

fn load_ca_certificate<P>(ca_path: P) -> CaCertificate
where
    P: AsRef<Path>,
{
    CaCertificate::file(ca_path.as_ref().to_owned())
}

pub struct IsahcConfigBuilder(HttpClientBuilder);

impl ConfigBuilder for IsahcConfigBuilder {
    type Client = HttpClient;

    fn new() -> Self {
        Self(HttpClientBuilder::new())
    }

    fn build(self) -> Result<Self::Client, ClientError> {
        self.0.build().map_err(|err| err.into())
    }

    fn load_ca_certificate<P>(self, ca_path: P) -> Result<Self, IoError>
    where
        P: AsRef<Path>,
    {
        let ca_certificate = load_ca_certificate(ca_path);

        debug!("retrieved CA certificate");
        let inner = self.0.ssl_ca_certificate(ca_certificate);

        Ok(Self(inner))
    }

    fn load_client_certificate<P>(
        self,
        client_crt_path: P,
        client_key_path: P,
    ) -> Result<Self, IoError>
    where
        P: AsRef<Path>,
    {
        let client_certificate = load_client_certificate(client_crt_path, client_key_path)?;
        debug!("retrieved client certs from kubeconfig");
        let inner = self.0.ssl_client_certificate(client_certificate);
        Ok(Self(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn get_test_certificate() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data/client.crt")
    }

    fn get_test_key() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data/client.key")
    }

    #[test]
    fn test_verify_certs() {
        let client_cert_path = get_test_certificate();
        let client_key_path = get_test_key();

        let p12 = load_pk12_certificate(client_cert_path, client_key_path).expect("Should get p12");
        let p12_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data/client.p12");
        std::fs::write(&p12_path, &p12);
    }
}
