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

/// load client certificate
fn load_client_certificate<P>(client_crt_path: P, client_key_path: P) -> Result<ClientCertificate, IoError>
where
    P: AsRef<Path>,
{
    let client_cert = std::fs::read(client_crt_path)?;
    let private_key = std::fs::read(client_key_path)?;

    let x509 = X509::from_pem(&client_cert)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Client Cert invalid PEM: {}", e)))?;
    let pkey = PKey::private_key_from_pem(&private_key)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Private Key invalid PEM: {}", e)))?;
    let p12 = Pkcs12::builder().build("", "kubeconfig", &pkey, &x509)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Failed to create Pkcs12: {}", e)))?;
    let p12_der = p12.to_der()
        .map_err(|e| IoError::new(ErrorKind::Other, format!("Failed to write p12 to der: {}", e)))?;

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
