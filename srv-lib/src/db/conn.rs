use diesel::ConnectionError;
use diesel::ConnectionResult;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::ManagerConfig;
use diesel_async::pooled_connection::bb8::Pool;
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use std::env::var;
use tokio::time::Duration;
use vial_shared::CreateSecretRequest;
use vial_shared::EncryptedPayload;

use crate::db::models::Secret;
use crate::errors::ServerError;

#[derive(Clone)]
pub struct Handler {
    conn: Pool<AsyncPgConnection>,
}

pub async fn get_connection(url: &str) -> Handler {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let mut config = ManagerConfig::default();
    config.custom_setup = Box::new(establish_connection);
    let mgr = AsyncDieselConnectionManager::<AsyncPgConnection>::new_with_config(url, config);

    let conn = Pool::builder()
        .max_size(10)
        .min_idle(Some(5))
        .max_lifetime(Some(Duration::from_secs(60 * 60 * 24)))
        .idle_timeout(Some(Duration::from_secs(60 * 2)))
        .build(mgr)
        .await
        .unwrap();

    Handler { conn }
}

fn establish_connection(config: &str) -> BoxFuture<'_, ConnectionResult<AsyncPgConnection>> {
    let fut = async {
        let mut root_store = RootCertStore::empty();

        // Specifically for working with self signed certs.
        if let Ok(certs) = var("CA_CERT") {
            let cert = CertificateDer::from_pem_slice(certs.as_bytes()).unwrap();
            root_store.add(cert).unwrap();
        }

        let rustls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(rustls_config);
        let (client, conn) = tokio_postgres::connect(config, tls)
            .await
            .map_err(|e| ConnectionError::BadConnection(e.to_string()))?;

        AsyncPgConnection::try_from_client_and_connection(client, conn).await
    };
    fut.boxed()
}

impl Handler {
    pub async fn get_secret(&self, id: &str) -> Result<EncryptedPayload, ServerError> {
        let mut conn = self
            .conn
            .get()
            .await
            .map_err(|e| ServerError::DatabaseError(e.to_string()))?;

        Ok(Secret::get_secret(id, &mut conn)
            .await
            .map_err(|e| ServerError::DatabaseError(e.to_string()))?
            .get_payload())
    }

    pub async fn clear_expired(&self) -> Result<(), ServerError> {
        let mut conn = self
            .conn
            .get()
            .await
            .map_err(|e| ServerError::DatabaseError(e.to_string()))?;

        Secret::clear_expired(&mut conn)
            .await
            .map_err(|e| ServerError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn new_secret(&self, new_secret: CreateSecretRequest) -> Result<String, ServerError> {
        let mut conn = self
            .conn
            .get()
            .await
            .map_err(|e| ServerError::DatabaseError(e.to_string()))?;

        let secret = Secret::new(
            new_secret.ciphertext,
            new_secret.expires_at,
            new_secret.max_views,
        )?;

        let secret_id = secret.get_id();

        secret
            .insert(&mut conn)
            .await
            .map_err(|e| ServerError::DatabaseError(e.to_string()))?;

        Ok(secret_id)
    }
}
