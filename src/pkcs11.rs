use std::sync::Arc;

use cryptoki::context::Pkcs11;

use cryptoki::object::{Attribute, AttributeType, ObjectClass};

use rustls::Certificate;

use rustls::client::ResolvesClientCert;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct PKCS11Resolver {
    pkcs11: Pkcs11,
    pin_fn: Arc<dyn FnOnce() -> String + Sync + Send>,
}

impl PKCS11Resolver {
    pub fn new<F>(pin_fn: Arc<F>, module: String) -> Result<Self>
    where
        F: FnOnce() -> String + Sync + Send + 'static,
    {
        let pkcs11 = Pkcs11::new(module)?;
        return Ok(Self {
            pin_fn: pin_fn.clone(),
            pkcs11,
        });
    }

    fn get_slot() {}
}

impl Drop for PKCS11Resolver {
    fn drop(&mut self) {
        self.pkcs11.clone().finalize()
    }
}

impl ResolvesClientCert for PKCS11Resolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

pub struct PKCS11SigningKey {
    handle: cryptoki::object::ObjectHandle,
}

impl rustls::sign::SigningKey for PKCS11SigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        todo!()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, net::SocketAddr};

    use super::*;

    use hyper::{
        server::conn::AddrIncoming,
        service::{make_service_fn, service_fn},
        Response,
    };
    use rustls::{PrivateKey, ServerConfig};

    async fn handle(
        _: hyper::Request<hyper::Body>,
    ) -> std::result::Result<Response<hyper::Body>, Infallible> {
        Ok(Response::new("Hello, World!".into()))
    }

    async fn setup_server() -> Result<()> {
        let cert = Certificate(std::fs::read("./certs/cer.der")?);
        let key = PrivateKey(std::fs::read("./certs/key.der")?);
        let cfg = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        let addr: SocketAddr = "127.0.0.1:8899".parse().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tls_listener::TlsListener::new_hyper(acceptor, AddrIncoming::bind(&addr)?);

        let make_svc = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle)) });

        let server = hyper::Server::builder(listener).serve(make_svc);
        Ok(())
    }

    fn setup_client() -> Result<()> {
        Ok(())
    }

    #[tokio::test]
    async fn test_resolver() -> Result<()> {
        setup_server().await?;
        Ok(())
    }
}

/*
fn get_slot() -> Result<(Certificate, PKCS11SigningKey), ()> {
    //let mut pkcs11 = Pkcs11::new("/usr/local/lib/opensc-pkcs11.so").expect("could not load module");
    let mut pkcs11 = Pkcs11::new("/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so")
        .expect("could not load module");
    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .expect("could not initialize");

    let slot = pkcs11
        .get_slots_with_token()
        .expect("could not list slots")
        .remove(0);
    println!("slot id {}", slot.id());
    let info = pkcs11
        .get_token_info(slot)
        .expect("could not get token info");
    println!("token label {}", info.label());

    let session = pkcs11
        .open_ro_session(slot)
        .expect("could not open session");
    session
        .login(cryptoki::session::UserType::User, Some("1234"))
        .expect("login failed");
    let pairs = session
        .find_objects(&[Attribute::Private(true)])
        .expect("could not find objects");

    println!("found {} keys", pairs.len());

    let certificate: rustls::Certificate;
    let privateKey: PKCS11SigningKey;

    pairs.iter().for_each(|h| {
        let h = h.clone();
        let attrs = session
            .get_attributes(h, &[AttributeType::Id])
            .expect("could not get attributes");
        if let Attribute::Id(id) = attrs.get(0).unwrap() {
            let privkey = session
                .find_objects(&[
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::Id(id.clone()),
                ])
                .expect("could not get private key");
            let privkey = privkey.get(0).unwrap();

            let cert = session
                .find_objects(&[
                    Attribute::Class(ObjectClass::CERTIFICATE),
                    Attribute::Id(id.clone()),
                ])
                .expect("could not get cert");
            let cert = cert.get(0).unwrap();
            let cert_val = session
                .get_attributes(cert.clone(), &[AttributeType::Value])
                .expect("could not get cert value");
            let cert_val = cert_val.get(0).unwrap();
            if let Attribute::Value(cert_data) = cert_val {
                certificate = rustls::Certificate(cert_data.clone());
            } else {
                println!("did not find cert value");
                return;
            }
        }
    });

    pkcs11.finalize();

    Ok((certificate, privateKey))
}
*/
