use std::sync::Arc;

use hyper::client::HttpConnector;
use hyper_rustls::ConfigBuilderExt;
use rustls::{client::ResolvesClientCert, ClientConfig};

pub fn make_client(
    cert_resolver: Option<Arc<dyn ResolvesClientCert>>,
) -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>> {
    let builder = ClientConfig::builder()
        .with_safe_defaults()
        .with_native_roots();
    let config: ClientConfig;
    if let Some(resolver) = cert_resolver {
        config = builder.with_client_cert_resolver(resolver);
    } else {
        config = builder.with_no_client_auth();
    }
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only()
        .enable_http1()
        .build();
    let client = hyper::Client::builder().build::<_, hyper::Body>(https);
    client
}
