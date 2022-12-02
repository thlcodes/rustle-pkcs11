use std::sync::Arc;

mod client;
mod pkcs11;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    //let module = "/usr/local/lib/opensc-pkcs11.so";
    let module = "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so";
    let resolver = pkcs11::PKCS11Resolver::new(Arc::new(|| String::from("")), module.into())
        .expect("could not build resolver:w");
    let client = client::make_client(Some(Arc::new(resolver)));
    let url = "https://idp-sso1.audi.de/isam/sps/live-www-StrongMulti-02-audiIDP/saml20/logininitial?RequestBinding=HTTPPost&PartnerId=urn:amazon:webservices".parse().unwrap();
    let result = client.get(url).await.unwrap();
    let status = result.status().clone();
    let body = result.into_body();
    let body = hyper::body::to_bytes(body)
        .await
        .expect("could not read body");
    let body = String::from_utf8_lossy(&body);
    println!("status: {} body: {}", status, body);
    Ok(())
}
