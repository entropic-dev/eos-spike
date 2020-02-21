use std::env;
use tracing::{ info, error, span, Level };
use tide::{ Request, Response, Next };
mod middleware;
mod handlers;

#[async_std::main]
async fn main() -> Result<(), std::io::Error> {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let mut app = tide::new();
    app.middleware(middleware::Logging::new());

    let _span = span!(Level::INFO, "server started");

    let port = env::var("PORT").ok().unwrap_or_else(|| "8080".to_string());
    let host = env::var("HOST").ok().unwrap_or_else(|| "127.0.0.1".to_string());
    let addr = format!("{}:{}", host, port);

    app.at("/:pkg")
        .get(handlers::get_packument)
        .put(handlers::put_packument);

    app.at("/:pkg/-/*tarball")
        .get(handlers::get_tarball);

    app.at("/:scope/:pkg/-/*tarball")
        .get(handlers::get_scoped_tarball);

    app.at("/-/v1/login")
        .post(handlers::post_login);

    app.at("/-/v1/login/poll/:session")
        .get(handlers::get_login_poll);

    info!("server listening on address {}", addr);
    app.listen(addr).await?;
    Ok(())
}
