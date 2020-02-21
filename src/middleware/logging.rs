use tracing::{ info, error, span, Level };
use tide::{ Request, Response, Next, Middleware };
use async_trait::async_trait;
use futures::future::BoxFuture;

pub struct Logging {}

impl Logging {
    pub fn new() -> Self {
        Logging {}
    }
}

impl<Data: Send + Sync + 'static> Middleware<Data> for Logging {
    fn handle<'a>(
        &'a self,
        mut cx: Request<Data>,
        next: Next<'a, Data>,
    ) -> BoxFuture<'a, Response> {
        Box::pin(async move {
            let method = cx.method();
            let url = cx.uri();
            let _span = span!(Level::INFO, "handling request", method=?method, url=?url);
            let response = next.run(cx).await;
            info!(status=?response.status());
            response
        })
    }
}
