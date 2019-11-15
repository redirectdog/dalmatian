use futures::{Future, IntoFuture};
use serde_derive::Serialize;

use crate::ServerState;

#[derive(Serialize)]
struct Output<'a> {
    free_visits: i32,
    redirect_host: &'a Option<String>,
    stripe_publishable_key: &'a Option<String>,
}

pub fn settings(
    server_state: &ServerState,
    req: hyper::Request<hyper::Body>,
    path: &str,
) -> Box<dyn Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    if path.is_empty() {
        match *req.method() {
            hyper::Method::GET => {
                let settings = &*server_state.settings;
                let output = Output {
                    free_visits: settings.free_visits,
                    redirect_host: &settings.redirect_host,
                    stripe_publishable_key: &settings.stripe_publishable_key,
                };
                Box::new(
                    serde_json::to_vec(&output)
                        .map_err(|err| crate::Error::Internal(Box::new(err)))
                        .and_then(|body| {
                            hyper::Response::builder()
                                .header(hyper::header::CONTENT_TYPE, "application/json")
                                .body(body.into())
                                .map_err(|err| crate::Error::Internal(Box::new(err)))
                        })
                        .into_future(),
                )
            }
            _ => Box::new(futures::future::err(crate::Error::InvalidMethod)),
        }
    } else {
        Box::new(futures::future::err(crate::Error::NotFound))
    }
}
