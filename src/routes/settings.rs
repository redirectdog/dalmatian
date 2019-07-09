use futures::{Future, IntoFuture};

use crate::ServerState;

pub fn settings(
    server_state: &ServerState,
    req: hyper::Request<hyper::Body>,
    path: &str,
) -> Box<Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    if path.is_empty() {
        match *req.method() {
            hyper::Method::GET => {
                Box::new(serde_json::to_vec(&*server_state.settings)
                         .map_err(|err| crate::Error::Internal(Box::new(err)))
                         .and_then(|body| {
                             hyper::Response::builder()
                                 .header(hyper::header::CONTENT_TYPE, "application/json")
                                 .body(body.into())
                                 .map_err(|err| crate::Error::Internal(Box::new(err)))
                         })
                         .into_future(),
                )
            },
            _ => Box::new(futures::future::err(crate::Error::InvalidMethod)),
        }
    } else {
        Box::new(futures::future::err(crate::Error::NotFound))
    }
}
