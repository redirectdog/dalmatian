use futures::{Future, Stream};
use serde_derive::Serialize;

use crate::routes::users::RedirectInfo;
use crate::{tack_on, DbPool, ErrorWrapper};

#[derive(Serialize)]
enum RedirectTLSState {
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "pending")]
    Pending,
}

#[derive(Serialize)]
struct RedirectTLSInfo {
    enabled: bool,
    state: RedirectTLSState,
}

#[derive(Serialize)]
struct RedirectInfoExpanded {
    #[serde(flatten)]
    base: RedirectInfo,
    tls: RedirectTLSInfo,
}

pub fn redirects_path(
    db_pool: &DbPool,
    req: hyper::Request<hyper::Body>,
    path: &str,
) -> Box<Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    if path.is_empty() {
        Box::new(futures::future::err(crate::Error::InvalidMethod))
    } else if let Some((segment, path)) = crate::consume_path_segment(path) {
        match segment.parse::<i32>() {
            Ok(id) => redirect_path(db_pool, req, id, path),
            Err(_err) => Box::new(futures::future::err(crate::Error::Custom(
                hyper::Response::builder()
                    .status(hyper::StatusCode::BAD_REQUEST)
                    .body("Invalid redirect ID".into()),
            ))),
        }
    } else {
        Box::new(futures::future::err(crate::Error::NotFound))
    }
}

fn redirect_path(
    db_pool: &DbPool,
    req: hyper::Request<hyper::Body>,
    id: i32,
    path: &str,
) -> Box<Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    if path.is_empty() {
        match *req.method() {
            hyper::Method::GET => {
                Box::new(crate::rd_login(&db_pool, &req)
                         .join(db_pool.run(move |mut conn| {
                             conn.prepare("SELECT host, destination, owner, cache_visit_count_total, cache_visit_count_month, allow_tls, acme_failed, (tls_cert IS NOT NULL AND tls_privkey IS NOT NULL) FROM redirects WHERE id=$1")
                                 .then(|res| tack_on(res, conn))
                                 .and_then(move |(stmt, mut conn)| {
                                     conn.query(&stmt, &[&id])
                                         .into_future()
                                         .map(|(res, _)| res)
                                         .map_err(|(err, _)| err)
                                         .then(|res| tack_on(res, conn))
                                 })
                         })
                               .map_err(ErrorWrapper::from)
                               .map_err(crate::Error::internal)
                               .and_then(|row| {
                                   row.ok_or_else(|| crate::Error::Custom(
                                           hyper::Response::builder()
                                           .status(hyper::StatusCode::NOT_FOUND)
                                           .body("No such redirect".into())))
                               }))
                         .and_then(move |(login_user, row)| {
                             let owner: i32 = row.get(2);
                             if let Some(login_user) = login_user {
                                 if owner != login_user.to_raw() {
                                     Err(crate::Error::Custom(hyper::Response::builder()
                                                              .status(hyper::StatusCode::FORBIDDEN)
                                                              .body("That's not your redirect".into())))
                                 } else {
                                     Ok(row)
                                 }
                             } else {
                                 Err(crate::Error::Custom(hyper::Response::builder()
                                                          .status(hyper::StatusCode::UNAUTHORIZED)
                                                          .body("Login is required to access redirects".into())))
                             }
                         })
                         .and_then(move |row| {
                             let info = RedirectInfoExpanded {
                                 base: RedirectInfo {
                                     id,
                                     host: row.get(0),
                                     destination: row.get(1),
                                     visits_total: row.get(3),
                                     visits_month: row.get(4),
                                 },
                                 tls: RedirectTLSInfo {
                                     enabled: row.get(5),
                                     state: if row.get(7) {
                                         RedirectTLSState::Ready
                                     } else if row.get(6) {
                                         RedirectTLSState::Error
                                     } else {
                                         RedirectTLSState::Pending
                                     },
                                 },
                             };

                             serde_json::to_vec(&info)
                                 .map_err(crate::Error::internal)
                                 .and_then(|body| {
                                     hyper::Response::builder()
                                         .header(hyper::header::CONTENT_TYPE, "application/json")
                                         .body(body.into())
                                         .map_err(crate::Error::internal)
                                 })
                         }))
            },
            _ => Box::new(futures::future::err(crate::Error::InvalidMethod)),
        }
    } else {
        Box::new(futures::future::err(crate::Error::NotFound))
    }
}
