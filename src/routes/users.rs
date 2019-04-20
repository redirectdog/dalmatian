use futures::{Future, IntoFuture, Stream};
use serde_derive::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{rd_login, tack_on, DbPool, ErrorWrapper, UserError, UserID};

#[derive(Deserialize)]
struct SignupReqBody {
    email: String,
    password: String,
}

enum UserIDOrMe {
    ID(UserID),
    Me,
}

#[derive(Serialize)]
struct RedirectInfo {
    id: i32,
    host: String,
    destination: String,
}

impl std::str::FromStr for UserIDOrMe {
    type Err = std::num::ParseIntError;
    fn from_str(src: &str) -> Result<UserIDOrMe, Self::Err> {
        if src == "~me" {
            Ok(UserIDOrMe::Me)
        } else {
            src.parse().map(UserIDOrMe::ID)
        }
    }
}

pub fn users(
    cpupool: &Arc<futures_cpupool::CpuPool>,
    db_pool: &DbPool,
    req: hyper::Request<hyper::Body>,
    path: &str,
) -> Box<Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    if path.is_empty() {
        match req.method() {
            &hyper::Method::POST => {
                let cpupool = cpupool.clone();
                let db_pool = db_pool.clone();

                Box::new(req.into_body()
                         .concat2()
                         .map_err(|err| crate::Error::Internal(Box::new(err)))
                         .and_then(|body| {
                             serde_json::from_slice(&body)
                                 .map_err(|err| crate::Error::Internal(Box::new(err)))
                         })
                         .and_then(move |body: SignupReqBody| {
                             let SignupReqBody { email, password } = body;

                             cpupool.spawn_fn(move || {
                                 bcrypt::hash(password, bcrypt::DEFAULT_COST)
                             })
                             .map_err(|err| crate::Error::Internal(Box::new(err)))
                                 .and_then(move |passhash| {
                                     db_pool.run(move |mut conn| {
                                         conn.prepare("INSERT INTO users (email, passhash) VALUES ($1, $2) RETURNING id")
                                             .then(|res| tack_on(res, conn))
                                             .and_then(move |(stmt, mut conn)| {
                                                 conn.query(&stmt, &[&email, &passhash])
                                                     .into_future()
                                                     .map(|(res, _)| res)
                                                     .map_err(|(err, _)| err)
                                                     .and_then(|row| {
                                                         let id: i32 = row.expect("RETURNING clause failed?").get(0);
                                                         Ok(hyper::Response::builder()
                                                             .body(id.to_string().into())
                                                             .map_err(|err| crate::Error::Internal(Box::new(err))))
                                                     })
                                                 .then(|res| tack_on(res, conn))
                                             })
                                     })
                                     .map_err(ErrorWrapper::from)
                                         .map_err(|err| crate::Error::Internal(Box::new(err)))
                                         .and_then(|x| x)
                                 })
                         }))
            }
            _ => Box::new(futures::future::err(crate::Error::InvalidMethod)),
        }
    } else if let Some((segment, path)) = crate::consume_path_segment(path) {
        match segment.parse::<UserIDOrMe>() {
            Ok(id_or_me) => user_path(db_pool, req, id_or_me, path),
            Err(err) => Box::new(futures::future::err(crate::Error::Custom(
                hyper::Response::builder()
                    .status(hyper::StatusCode::BAD_REQUEST)
                    .body("Invalid user ID segment. Must be an integer or '~me'".into()),
            ))),
        }
    } else {
        Box::new(futures::future::err(crate::Error::NotFound))
    }
}

fn ensure_me(is_me: bool) -> Result<(), crate::Error> {
    match is_me {
        true => Ok(()),
        false => Err(crate::Error::Custom(
            hyper::Response::builder()
                .status(hyper::StatusCode::UNAUTHORIZED)
                .body("This endpoint is only available for ~me".into()),
        )),
    }
}

fn user_path(
    db_pool: &DbPool,
    req: hyper::Request<hyper::Body>,
    id_or_me: UserIDOrMe,
    path: &str,
) -> Box<Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    let db_pool = db_pool.clone();
    let path = path.to_owned();
    Box::new(rd_login(&db_pool, &req)
             .and_then(|login_user| {
                 match id_or_me {
                     UserIDOrMe::ID(id) => {
                         let is_me = match login_user {
                             Some(login_user) => login_user == id,
                             None => false,
                         };
                         Ok((id, is_me))
                     }
                     UserIDOrMe::Me => match login_user {
                         Some(id) => Ok((id, true)),
                         None => Err(crate::Error::Custom(hyper::Response::builder()
                                                          .status(hyper::StatusCode::UNAUTHORIZED)
                                                          .body("Login is required for '~me' paths".into())))
                     }
                 }
             })
             .and_then(move |(id, is_me)| -> Box<Future<Item=hyper::Response<hyper::Body>, Error=crate::Error> + Send> {
                 if let Some(path) = crate::consume_path(&path, "redirects/") {
                     if path.is_empty() {
                         return match req.method() {
                             &hyper::Method::GET => {
                                 Box::new(ensure_me(is_me)
                                          .into_future()
                                          .and_then(move |_| {
                                              db_pool.run(move |mut conn| {
                                                  conn.prepare("SELECT id, host, destination FROM redirects WHERE owner=$1")
                                                      .then(|res| tack_on(res, conn))
                                                      .and_then(move |(stmt, mut conn)| {
                                                          conn.query(&stmt, &[&id.to_raw()])
                                                              .collect()
                                                              .then(|res| tack_on(res, conn))
                                                      })
                                              })
                                              .map_err(ErrorWrapper::from)
                                                  .map_err(|err| crate::Error::Internal(Box::new(err)))
                                                  .map(|rows| {
                                                      rows.into_iter().map(|row| {
                                                          RedirectInfo {
                                                              id: row.get(0),
                                                              host: row.get(1),
                                                              destination: row.get(2),
                                                          }
                                                      }).collect::<Vec<_>>()
                                                  })
                                          })
                                 .and_then(|result| {
                                     serde_json::to_vec(&result)
                                         .map_err(|err| crate::Error::Internal(Box::new(err)))
                                         .and_then(|body| {
                                             hyper::Response::builder()
                                                 .header(hyper::header::CONTENT_TYPE, "application/json")
                                                 .body(body.into())
                                                 .map_err(|err| crate::Error::Internal(Box::new(err)))
                                         })
                                 }))
                             },
                             _ => Box::new(futures::future::err(crate::Error::InvalidMethod))
                         }
                     }
                 }
                 Box::new(futures::future::err(crate::Error::NotFound))
             })
             )
}
