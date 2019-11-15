use futures::{Future, IntoFuture, Stream};
use serde_derive::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{rd_login, tack_on, DbPool, ErrorWrapper, ServerState, UserID};

mod checkout_sessions;

#[derive(Deserialize)]
struct SignupReqBody {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct RedirectCreateReqBody {
    host: String,
    destination: String,
}

enum UserIDOrMe {
    ID(UserID),
    Me,
}

#[derive(Serialize)]
pub struct RedirectInfo {
    pub id: i32,
    pub host: String,
    pub destination: String,
    pub visits_total: Option<i32>,
    pub visits_month: Option<i32>,
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
    server_state: &ServerState,
    req: hyper::Request<hyper::Body>,
    path: &str,
) -> Box<dyn Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    if path.is_empty() {
        match *req.method() {
            hyper::Method::POST => {
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
            Ok(id_or_me) => user_path(db_pool, server_state, req, id_or_me, path),
            Err(_err) => Box::new(futures::future::err(crate::Error::Custom(
                hyper::Response::builder()
                    .status(hyper::StatusCode::BAD_REQUEST)
                    .body("Invalid user ID segment. Must be an integer or '~me'".into()),
            ))),
        }
    } else {
        Box::new(futures::future::err(crate::Error::NotFound))
    }
}

pub fn ensure_me(is_me: bool) -> Result<(), crate::Error> {
    if is_me {
        Ok(())
    } else {
        Err(crate::Error::Custom(
            hyper::Response::builder()
                .status(hyper::StatusCode::UNAUTHORIZED)
                .body("This endpoint is only available for ~me".into()),
        ))
    }
}

fn user_path(
    db_pool: &DbPool,
    server_state: &ServerState,
    req: hyper::Request<hyper::Body>,
    id_or_me: UserIDOrMe,
    path: &str,
) -> Box<dyn Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    let db_pool = db_pool.clone();
    let server_state = server_state.clone();
    let path = path.to_owned();
    Box::new(rd_login(&db_pool, &req)
             .and_then(move |login_user| {
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
             .and_then(move |(id, is_me)| -> Box<dyn Future<Item=hyper::Response<hyper::Body>, Error=crate::Error> + Send> {
                 if path.is_empty() {
                     return match *req.method() {
                         hyper::Method::GET => {
                             Box::new(serde_json::to_vec(&serde_json::json!({"id": id}))
                                      .map_err(|err| crate::Error::Internal(Box::new(err)))
                                      .and_then(|body| {
                                          hyper::Response::builder()
                                              .header(hyper::header::CONTENT_TYPE, "application/json")
                                              .body(body.into())
                                              .map_err(|err| crate::Error::Internal(Box::new(err)))
                                      })
                                      .into_future())
                         },
                         _ => Box::new(futures::future::err(crate::Error::InvalidMethod))
                     }
                 }
                 if let Some(path) = crate::consume_path(&path, "redirects/") {
                     if path.is_empty() {
                         return match *req.method() {
                             hyper::Method::GET => {
                                 Box::new(ensure_me(is_me)
                                          .into_future()
                                          .and_then(move |_| {
                                              db_pool.run(move |mut conn| {
                                                  conn.prepare("SELECT id, host, destination, cache_visit_count_total, cache_visit_count_month FROM redirects WHERE owner=$1")
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
                                                              visits_total: row.get(3),
                                                              visits_month: row.get(4),
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
                             hyper::Method::POST => {
                                 Box::new(ensure_me(is_me)
                                          .into_future()
                                          .and_then(move |_| {
                                              req.into_body()
                                                  .concat2()
                                                  .map_err(|err| crate::Error::Internal(Box::new(err)))
                                                  .and_then(|body| {
                                                      serde_json::from_slice(&body)
                                                          .map_err(|err| crate::Error::Internal(Box::new(err)))
                                                  })
                                              .and_then(move |body: RedirectCreateReqBody| {
                                                  db_pool.run(move |mut conn| {
                                                      conn.prepare("INSERT INTO redirects (host, destination, owner) VALUES ($1, $2, $3) RETURNING id")
                                                          .then(|res| tack_on(res, conn))
                                                          .and_then(move |(stmt, mut conn)| {
                                                              conn.query(&stmt, &[&body.host, &body.destination, &id.0])
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
                             },
                             _ => Box::new(futures::future::err(crate::Error::InvalidMethod))
                         }
                     }
                 } else if let Some(path) = crate::consume_path(&path, "subscription_tier/") {
                     if path.is_empty() {
                         return match *req.method() {
                             hyper::Method::GET => {
                                 Box::new(db_pool.run(move |mut conn| {
                                     conn.prepare("SELECT tier FROM users WHERE id=$1")
                                         .then(|res| tack_on(res, conn))
                                         .and_then(move |(stmt, mut conn)| {
                                             conn.query(&stmt, &[&id.0])
                                                 .into_future()
                                                 .map(|(res, _)| res)
                                                 .map_err(|(err, _)| err)
                                                 .map(|row| -> Option<i32> {
                                                     row.map(|row| {
                                                         row.get(0)
                                                     })
                                                 })
                                             .then(|res| tack_on(res, conn))
                                         })
                                 })
                                          .map_err(ErrorWrapper::from)
                                          .map_err(|err| crate::Error::Internal(Box::new(err)))
                                          .and_then(|tier| {
                                                     tier.ok_or_else(|| crate::Error::Custom(
                                                             hyper::Response::builder()
                                                             .status(hyper::StatusCode::NOT_FOUND)
                                                             .body("No such user".into())))
                                          })
                                          .and_then(move |user_tier| {
                                              for tier in server_state.tiers.read().unwrap().iter() {
                                                  if tier.id == user_tier {
                                                      return serde_json::to_vec(tier)
                                                          .map_err(|err| crate::Error::Internal(Box::new(err)))
                                                  }
                                              }

                                              Err(crate::Error::Internal(Box::new(crate::ErrorWrapper::Text("No such tier found".to_owned()))))
                                          })
                                          .and_then(|body| {
                                              hyper::Response::builder()
                                                  .header(hyper::header::CONTENT_TYPE, "application/json")
                                                  .body(body.into())
                                                  .map_err(|err| crate::Error::Internal(Box::new(err)))
                                          })
                                          )
                             },
                             _ => Box::new(futures::future::err(crate::Error::InvalidMethod)),
                         }
                     }
                 } else if let Some(path) = crate::consume_path(&path, "checkout_sessions/") {
                     return checkout_sessions::checkout_sessions_path(&db_pool, &server_state, req, id, is_me, path);
                 }
                 Box::new(futures::future::err(crate::Error::NotFound))
             })
             )
}
