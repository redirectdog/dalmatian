use futures::{Future, IntoFuture, Stream};
use serde_derive::{Deserialize, Serialize};
use std::sync::Arc;
use warp::Filter;

use crate::{DbPool, ErrorWrapper, rd_login, tack_on, UserError, UserID};

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

pub fn users(cpupool: &Arc<futures_cpupool::CpuPool>, db_pool: &Arc<DbPool>) -> warp::filters::BoxedFilter<(impl warp::reply::Reply,)> {
    warp::post2()
        .and(warp::body::json())
        .and_then({
            let cpupool = cpupool.clone();
            let db_pool = db_pool.clone();
            move |body: SignupReqBody| {
                let db_pool = db_pool.clone();

                let password = body.password;
                let email = body.email;

                cpupool.spawn_fn(move || {
                    bcrypt::hash(password, bcrypt::DEFAULT_COST)
                        .or_else(|err| Err(warp::reject::custom(err)))
                })
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
                                        Ok(id.to_string())
                                    })
                                .then(|res| tack_on(res, conn))
                            })
                    })
                    .map_err(ErrorWrapper::from)
                        .map_err(warp::reject::custom)
                })
            }
        })
    .or(user_path(db_pool))
        .boxed()
}

pub fn user_path(db_pool: &Arc<DbPool>) -> warp::filters::BoxedFilter<(impl warp::reply::Reply,)> {
    warp::path::param::<UserIDOrMe>()
        .and(rd_login(db_pool.clone()))
        .and_then(|id_or_me, login| {
            match id_or_me {
                UserIDOrMe::ID(id) => Ok((id, false)),
                UserIDOrMe::Me => match login {
                    Some(id) => Ok((id, true)),
                    None => Err(warp::reject::custom(UserError::LoginRequired)),
                }
            }.into_future()
        })
    .and(warp::path("redirects"))
        .and(warp::get2())
        .and_then({
            let db_pool = db_pool.clone();
            move |(id, is_me): (UserID, bool)| {
                if !is_me {
                    futures::future::Either::A(futures::future::err(warp::reject::custom(UserError::OnlyForMe)))
                } else {
                    futures::future::Either::B(db_pool.run(move |mut conn| {
                        conn.prepare("SELECT id, host, destination FROM redirects WHERE owner=$1")
                            .then(|res| tack_on(res, conn))
                            .and_then(move |(stmt, mut conn)| {
                                conn.query(&stmt, &[&id.to_raw()])
                                    .collect()
                                    .then(|res| tack_on(res, conn))
                            })
                    })
                                               .map_err(ErrorWrapper::from)
                                               .map_err(warp::reject::custom)
                                               .map(|rows| {
                                                   warp::reply::json(&rows.into_iter().map(|row| {
                                                       RedirectInfo {
                                                           id: row.get(0),
                                                           host: row.get(1),
                                                           destination: row.get(2),
                                                       }
                                                   }).collect::<Vec<_>>())
                                               })
                                              )
                }
            }
        })
    .boxed()
}
