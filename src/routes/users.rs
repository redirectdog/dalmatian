use futures::{Future, Stream};
use serde_derive::Deserialize;
use std::sync::Arc;
use warp::Filter;

use crate::{DbPool, ErrorWrapper, tack_on};

#[derive(Deserialize)]
struct SignupReqBody {
    email: String,
    password: String,
}

pub fn users(cpupool: &Arc<futures_cpupool::CpuPool>, db_pool: &Arc<DbPool>) -> impl Filter<Error=warp::reject::Rejection, Extract=(impl warp::reply::Reply,)> + Clone {
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
}
