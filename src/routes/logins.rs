use futures::{Future, Stream};
use serde_derive::Deserialize;
use std::sync::Arc;
use warp::Filter;

use crate::{DbPool, ErrorWrapper, tack_on};

#[derive(Debug)]
enum LoginUserError {
    IncorrectPassword,
    NoSuchUserWithEmail,
}

impl std::fmt::Display for LoginUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LoginUserError::IncorrectPassword => write!(f, "Incorrect password"),
            LoginUserError::NoSuchUserWithEmail => write!(f, "No such user with that email address"),
        }
    }
}

impl std::error::Error for LoginUserError {}

#[derive(Deserialize)]
struct LoginReqBody {
    email: String,
    password: String,
}

pub fn logins(cpupool: &Arc<futures_cpupool::CpuPool>, db_pool: &Arc<DbPool>) -> impl Filter<Error=warp::reject::Rejection, Extract=(impl warp::reply::Reply,)> + Clone {
    warp::post2()
        .and(warp::body::json())
        .and_then({
            let cpupool = cpupool.clone();
            let db_pool = db_pool.clone();
            move |body: LoginReqBody| {
                let cpupool = cpupool.clone();
                let db_pool = db_pool.clone();

                let LoginReqBody { email, password } = body;

                db_pool.run(move |mut conn| {
                    conn.prepare("SELECT id, passhash FROM users WHERE email=$1")
                        .then(|res| tack_on(res, conn))
                        .and_then(move |(stmt, mut conn)| {
                            conn.query(&stmt, &[&email])
                                .into_future()
                                .map(|(res, _)| res)
                                .map_err(|(err, _)| err)
                                .then(|res| tack_on(res, conn))
                        })
                })
                .map_err(ErrorWrapper::from)
                    .map_err(warp::reject::custom)
                    .and_then(|row| {
                        match row {
                            Some(row) => Ok(row),
                            None => Err(warp::reject::custom(LoginUserError::NoSuchUserWithEmail)),
                        }
                    })
                .and_then(move |row| {
                        let user_id: i32 = row.get(0);
                        let passhash: String = row.get(1);

                        cpupool.spawn_fn(move || {
                            bcrypt::verify(password, &passhash)
                                .or_else(|err| Err(warp::reject::custom(err)))
                        })
                        .and_then(|correct| {
                            if !correct {
                                Err(warp::reject::custom(LoginUserError::IncorrectPassword))
                            }
                            else {
                                Ok(())
                            }
                        })
                        .and_then(move |_| {
                            let token = uuid::Uuid::new_v4();
                            db_pool.run(move |mut conn| {
                                conn.prepare("INSERT INTO logins (token, user_id, created) VALUES ($1, $2, localtimestamp)")
                                    .then(|res| tack_on(res, conn))
                                    .and_then(move |(stmt, mut conn)| {
                                        conn.execute(&stmt, &[&token, &user_id])
                                            .map(move |_| token)
                                            .then(|res| tack_on(res, conn))
                                    })
                            })
                            .map_err(ErrorWrapper::from)
                                .map_err(warp::reject::custom)
                        })
                    })
                .map(|token| {
                    token.to_string()
                })
            }
        })
    .recover(|err: warp::reject::Rejection| {
        if let Some(err) = err.find_cause::<LoginUserError>() {
            Ok(http::Response::builder()
               .status(
                   match err {
                       _ => http::StatusCode::BAD_REQUEST,
                   }
                )
               .body(err.to_string())
           )
        }
        else {
            Err(err)
        }
    })
}
