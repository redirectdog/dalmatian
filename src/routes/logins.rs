use futures::{Future, Stream};
use serde_derive::Deserialize;
use std::sync::Arc;

use crate::{tack_on, DbPool, ErrorWrapper};

#[derive(Debug, Deserialize)]
struct LoginReqBody {
    email: String,
    password: String,
}

pub fn logins(
    cpupool: &Arc<futures_cpupool::CpuPool>,
    db_pool: &DbPool,
    req: hyper::Request<hyper::Body>,
    path: &str,
) -> Box<Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    if path.is_empty() {
        match req.method() {
            &hyper::Method::POST => {
                let db_pool = db_pool.clone();
                let cpupool = cpupool.clone();

                Box::new(req.into_body()
                         .concat2()
                         .map_err(|err| crate::Error::Internal(Box::new(err)))
                         .and_then(|body| {
                             serde_json::from_slice(&body)
                                 .map_err(|err| crate::Error::Internal(Box::new(err)))
                         })
                         .and_then(move |body: LoginReqBody| {
                             println!("{:?}", body);

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
                                 .map_err(|err| crate::Error::Internal(Box::new(err)))
                                 .and_then(|row| {
                                     match row {
                                         Some(row) => Ok(row),
                                         None => {
                                             Err(crate::Error::Custom(hyper::Response::builder()
                                                                      .status(hyper::StatusCode::BAD_REQUEST)
                                                                      .body("No such user with that email address".into())))
                                         }
                                     }
                                 })
                             .and_then(move |row| {
                                 let user_id: i32 = row.get(0);
                                 let passhash: String = row.get(1);

                                 cpupool.spawn_fn(move || {
                                     bcrypt::verify(password, &passhash)
                                 })
                                 .map_err(|err| crate::Error::Internal(Box::new(err)))
                                 .and_then(|correct| {
                                     if !correct {
                                         Err(crate::Error::Custom(hyper::Response::builder()
                                                                  .status(hyper::StatusCode::UNAUTHORIZED)
                                                                  .body("Incorrect password".into())))
                                     } else {
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
                                         .map_err(|err| crate::Error::Internal(Box::new(err)))
                                 })
                             })
                             .and_then(|token| {
                                 hyper::Response::builder()
                                     .body(token.to_string().into())
                                     .map_err(|err| crate::Error::Internal(Box::new(err)))
                             })
                         }))
            }
            _ => Box::new(futures::future::err(crate::Error::InvalidMethod)),
        }
    } else {
        Box::new(futures::future::err(crate::Error::NotFound))
    }
}
