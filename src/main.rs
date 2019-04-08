use futures::{Future, Stream};
use serde_derive::{Deserialize};
use std::sync::Arc;

#[derive(Debug)]
enum ErrorWrapper {
    Pool(bb8::RunError<tokio_postgres::Error>),
}

impl From<bb8::RunError<tokio_postgres::Error>> for ErrorWrapper {
    fn from(err: bb8::RunError<tokio_postgres::Error>) -> ErrorWrapper {
        ErrorWrapper::Pool(err)
    }
}

impl std::fmt::Display for ErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ErrorWrapper::Pool(err) => {
                match err {
                    bb8::RunError::User(err) => write!(f, "Database error: {}", err),
                    bb8::RunError::TimedOut => write!(f, "Database connection timed out"),
                }
            }
        }
    }
}

impl std::error::Error for ErrorWrapper {}

fn tack_on<T, E, A>(src: Result<T, E>, add: A) -> Result<(T, A), (E, A)> {
    match src {
        Ok(value) => Ok((value, add)),
        Err(err) => Err((err, add)),
    }
}

fn main() {
    let port: u16 = std::env::var("PORT").unwrap_or_else(|_| "5000".to_owned()).parse()
        .expect("Failed to parse port");

    let database_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");

    tokio::run(futures::lazy(move || {
        let cpupool = Arc::new(futures_cpupool::CpuPool::new_num_cpus());

        bb8::Pool::builder()
            .build(bb8_postgres::PostgresConnectionManager::new(database_url, tokio_postgres::NoTls))
            .map_err(|err| panic!("Failed to connect to database: {:?}", err))
            .and_then(move |db_pool| {
                use warp::Filter;

                let db_pool = Arc::new(db_pool);

                #[derive(Deserialize)]
                struct SignupReqBody {
                    email: String,
                    password: String,
                }

                warp::serve(
                    warp::path("users")
                    .and(warp::post2())
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
                    .map(|res| warp::reply::with_header(res, "Access-Control-Allow-Origin", "*"))
                    .with(warp::log("server"))
                    .recover(|err| -> Result<String, _> {
                        println!("{:?}", err);
                        Err(err)
                    })
                )
                    .bind((std::net::Ipv6Addr::UNSPECIFIED, port))
            })
    }))
}
