use futures::{Future};
use std::sync::Arc;

mod routes;

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

type DbPool = bb8::Pool<bb8_postgres::PostgresConnectionManager<tokio_postgres::NoTls>>;

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

                warp::serve(
                    warp::path("users")
                    .and(routes::users(&cpupool, &db_pool))
                    .map(|res| warp::reply::with_header(res, "Access-Control-Allow-Origin", "*"))
                    .with(warp::log("server"))
                    .recover(|err: warp::reject::Rejection| -> Result<_, _> {
                        let status = err.status();

                        if status.is_server_error() {
                            eprintln!("server error! {:?}", err);
                            return Ok(
                                http::Response::builder()
                                .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                                .body("Internal Server Error")
                            );
                        }
                        Err(err)
                    })
                )
                    .bind((std::net::Ipv6Addr::UNSPECIFIED, port))
            })
    }))
}
