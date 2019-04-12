use futures::{Future, IntoFuture, Stream};
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

pub struct UserID(i32);

impl std::str::FromStr for UserID {
    type Err = std::num::ParseIntError;
    fn from_str(src: &str) -> Result<UserID, Self::Err> {
        src.parse().map(UserID)
    }
}

impl UserID {
    pub fn to_raw(&self) -> i32 {
        self.0
    }
}

#[derive(Debug)]
pub enum UserError {
    InvalidAuthorizationHeader,
    InvalidToken,
    LoginRequired,
    OnlyForMe,
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UserError::InvalidAuthorizationHeader => write!(f, "Invalid Authorization header value"),
            UserError::InvalidToken => write!(f, "Unrecognized authentication token"),
            UserError::LoginRequired => write!(f, "You must log in to do that"),
            UserError::OnlyForMe => write!(f, "This endpoint is only available for ~me"),
        }
    }
}

impl std::error::Error for UserError {}

pub fn rd_login(db_pool: Arc<DbPool>) -> warp::filters::BoxedFilter<(Option<UserID>,)> {
    use headers::Header;
    use warp::Filter;

    warp::header::optional("Authorization") // TODO find some way to avoid this string
        .and_then(|value: Option<String>| value.map(|value| {
            http::header::HeaderValue::from_str(&value)
                .map_err(|_| UserError::InvalidAuthorizationHeader)
                .and_then(|value| {
                    headers::Authorization::<headers::authorization::Bearer>::decode(&mut [value].iter())
                        .map_err(|_| UserError::InvalidAuthorizationHeader)
                })
            .map(|value| {
                value.0.token().to_owned()
            })
            .map_err(warp::reject::custom)
                .into_future()
        }))
    .and_then(move |token: Option<String>| {
        match token.map(|src| src.parse::<uuid::Uuid>()) {
            Some(Ok(token)) => {
                futures::future::Either::A(db_pool.run(move |mut conn| {
                    conn.prepare("SELECT user_id FROM logins WHERE token=$1")
                        .then(|res| tack_on(res, conn))
                        .and_then(move |(stmt, mut conn)| {
                            conn.query(&stmt, &[&token])
                                .into_future()
                                .map(|(res, _)| res)
                                .map_err(|(err, _)| err)
                                .then(|res| tack_on(res, conn))
                        })
                })
                .map_err(ErrorWrapper::from)
                    .map_err(warp::reject::custom)
                    .and_then(|row| {
                        row.ok_or_else(|| warp::reject::custom(UserError::InvalidToken))
                    })
                .and_then(|row| {
                    let user_id: i32 = row.get(0);
                    let user_id = UserID(user_id);
                    Ok(Some(user_id))
                }))
            },
            None | Some(Err(_)) => futures::future::Either::B(futures::future::ok(None)),
        }
    })
    .boxed()
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
                    warp::path("users").and(routes::users(&cpupool, &db_pool))
                    .or(warp::path("logins").and(routes::logins(&cpupool, &db_pool)))
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
