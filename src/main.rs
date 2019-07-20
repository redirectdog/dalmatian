use futures::{Future, Stream};
use serde_derive::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

mod routes;

pub enum Error {
    NotFound,
    InvalidMethod,
    Custom(Result<hyper::Response<hyper::Body>, http::Error>),
    Unimplemented,
    Internal(Box<dyn std::error::Error + Send>),
}

impl Error {
    pub fn internal<E: std::error::Error + Send + 'static>(err: E) -> Self {
        Error::Internal(Box::new(err))
    }
}

#[derive(Debug)]
enum ErrorWrapper {
    Pool(bb8::RunError<tokio_postgres::Error>),
    Text(String),
}

impl From<bb8::RunError<tokio_postgres::Error>> for ErrorWrapper {
    fn from(err: bb8::RunError<tokio_postgres::Error>) -> ErrorWrapper {
        ErrorWrapper::Pool(err)
    }
}

impl std::fmt::Display for ErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ErrorWrapper::Pool(err) => match err {
                bb8::RunError::User(err) => write!(f, "Database error: {}", err),
                bb8::RunError::TimedOut => write!(f, "Database connection timed out"),
            },
            ErrorWrapper::Text(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ErrorWrapper {}

type DbPool = bb8::Pool<bb8_postgres::PostgresConnectionManager<tokio_postgres::NoTls>>;
type HttpClient = Arc<hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>>;

const STRIPE_API: &str = "https://api.stripe.com/";

#[derive(Serialize)]
pub struct TierInfo {
    id: i32,
    name: String,
    stripe_plan: Option<String>,
    visit_limit: i32,

    monthly_price: Option<u32>,
}

pub struct Settings {
    pub free_visits: i32,
    pub frontend_host: Option<String>,
    pub stripe_secret_key: Option<String>,
    pub stripe_publishable_key: Option<String>,
}

#[derive(Clone)]
pub struct ServerState {
    pub http_client: HttpClient,
    pub settings: Arc<Settings>,
    pub tiers: Arc<RwLock<Vec<TierInfo>>>,
}

impl ServerState {
    pub fn new(settings: Settings) -> ServerState {
        Self {
            http_client: Arc::new(hyper::Client::builder().build(
                hyper_tls::HttpsConnector::new(4).expect("TLS client initialization failed"),
            )),
            settings: Arc::new(settings),
            tiers: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

fn tack_on<T, E, A>(src: Result<T, E>, add: A) -> Result<(T, A), (E, A)> {
    match src {
        Ok(value) => Ok((value, add)),
        Err(err) => Err((err, add)),
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct UserID(i32);

impl std::str::FromStr for UserID {
    type Err = std::num::ParseIntError;
    fn from_str(src: &str) -> Result<UserID, Self::Err> {
        src.parse().map(UserID)
    }
}

impl serde::Serialize for UserID {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.to_raw().serialize(ser)
    }
}

impl UserID {
    pub fn to_raw(&self) -> i32 {
        self.0
    }
}

pub fn rd_login(
    db_pool: &DbPool,
    req: &hyper::Request<hyper::Body>,
) -> impl Future<Item = Option<UserID>, Error = Error> + Send {
    use headers::Header;

    let value = req.headers().get(hyper::header::AUTHORIZATION);
    let value = value.map(|value| {
        headers::Authorization::<headers::authorization::Bearer>::decode(
            &mut vec![value].into_iter(),
        )
        .map_err(|_| {
            Error::Custom(
                hyper::Response::builder()
                    .status(hyper::StatusCode::BAD_REQUEST)
                    .body("Invalid Authorization header value".into()),
            )
        })
        .map(|value| value.0.token().to_owned())
    });
    let value = value.map(|src| {
        src.and_then(|src| {
            src.parse::<uuid::Uuid>()
                .map_err(|err| Error::Internal(Box::new(err)))
        })
    });
    match value {
        Some(Ok(token)) => futures::future::Either::A(
            db_pool
                .run(move |mut conn| {
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
                .map_err(|err| Error::Internal(Box::new(err)))
                .and_then(|row| {
                    row.ok_or_else(|| {
                        Error::Custom(
                            hyper::Response::builder()
                                .status(hyper::StatusCode::BAD_REQUEST)
                                .body("Unrecognized authentication token".into()),
                        )
                    })
                })
                .and_then(|row| {
                    let user_id: i32 = row.get(0);
                    let user_id = UserID(user_id);
                    Ok(Some(user_id))
                }),
        ),
        None | Some(Err(_)) => futures::future::Either::B(futures::future::ok(None)),
    }
}

fn consume_path<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if path.starts_with(prefix) {
        Some(&path[prefix.len()..])
    } else {
        None
    }
}

fn consume_path_segment(path: &str) -> Option<(&str, &str)> {
    path.find('/').map(|idx| (&path[..idx], &path[(idx + 1)..]))
}

fn handle_request(
    req: hyper::Request<hyper::Body>,
    cpupool: &Arc<futures_cpupool::CpuPool>,
    db_pool: &DbPool,
    server_state: &ServerState,
) -> impl Future<Item = hyper::Response<hyper::Body>, Error = hyper::Error> + Send {
    let path_with_slash = format!("{}/", req.uri().path());
    let mut path = &path_with_slash[..];
    if path.ends_with("//") {
        path = &path[..(path.len() - 1)];
    }
    if path.starts_with('/') {
        path = &path[1..];
    }

    let result = if let Some(path) = consume_path(path, "logins/") {
        routes::logins(cpupool, db_pool, req, path)
    } else if let Some(path) = consume_path(path, "users/") {
        routes::users(cpupool, db_pool, server_state, req, path)
    } else if let Some(path) = consume_path(path, "subscription_tiers/") {
        routes::subscription_tiers(server_state, req, path)
    } else if let Some(path) = consume_path(path, "settings/") {
        routes::settings(server_state, req, path)
    } else {
        Box::new(futures::future::err(Error::NotFound))
    };

    result.or_else(|mut err| {
        if let Error::Custom(res) = err {
            match res {
                Ok(res) => {
                    return Ok(res);
                }
                Err(err2) => err = Error::Internal(Box::new(err2)),
            }
        }

        // err cannot be Error::Custom at this point

        if let Error::Internal(ref err) = err {
            eprintln!("server error: {:?}", err);
        } else if let Error::Unimplemented = err {
            eprintln!("server error: unimplemented");
        }

        Ok(hyper::Response::builder()
            .status(match err {
                Error::NotFound => hyper::StatusCode::NOT_FOUND,
                Error::InvalidMethod => hyper::StatusCode::METHOD_NOT_ALLOWED,
                Error::Internal(_) | Error::Unimplemented => {
                    hyper::StatusCode::INTERNAL_SERVER_ERROR
                }
                Error::Custom(_) => unreachable!(),
            })
            .body(
                match err {
                    Error::NotFound => "Not Found",
                    Error::InvalidMethod => "Method Not Allowed",
                    Error::Internal(_) | Error::Unimplemented => "Internal Server Error",
                    Error::Custom(_) => unreachable!(),
                }
                .into(),
            )
            .unwrap())
    })
}

fn main() {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "5000".to_owned())
        .parse()
        .expect("Failed to parse port");

    let database_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");

    tokio::run(futures::lazy(move || {
        let cpupool = Arc::new(futures_cpupool::CpuPool::new_num_cpus());
        bb8::Pool::builder()
            .build(bb8_postgres::PostgresConnectionManager::new(
                database_url,
                tokio_postgres::NoTls,
            ))
            .map_err(|err| panic!("Failed to connect to database: {:?}", err))
            .and_then(|db_pool| {
                db_pool
                    .run(move |mut conn| {
                        conn.prepare("SELECT free_visits FROM settings LIMIT 1")
                            .then(|res| tack_on(res, conn))
                            .and_then(move |(stmt, mut conn)| {
                                conn.query(&stmt, &[])
                                    .into_future()
                                    .map(|(res, _)| res)
                                    .map_err(|(err, _)| err)
                                    .map(|row| {
                                        row.map(|row| Settings {
                                            free_visits: row.get(0),
                                            frontend_host: std::env::var("FRONTEND_HOST").ok(),
                                            stripe_publishable_key: std::env::var(
                                                "STRIPE_PUBLISHABLE_KEY",
                                            )
                                            .ok(),
                                            stripe_secret_key: std::env::var("STRIPE_SECRET_KEY")
                                                .ok(),
                                        })
                                    })
                                    .then(|res| tack_on(res, conn))
                            })
                    })
                    .map_err(|err| panic!("Failed to retrieve settings: {:?}", err))
                    .map(|settings| match settings {
                        Some(settings) => (db_pool, ServerState::new(settings)),
                        None => panic!("Failed to retrieve settings: no row returned"),
                    })
            })
            .and_then(move |(db_pool, server_state)| {
                tokio::spawn(retrieve_plans(&db_pool, server_state.clone()));

                hyper::Server::bind(&std::net::SocketAddr::from((
                    std::net::Ipv6Addr::UNSPECIFIED,
                    port,
                )))
                .serve(move || {
                    let db_pool = db_pool.clone();
                    let cpupool = cpupool.clone();
                    let server_state = server_state.clone();
                    hyper::service::service_fn(move |req| {
                        handle_request(req, &cpupool, &db_pool, &server_state)
                    })
                })
                .map_err(|err| panic!("Server execution failed: {:?}", err))
            })
    }))
}

fn retrieve_plans(
    db_pool: &DbPool,
    server_state: ServerState,
) -> impl Future<Item = (), Error = ()> + Send {
    db_pool
        .run(move |mut conn| {
            conn.prepare("SELECT id, name, stripe_plan, visit_limit FROM subscription_tiers")
                .then(|res| tack_on(res, conn))
                .and_then(move |(stmt, mut conn)| {
                    conn.query(&stmt, &[])
                        .map(|row| {
                            let id = row.get(0);
                            TierInfo {
                                id,
                                name: row.get(1),
                                stripe_plan: row.get(2),
                                visit_limit: row.get(3),
                                monthly_price: if id == 0 { Some(0) } else { None },
                            }
                        })
                        .collect()
                        .then(|res| tack_on(res, conn))
                })
        })
        .map_err(|err| format!("Failed to retrieve plan list: {:?}", err))
        .and_then(move |tiers| {
            let fetches: Vec<_> = match server_state.settings.stripe_secret_key.as_ref() {
                Some(stripe_secret_key) => {
                    let auth_header = format!(
                        "Basic {}",
                        base64::encode(&format!("{}:", stripe_secret_key))
                    );

                    let server_state = server_state.clone();

                    tiers
                        .iter()
                        .filter_map(|row| {
                            let tier_id = row.id;
                            let server_state = server_state.clone();
                            let auth_header = auth_header.clone();
                            row.stripe_plan.as_ref().and_then(move |plan_id| {
                                let auth_header: &str = &auth_header;
                                match hyper::Request::get(format!(
                                    "{}v1/plans/{}",
                                    STRIPE_API,
                                    percent_encoding::utf8_percent_encode(
                                        plan_id,
                                        percent_encoding::DEFAULT_ENCODE_SET
                                    )
                                ))
                                .header(hyper::header::AUTHORIZATION, auth_header)
                                .body(hyper::Body::empty())
                                {
                                    Ok(req) => {
                                        #[derive(Deserialize)]
                                        struct Plan {
                                            amount: u32,
                                        }

                                        Some(
                                            server_state
                                                .http_client
                                                .request(req)
                                                .and_then(|res| {
                                                    let status = res.status();
                                                    res.into_body()
                                                        .concat2()
                                                        .map(move |body| (body, status))
                                                })
                                                .map_err(|err| {
                                                    format!(
                                                        "Failed to request plan info: {:?}",
                                                        err
                                                    )
                                                })
                                                .and_then(|(body, status)| {
                                                    if status.is_success() {
                                                        serde_json::from_slice(&body)
														 .map_err(|err| format!("Failed to parse response: {:?}", err))
                                                    } else {
                                                        Err(format!("Received error: {:?}", body))
                                                    }
                                                })
                                                .and_then(move |plan: Plan| {
                                                    let tiers =
                                                        &mut *server_state.tiers.write().unwrap();

                                                    for mut tier in tiers.iter_mut() {
                                                        if tier.id == tier_id {
                                                            tier.monthly_price = Some(plan.amount);
                                                            break;
                                                        }
                                                    }

                                                    Ok(())
                                                }),
                                        )
                                    }
                                    Err(err) => {
                                        eprintln!("Failed to construct request: {:?}", err);
                                        None
                                    }
                                }
                            })
                        })
                        .collect()
                }
                None => {
                    println!("Missing STRIPE_SECRET_KEY, skipping price fetch");
                    Vec::new()
                }
            };

            *server_state.tiers.write().unwrap() = tiers;

            futures::future::join_all(fetches).map(|_: Vec<()>| ())
        })
        .map_err(|err| {
            eprintln!("failed in retrieve_plans: {:?}", err);
        })
}
