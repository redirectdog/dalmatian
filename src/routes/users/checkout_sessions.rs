use futures::{Future, IntoFuture, Stream};

use super::ensure_me;
use crate::{tack_on, DbPool, ErrorWrapper, ServerState, UserID, STRIPE_API};

pub fn checkout_sessions_path(
    db_pool: &DbPool,
    server_state: &ServerState,
    req: hyper::Request<hyper::Body>,
    user_id: UserID,
    is_me: bool,
    path: &str,
) -> Box<dyn Future<Item = hyper::Response<hyper::Body>, Error = crate::Error> + Send> {
    if path.is_empty() {
        match *req.method() {
            hyper::Method::POST => {
                #[derive(serde_derive::Deserialize)]
                pub struct StartCheckoutBody {
                    subscription_tier: i32,
                }

                #[derive(serde_derive::Deserialize)]
                pub struct StartCheckoutResponseBody {
                    id: String,
                }

                let db_pool = db_pool.clone();
                let http_client = server_state.http_client.clone();

                Box::new(req.into_body()
                         .concat2()
                         .map_err(crate::Error::internal)
                         .and_then(|body| {
                             serde_json::from_slice(&body)
                                 .map_err(crate::Error::internal)
                         })
                         .and_then({
                             let db_pool = db_pool.clone();
                             move |body: StartCheckoutBody| {
                                 db_pool.run(move |mut conn| {
                                     conn.prepare("SELECT stripe_plan FROM subscription_tiers WHERE id=$1")
                                         .then(|res| tack_on(res, conn))
                                         .and_then(move |(stmt, mut conn)| {
                                             conn.query(&stmt, &[&body.subscription_tier])
                                                 .into_future()
                                                 .map(|(res, _)| res)
                                                 .map_err(|(err, _)| err)
                                                 .map(move |res| (res, body.subscription_tier))
                                                 .then(|res| tack_on(res, conn))
                                         })
                                 })
                                 .map_err(ErrorWrapper::from)
                                     .map_err(crate::Error::internal)
                             }
                         })
                                 .and_then(|(row, tier_id)| {
                                     row.ok_or_else(|| crate::Error::Custom(hyper::Response::builder()
                                                                            .status(hyper::StatusCode::BAD_REQUEST)
                                                                            .body("No such subscription tier".into())))
                                         .map(|row| (row, tier_id))
                                 })
                             .map(|(row, tier_id)| (row.get::<_, String>(0), tier_id))
                                 .join(
                    ensure_me(is_me)
                    .and_then(|_| {
                        server_state.settings.stripe_secret_key.as_ref()
                            .map(|key| format!("Basic {}", base64::encode(&format!("{}:", key))))
                            .ok_or_else(|| crate::Error::internal(crate::ErrorWrapper::Text("Missing Stripe secret key".to_owned())))
                            .and_then(|auth_header| {
                                match &server_state.settings.frontend_host {
                                    Some(frontend_host) => Ok((auth_header, frontend_host.clone())),
                                    None => Err(crate::Error::internal(crate::ErrorWrapper::Text("Missing frontend host".to_owned()))),
                                }
                            })
                    })
                    .into_future())
                                 .and_then({
                                     let db_pool = db_pool.clone();
                                     move |((stripe_plan, tier_id), (auth_header, frontend_host))| {
                                         db_pool.run(move |mut conn| {
                                             conn.prepare("INSERT INTO subscription_checkout_sessions (user_id, tier_id, timestamp) VALUES ($1, $2, localtimestamp) RETURNING id")
                                                 .then(|res| tack_on(res, conn))
                                                 .and_then(move |(stmt, mut conn)| {
                                                     conn.query(&stmt, &[&user_id.to_raw(), &tier_id])
                                                         .into_future()
                                                         .map(|(res, _)| res)
                                                         .map_err(|(err, _)| err)
                                                         .then(|res| tack_on(res, conn))
                                                 })
                                         })
                                         .map_err(ErrorWrapper::from)
                                             .map_err(crate::Error::internal)
                                             .and_then(|row| {
                                                 row.ok_or_else(|| crate::Error::internal(crate::ErrorWrapper::Text("Missing ID after insert somehow".to_owned())))
                                             })
                                         .map(|row| {
                                             (stripe_plan, auth_header, frontend_host, row.get::<_, i32>(0))
                                         })
                                     }
                                 })
                                 .join(
                                     db_pool.run(move |mut conn| {
                                         conn.prepare("SELECT email FROM users WHERE id=$1")
                                             .then(|res| tack_on(res, conn))
                                             .and_then(move |(stmt, mut conn)| {
                                                 conn.query(&stmt, &[&user_id.to_raw()])
                                                     .into_future()
                                                     .map(|(res, _)| res)
                                                     .map_err(|(err, _)| err)
                                                     .then(|res| tack_on(res, conn))
                                             })
                                     })
                                     .map_err(ErrorWrapper::from)
                                     .map_err(crate::Error::internal)
                                     .and_then(|row| {
                                         row.ok_or_else(|| crate::Error::internal(ErrorWrapper::Text("Missing user somehow".to_owned())))
                                     })
                                     .map(|row| {
                                         let email: String = row.get(0);
                                         email
                                     }))
                         .and_then(move |((stripe_plan, auth_header, frontend_host, session_id), email)| {
                             #[derive(serde_derive::Serialize)]
                             struct SubscriptionItem<'a> {
                                 plan: &'a str,
                             }

                             #[derive(serde_derive::Serialize)]
                             struct SubscriptionData<'a> {
                                 items: &'a [SubscriptionItem<'a>],
                             }

                             #[derive(serde_derive::Serialize)]
                             struct Body<'a> {
                                 cancel_url: &'a str,
                                 client_reference_id: &'a str,
                                 customer_email: &'a str,
                                 payment_method_types: &'a [&'a str],
                                 subscription_data: SubscriptionData<'a>,
                                 success_url: &'a str,
                             }

                             let body = Body {
                                 cancel_url: &format!("{}/pricing", frontend_host),
                                 client_reference_id: &user_id.to_raw().to_string(),
                                 customer_email: &email,
                                 payment_method_types: &["card"],
                                 subscription_data: SubscriptionData {
                                     items: &[
                                         SubscriptionItem {
                                             plan: &stripe_plan,
                                         }
                                     ],
                                 },
                                 success_url: &format!("{}/purchaseCallback", frontend_host),
                             };

                             serde_qs::to_string(&body)
                                 .map_err(crate::Error::internal)
                                 .map(|body| (body, auth_header, session_id))
                         })
                             .and_then(|(body, auth_header, session_id)| {
                                 let auth_header: &str = &auth_header;
                                 hyper::Request::post(format!("{}v1/checkout/sessions", STRIPE_API))
                                     .header(hyper::header::AUTHORIZATION, auth_header)
                                     .body(body.into())
                                     .map_err(crate::Error::internal)
                                     .map(move |req| {
                                         http_client.request(req)
                                             .map_err(crate::Error::internal)
                                             .map(move |res| (res, session_id))
                                     })
                             })
                         .into_future()
                         .and_then(|x| x)
                         .and_then(|(res, session_id)| {
                             if res.status().is_success() {
                                 futures::future::Either::A(res.into_body().concat2()
                                                            .map_err(crate::Error::internal)
                                                            .map(move |res| (res, session_id)))
                             } else {
                                 futures::future::Either::B(res.into_body().concat2()
                                                            .map_err(crate::Error::internal)
                                                            .and_then(|err| {
                                                                Err(crate::Error::internal(ErrorWrapper::Text(format!("Received error from stripe: {:?}", err))))
                                                            }))
                             }
                         })
                         .and_then(|(res, session_id)| {
                             serde_json::from_slice(&res)
                                 .map_err(crate::Error::internal)
                                 .map(|res| (res, session_id))
                         })
                         .and_then(move |(session, session_id): (StartCheckoutResponseBody, _)| {
                             db_pool.run(move |mut conn| {
                                 conn.prepare("UPDATE subscription_checkout_sessions SET stripe_id=$1 WHERE id=$2")
                                     .then(|res| tack_on(res, conn))
                                     .and_then(move |(stmt, mut conn)| {
                                         conn.execute(&stmt, &[&session.id, &session_id])
                                             .map(|_| session)
                                             .then(|res| tack_on(res, conn))
                                     })
                             })
                             .map_err(ErrorWrapper::from)
                                 .map_err(crate::Error::internal)
                         })
                         .and_then(|session| {
                             serde_json::to_vec(&serde_json::json!({
                                 "stripe_session": session.id,
                             }))
                             .map_err(crate::Error::internal)
                         })
                         .and_then(|body| {
                             hyper::Response::builder()
                                 .header(hyper::header::CONTENT_TYPE, "application/json")
                                 .body(body.into())
                                 .map_err(crate::Error::internal)
                         }))
            }
            _ => Box::new(futures::future::err(crate::Error::InvalidMethod)),
        }
    } else {
        Box::new(futures::future::err(crate::Error::NotFound))
    }
}
