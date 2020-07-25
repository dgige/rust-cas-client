extern crate env_logger;
#[macro_use]
extern crate log;
#[allow(unused_imports)]
#[macro_use]
extern crate serde;

extern crate cas_client_core;

pub mod urls;

use cas_client_core::CasUser;
use cas_client_core::{CasClient, NoAuthBehavior};
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_session::UserSession;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::web;
use actix_web::{http, Error, HttpResponse};
use futures::future::{ok, Either, Ready};

use std::collections::HashMap;

const CAS_USER_SESSION_KEY: &str = "cas_user";
const AFTER_LOGGED_IN_URL_SESSION_KEY: &str = "after_logged_in_url";

#[derive(Clone)]
pub struct ActixCasClient {
    cas_client: CasClient,
}

fn ticket_for_query_string(
    query_string: &str,
) -> Result<Option<String>, actix_web::error::QueryPayloadError> {
    let params = web::Query::<HashMap<String, String>>::from_query(query_string)?;
    // Clone the inner string and return Ok of ticket value
    Ok(params.get("ticket").map(|t| t.clone()))
}

impl ActixCasClient {
    pub fn new(cas_client: CasClient) -> Self {
        ActixCasClient { cas_client }
    }

    pub fn login_url(&self) -> String {
        self.cas_client.login_url().unwrap()
    }

    pub fn logout_url(&self) -> String {
        self.cas_client.logout_url().unwrap()
    }

    pub fn app_url(&self) -> String {
        self.cas_client.app_url().to_string()
    }
}

impl<S, B> Transform<S> for ActixCasClient
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = ActixCasClientMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ActixCasClientMiddleware {
            service,
            cas_client: self.cas_client.clone(),
        })
    }
}
pub struct ActixCasClientMiddleware<S> {
    service: S,
    cas_client: CasClient,
}

#[derive(Debug, Deserialize)]
struct CasTicketQuery {
    ticket: String,
}

impl<S, B> ActixCasClientMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    fn authenticate(&self, req: &mut ServiceRequest) -> Option<HttpResponse> {
        let session = req.get_session();
        if let Ok(None) = session.get::<CasUser>(CAS_USER_SESSION_KEY) {
            return self.authenticate_user(req);
        }
        None
    }

    fn authenticated_or_403(&self, req: &mut ServiceRequest) -> Option<HttpResponse> {
        self.authenticated_or_error(req, http::StatusCode::FORBIDDEN)
    }

    fn authenticated_or_404(&self, req: &mut ServiceRequest) -> Option<HttpResponse> {
        self.authenticated_or_error(req, http::StatusCode::NOT_FOUND)
    }

    fn force_authentication(&self, req: &mut ServiceRequest) -> Option<HttpResponse> {
        self.authenticate_user(req)
    }

    // private functions
    pub(self) fn authenticate_user(&self, req: &mut ServiceRequest) -> Option<HttpResponse> {
        let ticket = ticket_for_query_string(req.query_string());
        match ticket {
            Ok(Some(ticket)) => self.handle_ticket(req, ticket),
            _ => self.handle_needs_authentication(req),
        }
    }

    pub(self) fn authenticated_or_error(&self, req: &mut ServiceRequest, status_code: http::StatusCode) -> Option<HttpResponse> {
        let session = req.get_session();
        if let Ok(Some(_)) = session.get::<CasUser>(CAS_USER_SESSION_KEY) {
            return Some(HttpResponse::build(status_code).finish())
        }
        None
    }

    fn handle_needs_authentication(&self, req: &mut ServiceRequest) -> Option<HttpResponse> {
        self.set_after_logged_in_url(req);
        let response = match self.cas_client.login_url() {
            Some(login_url) => HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
                .header(http::header::LOCATION, login_url)
                .finish(),
            None => HttpResponse::build(http::StatusCode::INTERNAL_SERVER_ERROR)
                .body("CAS login URL not configured"),
        };
        Some(response)
    }

    fn handle_ticket(&self, req: &mut ServiceRequest, ticket: String) -> Option<HttpResponse> {
        let user = self.cas_client.validate_service_ticket(&ticket);
        match user {
            Ok(Some(cas_user)) => self.handle_user(req, cas_user),
            _ => self.handle_needs_authentication(req),
        }
    }

    fn handle_user(&self, req: &mut ServiceRequest, cas_user: CasUser) -> Option<HttpResponse> {
        let session = req.get_session();
        if let Err(err) = session.set(CAS_USER_SESSION_KEY, cas_user) {
            error!("Error while saving cas_user in session! Error: {}", err);
        };
        let return_path = session.get::<String>(AFTER_LOGGED_IN_URL_SESSION_KEY);
        match return_path {
            Ok(Some(return_path)) => {
                session.remove(AFTER_LOGGED_IN_URL_SESSION_KEY);
                Some(
                    HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
                        .header(http::header::LOCATION, return_path)
                        .finish(),
                )
            }
            _ => None,
        }
    }

    pub(self) fn set_after_logged_in_url(&self, req: &mut ServiceRequest) {
        let session = req.get_session();
        let connection_info = req.connection_info();
        let after_logged_in_url = format!(
            "{}://{}{}",
            connection_info.scheme(),
            connection_info.host(),
            req.uri()
        );
        let result = session.set(AFTER_LOGGED_IN_URL_SESSION_KEY, after_logged_in_url);
        if let Err(err) = result {
            error!(
                "Error while saving after_logged_in_url in session! Error: {}",
                err
            );
        };
    }
}

impl<S, B> Service for ActixCasClientMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, mut req: ServiceRequest) -> Self::Future {
        debug!("*** BEGIN CAS CLIENT MIDDLEWARE ***");
        let resp = match self.cas_client.no_auth_behavior() {
            NoAuthBehavior::AuthenticatedOr403 => self.authenticated_or_403(&mut req),
            NoAuthBehavior::AuthenticatedOr404 => self.authenticated_or_404(&mut req),
            NoAuthBehavior::Authenticate => self.authenticate(&mut req),
            NoAuthBehavior::ForceAuthentication => self.force_authentication(&mut req),
        };
        match resp {
            Some(resp) => {
                debug!("*** CAS CLIENT MIDDLEWARE RESPONSE: INTERCEPT REQUEST ***");
                Either::Right(ok(req.into_response(resp.into_body())))
            }
            None => {
                debug!("*** CAS CLIENT MIDDLEWARE RESPONSE: CONTINUE ***");
                Either::Left(self.service.call(req))
            }
        }
    }
}

#[cfg(test)]
mod cas_client_actix_test {
    use super::*;
    use actix_http::httpmessage::HttpMessage;
    use actix_session::CookieSession;
    use actix_web::http::StatusCode;
    use actix_web::{
        get, middleware,
        test::{start, TestServer},
        App, HttpRequest,
    };

    const SESSION_COOKIE_NAME: &str = "foo";

    #[get("/")]
    async fn guest(_req: HttpRequest) -> Result<HttpResponse, Error> {
        Ok(HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body("Welcome <b>Guest</b>!<br><a href='/user'>Login</a>"))
    }

    #[get("/user")]
    async fn user(
        req: HttpRequest,
        cas_client: web::Data<ActixCasClient>,
    ) -> Result<HttpResponse, Error> {
        let session = req.get_session();
        let user = session.get::<CasUser>("cas_user").unwrap().unwrap();
        Ok(HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body(format!(
                "Welcome <b>{}</b>!<br><a href='{}'>Logout</a>",
                user.username(),
                cas_client.logout_url()
            )))
    }

    fn get_server() -> TestServer {
        let srv = start(|| {
            let cas = CasClient::new("http://fake.cas");
            let cookie_store = CookieSession::signed(&[0; 32])
                .secure(false)
                .name(SESSION_COOKIE_NAME);
            App::new()
                .wrap(cookie_store)
                .wrap(middleware::Logger::default())
                .data(cas.clone())
                .service(guest)
                .service(user)
                .route("/login", web::get().to(urls::login))
                .route("/logout", web::get().to(urls::logout))
        });
        srv
    }

    #[actix_rt::test]
    async fn test_cookie_is_set() {
        let srv = get_server();
        let req_1 = srv.get("/").send();
        let resp_1 = req_1.await.unwrap();
        let cookie_1 = resp_1
            .cookies()
            .unwrap()
            .clone()
            .into_iter()
            .find(|c| c.name() == SESSION_COOKIE_NAME);
        if let None = cookie_1 {
            let msg = ["Expected to find cookie with name ", SESSION_COOKIE_NAME].join(" ");
            panic!(msg);
        }
    }
}
