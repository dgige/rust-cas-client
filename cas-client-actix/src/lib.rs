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
use futures::future::{ok, ready, Either, FutureExt, LocalBoxFuture, Ready};

use std::collections::HashMap;

const CAS_USER_SESSION_KEY: &str = "cas_user";
const AFTER_LOGGED_IN_URL_SESSION_KEY: &str = "after_logged_in_url";

#[derive(Clone)]
pub struct ActixCasClient {
    cas_client: CasClient,
    // Indicates that the server's URL should be
    // used as the CAS `service_url`.
    server_is_service: bool,
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
        ActixCasClient {
            cas_client,
            server_is_service: false,
        }
    }

    pub fn set_server_is_service(&mut self, server_is_service: bool) -> &mut Self {
        self.server_is_service = server_is_service;
        self
    }

    pub fn login_url(&self) -> String {
        self.cas_client.login_url().unwrap()
    }

    pub fn logout_url(&self) -> Option<String> {
        self.cas_client.logout_url()
    }

    pub fn app_url(&self) -> String {
        self.cas_client.app_url().to_string()
    }
}

impl<S, B> Transform<S> for ActixCasClient
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
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
            server_is_service: self.server_is_service,
        })
    }
}
pub struct ActixCasClientMiddleware<S> {
    service: S,
    cas_client: CasClient,
    server_is_service: bool,
}

#[derive(Debug, Deserialize)]
struct CasTicketQuery {
    ticket: String,
}

fn host_scheme_for_request(req: &ServiceRequest) -> String {
    let connection_info = req.connection_info();
    let the_url = format!("{}://{}", connection_info.scheme(), connection_info.host(),);
    the_url
}

fn url_for_request(req: &ServiceRequest) -> String {
    let the_url = format!("{}{}", host_scheme_for_request(req), req.uri());
    the_url
}

impl<S, B> ActixCasClientMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    fn authenticate(&self, req: &ServiceRequest) -> Option<HttpResponse> {
        let session = req.get_session();
        if let Ok(None) = session.get::<CasUser>(CAS_USER_SESSION_KEY) {
            return self.authenticate_user(req);
        }
        None
    }

    fn authenticated_or_403(&self, req: &ServiceRequest) -> Option<HttpResponse> {
        self.authenticated_or_error(req, http::StatusCode::FORBIDDEN)
    }

    fn authenticated_or_404(&self, req: &ServiceRequest) -> Option<HttpResponse> {
        self.authenticated_or_error(req, http::StatusCode::NOT_FOUND)
    }

    fn force_authentication(&self, req: &ServiceRequest) -> Option<HttpResponse> {
        self.authenticate_user(req)
    }

    // private functions
    pub(self) fn authenticate_user(&self, req: &ServiceRequest) -> Option<HttpResponse> {
        let ticket = ticket_for_query_string(req.query_string());
        match ticket {
            Ok(Some(ticket)) => {
                info!("Ticket = {}!", ticket);
                self.handle_ticket(req, ticket)
            }
            _ => {
                info!("Ticket not found!");
                self.handle_needs_authentication(req)
            }
        }
    }

    pub(self) fn authenticated_or_error(&self, req: &ServiceRequest, status_code: http::StatusCode) -> Option<HttpResponse> {
        let session = req.get_session();
        if let Ok(None) = session.get::<CasUser>(CAS_USER_SESSION_KEY) {
            return Some(HttpResponse::build(status_code).finish())
        }
        None
    }

    fn handle_needs_authentication(&self, req: &ServiceRequest) -> Option<HttpResponse> {
        self.set_after_logged_in_url(req);
        let login_url = match self.server_is_service {
            true => self
                .cas_client
                .login_url_for_service(&host_scheme_for_request(req)),
            false => self.cas_client.login_url(),
        };
        let response = match login_url {
            Some(login_url) => HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
                .header(http::header::LOCATION, login_url)
                .finish(),
            None => HttpResponse::build(http::StatusCode::INTERNAL_SERVER_ERROR)
                .body("CAS login URL not configured"),
        };
        Some(response)
    }

    fn handle_ticket(&self, req: &ServiceRequest, ticket: String) -> Option<HttpResponse> {
        let user = self.cas_client.validate_service_ticket(&ticket);
        match user {
            Ok(Some(cas_user)) => self.handle_user(req, cas_user),
            _ => self.handle_needs_authentication(req),
        }
    }

    fn handle_user(&self, req: &ServiceRequest, cas_user: CasUser) -> Option<HttpResponse> {
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

    fn no_auth_response(&mut self, req: &ServiceRequest) -> Option<LocalBoxFuture<'static, HttpResponse>> {
        let resp = match self.cas_client.no_auth_behavior() {
            NoAuthBehavior::AuthenticatedOr403 => self.authenticated_or_403(req),
            NoAuthBehavior::AuthenticatedOr404 => self.authenticated_or_404(req),
            NoAuthBehavior::Authenticate => self.authenticate(req),
            NoAuthBehavior::ForceAuthentication => self.force_authentication(req),
        };
        resp.map(|r| ready(r).boxed_local())
    }

    fn do_call(
        &mut self,
        req: ServiceRequest,
    ) -> Either<S::Future, LocalBoxFuture<'static, Result<ServiceResponse<B>, Error>>> {
        debug!("*** BEGIN CAS CLIENT MIDDLEWARE ***");
        debug!("*** CAS CLIENT MIDDLEWARE: CURRENT URL : {:?} ***", url_for_request(&req));
        let resp = self.no_auth_response(&req);
        match resp {
            Some(resp) => {
                debug!("*** CAS CLIENT MIDDLEWARE RESPONSE: INTERCEPT REQUEST ***");
                let service_resp = resp.map(|r| Ok(req.into_response(r.into_body())));
                Either::Right(service_resp.boxed_local())
            }
            None => {
                debug!("*** CAS CLIENT MIDDLEWARE RESPONSE: CONTINUE ***");
                Either::Left(self.service.call(req))
            }
        }
    }

    pub(self) fn set_after_logged_in_url(&self, req: &ServiceRequest) {
        let session = req.get_session();
        let after_logged_in_url = url_for_request(req);
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
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Either<
        S::Future,
        // Ready<Result<Self::Response, Self::Error>>
        LocalBoxFuture<'static, Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        self.do_call(req)
    }
}

#[cfg(test)]
mod cas_client_actix_test {
    use super::*;
    use actix_http::httpmessage::HttpMessage;
    use actix_session::CookieSession;
    use actix_web::{
        // client::{Client, ClientResponse},
        http::StatusCode,
        middleware,
        test::{start, TestServer},
        App, HttpRequest,
    };

    const SESSION_COOKIE_NAME: &str = "foo";
    const LOGIN_PATH: &str = "/login";
    const LOGOUT_PATH: &str = "/logout";
    const USER_PATH: &str = "/user";
    const PROTECTED_PATH_403: &str = "/protected-403";
    const PROTECTED_PATH_404: &str = "/protected-404";
    const CAS_URL: &str = "http://fake.cas";

    fn get_cas_client(
        auth_service: &str,
        cas_url: &str,
        behavior: NoAuthBehavior,
    ) -> ActixCasClient {
        let mut cas_client = CasClient::new(&cas_url).unwrap();
        cas_client.set_no_auth_behavior(behavior);
        cas_client.set_login_service(auth_service);
        let mut a = ActixCasClient::new(cas_client);
        a.set_server_is_service(true);
        a
    }

    async fn guest() -> Result<HttpResponse, Error> {
        Ok(HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body("Welcome <b>Guest</b>!<br><a href='/user'>Login</a>"))
    }

    async fn user(
        req: HttpRequest,
        cas_client: web::Data<ActixCasClient>,
    ) -> Result<HttpResponse, Error> {
        let session = req.get_session();
        let user_session = session.get::<CasUser>("cas_user");
        let user = user_session.unwrap_or(None);
        let username = match user {
            Some(user) => user.username().to_owned(),
            None => "guest".to_owned(),
        };
        let logout_url = cas_client.logout_url();
        let link = match logout_url {
            Some(logout_url) => format!("<a href='{}'>Logout</a>", logout_url),
            None => String::from(""),
        };
        Ok(HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body(format!("Welcome <b>{}</b>!<br>{}", username, link,)))
    }

    fn get_server() -> TestServer {
        // This will return a TestServer instance and you can
        // get ClientResponse objects from it like
        // `srv.get(url).send().await.unwrap()
        // You could also construct your own client like this
        //  let http_client = Client::default();
        //  let req = http_client.get(srv.url(USER_PATH).as_str()).send();
        //  let mut resp = req.get(url).send().await.unwrap()
        //  let bytes = resp.body().await.unwrap();
        //  println!("{:?}", bytes);
        // You'd do that, e.g. if you needed to get the
        // servers full URL.
        let srv = start(|| {
            let cas_with_auth = get_cas_client("auth/cas", CAS_URL, NoAuthBehavior::Authenticate);
            let cas_with_403 =
                get_cas_client("auth/cas", CAS_URL, NoAuthBehavior::AuthenticatedOr403);
            let cas_with_404 =
                get_cas_client("auth/cas", CAS_URL, NoAuthBehavior::AuthenticatedOr404);
            let cookie_store = CookieSession::signed(&[0; 32])
                .secure(false)
                .name(SESSION_COOKIE_NAME);
            App::new()
                .wrap(cookie_store)
                .wrap(middleware::Logger::default())
                .data(cas_with_auth.clone())
                .route("/", web::get().to(guest))
                .service(
                    web::scope(USER_PATH)
                        .wrap(cas_with_auth.clone())
                        .route("", web::get().to(user)),
                )
                .service(
                    web::scope(PROTECTED_PATH_403)
                        .wrap(cas_with_403.clone())
                        .route("", web::get().to(user)),
                )
                .service(
                    web::scope(PROTECTED_PATH_404)
                        .wrap(cas_with_404.clone())
                        .route("", web::get().to(user)),
                )
                .route(LOGIN_PATH, web::get().to(urls::login))
                .route(LOGOUT_PATH, web::get().to(urls::logout))
        });
        srv
    }

    #[actix_rt::test]
    async fn test_redirect() {
        // Check that URLs where the unauthorized behavior
        // is to authorize produce a redirect.
        let srv = get_server();
        let req = srv.get(USER_PATH).send();
        let resp = req.await.unwrap();
        let headers = resp.headers();
        let location_header = headers.get("location").unwrap();
        let location_value = location_header.to_str().unwrap();
        // TODO: Make this test better. The test merely checks
        // for the presence of the CAS_URL inside of the location
        // header. It would be better to have a more specific check.
        assert!(location_value.contains(CAS_URL));
    }

    #[actix_rt::test]
    async fn test_protected_403() {
        let srv = get_server();
        let req = srv.get(PROTECTED_PATH_403).send();
        let resp = req.await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_rt::test]
    async fn test_protected_404() {
        let srv = get_server();
        let req = srv.get(PROTECTED_PATH_404).send();
        let resp = req.await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[actix_rt::test]
    async fn test_cookie_is_set() {
        let srv = get_server();
        let req_1 = srv.get("/").send();
        let resp = req_1.await.unwrap();
        let cookie_1 = resp
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
