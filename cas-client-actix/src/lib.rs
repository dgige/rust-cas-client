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

#[derive(Clone)]
pub struct ActixCasClient {
    cas_client: CasClient,
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
        if let Ok(None) = session.get::<CasUser>("cas_user") {
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
        let session = req.get_session();
        let query = String::from(req.query_string());
        let params = web::Query::<HashMap<String, String>>::from_query(&query);
        if let Err(_) = params {
            return None;
        };
        let login_url = match self.cas_client.login_url() {
            Some(login_url) => login_url,
            None => {
                return Some(HttpResponse::build(http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body("CAS login URL not configured"));
            }
        };
        let user = match params.unwrap().get("ticket") {
            Some(ticket) => {
                info!("Ticket = {}!", ticket);
                self.cas_client.validate_service_ticket(ticket)
            }
            _ => {
                info!("Ticket not found!");
                Ok(None)
            }
        };
        let redirect_url = match user {
            Ok(Some(cas_user)) => {
                if let Err(err) = session.set("cas_user", cas_user) {
                    error!("Error while saving cas_user in session! Error: {}", err);
                };
                match session.get::<String>("after_logged_in_url") {
                    Ok(Some(return_path)) => {
                        session.remove("after_logged_in_url");
                        return_path
                    },
                    _ => {
                        self.cas_client.app_url().to_string()
                    }
                }
            }
            _ => {
                let connection_info = req.connection_info();
                let after_logged_in_url = format!("{}://{}{}", connection_info.scheme(), connection_info.host(), req.uri());
                if let Err(err) = session.set("after_logged_in_url", after_logged_in_url ) {
                    error!("Error while saving after_logged_in_url in session! Error: {}", err);
                };
                login_url
            }
        };
        Some(
            HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
                .header(http::header::LOCATION, redirect_url)
                .finish(),
        )
    }

    pub(self) fn authenticated_or_error(&self, req: &mut ServiceRequest, status_code: http::StatusCode) -> Option<HttpResponse> {
        let session = req.get_session();
        if let Ok(Some(_)) = session.get::<CasUser>("cas_user") {
            return Some(HttpResponse::build(status_code).finish())
        }
        None
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

    // fn poll_ready(&mut self) -> Poll<Result<(), Self::Error>> {
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
