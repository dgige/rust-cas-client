use crate::cas::{CasClient, CasUser, NoAuthBehavior};

use actix_service::{Service, Transform};
use actix_session::UserSession;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::web;
use actix_web::{http, Error, HttpResponse};
use futures::future::{ok, Either, FutureResult};
use futures::Poll;

use std::collections::HashMap;

pub struct ActixCasClient {
    cas_client: CasClient,
}

impl ActixCasClient {
    pub fn new(cas_client: CasClient) -> Self {
        ActixCasClient { cas_client }
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
    type Future = FutureResult<Self::Transform, Self::InitError>;

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
        if let Ok(session_key) = session.get::<CasUser>("cas_user") {
            match session_key {
                None => self.authenticate_user(req),
                _ => None,
            }
        } else {
            None
        }
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
        let query = String::from(req.query_string());
        let params = web::Query::<HashMap<String, String>>::from_query(&query);
        if let Err(_) = params {
            return None;
        };
        let user = match params.unwrap().get("ticket") {
            Some(ticket) => self.cas_client.validate_service_ticket(ticket),
            _ => {
                info!("Ticket not found!");
                None
            }
        };
        match user {
            Some(cas_user) => {
                let session = req.get_session();
                if let Err(err) = session.set("cas_user", cas_user) {
                    error!("Error while saving user in session! Error: {}", err);
                };
                None
            }
            None => {
                let login_url = self.cas_client.login_url().unwrap();
                Some(
                    HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
                        .header(http::header::LOCATION, login_url)
                        .finish(),
                )
            }
        }
    }

    pub(self) fn authenticated_or_error(
        &self,
        req: &mut ServiceRequest,
        status_code: http::StatusCode,
    ) -> Option<HttpResponse> {
        let session = req.get_session();
        if let Ok(session_key) = session.get::<CasUser>("cas_user") {
            match session_key {
                None => Some(HttpResponse::build(status_code).finish()),
                _ => None,
            }
        } else {
            Some(HttpResponse::build(status_code).finish())
        }
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
    type Future = Either<S::Future, FutureResult<Self::Response, Self::Error>>;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        self.service.poll_ready()
    }

    fn call(&mut self, mut req: ServiceRequest) -> Self::Future {
        let resp = match self.cas_client.no_auth_behavior() {
            NoAuthBehavior::AuthenticatedOr403 => self.authenticated_or_403(&mut req),
            NoAuthBehavior::AuthenticatedOr404 => self.authenticated_or_404(&mut req),
            NoAuthBehavior::Authenticate => self.authenticate(&mut req),
            NoAuthBehavior::ForceAuthentication => self.force_authentication(&mut req),
        };
        match resp {
            Some(resp) => Either::B(ok(req.into_response(resp.into_body()))),
            None => Either::A(self.service.call(req)),
        }
    }
}
