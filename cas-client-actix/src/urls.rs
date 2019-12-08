use super::ActixCasClient;
use actix_session::UserSession;
use actix_web::http;
use actix_web::{web, HttpRequest, HttpResponse, Responder};

pub fn login() -> impl Responder {
    HttpResponse::build(http::StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body("login")
}

pub fn logout(
    mut req: HttpRequest,
    cas_client: web::Data<ActixCasClient>,
) -> impl Responder {
    let session = req.get_session();
    session.remove("cas_user");
    HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
        .header(http::header::LOCATION, cas_client.logout_url())
        .finish()
}
