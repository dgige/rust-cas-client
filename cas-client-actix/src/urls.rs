use super::ActixCasClient;
use actix_session::UserSession;
use actix_web::http;
use actix_web::{web, Error, HttpRequest, HttpResponse};

pub async fn login() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(http::StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body("login"))
}

pub async fn logout(
    req: HttpRequest,
    cas_client: web::Data<ActixCasClient>,
) -> Result<HttpResponse, Error> {
    let session = req.get_session();
    session.remove("cas_user");
    Ok(HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
        .header(http::header::LOCATION, cas_client.logout_url())
        .finish())
}
