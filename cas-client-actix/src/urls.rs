use super::ActixCasClient;
use actix_session::UserSession;
use actix_web::http;
use actix_web::{Error, HttpRequest, HttpResponse};

pub async fn login(cas_client: ActixCasClient) -> Result<HttpResponse, Error> {
    debug!("{:?}", cas_client);
    Ok(HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
        .header(http::header::LOCATION, cas_client.app_url())
        .finish())
}

pub async fn logout(req: HttpRequest, cas_client: ActixCasClient) -> Result<HttpResponse, Error> {
    let session = req.get_session();
    session.purge();
    let logout_url = cas_client.logout_url();
    match logout_url {
        Some(logout_url) => Ok(HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
            .header(http::header::LOCATION, logout_url)
            .finish()),
        _ => Ok(HttpResponse::build(http::StatusCode::NOT_FOUND).finish()),
    }
}
