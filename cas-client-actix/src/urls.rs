use super::ActixCasClient;
use actix_session::UserSession;
use actix_web::http;
use actix_web::{Error, HttpRequest, HttpResponse};

pub async fn login(cas_client: ActixCasClient) -> Result<HttpResponse, Error> {
    debug!("*** CAS LOGIN: {:?} ***", cas_client);
    Ok(HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
        .header(http::header::LOCATION, cas_client.app_url())
        .finish())
}

pub async fn logout(req: HttpRequest, cas_client: ActixCasClient) -> Result<HttpResponse, Error> {
    debug!("*** CAS LOGOUT: {:?} ***", cas_client);
    let session = req.get_session();
    session.purge();
    let logout_url = cas_client.logout_url();
    match logout_url {
        Some(logout_url) => Ok(HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
            .header(http::header::LOCATION, logout_url)
            .finish()),
        _ => logout_404_error(cas_client),
    }
}

fn logout_404_error(cas_client: ActixCasClient) -> Result<HttpResponse, Error> {
    match cas_client.url_to_404 {
        Some(url_to_404) =>Ok(HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
            .header(http::header::LOCATION, url_to_404)
            .finish()),
        _ => Ok(HttpResponse::build(http::StatusCode::NOT_FOUND).finish())
    }
}

pub fn register(cfg: &mut actix_web::web::ServiceConfig, auth_service: &str, cas_client: &ActixCasClient) {
    use actix_web::web;

    cfg.service(
        web::resource(&format!("{}/logout", auth_service))
            .route(web::get().to(crate::urls::logout))
    );
    cfg.service(
        web::resource(&format!("{}/login", auth_service))
            .wrap(cas_client.clone())
            .route(web::get().to(crate::urls::login))
    );
}
