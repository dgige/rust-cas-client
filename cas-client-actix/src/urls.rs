use super::ActixCasClient;
use actix_session::UserSession;
use actix_web::http;
use actix_web::{get, HttpRequest, HttpResponse, Responder};

#[get("/")]
pub async fn cas_login(cas_client: ActixCasClient) -> impl Responder {
    debug!("*** CAS LOGIN: {:?} ***", cas_client);
    let after_logged_in_path = match cas_client.cas_client.default_after_logged_in_path() {
        Some(url) => url,
        _ => cas_client.app_url()
    };
    HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
        .header(http::header::LOCATION, after_logged_in_path)
        .finish()
}

#[get("/")]
pub async fn cas_logout(req: HttpRequest, cas_client: ActixCasClient) -> impl Responder {
    debug!("*** CAS LOGOUT: {:?} ***", cas_client);
    let session = req.get_session();
    session.purge();
    let logout_url = cas_client.logout_url();
    match logout_url {
        Some(logout_url) => HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
            .header(http::header::LOCATION, logout_url)
            .finish(),
        _ => logout_404_error(cas_client),
    }
}

fn logout_404_error(cas_client: ActixCasClient) -> HttpResponse {
    match cas_client.url_to_404 {
        Some(url_to_404) => HttpResponse::build(http::StatusCode::TEMPORARY_REDIRECT)
            .header(http::header::LOCATION, url_to_404)
            .finish(),
        _ => HttpResponse::build(http::StatusCode::NOT_FOUND).finish()
    }
}

pub fn register(cfg: &mut actix_web::web::ServiceConfig, auth_service: &str, cas_client: &ActixCasClient) {
    use actix_web::web;

    cfg.service(
        web::scope(&format!("{}/logout", auth_service))
            .service(cas_logout)
    );
    cfg.service(
        web::scope(&format!("{}/login", auth_service))
            .wrap(cas_client.clone())
            .service(cas_login)
    );
}
