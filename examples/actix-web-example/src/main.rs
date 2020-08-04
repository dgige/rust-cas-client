extern crate cas_client;
extern crate dotenv;

use actix_session::{CookieSession, UserSession};
use actix_web::http::StatusCode;
use actix_web::middleware::Logger;
use actix_web::{get, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use cas_client::actix::ActixCasClient;
use cas_client::{CasClient, CasUser, NoAuthBehavior};
use dotenv::dotenv;
use env_logger::Env;
use std::env;

#[get("/")]
async fn guest(_req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body("
            Welcome <b>Guest</b>!
            <br>
            <br><a href='/auth/cas/login'>Login (to '/auth/cas/login')</a>
            <br>
            <br><a href='/user'>Login (to '/user')</a>
            <br><a href='/user/welcome'>Login (to '/user/welcome')</a>
            <br>
            <br><a href='/user_or_403'>Login (to '/user_or_403')</a>
            <br><a href='/user_or_403/welcome'>Login (to '/user_or_403/welcome')</a>
            <br>
            <br><a href='/user_or_404'>Login (to '/user_or_404')</a>
            <br><a href='/user_or_404/welcome'>Login (to '/user_or_404/welcome')</a>
        "))
}

#[get("/404")]
async fn not_found(_req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::NOT_FOUND)
        .content_type("text/html; charset=utf-8")
        .body("PAGE NOT FOUND"))
}

#[get("/403")]
async fn unauthorized(_req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::UNAUTHORIZED)
        .content_type("text/html; charset=utf-8")
        .body("PAGE UNAUTHORIZED"))
}

async fn user(req: HttpRequest) -> Result<HttpResponse, Error> {
    let session = req.get_session();
    let user_session = session.get::<CasUser>("cas_user");
    let user = user_session.unwrap_or(None);
    let username = match user {
        Some(user) => user.username().to_owned(),
        None => "guest".to_owned(),
    };
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(format!(
            "Welcome <b>{}</b>!
            <br>
            <br>
            <a href='/auth/cas/logout'>Logout</a>",
            username,
        )))
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let logger_environment: Env = Env::default()
        .filter_or("APP_LOG_LEVEL", "info")
        .write_style_or("APP_LOG_STYLE", "always");
    env_logger::init_from_env(logger_environment);

    let server_bind_address = env_or_default("SERVER_BIND_ADDRESS", "127.0.0.1:8080");

    HttpServer::new(|| {
        let auth_service = "auth/cas";
        let mut cas_client_auth = init_cas_client(&auth_service, NoAuthBehavior::Authenticate);
        cas_client_auth.set_default_after_logged_in_path(Some("/user".to_string()));

        let cas_client_403 = init_cas_client(&auth_service, NoAuthBehavior::AuthenticatedOr403);
        let cas_client_404 = init_cas_client(&auth_service, NoAuthBehavior::AuthenticatedOr404);
        App::new()
            .wrap(Logger::default())
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            .app_data(cas_client_auth.clone())
            .service(guest)
            .service(
                web::scope("/user")
                    .wrap(cas_client_auth.clone())
                    .route("", web::get().to(user))
                    .route("/welcome", web::get().to(user))
            )
            .service(
                web::scope("/user_or_403")
                    .wrap(cas_client_403.clone())
                    .route("", web::get().to(user))
                    .route("/welcome", web::get().to(user))
            )
            .service(
                web::scope("/user_or_404")
                    .wrap(cas_client_404.clone())
                    .route("", web::get().to(user))
                    .route("/welcome", web::get().to(user))
            )
            .service(
                web::scope("/protected_or_error")
                    .service(not_found)
                    .service(unauthorized)
            )
            .configure(|cfg| { cas_client::actix::urls::register(cfg, auth_service, &cas_client_auth) })
        })
        .bind(server_bind_address)?
        .run()
    .await
}

fn env_or_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or(default.to_string())
}

fn init_cas_client(auth_service: &str, behavior: NoAuthBehavior) -> ActixCasClient {
    let cas_url = env_or_default("CAS_URL", "https://cas.example.com");
    let app_url = env_or_default("APP_URL", "http://localhost:8080");
    let mut cas_client = CasClient::new(&cas_url).unwrap();

    if let Ok(login_prefix) = env::var("CAS_LOGIN_PREFIX") {
        cas_client.set_login_prefix(login_prefix.as_ref());
    }
    if let Ok(service_validate_prefix) = env::var("CAS_SERVICE_VALIDATE_PREFIX") {
        cas_client.set_service_validate_prefix(service_validate_prefix.as_ref());
    }

    cas_client.set_app_url(&app_url);
    cas_client.set_no_auth_behavior(behavior);
    cas_client.set_login_service(auth_service);

    ActixCasClient::new(cas_client, Some("/protected_or_error/403".to_string()), Some("/protected_or_error/404".to_string()))
}
