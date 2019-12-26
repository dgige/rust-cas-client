extern crate cas_client;
extern crate dotenv;

use actix_session::{CookieSession, UserSession};
use actix_web::http::StatusCode;
use actix_web::middleware::Logger;
use actix_web::{get, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use cas_client::actix::ActixCasClient;
use cas_client::{CasClient, CasUser, NoAuthBehavior};
use dotenv::dotenv;
use std::env;

#[get("/")]
async fn guest(_req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body("Welcome <b>Guest</b>!<br><a href='/user'>Login</a>"))
}

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

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv().ok();

    HttpServer::new(|| {
        let auth_service = "auth/cas";
        let cas_client = init_cas_client(&auth_service);
        App::new()
            .wrap(Logger::default())
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            .data(cas_client.clone())
            .service(guest)
            .service(
                web::scope("/user")
                    .wrap(cas_client.clone())
                    .route("", web::get().to(user))
                    .route("/welcome", web::get().to(user)),
            )
            .service(
                web::scope(auth_service)
                    .wrap(cas_client.clone())
                    .route("/login", web::get().to(cas_client::actix::urls::login))
                    .route("/logout", web::get().to(cas_client::actix::urls::logout)),
            )
    })
    .bind("localhost:8080")?
    .run()
    .await
}

fn init_cas_client(auth_service: &str) -> ActixCasClient {
    let env_or_default =
        |key: &str, default: &str| env::var(key).unwrap_or(default.to_string());
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
    cas_client.set_no_auth_behavior(NoAuthBehavior::Authenticate);
    cas_client.set_login_service(auth_service);

    ActixCasClient::new(cas_client)
}
