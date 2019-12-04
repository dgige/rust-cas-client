extern crate cas_client;
extern crate dotenv;

use actix_session::{CookieSession, UserSession};
use actix_web::http::StatusCode;
use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use cas_client::actix::ActixCasClient;
use cas_client::{CasClient, CasUser, NoAuthBehavior};
use dotenv::dotenv;
use std::env;

#[get("/")]
fn guest() -> impl Responder {
    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body("Welcome <b>Guest</b>!<br><a href='/user'>Login</a>")
}

fn user(mut req: HttpRequest) -> impl Responder {
    let session = req.get_session();
    let user = session.get::<CasUser>("cas_user").unwrap().unwrap();
    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(format!("Welcome <b>{}</b>!", user.username()))
}

fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv().ok();

    let server_bind_address =
        env::var("SERVER_BIND_ADDRESS").unwrap_or("127.0.0.1:3000".to_string());
    let workers: usize = env::var("WORKERS")
        .unwrap_or("1".to_string())
        .parse()
        .unwrap();
    HttpServer::new(|| {
        let auth_service = "auth/cas";
        let cas_client = init_cas_client(&auth_service);
        App::new()
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
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
                    .route("/login", web::get().to(|| HttpResponse::Ok().body("login")))
                    .route(
                        "/logout",
                        web::get().to(|| HttpResponse::Ok().body("logout")),
                    ),
            )
    })
    .bind(server_bind_address)?
    .workers(workers)
    .run()
}

fn init_cas_client(auth_service: &str) -> ActixCasClient {
    let cas_url = env::var("CAS_URL").unwrap_or("https://cas.example.com".to_string());
    let app_url = env::var("APP_URL").unwrap_or("http://localhost:3000".to_string());
    let mut cas_client = CasClient::new(&cas_url).unwrap();
    cas_client.set_app_url(&app_url);
    cas_client.set_no_auth_behavior(NoAuthBehavior::Authenticate);
    cas_client.set_login_service(auth_service);
    ActixCasClient::new(cas_client)
}
