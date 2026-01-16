use actix_web::web::{self, Data, Json, Path};
use actix_web::{App, HttpResponse, HttpServer};
use log::{LevelFilter, error, info};
use std::env::var;
use vial_shared::CreateSecretRequest;
use vial_srv::db::{Handler, get_connection};
use vial_srv::errors::ServerError;

#[actix_web::main]
async fn main() {
    dotenvy::dotenv().ok();

    pretty_env_logger::formatted_timed_builder()
        .format_timestamp_millis()
        .filter_level(LevelFilter::Info)
        .init();

    let db_url = var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_handler = get_connection(&db_url).await;

    let port = var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    let address = var("ADDRESS").unwrap_or("127.0.0.1".to_string());

    HttpServer::new(move || {
        App::new().app_data(Data::new(db_handler.clone())).service(
            web::scope("/secrets")
                .route("/{id}", web::get().to(get_secret))
                .route("", web::post().to(create_secret)),
        )
    })
    .bind((address, port))
    .unwrap()
    .run()
    .await
    .unwrap();
}

async fn get_secret(id: Path<String>, db_handler: Data<Handler>) -> HttpResponse {
    let id = id.into_inner();
    info!("Getting secret with id: {}", id);

    db_handler
        .get_secret(&id)
        .await
        .map(|secret| {
            if let Some(secret) = secret {
                HttpResponse::Ok().json(secret)
            } else {
                HttpResponse::NotFound().body("secret not found")
            }
        })
        .unwrap_or_else(server_error_to_response)
}

async fn create_secret(
    db_handler: Data<Handler>,
    payload: Json<CreateSecretRequest>,
) -> HttpResponse {
    db_handler
        .new_secret(payload.into_inner())
        .await
        .map(|id| {
            info!("Created secret with id: {}", id);
            HttpResponse::Ok().json(id)
        })
        .unwrap_or_else(server_error_to_response)
}

fn server_error_to_response(e: ServerError) -> HttpResponse {
    match e {
        ServerError::ViewAndExpireEmpty
        | ServerError::InvalidExpire
        | ServerError::InvalidViewCount => HttpResponse::BadRequest().body(e.to_string()),

        ServerError::DatabaseError(e) => {
            error!("Database error: {}", e);
            HttpResponse::InternalServerError().body("internal server error")
        }
    }
}
