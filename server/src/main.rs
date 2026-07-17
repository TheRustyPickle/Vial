use actix_web::web::{self, Data, Json, Path};
use actix_web::{App, HttpResponse, HttpServer};
use chrono::{Days, Utc};
use log::{LevelFilter, error, info};
use vial_shared::CreateSecretRequest;
use vial_shared::config::Config;
use vial_srv::db::{Handler, get_connection};
use vial_srv::errors::ServerError;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let config = Config::get_config();

    let max_size = config.get_max_size_verified();

    pretty_env_logger::formatted_timed_builder()
        .format_timestamp_millis()
        .filter_level(LevelFilter::Info)
        .init();

    let db_url = config.get_database_url_verified();

    let db_handler = get_connection(&db_url, 5, None).await;

    db_handler
        .initiate_days_cleanup(config.get_max_days_verified() as i32)
        .await;

    let port = config.get_port();

    let address = config.get_address();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(config.clone()))
            .app_data(Data::new(db_handler.clone()))
            .app_data(web::JsonConfig::default().limit((max_size * 4).div_ceil(3) + 1024))
            .service(
                web::scope("/api/secrets")
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
    info!("Getting secret with id: {id}");

    db_handler
        .get_secret(&id)
        .await
        .map_or_else(server_error_to_response, |secret| {
            if let Some(secret) = secret {
                HttpResponse::Ok().json(secret)
            } else {
                HttpResponse::NotFound().body("secret not found")
            }
        })
}

async fn create_secret(
    db_handler: Data<Handler>,
    config: Data<Config>,
    payload: Json<CreateSecretRequest>,
) -> HttpResponse {
    let payload = payload.into_inner();

    if payload.expires_at.is_none() && payload.max_views.is_none() {
        return server_error_to_response(ServerError::ViewAndExpireEmpty);
    }

    let max_size = config.get_max_size_verified();
    let max_day = config.get_max_days_verified();
    let max_view = config.get_max_views_verified();

    if payload.ciphertext.len() > max_size || payload.ciphertext.is_empty() {
        info!(
            "Payload too large. Max size is {max_size} bytes. Gotten {}",
            payload.ciphertext.len()
        );

        return HttpResponse::PayloadTooLarge()
            .body(format!("Payload size is invalid. Max size is {max_size} bytes"));
    }

    if let Some(payload_day) = payload.expires_at {
        let max_naivetime = Utc::now().naive_utc() + Days::new(max_day as u64);

        if payload_day > max_naivetime || payload_day < Utc::now().naive_utc() {
            info!(
                "Payload day is invalid. Max day is {max_day}. Gotten {}",
                payload_day
            );

            return server_error_to_response(ServerError::InvalidExpire(max_day as i64));
        }
    }

    if let Some(payload_view) = payload.max_views
        && (payload_view > max_view as i32 || payload_view < 1)
    {
        info!("Payload view is invalid. Max view is {max_view}. Gotten {payload_view}");
        return server_error_to_response(ServerError::InvalidViewCount(max_view as i32));
    }

    db_handler
        .new_secret(payload)
        .await
        .map_or_else(server_error_to_response, |id| {
            info!("Created secret with id: {id}");
            HttpResponse::Ok().json(id)
        })
}

fn server_error_to_response(e: ServerError) -> HttpResponse {
    match e {
        ServerError::ViewAndExpireEmpty
        | ServerError::InvalidExpire(_)
        | ServerError::InvalidViewCount(_) => HttpResponse::BadRequest().body(e.to_string()),

        ServerError::DatabaseError(e) => {
            error!("Database error: {e}");
            HttpResponse::InternalServerError().body("internal server error")
        }
    }
}
