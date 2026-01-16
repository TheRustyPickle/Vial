use chrono::{Duration, NaiveDateTime, Utc};
use diesel::prelude::*;
use diesel::result::Error;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use ulid::Ulid;
use vial_shared::EncryptedPayload;

use crate::errors::ServerError;
use crate::schema::secrets;

#[derive(Default, Debug, Clone, Insertable, Queryable, Selectable)]
pub struct Secret {
    id: String,
    ciphertext: Vec<u8>,
    expires_at: Option<NaiveDateTime>,
    remaining_views: Option<i32>,
    created_at: NaiveDateTime,
}

impl Secret {
    pub fn new(
        ciphertext: Vec<u8>,
        expires_at: Option<NaiveDateTime>,
        remaining_views: Option<i32>,
    ) -> Result<Self, ServerError> {
        if expires_at.is_none() && remaining_views.is_none() {
            return Err(ServerError::ViewAndExpireEmpty);
        }

        if let Some(expires_at) = expires_at {
            if expires_at <= Utc::now().naive_utc() {
                return Err(ServerError::InvalidExpire);
            }

            let now = Utc::now().naive_utc();

            if expires_at - now > Duration::days(30) {
                return Err(ServerError::InvalidExpire);
            }
        }

        if let Some(remaining_views) = remaining_views {
            if remaining_views < 1 {
                return Err(ServerError::InvalidViewCount);
            }

            if remaining_views > 1000 {
                return Err(ServerError::InvalidViewCount);
            }
        }

        Ok(Self {
            id: Ulid::new().to_string(),
            ciphertext,
            expires_at,
            remaining_views,
            created_at: Utc::now().naive_utc(),
        })
    }

    pub fn get_payload(self) -> EncryptedPayload {
        EncryptedPayload {
            payload: self.ciphertext,
        }
    }

    pub fn get_id(&self) -> String {
        self.id.clone()
    }

    pub async fn insert(self, conn: &mut AsyncPgConnection) -> Result<usize, Error> {
        use crate::schema::secrets::dsl::secrets;

        diesel::insert_into(secrets)
            .values(self)
            .execute(conn)
            .await
    }

    pub async fn get_secret(
        secret_id: &str,
        conn: &mut AsyncPgConnection,
    ) -> Result<Option<Self>, Error> {
        use crate::schema::secrets::dsl::{id, remaining_views, secrets};

        let to_return = secrets
            .filter(id.eq(secret_id))
            .select(Self::as_select())
            .first(conn)
            .await
            .optional()?;

        if to_return.is_none() {
            return Ok(None);
        }

        let to_return = to_return.unwrap();

        if let Some(view_count) = to_return.remaining_views {
            let new_count = view_count - 1;

            let is_expired = if let Some(expiration) = to_return.expires_at {
                expiration < Utc::now().naive_utc()
            } else {
                false
            };

            if new_count == 0 || is_expired {
                diesel::delete(secrets.filter(id.eq(secret_id)))
                    .execute(conn)
                    .await?;
            } else {
                diesel::update(secrets.filter(id.eq(secret_id)))
                    .set(remaining_views.eq(new_count))
                    .execute(conn)
                    .await?;
            }
        }

        Ok(Some(to_return))
    }

    pub async fn clear_expired(conn: &mut AsyncPgConnection) -> Result<usize, Error> {
        use crate::schema::secrets::dsl::{expires_at, secrets};

        diesel::delete(secrets.filter(expires_at.lt(Utc::now().naive_utc())))
            .execute(conn)
            .await
    }
}
