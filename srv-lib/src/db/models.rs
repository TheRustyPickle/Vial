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
        max_days: i64,
        max_views: i32,
    ) -> Result<Self, ServerError> {
        if expires_at.is_none() && remaining_views.is_none() {
            return Err(ServerError::ViewAndExpireEmpty);
        }

        if let Some(expires_at) = expires_at {
            if expires_at <= Utc::now().naive_utc() {
                return Err(ServerError::InvalidExpire(max_days));
            }

            let now = Utc::now().naive_utc();

            if expires_at - now > Duration::days(max_days) {
                return Err(ServerError::InvalidExpire(max_days));
            }
        }

        if let Some(remaining_views) = remaining_views {
            if remaining_views < 1 {
                return Err(ServerError::InvalidViewCount(max_views));
            }

            if remaining_views > max_views {
                return Err(ServerError::InvalidViewCount(max_views));
            }
        }

        Ok(Self {
            id: Ulid::generate().to_string(),
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
        use crate::schema::secrets::dsl::{expires_at, id, remaining_views, secrets};

        let now = Utc::now().naive_utc();

        let secret = diesel::update(
            secrets
                .filter(id.eq(secret_id))
                .filter(expires_at.is_null().or(expires_at.gt(now)))
                .filter(remaining_views.is_null().or(remaining_views.gt(1))),
        )
        .set(remaining_views.eq(remaining_views - 1))
        .returning(Self::as_returning())
        .get_result(conn)
        .await
        .optional()?;

        if secret.is_some() {
            return Ok(secret);
        }

        diesel::delete(
            secrets
                .filter(id.eq(secret_id))
                .filter(expires_at.is_null().or(expires_at.gt(now)))
                .filter(remaining_views.eq(1)),
        )
        .returning(Self::as_returning())
        .get_result(conn)
        .await
        .optional()
    }

    pub async fn clear_expired(conn: &mut AsyncPgConnection) -> Result<usize, Error> {
        use crate::schema::secrets::dsl::{expires_at, secrets};

        diesel::delete(secrets.filter(expires_at.lt(Utc::now().naive_utc())))
            .execute(conn)
            .await
    }

    pub async fn clear_expired_days(
        days: i32,
        conn: &mut AsyncPgConnection,
    ) -> Result<usize, Error> {
        use crate::schema::secrets::dsl::{created_at, secrets};

        let cutoff = Utc::now() - Duration::days(days.into());

        diesel::delete(secrets.filter(created_at.lt(cutoff)))
            .execute(conn)
            .await
    }
}
