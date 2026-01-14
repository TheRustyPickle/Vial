// @generated automatically by Diesel CLI.

diesel::table! {
    secrets (id) {
        id -> Text,
        ciphertext -> Bytea,
        expires_at -> Nullable<Timestamptz>,
        remaining_views -> Nullable<Int4>,
        created_at -> Timestamptz,
    }
}
