// @generated automatically by Diesel CLI.

diesel::table! {
    likes (id) {
        id -> Integer,
        user_id -> Integer,
        track_id -> Integer,
        created_at -> Timestamp,
    }
}

diesel::table! {
    tracks (id) {
        id -> Integer,
        user_id -> Integer,
        #[max_length = 255]
        title -> Varchar,
        #[max_length = 255]
        genre -> Varchar,
        #[max_length = 255]
        file_path -> Varchar,
        created_at -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Integer,
        #[max_length = 255]
        username -> Varchar,
        #[max_length = 255]
        password -> Varchar,
        created_at -> Timestamp,
    }
}

diesel::joinable!(likes -> tracks (track_id));
diesel::joinable!(likes -> users (user_id));
diesel::joinable!(tracks -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    likes,
    tracks,
    users,
);
