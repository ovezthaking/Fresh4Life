// @generated automatically by Diesel CLI.

diesel::table! {
    comments (id) {
        id -> Integer,
        user_id -> Integer,
        track_id -> Integer,
        content -> Text,
        created_at -> Timestamp,
    }
}

diesel::table! {
    likes (id) {
        id -> Integer,
        user_id -> Integer,
        track_id -> Integer,
        created_at -> Timestamp,
    }
}

diesel::table! {
    saved_tracks (id) {
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

diesel::joinable!(comments -> tracks (track_id));
diesel::joinable!(comments -> users (user_id));
diesel::joinable!(likes -> tracks (track_id));
diesel::joinable!(likes -> users (user_id));
diesel::joinable!(saved_tracks -> tracks (track_id));
diesel::joinable!(saved_tracks -> users (user_id));
diesel::joinable!(tracks -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    comments,
    likes,
    saved_tracks,
    tracks,
    users,
);
