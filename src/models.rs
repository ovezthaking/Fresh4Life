use diesel::prelude::*;
use chrono::NaiveDateTime;
use serde::{Serialize, Deserialize};


#[derive(Queryable, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
    pub created_at: NaiveDateTime,
}

#[derive(Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser{
    pub username: String,
    pub password: String,
}


#[derive(Queryable, Serialize, Deserialize)]
pub struct Track{
    pub id: i32,
    pub user_id: i32,
    pub title: String,
    pub genre: String,
    pub file_path: String,
    pub created_at: NaiveDateTime,
}

#[derive(Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::tracks)]
pub struct NewTrack{
    pub user_id: i32,
    pub title: String,
    pub genre: String,
    pub file_path: String,
}


#[derive(Queryable, Serialize, Deserialize)]
pub struct Comment{
    pub id: i32,
    pub user_id: i32,
    pub track_id: i32,
    pub content: String,
    pub created_at: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::comments)]
pub struct NewComment{
    pub user_id: i32,
    pub track_id: i32,
    pub content: String,
}


#[derive(Queryable, Serialize, Deserialize)]
pub struct Like{
    pub id: i32,
    pub user_id: i32,
    pub track_id: i32,
    pub created_at: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::likes)]
pub struct NewLike{
    pub user_id: i32,
    pub track_id: i32,
}


#[derive(Queryable, Serialize, Deserialize)]
pub struct SavedTrack{
    pub id: i32,
    pub user_id: i32,
    pub track_id: i32,
    pub created_at: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::saved_tracks)]
pub struct NewSavedTrack{
    pub user_id: i32,
    pub track_id: i32,
}