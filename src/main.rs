mod models;
mod schema;


use models::NewUser;
//use crate::schema::users;
use rocket::response::Redirect;
use rocket::{Rocket, Build, State};
use rocket::fs::FileServer;
use rocket::response::content::RawHtml;
use rocket::get;
use rocket::routes;
use rocket::post;
use rocket::form::FromForm;
use rocket::form::Form;
use rocket::http::Status;
use rocket::http::CookieJar;
use rocket::http::Cookie;
use rocket::config::Config;
use rocket::data::{ByteUnit, Limits, ToByteUnit};
use rocket_multipart_form_data::{
    MultipartFormData, MultipartFormDataField, MultipartFormDataOptions,
};

//use rocket_multipart_form_data::{MultipartFormData, MultipartFormDataField};

use log::error;


use std::path::Path;

use tera::{Tera, Context};
use serde_json;
//use serde::Serialize;

use diesel::prelude::*;
//use crate::schema::users;
use dotenv::dotenv;
use diesel::r2d2::ConnectionManager;

use bcrypt::{hash, DEFAULT_COST, verify};

use std::fs::File;
use std::io::copy;

/* 
#[derive(Database)]
#[database("mysql_db")]
struct MyDatabaseSqlx(sqlx::MySqlPool);
*/

type DbPool = diesel::r2d2::Pool<ConnectionManager<MysqlConnection>>;

// Index route that renders a template
#[get("/")]
async fn index(pool: &State<DbPool>, tera: &State<Tera>, cookies: &CookieJar<'_>) -> RawHtml<String> {
    use schema::users::dsl as users_dsl;
    use schema::tracks::dsl as tracks_dsl;

    let mut context = Context::new();
    let mut conn = pool.get().expect("Failed to get DB connection");

    
    
    // Pobierz dane użytkownika z ciasteczka
    if let Some(cookie) = cookies.get("user_id") {
        let session_user_id = cookie.value().parse::<i32>().unwrap_or(0);
        context.insert("user_id", &session_user_id);
        let user_result = users_dsl::users
            .filter(users_dsl::id.eq(session_user_id))
            .first::<models::User>(&mut conn)
            .optional();

        match user_result {
            Ok(Some(user)) => context.insert("user", &user),
            Ok(None) => context.insert("error", "No users found"),
            Err(e) => {
                println!("Database error: {}", e);
                context.insert("error", "Error fetching user");
            }
        }
    } else {
        let testuser = models::User {
            id: 0,
            username: "You are not logged in".to_string(),
            password: "testpassword".to_string(),
            #[allow(deprecated)]
            created_at: chrono::NaiveDateTime::from_timestamp(0, 0),
        };
        context.insert("user", &testuser);
    }

    // Pobierz listę utworów wraz z danymi użytkowników
    let tracks_with_users = tracks_dsl::tracks
        .inner_join(users_dsl::users.on(users_dsl::id.eq(tracks_dsl::user_id)))
        .select((
            tracks_dsl::id,
            tracks_dsl::title,
            tracks_dsl::genre,
            tracks_dsl::file_path,
            tracks_dsl::created_at,
            tracks_dsl::user_id,
            users_dsl::username,
        ))
        .order_by(tracks_dsl::created_at.desc())
        .load::<(i32, String, String, String, chrono::NaiveDateTime, i32, String)>(&mut conn);

    match tracks_with_users {
        Ok(tracks) => {
            let tracks_with_authors: Vec<_> = tracks
                .into_iter()
                .map(|(id, title, genre, file_path, created_at, track_user_id, username)| {
                    serde_json::json!({
                        "id": id,
                        "title": title,
                        "genre": genre,
                        "file_path": file_path,
                        "created_at": created_at,
                        "track_user_id": track_user_id,
                        "username": username,
                    })
                })
                .collect();
            context.insert("tracks", &tracks_with_authors);
        }
        Err(e) => {
            error!("Błąd wczytywania utworów: {:?}", e);
            context.insert("error", "Error loading tracks");
        }
    }

    context.insert("title", "Welcome to Fresh4Life!");
    if cookies.get("user_id").is_some() {
        context.insert("logout", "Log Out");
        context.insert("upload", "Upload your track");
    }
    
    context.insert("login", "Log in");
    context.insert("register", "Sign Up");
    
    
    


    let rendered = tera.render("index.html", &context).unwrap_or_else(|e| {
        println!("Template error: {}", e);
        "Error rendering template".to_string()
    });

    RawHtml(rendered)
}


#[get("/user/<id>")]
async fn user(
    id: i32,
    tera: &State<Tera>,
    pool: &State<DbPool>,
) -> RawHtml<String> {

    
    let mut conn = pool.get().expect("Failed to get DB connection");

    let user: models::User = schema::users::table
        .filter(schema::users::id.eq(id))
        .first(&mut conn)
        .unwrap_or_else(|_| panic!("User not found"));

    let user_tracks: Vec<models::Track> = schema::tracks::table
        .filter(schema::tracks::user_id.eq(id))
        .load(&mut conn)
        .unwrap_or_default();

    let saved_tracks: Vec<models::Track> = schema::tracks::table
        .inner_join(schema::saved_tracks::table)
        .filter(schema::saved_tracks::user_id.eq(id))
        .select(schema::tracks::all_columns)
        .load(&mut conn)
        .unwrap_or_default();

    let mut context = Context::new();
    context.insert("title", &format!("Profile: {}", user.username));
    context.insert("user", &user);
    context.insert("tracks", &user_tracks);
    context.insert("saved_tracks", &saved_tracks);
    context.insert("logout", "Log Out");
    let rendered = tera
        .render("user.html", &context)
        .unwrap_or_else(|e| {
            println!("Template error: {}", e);
            "Error rendering template".to_string()
        });

    RawHtml(rendered)
}

// About route with a different template
#[get("/about")]
fn about(tera: &State<Tera>) -> RawHtml<String> {
    let mut context = Context::new();
    context.insert("title", "About Us");
    
    let rendered = tera.render("about.html", &context)
        .unwrap_or_else(|e| {
            println!("Template error: {}", e);
            "Error rendering template".to_string()
        });
    
    RawHtml(rendered)
}


#[derive(FromForm)]
struct RegisterForm {
    username: String,
    password: String,
}
/* 
#[post("/register", data = "<form>")]
async fn register(mut db: Connection<MyDatabaseSqlx>, form: Form<RegisterForm>) -> Result<Redirect, Status> {
    let hashed_password = hash(&form.password, DEFAULT_COST).map_err(|_| Status::InternalServerError)?;

    let new_user = NewUser {
        username: form.username.clone(),
        password: hashed_password,
    };

    sqlx::query(
        "INSERT INTO users (username, password) VALUES (?, ?)"
    )
    .bind(&new_user.username)
    .bind(&new_user.password)
    .execute(&mut **db) // Użyj &mut **db
    .await
    .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to("/login"))
}
*/


#[post("/register", data = "<form>")]
fn register(pool: &State<DbPool>, form: Form<RegisterForm>) -> Result<Redirect, Status> {
    use schema::users;

    let hashed_password = hash(&form.password, DEFAULT_COST)
        .map_err(|_| Status::InternalServerError)?;

    let new_user = models::NewUser {
        username: form.username.clone(),
        password: hashed_password,
    };

    let mut conn = pool.get().expect("Failed to get DB connection");

    diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&mut conn)
        .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to("/login"))
}

#[get("/register")]
fn register_form(tera: &State<Tera>) -> RawHtml<String> {
    let mut context = Context::new();
    context.insert("title", "Register");

    let rendered = tera.render("register.html", &context)
        .unwrap_or_else(|e| {
            println!("Template error: {}", e);
            "Error rendering template".to_string()
        });

    RawHtml(rendered)
}


#[derive(FromForm)]
struct LoginForm{
    username:String,
    password:String,
}

#[post("/login", data = "<form>")]
fn login(pool: &State<DbPool>, form: Form<LoginForm>, cookies: &CookieJar<'_>) -> Result<Redirect, Status> {
    use schema::users::dsl::*;

    let login_user = NewUser{
        username: form.username.clone(),
        password: form.password.clone(),
    };
    //let fusername = form.username.clone();
    //let fpassword: String = form.password.clone();
    
    let mut conn = pool.get().expect("Falied to get DB connection");

    let user_result = users
        .filter(username.eq(&form.username))
        .first::<models::User>(&mut conn)
        .map_err(|_| Status::Unauthorized)?;

    if verify(&login_user.password, &user_result.password).map_err(|_| Status::InternalServerError)?{
        // Passwd correct, set cookie
        cookies.add(Cookie::new("user_id", user_result.id.to_string()));
        Ok(Redirect::to("/"))
    }
    else{
        // Passwd incrrct, to login page
        Err(Status::Unauthorized)
    }

}

#[get("/login")]
fn login_form(tera: &State<Tera>, cookies: &CookieJar<'_>) -> RawHtml<String>{
    let mut context = Context::new();
    context.insert("title", "Login");
    if cookies.get("user_id").is_some(){
        context.insert("error", "Already logged in");
    }

    let rendered = tera.render("login.html", &context)
        .unwrap_or_else(|e|{
            println!("Template error: {}", e);
            "Error rendering template".to_string()
        });
    RawHtml(rendered)

}


#[get("/logout")]
fn logout(cookies: &CookieJar<'_>) -> Redirect{
    cookies.remove(Cookie::from("user_id"));
    Redirect::to("/")
}





#[post("/upload", data = "<data>")]
async fn upload(
    content_type: &rocket::http::ContentType,
    data: rocket::Data<'_>,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
) -> Result<Redirect, Status> {
    // Konfiguracja parsera multipart
    let mut options = MultipartFormDataOptions::new();
    options.allowed_fields = vec![
        MultipartFormDataField::text("title"),
        MultipartFormDataField::text("genre"),
        MultipartFormDataField::file("file").size_limit(100.megabytes().into()),
    ];

    let mut form = MultipartFormData::parse(content_type, data, options)
        .await
        .map_err(|e| {
            error!("Multipart parsing failed: {:?}", e);
            Status::BadRequest
        })?;

    // Pobranie user_id z ciasteczka
    let user_id: i32 = cookies
        .get("user_id")
        .ok_or(Status::Unauthorized)?
        .value()
        .parse()
        .map_err(|e| {
            error!("Błąd parsowania user_id: {:?}", e);
            Status::Unauthorized
        })?;

    // Pobierz pola
    let title = form.texts.remove("title")
        .and_then(|mut v| v.pop())
        .map(|field| field.text)
        .ok_or(Status::BadRequest)?;

    let genre = form.texts.remove("genre")
        .and_then(|mut v| v.pop())
        .map(|field| field.text)
        .ok_or(Status::BadRequest)?;

    let file_field = form.files.remove("file")
        .and_then(|mut v| v.pop())
        .ok_or(Status::BadRequest)?;

    let temp_path = file_field.path;
    let original_file_name = file_field.file_name.unwrap_or("uploaded".into());

    let extension = Path::new(&original_file_name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("mp3");

    let valid_extensions = ["mp3", "wav"];
    if !valid_extensions.contains(&extension.to_lowercase().as_str()) {
        return Err(Status::BadRequest);
    }

    std::fs::create_dir_all("uploads").map_err(|e| {
        error!("Couldn't create uploads dir: {:?}", e);
        Status::InternalServerError
    })?;

    let final_file_name = format!("uploads/{}_{}.{}", user_id, original_file_name, extension);
    let mut dest = File::create(&final_file_name).map_err(|e| {
        error!("Couldn't create final file: {:?}", e);
        Status::InternalServerError
    })?;
    let mut src = File::open(&temp_path).map_err(|e| {
        error!("Couldn't open temp file: {:?}", e);
        Status::InternalServerError
    })?;

    copy(&mut src, &mut dest).map_err(|e| {
        error!("Copy failed: {:?}", e);
        Status::InternalServerError
    })?;

    let new_track = models::NewTrack {
        user_id,
        title,
        genre,
        file_path: final_file_name,
    };

    let mut conn = pool.get().map_err(|e| {
        error!("DB conn error: {:?}", e);
        Status::InternalServerError
    })?;

    diesel::insert_into(schema::tracks::table)
        .values(&new_track)
        .execute(&mut conn)
        .map_err(|e| {
            error!("DB insert error: {:?}", e);
            Status::InternalServerError
        })?;

    Ok(Redirect::to("/"))
}


#[get("/upload")]
fn upload_form(tera: &State<Tera>) -> RawHtml<String> {
    let mut context = Context::new();
    context.insert("title", "Upload track");

    let rendered = tera.render("upload.html", &context)
        .unwrap_or_else(|e| {
            println!("Template error: {}", e);
            "Error rendering template".to_string()
        });

    RawHtml(rendered)
}


#[get("/tracks")]
async fn tracks(tera: &State<Tera>, pool: &State<DbPool>) -> Result<RawHtml<String>, Status> {
    use schema::users::dsl as users_dsl;
    use schema::tracks::dsl as tracks_dsl;
    let mut conn = pool.get().map_err(|e| {
        error!("Błąd połączenia z bazą danych: {:?}", e);
        Status::InternalServerError
    })?;

    let tracks_result = schema::tracks::table
        .load::<models::Track>(&mut conn)
        .map_err(|e| {
            error!("Błąd wczytywania utworów: {:?}", e);
            Status::InternalServerError
        })?;

    let mut context = Context::new();
    context.insert("title", "All Tracks");
    context.insert("tracks", &tracks_result);

    let tracks_with_users = tracks_dsl::tracks
        .inner_join(users_dsl::users.on(users_dsl::id.eq(tracks_dsl::user_id)))
        .select((
            tracks_dsl::id,
            tracks_dsl::title,
            tracks_dsl::genre,
            tracks_dsl::file_path,
            tracks_dsl::created_at,
            tracks_dsl::user_id,
            users_dsl::username,
        ))
        .load::<(i32, String, String, String, chrono::NaiveDateTime, i32, String)>(&mut conn);

    match tracks_with_users {
        Ok(tracks) => {
            let tracks_with_authors: Vec<_> = tracks
                .into_iter()
                .map(|(id, title, genre, file_path, created_at,track_user_id, username)| {
                    serde_json::json!({
                        "id": id,
                        "title": title,
                        "genre": genre,
                        "file_path": file_path,
                        "created_at": created_at,
                        "track_user_id": track_user_id,
                        "username": username,
                    })
                })
                .collect();
            context.insert("tracks", &tracks_with_authors);
        }
        Err(e) => {
            error!("Błąd wczytywania utworów: {:?}", e);
            context.insert("error", "Error loading tracks");
        }
    }

    let rendered: String = tera
        .render("tracks.html", &context)
        .map_err(|e| {
            error!("Błąd renderowania szablonu: {:?}", e);
            Status::InternalServerError
        })?;

    Ok(RawHtml(rendered))
}



#[get("/tracks/<id>")]
async fn track(
    id: i32,
    tera: &State<Tera>,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
) -> RawHtml<String> {
    let mut conn = pool.get().expect("Failed to get DB connection");

    let track_with_user: (models::Track, String, i32) = crate::schema::tracks::table
        .inner_join(crate::schema::users::table.on(crate::schema::users::id.eq(crate::schema::tracks::user_id)))
        .filter(crate::schema::tracks::id.eq(id))
        .select((crate::schema::tracks::all_columns, crate::schema::users::username, crate::schema::users::id))
        .first(&mut conn)
        .unwrap_or_else(|_| panic!("Track not found"));

    let (track, username, user_track_id) = track_with_user;
    

    
    #[derive(serde::Serialize)]
    struct CommentWithUsername {
        content: String,
        username: String,
    }
    
    let comments: Vec<CommentWithUsername> = crate::schema::comments::table
        .inner_join(crate::schema::users::table)
        .filter(crate::schema::comments::track_id.eq(id))
        .select((crate::schema::comments::content, crate::schema::users::username))
        .load::<(String, String)>(&mut conn)
        .unwrap_or_default()
        .into_iter()
        .map(|(content, username)| CommentWithUsername { content, username })
        .collect();

    let user_id: Option<i32> = cookies.get("user_id")
        .and_then(|c| c.value().parse().ok());

    let is_liked = if let Some(uid) = user_id {
        if let Ok(mut conn) = pool.get() {
            crate::schema::likes::table
                .filter(crate::schema::likes::user_id.eq(uid))
                .filter(crate::schema::likes::track_id.eq(id))
                .first::<models::Like>(&mut conn)
                .is_ok()
        } else {
            false
        }
    } else {
        false
    };

    let mut context = Context::new();
    context.insert("title", &track.title);
    context.insert("track", &track);
    context.insert("comments", &comments);
    context.insert("is_liked", &is_liked);
    context.insert("user_id", &user_id);
    context.insert("author", &username);
    context.insert("id", &user_track_id);


    let rendered = tera.render("track.html", &context)
        .unwrap_or_else(|e| {
            println!("Template error: {}", e);
            "Error rendering template".to_string()
        });

    RawHtml(rendered)
}


#[derive(FromForm)]
struct CommentForm {
    track_id: i32,
    content: String,
}

#[post("/comment", data = "<form>")]
async fn comment(
    form: Form<CommentForm>,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
) -> Result<Redirect, Status> {
    let user_id: i32 = cookies.get("user_id")
        .ok_or(Status::Unauthorized)?
        .value()
        .parse()
        .map_err(|_| Status::Unauthorized)?;

    let new_comment = models::NewComment {
        user_id,
        track_id: form.track_id,
        content: form.content.clone(),
    };

    let mut conn = pool.get().map_err(|_| Status::InternalServerError)?;
    diesel::insert_into(crate::schema::comments::table)
        .values(&new_comment)
        .execute(&mut conn)
        .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(format!("/tracks/{}", form.track_id)))
}


#[derive(FromForm)]
struct LikeForm {
    track_id: i32,
}

#[post("/like", data = "<form>")]
async fn like(
    form: Form<LikeForm>,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
) -> Result<Redirect, Status> {
    let user_id: i32 = cookies.get("user_id")
        .ok_or(Status::Unauthorized)?
        .value()
        .parse()
        .map_err(|_| Status::Unauthorized)?;

    let new_like = models::NewLike {
        user_id,
        track_id: form.track_id,
    };

    let mut conn = pool.get().map_err(|_| Status::InternalServerError)?;

    diesel::insert_into(crate::schema::likes::table)
        .values(&new_like)
        .execute(&mut conn)
        .map_err(|_| Status::BadRequest)?;

    Ok(Redirect::to(format!("/tracks/{}", form.track_id)))
}

#[post("/unlike", data = "<form>")]
async fn unlike(
    form: Form<LikeForm>,
    pool: &State<DbPool>,
    cookies: &CookieJar<'_>,
) -> Result<Redirect, Status> {
    let user_id: i32 = cookies.get("user_id")
        .ok_or(Status::Unauthorized)?
        .value()
        .parse()
        .map_err(|_| Status::Unauthorized)?;

    let mut conn = pool.get().map_err(|_| Status::InternalServerError)?;

    diesel::delete(
        crate::schema::likes::table
            .filter(crate::schema::likes::user_id.eq(user_id))
            .filter(crate::schema::likes::track_id.eq(form.track_id))
    )
    .execute(&mut conn)
    .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(format!("/tracks/{}", form.track_id)))
}



// Main function to set up the Rocket instance
// and configure the routes

// Configure and launch the Rocket instance
fn rocket() -> Rocket<Build> {
    // Initialize Tera with template directory
    let tera = Tera::new("templates/**/*")
        .expect("Failed to initialize Tera templates");
    
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env file");
    let manager = ConnectionManager::<MysqlConnection>::new(database_url);
    let pool = diesel::r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create DB pool");

    // Konfiguracja z limitami
    let config = Config {
        limits: Limits::new()
            .limit("form", ByteUnit::Megabyte(100))
            .limit("file", ByteUnit::Megabyte(100))
            .limit("multipart", ByteUnit::Megabyte(100))
            .limit("data-stream", ByteUnit::Megabyte(100))
            .limit("temp_file", ByteUnit::Megabyte(100)), // Jawne ustawienie dla TempFile
        ..Config::default()
    };
    println!("Limits: {:?}", config.limits); // Debugowanie
    rocket::custom(config)
        .manage(tera)
        .manage(pool)
        .mount("/uploads", FileServer::from("uploads"))
        .mount("/", routes![
            index,
            about,
            user,
            register_form,
            register,
            login_form,
            login,
            logout,
            upload,
            upload_form,
            tracks,
            track,
            comment,
            like,
            unlike
        ])
        .mount("/static", FileServer::from("static"))
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    
    

    dotenv().ok();
    rocket().launch().await?;
    Ok(())
}
