mod models;
mod schema;

//use crate::schema::users;
use rocket::response::Redirect;
use rocket::{Rocket, Build, State};
use rocket::fs::FileServer;
use rocket::response::content::RawHtml;
use tera::{Tera, Context};
use serde::Serialize;
use rocket::get;
use rocket::routes;
use rocket::post;
use rocket::form::FromForm;
use rocket::form::Form;
use rocket::http::Status;
use bcrypt::{hash, DEFAULT_COST};
use diesel::prelude::*;
use rocket_sync_db_pools::database;
use models::{User, NewUser};
use crate::schema::users;
use rocket_db_pools::{sqlx, Connection, Database};

#[derive(Database)]
#[database("mysql_db")]
struct MyDatabase(sqlx::MySqlPool);




// Index route that renders a template
#[get("/")]
fn index(tera: &State<Tera>) -> RawHtml<String> {
    let mut context = Context::new();
    
    // Sample data
    let user = User {
        id: 1,
        username: "John Poe".to_string(),
        password: "30".to_string(),
        created_at: chrono::NaiveDateTime::from_timestamp(0, 0),
    };
    
    context.insert("user", &user);
    context.insert("title", "Welcome");
    
    // Render the template
    let rendered = tera.render("index.html", &context)
        .unwrap_or_else(|e| {
            println!("Template error: {}", e);
            "Error rendering template".to_string()
        });
    
    RawHtml(rendered)
}


#[get("/user/<id>")]
fn user(tera: &State<Tera>, id: i32) -> RawHtml<String> {
    let mut context = Context::new();
    context.insert("id", &id);
    context.insert("title", "User Profile");
    
    let rendered = tera.render("user.html", &context)
        .unwrap_or_else(|_e| "Error rendering template".to_string());
    
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



#[post("/register", data = "<form>")]
async fn register(mut db: Connection<MyDatabase>, form: Form<RegisterForm>) -> Result<Redirect, Status> {
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


// Main function to set up the Rocket instance
// and configure the routes

// Configure and launch the Rocket instance
fn rocket() -> Rocket<Build> {
    // Initialize Tera with template directory
    let tera = Tera::new("templates/**/*")
        .expect("Failed to initialize Tera templates");
    
        rocket::build()
        .attach(MyDatabase::init()) // Inicjalizacja bazy danych
        .manage(tera) // Dodanie Tera do stanu zarządzanego
        .mount("/", routes![about, user, register, register_form])
        .mount("/static", FileServer::from("static"))
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    rocket().launch().await?;
    Ok(())
}
