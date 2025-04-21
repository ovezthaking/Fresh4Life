mod models;
mod schema;

//use crate::schema::users;
use rocket::response::Redirect;
use rocket::{Rocket, Build, State};
use rocket::fs::FileServer;
use rocket::response::content::RawHtml;
use tera::{Tera, Context};
//use serde::Serialize;
use rocket::get;
use rocket::routes;
use rocket::post;
use rocket::form::FromForm;
use rocket::form::Form;
use rocket::http::Status;
use bcrypt::{hash, DEFAULT_COST};
use diesel::prelude::*;
use rocket_sync_db_pools::database;
use models::NewUser;
//use crate::schema::users;
use rocket_db_pools::{sqlx, Connection, Database};
use dotenv::dotenv;
use diesel::r2d2::ConnectionManager;

#[derive(Database)]
#[database("mysql_db")]
struct MyDatabaseSqlx(sqlx::MySqlPool);

type DbPool = diesel::r2d2::Pool<ConnectionManager<MysqlConnection>>;

// Index route that renders a template
#[get("/")]
async fn index(pool: &State<DbPool>, tera: &State<Tera>) -> RawHtml<String> {
    use schema::users::dsl::*;

    let mut context = Context::new();

    // Get a connection from the pool
    let mut conn = pool.get().expect("Failed to get DB connection");

    // Retrieve the first user from the database
    let user_result = users
        .first::<models::User>(&mut conn)
        .optional();

    match user_result {
        Ok(Some(user)) => {
            context.insert("user", &user);
        }
        Ok(None) => {
            context.insert("error", "No users found");
        }
        Err(e) => {
            println!("Database error: {}", e);
            context.insert("error", "Error fetching user");
        }
    }

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
    
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env file");
    let manager = ConnectionManager::<MysqlConnection>::new(database_url);
    let pool = diesel::r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create DB pool");

        rocket::build()
        .attach(MyDatabaseSqlx::init())
        .manage(tera) // Dodanie Tera do stanu zarządzanego
        .manage(pool)
        .mount("/", routes![
            index,
            about,
            user,
            register_form,
            register
            ])
        .mount("/static", FileServer::from("static"))
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    dotenv().ok();
    rocket().launch().await?;
    Ok(())
}
