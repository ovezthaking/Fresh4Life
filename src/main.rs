use rocket::{Rocket, Build, State};
use rocket::fs::FileServer;
use rocket::response::content::RawHtml;
use tera::{Tera, Context};
use serde::Serialize;
use rocket::get;
use rocket::routes;


// A simple struct to pass to our template
#[derive(Serialize)]
struct User {
    name: String,
    age: i32,
}

// Index route that renders a template
#[get("/")]
fn index(tera: &State<Tera>) -> RawHtml<String> {
    let mut context = Context::new();
    
    // Sample data
    let user = User {
        name: "John Doe".to_string(),
        age: 30,
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
        .unwrap_or_else(|e| "Error rendering template".to_string());
    
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

// Configure and launch the Rocket instance
fn rocket() -> Rocket<Build> {
    // Initialize Tera with template directory
    let tera = Tera::new("templates/**/*")
        .expect("Failed to initialize Tera templates");
    
    rocket::build()
        .manage(tera) // Add Tera to Rocket's managed state
        .mount("/", routes![index, about])
        .mount("/static", FileServer::from("static"))
        .mount("/user", routes![user]) // Mount user route)
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    rocket().launch().await?;
    Ok(())
}
