#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;

use rocket_contrib::serve::StaticFiles;
use rocket_contrib::templates::Template;
use std::collections::HashMap;
use chrono::prelude::*;

#[get("/")]
fn index() -> Template {
    let mut context = HashMap::new();
    context.insert("title", "My Portfolio");
    context.insert("subtitle", "Welcome to my portfolio website!");
    let projects = vec![
        Project {
            name: "Project 1",
            url: "https://project1.example.com",
            description: "This is my first project.",
        },
        Project {
            name: "Project 2",
            url: "https://project2.example.com",
            description: "This is my second project.",
        },
        Project {
            name: "Project 3",
            url: "https://project3.example.com",
            description: "This is my third project.",
        },
    ];
    context.insert("projects", &projects);
    context.insert("year", Utc::now().year());
    Template::render("index", &context)
}

struct Project {
    name: &'static str,
    url: &'static str,
    description: &'static str,
}

fn main() {
    rocket::ignite()
        .mount("/", routes![index])
        .mount("/static", StaticFiles::from("static"))
        .attach(Template::fairing())
        .launch();
}
