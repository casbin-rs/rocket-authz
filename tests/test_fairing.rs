#![feature(proc_macro_hygiene, decl_macro)]
use rocket_authz;
use casbin::{DefaultModel, FileAdapter};
use rocket::{
    get,
    routes,
    http::{Cookies, Cookie},
};

#[get("/login")]
fn login(mut cookies: Cookies) -> &'static str {
    cookies.add(Cookie::new("subject", "alice"));
    "success"
}

#[get("/data1")]
fn data1(_g: rocket_authz::CasbinGuard) -> &'static str {
    "data1"
}

#[get("/data2")]
fn data2(_g: rocket_authz::CasbinGuard) -> &'static str {
    "data2"
}

fn rocket() -> rocket::Rocket {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let m = match rt.block_on(DefaultModel::from_file("examples/rbac_with_pattern_model.conf")) {
        Ok(m) => m,
        Err(_) => panic!(""),
    };
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");
    
    let casbin_fairing = match rt.block_on(rocket_authz::CasbinFairing::new(m, a)){
        Ok(f) => f,
        Err(_) => panic!(""),
    };
    rocket::ignite()
        .attach(casbin_fairing)
        .mount("/", routes![login, data1, data2])
}

#[cfg(test)]
mod test {
    use super::rocket;
    use rocket::local::Client;
    use rocket::http::Status; 

    #[test]
    fn login_data2() {
        let client = Client::new(rocket()).expect("valid rocket instance");
        let req = client.get("/login");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let req = client.get("/data2");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let req = client.get("/data1");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Forbidden);
    }
}