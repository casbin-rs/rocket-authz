#![feature(proc_macro_hygiene, decl_macro)]
use casbin::{DefaultModel, FileAdapter};
use rocket::{
    fairing::{Fairing, Info, Kind},
    get,
    request::Request,
    routes, Data,
};
use rocket_authz;

struct FakeAuthFairing;

impl Fairing for FakeAuthFairing {
    fn info(&self) -> Info {
        Info {
            name: "Fake Auth Fairing",
            kind: Kind::Request | Kind::Response,
        }
    }

    fn on_request(&self, request: &mut Request, _data: &Data) {
        request.local_cache(|| rocket_authz::CasbinVals::new(Some("alice".to_string()), None));
    }
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
    let m = match rt.block_on(DefaultModel::from_file(
        "examples/rbac_with_pattern_model.conf",
    )) {
        Ok(m) => m,
        Err(_) => panic!(""),
    };
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_fairing = match rt.block_on(rocket_authz::CasbinFairing::new(m, a)) {
        Ok(f) => f,
        Err(_) => panic!(""),
    };
    let fake_auth_fairing = FakeAuthFairing;
    rocket::ignite()
        .attach(fake_auth_fairing)
        .attach(casbin_fairing)
        .mount("/", routes![data1, data2])
}

#[cfg(test)]
mod test {
    use super::rocket;
    use rocket::http::Status;
    use rocket::local::Client;

    #[test]
    fn login_data2() {
        let client = Client::new(rocket()).expect("valid rocket instance");
        let req = client.get("/data2");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let req = client.get("/data1");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Forbidden);
    }
}
