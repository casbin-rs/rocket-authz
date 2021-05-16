# Rocket Casbin Middleware
[Casbin](https://github.com/casbin/casbin-rs) access control middleware for [Rocket](https://github.com/SergioBenitez/Rocket) framework
## Install
Add it to `Cargo.toml`

```rust
rocket-authz = "0.1.0"
```
## Requirement
**Casbin only takes charge of permission control**, so you need to implement an `Authentication Middleware` to identify user.
You need to put `rocket_authz::CasbinVals` which contains `subject` and `domain`(optional) into `reqeust.local_cache()` through an `Authentication Middleware`. You could see an example of using rocket-authz in [Example](#example).
## Example
```rust
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
```
## License
This project is licensed under

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))