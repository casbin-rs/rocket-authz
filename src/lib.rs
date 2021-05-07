use rocket::{
    fairing::{Fairing, Info, Kind},
    http::Status,
    request::{self, FromRequest, Request},
    Data,
};

use casbin::prelude::*;
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct CasbinGuard(Option<Status>);

impl<'a, 'r> FromRequest<'a, 'r> for CasbinGuard {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<CasbinGuard, ()> {
        match *request.local_cache(|| CasbinGuard(Status::from_code(0))) {
            CasbinGuard(Some(Status::Ok)) => {
                request::Outcome::Success(CasbinGuard(Some(Status::Ok)))
            }
            CasbinGuard(Some(err_status)) => request::Outcome::Failure((err_status, ())),
            _ => request::Outcome::Failure((Status::BadGateway, ())),
        }
    }
}

#[derive(Clone)]
pub struct CasbinFairing {
    pub enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl CasbinFairing {
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> CasbinResult<Self> {
        let enforcer: CachedEnforcer = CachedEnforcer::new(m, a).await?;
        Ok(CasbinFairing {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }

    pub fn get_enforcer(&mut self) -> Arc<RwLock<CachedEnforcer>> {
        self.enforcer.clone()
    }

    pub fn set_enforcer(e: Arc<RwLock<CachedEnforcer>>) -> CasbinFairing {
        CasbinFairing { enforcer: e }
    }
}

impl Fairing for CasbinFairing {
    fn info(&self) -> Info {
        Info {
            name: "Casbin Fairing",
            kind: Kind::Request | Kind::Response,
        }
    }

    fn on_request(&self, request: &mut Request, _data: &Data) {
        let cloned_enforce = self.enforcer.clone();
        let path = request.uri().path().to_owned();
        let action = request.method().as_str().to_owned();
        // Get subject and domain from cookie.
        let subject = request.cookies().get("subject").map(|x| x.to_owned());
        let domain = request.cookies().get("domain").map(|x| x.to_owned());

        if let Some(subject) = subject {
            if let Some(domain) = domain {
                let subject_str = subject.value().to_string();
                let domain_str = domain.value().to_string();
                let mut lock = cloned_enforce.write().unwrap();
                match lock.enforce_mut(vec![subject_str, domain_str, path, action]) {
                    Ok(true) => {
                        drop(lock);
                        request.local_cache(|| CasbinGuard(Some(Status::Ok)));
                    }
                    Ok(false) => {
                        drop(lock);
                        request.local_cache(|| CasbinGuard(Some(Status::Forbidden)));
                    }
                    Err(_) => {
                        drop(lock);
                        request.local_cache(|| CasbinGuard(Some(Status::BadGateway)));
                    }
                };
            } else {
                let subject_str = subject.value().to_string();
                let mut lock = cloned_enforce.write().unwrap();
                match lock.enforce_mut(vec![subject_str, path, action]) {
                    Ok(true) => {
                        drop(lock);
                        request.local_cache(|| CasbinGuard(Some(Status::Ok)));
                    }
                    Ok(false) => {
                        drop(lock);
                        request.local_cache(|| CasbinGuard(Some(Status::Forbidden)));
                    }
                    Err(_) => {
                        drop(lock);
                        request.local_cache(|| CasbinGuard(Some(Status::BadGateway)));
                    }
                };
            }
        } else {
            request.local_cache(|| CasbinGuard(Some(Status::BadGateway)));
        }
    }
}
