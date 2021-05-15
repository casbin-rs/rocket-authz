use rocket::{
    fairing::{Fairing, Info, Kind},
    http::Status,
    request::{self, FromRequest, Request},
    Data,
};

use casbin::prelude::*;
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};
use parking_lot::RwLock;
use std::sync::Arc;

pub struct CasbinVals {
    pub subject: Option<String>,
    pub domain: Option<String>,
}

impl CasbinVals {
    pub fn new(subject: Option<String>, domain: Option<String>) -> CasbinVals {
        CasbinVals { subject, domain }
    }
}

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

        let (subject, domain) = match request.local_cache(|| CasbinVals {
            subject: None,
            domain: None,
        }) {
            CasbinVals {
                subject: Some(x),
                domain: Some(y),
            } => (Some(x.to_owned()), Some(y.to_owned())),
            CasbinVals {
                subject: Some(x),
                domain: None,
            } => (Some(x.to_owned()), None),
            _ => (None, None),
        };

        if let Some(subject) = subject {
            if let Some(domain) = domain {
                let mut lock = cloned_enforce.write();
                match lock.enforce_mut(vec![subject, domain, path, action]) {
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
                let mut lock = cloned_enforce.write();
                match lock.enforce_mut(vec![subject, path, action]) {
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
