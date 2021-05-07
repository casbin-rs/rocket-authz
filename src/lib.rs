use rocket::{
    fairing::{Info, Kind, Fairing},
};

use std::sync::{Arc, RwLock};
use casbin::prelude::*;
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};

#[derive(Clone)]
pub struct CasbinFairing {
    pub enforcer: Arc<RwLock<CachedEnforcer>>
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
        CasbinFairing{enforcer: e}
    }
}

impl Fairing for CasbinFairing {
    
    fn info(&self) -> Info { 
        Info {
            name: "Casbin Fairing",
            kind: Kind::Request | Kind::Response,
        }
    }
}