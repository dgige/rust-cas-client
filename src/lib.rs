extern crate cas_client_core;

pub use cas_client_core::CasUser;
pub use cas_client_core::{CasClient, CasProtocol, NoAuthBehavior};

#[cfg(feature = "actix-framework")]
pub mod actix;
