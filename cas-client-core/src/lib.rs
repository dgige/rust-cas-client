extern crate env_logger;
#[macro_use]
extern crate log;
#[allow(unused_imports)]
#[macro_use]
extern crate serde;

mod client;
mod user;

pub use crate::client::{CasClient, CasProtocol, NoAuthBehavior};
pub use crate::user::CasUser;
