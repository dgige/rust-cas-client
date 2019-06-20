use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CasUser {
    username: String,
    attributes: HashMap<String, String>,
}

impl CasUser {
    pub fn new(username: &str, attributes: Option<HashMap<String, String>>) -> CasUser {
        debug!(
            "New CAS user : {{ username: {}, attributes: {:?} }}",
            username, attributes
        );
        CasUser {
            username: username.to_string(),
            attributes: match attributes {
                Some(v) => v,
                None => HashMap::new(),
            },
        }
    }

    // Getters
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    pub fn attributes(&self) -> HashMap<String, String> {
        self.attributes.clone()
    }

    // Setters

    // Public functions
    pub fn into_raw(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_raw(raw: &str) -> Self {
        debug!("CAS user from raw: {}", raw);
        serde_json::from_str(raw).unwrap()
    }
}
