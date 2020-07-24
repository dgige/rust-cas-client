use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Struct for CAS user
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct CasUser {
    username: String,
    attributes: HashMap<String, String>,
}

impl CasUser {
    // ################################################################################
    // Constructor
    // ################################################################################
    //
    /// Returns new CAS user
    ///
    /// # Examples
    ///
    /// - Without attributes:
    /// ```
    /// use cas_client_core::CasUser;
    /// use std::collections::HashMap;
    ///
    /// let cas_user = CasUser::new("user", None);
    /// assert_eq!(cas_user.username(), "user");
    /// assert_eq!(cas_user.attributes(), HashMap::new());
    /// ```
    ///
    /// - With attributes:
    /// ```
    /// use cas_client_core::CasUser;
    /// use std::collections::HashMap;
    ///
    /// let mut attributes: HashMap<String, String> = HashMap::new();
    /// attributes.insert("Attribute 1".to_string(), "value 1".to_string());
    /// attributes.insert("Attribute 2".to_string(), "value 2".to_string());
    /// let cas_user = CasUser::new("user", Some(attributes.clone()));
    /// assert_eq!(cas_user.username(), "user");
    /// assert_eq!(cas_user.attributes(), attributes);
    /// ```
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

    // ################################################################################
    // Instance functtions
    // ################################################################################
    //
    /// Get CAS user's username
    ///
    /// # Examples
    /// ```
    /// use cas_client_core::CasUser;
    ///
    /// let cas_user = CasUser::new("user", None);
    /// assert_eq!(cas_user.username(), "user");
    /// ```
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    /// Get CAS user's attributes
    ///
    /// # Examples
    /// ```
    /// use cas_client_core::CasUser;
    /// use std::collections::HashMap;
    ///
    /// let mut attributes: HashMap<String, String> = HashMap::new();
    /// attributes.insert("Attribute 1".to_string(), "value 1".to_string());
    /// attributes.insert("Attribute 2".to_string(), "value 2".to_string());
    /// let cas_user = CasUser::new("user", Some(attributes.clone()));
    /// assert_eq!(cas_user.attributes(), attributes);
    /// ```
    pub fn attributes(&self) -> HashMap<String, String> {
        self.attributes.clone()
    }

    /// Converts CAS user to String
    ///
    /// # Examples
    /// - Without attributes:
    /// ```
    /// use cas_client_core::CasUser;
    /// use std::collections::HashMap;
    ///
    /// let cas_user = CasUser::new("user", None);
    /// assert_eq!(cas_user.to_raw(), "{\"username\":\"user\",\"attributes\":{}}");
    /// ```
    /// - With attributes:
    /// ```
    /// use cas_client_core::CasUser;
    /// use std::collections::HashMap;
    ///
    /// let mut attributes: HashMap<String, String> = HashMap::new();
    /// attributes.insert("Attribute 1".to_string(), "value 1".to_string());
    /// attributes.insert("Attribute 2".to_string(), "value 2".to_string());
    /// let cas_user = CasUser::new("user", Some(attributes.clone()));
    /// assert_eq!(cas_user.to_raw(), serde_json::to_string(&cas_user).unwrap());
    /// ```
    pub fn to_raw(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    // ################################################################################
    // Class functions
    // ################################################################################    /// Converts String to CAS user
    //
    /// # Examples
    /// - Without attributes:
    /// ```
    /// use cas_client_core::CasUser;
    /// use std::collections::HashMap;
    ///
    /// let cas_user = CasUser::from_raw("{\"username\":\"user\",\"attributes\":{}}");
    /// assert_eq!(cas_user, CasUser::new("user", None));
    /// ```
    /// - With attributes:
    /// ```
    /// use cas_client_core::CasUser;
    /// use std::collections::HashMap;
    ///
    /// let mut attributes: HashMap<String, String> = HashMap::new();
    /// attributes.insert("Attribute 1".to_string(), "value 1".to_string());
    /// attributes.insert("Attribute 2".to_string(), "value 2".to_string());
    /// let cas_user = CasUser::new("user", Some(attributes.clone()));
    /// assert_eq!(CasUser::from_raw(&cas_user.to_raw()), cas_user);
    /// ```
    pub fn from_raw(raw: &str) -> Self {
        debug!("CAS user from raw: {}", raw);
        serde_json::from_str(raw).unwrap()
    }
}
