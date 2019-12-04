extern crate curl;
extern crate roxmltree;
extern crate url;

use crate::CasUser;

use curl::easy::Easy;
use std::collections::HashMap;
use url::Url;

#[derive(Clone, Debug, PartialEq)]
pub struct CasClient {
    cas_base_url: Url,
    login_prefix: String,
    logout_prefix: String,
    no_auth_behavior: NoAuthBehavior,
    cas_protocol: CasProtocol,
    app_url: String,
    service_validate_prefix: String,
    login_service: String,
}

impl CasClient {
    // ################################################################################
    // Constructor
    // ################################################################################
    pub fn new(cas_base_url: &str) -> Result<Self, &str> {
        let _cas_base_url = match cas_base_url.ends_with('/') {
            true => cas_base_url.to_string(),
            _ => cas_base_url.to_string() + "/",
        };

        match Url::parse(&_cas_base_url) {
            Ok(url) => Ok(CasClient {
                cas_base_url: url,
                cas_protocol: CasProtocol::V3,
                login_prefix: String::from("login"),
                logout_prefix: String::from("logout"),
                no_auth_behavior: NoAuthBehavior::Authenticate,
                app_url: String::new(),
                service_validate_prefix: String::from("serviceValidate"),
                login_service: String::from("auth/cas"),
            }),
            Err(e) => {
                error!("CAS url is not valid! Error: {}", e);
                Err("CAS url is not valid!")
            }
        }
    }

    // ################################################################################
    // Getters / Setters
    // ################################################################################
    // CAS base url
    pub fn cas_base_url(&self) -> &Url {
        &self.cas_base_url
    }

    // Login service
    pub fn login_service(&self) -> &String {
        &self.login_service
    }

    pub fn set_login_service(&mut self, login_service: &str) -> &mut Self {
        if login_service.len() != 0 {
            self.login_service = login_service.to_string();
            if self.login_service.starts_with('/') {
                self.login_service = self.login_service[1..].to_string();
            }
            if self.login_service.ends_with('/') {
                self.login_service.pop();
            }
        } else {
            error!("Login service cannot be empty");
        }
        self
    }

    // Login prefix
    pub fn login_prefix(&self) -> &String {
        &self.login_prefix
    }

    pub fn set_login_prefix(&mut self, login_prefix: &str) -> &mut Self {
        if login_prefix.len() != 0 {
            self.login_prefix = login_prefix.to_string();
            if self.login_prefix.starts_with('/') {
                self.login_prefix = self.login_prefix[1..].to_string();
            }
            if self.login_prefix.ends_with('/') {
                self.login_prefix.pop();
            }
        } else {
            error!("Login prefix cannot be empty");
        }
        self
    }

    // Logout prefix
    pub fn logout_prefix(&self) -> &String {
        &self.logout_prefix
    }

    pub fn set_logout_prefix(&mut self, logout_prefix: &str) -> &mut Self {
        if logout_prefix.len() != 0 {
            self.logout_prefix = logout_prefix.to_string();
            if self.logout_prefix.starts_with('/') {
                self.logout_prefix = self.logout_prefix[1..].to_string();
            }
            if self.logout_prefix.ends_with('/') {
                self.logout_prefix.pop();
            }
        } else {
            error!("Logout prefix cannot be empty");
        }
        self
    }

    // No auth behavior
    pub fn no_auth_behavior(&self) -> &NoAuthBehavior {
        &self.no_auth_behavior
    }

    pub fn set_no_auth_behavior(
        &mut self,
        no_auth_behavior: NoAuthBehavior,
    ) -> &mut Self {
        self.no_auth_behavior = no_auth_behavior;
        self
    }

    // CAS protocol
    pub fn cas_protocol(&self) -> &CasProtocol {
        &self.cas_protocol
    }

    pub fn set_cas_protocol(&mut self, cas_protocol: CasProtocol) -> &mut Self {
        self.cas_protocol = cas_protocol;
        self
    }

    // Service url
    pub fn app_url(&self) -> &str {
        &self.app_url
    }

    pub fn set_app_url(&mut self, app_url: &str) -> &mut Self {
        match Url::parse(app_url) {
            Ok(_) => self.app_url = app_url.trim_end_matches("/").to_string(),
            Err(err) => error!("Invalid service url! Error: {:?}", err),
        };
        self
    }

    // Service validate prefix
    pub fn service_validate_prefix(&self) -> &String {
        &self.service_validate_prefix
    }

    pub fn set_service_validate_prefix(
        &mut self,
        service_validate_prefix: &str,
    ) -> &mut Self {
        if service_validate_prefix.len() != 0 {
            self.service_validate_prefix = service_validate_prefix.to_string();
            if self.service_validate_prefix.starts_with('/') {
                self.service_validate_prefix =
                    self.service_validate_prefix[1..].to_string();
            }
            if self.service_validate_prefix.ends_with('/') {
                self.service_validate_prefix.pop();
            }
        } else {
            error!("Service validate prefix cannot be empty");
        }
        self
    }

    // ################################################################################
    // Public functions
    // ################################################################################
    pub fn login_url(&self) -> Option<String> {
        match Url::parse_with_params(
            &format!("{}{}", &self.cas_base_url(), &self.login_prefix()),
            &[(
                "service",
                &format!("{}/{}/login", self.app_url(), self.login_service()),
            )],
        ) {
            Ok(url) => Some(url.to_string()),
            Err(e) => {
                error!("Error while parsing login url. Error: {}", e);
                None
            }
        }
    }

    pub fn logout_url(&self) -> Option<String> {
        match Url::parse_with_params(
            &format!("{}{}", &self.cas_base_url(), &self.logout_prefix()),
            &[("service", &format!("{}", self.app_url()))],
        ) {
            Ok(url) => Some(url.to_string()),
            Err(e) => {
                error!("Error while parsing logout url. Error: {}", e);
                None
            }
        }
    }

    // ###########
    // BEGIN TODO: TEST
    // ###########
    pub fn validate_service_ticket(&self, service_ticket: &str) -> Option<CasUser> {
        debug!("Validating service ticket: {:#?}", service_ticket);

        let resp = match self.fetch_cas_validation(service_ticket) {
            Some(r) => r,
            None => {
                error!("Error while fetching cas validation!");
                return None;
            }
        };
        let (user, attributes) = self.parse_saml_response(resp);

        match user.len() {
            0 => None,
            _ => Some(CasUser::new(&user, Some(attributes))),
        }
    }
    // ###########
    // END TODO
    // ###########

    // ################################################################################
    // Private functions
    // ################################################################################
    // ###########
    // BEGIN TODO: TEST
    // ###########
    pub(self) fn fetch_cas_validation(&self, ticket: &str) -> Option<String> {
        match self.service_validate_url(ticket) {
            Some(url) => {
                let mut data = Vec::new();
                let mut handle = Easy::new();
                handle.url(&url).unwrap();
                {
                    let mut transfer = handle.transfer();
                    transfer
                        .write_function(|new_data| {
                            data.extend_from_slice(new_data);
                            Ok(new_data.len())
                        })
                        .unwrap();
                    transfer.perform().unwrap();
                }
                match String::from_utf8(data) {
                    Ok(r) => Some(r),
                    Err(err) => {
                        error!(
                            "Error while requesting ticket validation! Error: {:?}",
                            err
                        );
                        return None;
                    }
                }
            }
            None => {
                error!("Error: service_ticket_validation_url returned None!");
                return None;
            }
        }
    }
    // ###########
    // END TODO
    // ###########

    pub(self) fn parse_saml_response(
        &self,
        resp: String,
    ) -> (String, HashMap<String, String>) {
        let mut user = String::new();
        let mut attributes: HashMap<String, String> = HashMap::new();
        let xml_resp = roxmltree::Document::parse(&resp);
        if let Ok(document) = xml_resp {
            for node in document.root().descendants() {
                if node.is_element() {
                    match node.tag_name().name() {
                        "authenticationFailure" => {
                            info!("Authentication error!");
                        }
                        "authenticationSuccess" => {
                            info!("Authentication success!");
                        }
                        "serviceResponse" | "attributes" => {}
                        "user" => {
                            if let Some(child) = node.first_child() {
                                if let Some(text) = child.text() {
                                    user.push_str(text);
                                }
                            }
                        }
                        attr => {
                            if let Some(child) = node.first_child() {
                                if let Some(text) = child.text() {
                                    attributes
                                        .entry(attr.to_string())
                                        .or_insert(text.to_string());
                                }
                            }
                        }
                    }
                }
            }
        };
        (user, attributes)
    }

    pub(self) fn service_validate_url(&self, ticket: &str) -> Option<String> {
        match Url::parse_with_params(
            &format!(
                "{}{}",
                &self.cas_base_url(),
                &self.service_validate_prefix()
            ),
            &[
                (
                    "service",
                    &format!("{}/{}/login", self.app_url(), self.login_service()),
                ),
                ("ticket", &format!("{}", ticket)),
            ],
        ) {
            Ok(url) => Some(url.to_string()),
            Err(e) => {
                error!("Error while parsing service validate url. Error: {}", e);
                None
            }
        }
    }
}
/// CAS protocal to use
///
/// NOT USED CURRENTLY
///
#[derive(Clone, Debug, PartialEq)]
pub enum CasProtocol {
    V2,
    V3,
}

/// Enum for CAS client behavior when user is not logged in
///
/// - AuthenticatedOr403: returns HTTP 403 status code if user is not logged in
/// - AuthenticatedOr404: returns HTTP 404 status code if user is not logged in
/// - Authenticate: authenticates user if is not logged in
/// - ForceAuthentication: authenticates user for each request
#[derive(Clone, Debug, PartialEq)]
pub enum NoAuthBehavior {
    AuthenticatedOr403,
    AuthenticatedOr404,
    Authenticate,
    ForceAuthentication,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    // ################################################################################
    // Constructor
    // ################################################################################
    #[test]
    fn new_should_return_client() {
        let cas_base_url = "https://cas.example.org";
        let cas_client = CasClient::new(cas_base_url).unwrap();
        assert_eq!(
            cas_client.cas_base_url.to_string(),
            "https://cas.example.org/"
        );
        assert_eq!(cas_client.login_prefix, "login");
        assert_eq!(cas_client.logout_prefix, "logout");
        assert_eq!(cas_client.no_auth_behavior, NoAuthBehavior::Authenticate);
        assert_eq!(cas_client.cas_protocol, CasProtocol::V3);
        assert_eq!(cas_client.app_url, String::new());
        assert_eq!(cas_client.service_validate_prefix, "serviceValidate");

        let cas_base_url = "https://cas.example.org/";
        let cas_client = CasClient::new(cas_base_url).unwrap();
        assert_eq!(
            cas_client.cas_base_url.to_string(),
            "https://cas.example.org/"
        );

        let cas_base_url = "https://cas.example.org/cas";
        let cas_client = CasClient::new(cas_base_url).unwrap();
        assert_eq!(
            cas_client.cas_base_url.to_string(),
            "https://cas.example.org/cas/"
        );

        let cas_base_url = "https://cas.example.org/cas/";
        let cas_client = CasClient::new(cas_base_url).unwrap();
        assert_eq!(
            cas_client.cas_base_url.to_string(),
            "https://cas.example.org/cas/"
        );
    }

    #[test]
    fn new_should_return_an_error_if_cas_url_is_empty() {
        let cas_url = "";
        let cas_client = CasClient::new(cas_url);
        assert_eq!(cas_client.is_err(), true);
    }

    #[test]
    fn new_should_return_an_error_if_cas_url_is_invalid() {
        let cas_url = "cas.example.org";
        let cas_client = CasClient::new(cas_url);
        assert_eq!(cas_client.is_err(), true);
    }

    // ################################################################################
    // Getters / Setters
    // ################################################################################
    // CAS base url
    #[test]
    fn cas_base_url_getter() {
        let cas_url = "https://cas.example.org";
        let cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(
            cas_client.cas_base_url().to_string(),
            "https://cas.example.org/"
        );

        let cas_url = "https://cas.example.org/cas";
        let cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(
            cas_client.cas_base_url().to_string(),
            "https://cas.example.org/cas/"
        );
    }

    // Login prefix
    #[test]
    fn login_prefix_getter_and_setter() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(cas_client.login_prefix, "login");

        // Invalid login_prefix
        cas_client.set_login_prefix("");
        assert_eq!(cas_client.login_prefix, "login");

        // Valid login_prefix
        cas_client.set_login_prefix("custom_login_path");
        assert_eq!(cas_client.login_prefix, "custom_login_path");

        cas_client.set_login_prefix("custom_login_path/");
        assert_eq!(cas_client.login_prefix, "custom_login_path");

        cas_client.set_login_prefix("/custom_login_path");
        assert_eq!(cas_client.login_prefix, "custom_login_path");
    }

    #[test]
    fn set_login_prefix_should_return_self() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();

        // Invalid login_prefix
        let return_value = cas_client.set_login_prefix("").clone();
        assert_eq!(return_value, cas_client);

        // Valid login_prefix
        let return_value = cas_client.set_login_prefix("custom_login_path").clone();
        assert_eq!(return_value, cas_client);
    }

    // Login service
    #[test]
    fn login_service_getter_and_setter() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(cas_client.login_service, "auth/cas");

        // Invalid login_service
        cas_client.set_login_service("");
        assert_eq!(cas_client.login_service, "auth/cas");

        // Valid login_service
        cas_client.set_login_service("auth/mycas");
        assert_eq!(cas_client.login_service, "auth/mycas");

        cas_client.set_login_service("auth/mycas/");
        assert_eq!(cas_client.login_service, "auth/mycas");

        cas_client.set_login_service("/auth/mycas");
        assert_eq!(cas_client.login_service, "auth/mycas");
    }

    #[test]
    fn set_login_service_should_return_self() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();

        // Invalid login_service
        let return_value = cas_client.set_login_service("").clone();
        assert_eq!(return_value, cas_client);

        // Valid login_service
        let return_value = cas_client.set_login_service("auth/mycas").clone();
        assert_eq!(return_value, cas_client);
    }

    // Logout prefix
    #[test]
    fn logout_prefix_getter_and_setter() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(cas_client.logout_prefix, "logout");

        // Invalid logout prefix
        cas_client.set_logout_prefix("");
        assert_eq!(cas_client.logout_prefix, "logout");

        // Valid logout prefix
        cas_client.set_logout_prefix("custom_logout_path");
        assert_eq!(cas_client.logout_prefix, "custom_logout_path");

        cas_client.set_logout_prefix("custom_logout_path/");
        assert_eq!(cas_client.logout_prefix, "custom_logout_path");

        cas_client.set_logout_prefix("/custom_logout_path");
        assert_eq!(cas_client.logout_prefix, "custom_logout_path");
    }

    #[test]
    fn set_logout_prefix_should_return_self() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();

        // Invalid logout_prefix
        let return_value = cas_client.set_logout_prefix("").clone();
        assert_eq!(return_value, cas_client);

        // Valid logout_prefix
        let return_value = cas_client.set_logout_prefix("custom_logout_path").clone();
        assert_eq!(return_value, cas_client);
    }

    // No authentication behavior
    #[test]
    fn no_auth_behavior_getter_and_setter() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(cas_client.no_auth_behavior(), &NoAuthBehavior::Authenticate);

        cas_client.set_no_auth_behavior(NoAuthBehavior::AuthenticatedOr403);
        assert_eq!(
            cas_client.no_auth_behavior(),
            &NoAuthBehavior::AuthenticatedOr403
        );
    }

    #[test]
    fn set_no_auth_behavior_should_return_self() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        let return_value = cas_client
            .set_no_auth_behavior(NoAuthBehavior::AuthenticatedOr403)
            .clone();
        assert_eq!(return_value, cas_client);
    }

    // CAS protocol
    #[test]
    fn cas_protocol_getter_and_setter() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(cas_client.cas_protocol(), &CasProtocol::V3);

        cas_client.set_cas_protocol(CasProtocol::V2);
        assert_eq!(cas_client.cas_protocol(), &CasProtocol::V2);
    }

    #[test]
    fn set_cas_protocol_should_return_self() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        let return_value = cas_client.set_cas_protocol(CasProtocol::V2).clone();
        assert_eq!(return_value, cas_client);
    }

    // App url
    #[test]
    fn app_url_getter_and_setter() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(cas_client.app_url(), "");

        cas_client.set_app_url("https://service.example.org");
        assert_eq!(cas_client.app_url(), "https://service.example.org");

        cas_client.set_app_url("https://service.example.org/");
        assert_eq!(cas_client.app_url(), "https://service.example.org");
    }

    #[test]
    fn app_url_not_updated_if_app_url_is_invalid() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(cas_client.app_url(), "");

        cas_client.set_app_url("service2.example.org");
        assert_eq!(cas_client.app_url(), "");

        cas_client.set_app_url("https//service.example.org/");
        assert_eq!(cas_client.app_url(), "");
    }

    #[test]
    fn set_app_url_should_return_self() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();

        // Invalid app_url
        let return_value = cas_client.set_app_url("").clone();
        assert_eq!(return_value, cas_client);

        // Valid app_url
        let return_value = cas_client
            .set_app_url("https://service.example.org")
            .clone();
        assert_eq!(return_value, cas_client);
    }

    // Service validate prefix
    #[test]
    fn service_validate_prefix_getter_and_setter() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(cas_client.service_validate_prefix, "serviceValidate");

        // Invalid service_validate_prefix
        cas_client.set_service_validate_prefix("");
        assert_eq!(cas_client.service_validate_prefix, "serviceValidate");

        // Valid service_validate_prefix
        cas_client.set_service_validate_prefix("custom_serviceValidate_path");
        assert_eq!(
            cas_client.service_validate_prefix,
            "custom_serviceValidate_path"
        );

        cas_client.set_service_validate_prefix("custom_serviceValidate_path/");
        assert_eq!(
            cas_client.service_validate_prefix,
            "custom_serviceValidate_path"
        );

        cas_client.set_service_validate_prefix("/custom_serviceValidate_path");
        assert_eq!(
            cas_client.service_validate_prefix,
            "custom_serviceValidate_path"
        );
    }

    #[test]
    fn set_service_validate_prefix_should_return_self() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();

        // Invalid service_validate_prefix
        let return_value = cas_client.set_service_validate_prefix("").clone();
        assert_eq!(return_value, cas_client);

        // Valid service_validate_prefix
        let return_value = cas_client
            .set_service_validate_prefix("custom_serviceValidate_path")
            .clone();
        assert_eq!(return_value, cas_client);
    }

    // ################################################################################
    // Public functions
    // ################################################################################
    // Login Url
    #[test]
    fn should_return_login_url() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(
            cas_client.login_url(),
            Some(String::from(
                "https://cas.example.org/login?service=%2Fauth%2Fcas%2Flogin"
            ))
        );
        cas_client.set_app_url("https://service.example.org");
        assert_eq!(
            cas_client.login_url(),
            Some(String::from(
                "https://cas.example.org/login?service=https%3A%2F%2Fservice.example.org%2Fauth%2Fcas%2Flogin"
            ))
        );
        cas_client.set_app_url("https://service.example.org/");
        assert_eq!(
            cas_client.login_url(),
            Some(String::from(
                "https://cas.example.org/login?service=https%3A%2F%2Fservice.example.org%2Fauth%2Fcas%2Flogin"
            ))
        );
        cas_client.set_app_url("https://service.example.org/path");
        assert_eq!(
            cas_client.login_url(),
            Some(String::from(
                "https://cas.example.org/login?service=https%3A%2F%2Fservice.example.org%2Fpath%2Fauth%2Fcas%2Flogin"
            ))
        );
        cas_client.set_app_url("https://service.example.org/path/");
        assert_eq!(
            cas_client.login_url(),
            Some(String::from(
                "https://cas.example.org/login?service=https%3A%2F%2Fservice.example.org%2Fpath%2Fauth%2Fcas%2Flogin"
            ))
        );
    }

    // Logout Url
    #[test]
    fn should_return_logout_url() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(
            cas_client.logout_url(),
            Some(String::from("https://cas.example.org/logout?service="))
        );
        cas_client.set_app_url("https://service.example.org");
        assert_eq!(
            cas_client.logout_url(),
            Some(String::from(
                "https://cas.example.org/logout?service=https%3A%2F%2Fservice.example.org"
            ))
        );
        cas_client.set_app_url("https://service.example.org/");
        assert_eq!(
            cas_client.logout_url(),
            Some(String::from(
                "https://cas.example.org/logout?service=https%3A%2F%2Fservice.example.org"
            ))
        );
        cas_client.set_app_url("https://service.example.org/path");
        assert_eq!(
            cas_client.logout_url(),
            Some(String::from(
                "https://cas.example.org/logout?service=https%3A%2F%2Fservice.example.org%2Fpath"
            ))
        );
    }

    // ################################################################################
    // Private functions
    // ################################################################################

    // parse_saml_response
    #[test]
    fn should_parse_saml_response() {
        let cas_url = "https://cas.example.org";
        let cas_client = CasClient::new(cas_url).unwrap();

        let resp = "
        <cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">
        <cas:authenticationFailure code=\"INVALID_TICKET\">
            Ticket ST-1856339-aA5Yuvrxzpv8Tau1cYQ7 not recognized
            </cas:authenticationFailure>
        </cas:serviceResponse>";
        let (user, attr) = cas_client.parse_saml_response(String::from(resp));
        assert_eq!(user, "");
        assert_eq!(attr, HashMap::new());

        let resp = "
        <cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">
        <cas:authenticationSuccess>
            <cas:user>username</cas:user>
        </cas:authenticationSuccess>
        </cas:serviceResponse>";
        let (user, attr) = cas_client.parse_saml_response(String::from(resp));
        assert_eq!(user, "username");
        assert_eq!(attr, HashMap::new());

        let resp = "
        <cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">
        <cas:authenticationSuccess>
            <cas:user>username</cas:user>
            <cas:attributes>
                <cas:firstname>John</cas:firstname>
                <cas:lastname>Doe</cas:lastname>
                <cas:title>Mr.</cas:title>
            </cas:attributes>
        </cas:authenticationSuccess>
        </cas:serviceResponse>";
        let mut attributes: HashMap<String, String> = HashMap::new();
        attributes
            .entry("firstname".to_string())
            .or_insert("John".to_string());
        attributes
            .entry("lastname".to_string())
            .or_insert("Doe".to_string());
        attributes
            .entry("title".to_string())
            .or_insert("Mr.".to_string());
        let (user, attr) = cas_client.parse_saml_response(String::from(resp));
        assert_eq!(user, "username");
        assert_eq!(attr, attributes);
    }

    // Service validate Url
    #[test]
    fn should_return_service_validate_url() {
        let cas_url = "https://cas.example.org";
        let mut cas_client = CasClient::new(cas_url).unwrap();
        assert_eq!(
            cas_client.service_validate_url(""),
            Some(String::from(
                "https://cas.example.org/serviceValidate?service=%2Fauth%2Fcas%2Flogin&ticket="
            ))
        );

        cas_client.set_app_url("https://service.example.org/");
        assert_eq!(
            cas_client.service_validate_url(""),
            Some(String::from(
                "https://cas.example.org/serviceValidate?service=https%3A%2F%2Fservice.example.org%2Fauth%2Fcas%2Flogin&ticket="
            ))
        );

        assert_eq!(
            cas_client.service_validate_url("fake_ticket"),
            Some(String::from(
                "https://cas.example.org/serviceValidate?service=https%3A%2F%2Fservice.example.org%2Fauth%2Fcas%2Flogin&ticket=fake_ticket"
            ))
        );
    }
}
