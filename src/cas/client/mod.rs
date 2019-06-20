extern crate reqwest;
extern crate roxmltree;

use crate::cas::CasUser;
use reqwest::Client;
use std::collections::HashMap;
use url::Url;

#[derive(Clone, Debug, PartialEq)]
pub struct CasClient {
    cas_base_url: Url,
    login_prefix: String,
    logout_prefix: String,
    no_auth_behavior: NoAuthBehavior,
    cas_protocol: CasProtocol,
    service_url: String,
    service_validate_prefix: String,
}

impl CasClient {
    // ################################################################################
    // Constructor
    // ################################################################################
    pub fn new(cas_base_url: &str) -> Result<Self, &str> {
        let _cas_base_url = match cas_base_url.chars().last().unwrap_or_default() {
            '/' => cas_base_url.to_string(),
            _ => cas_base_url.to_string() + "/",
        };
        match Url::parse(&_cas_base_url) {
            Ok(url) => Ok(CasClient {
                cas_base_url: url,
                cas_protocol: CasProtocol::V3,
                login_prefix: String::from("login"),
                logout_prefix: String::from("logout"),
                no_auth_behavior: NoAuthBehavior::Authenticate,
                service_url: String::new(),
                service_validate_prefix: String::from("serviceValidate"),
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

    // Login prefix
    pub fn login_prefix(&self) -> &String {
        &self.login_prefix
    }

    pub fn set_login_prefix(&mut self, login_prefix: &str) -> &mut Self {
        if login_prefix.len() != 0 {
            self.login_prefix = match login_prefix.chars().next().unwrap() {
                '/' => login_prefix[1..].to_string(),
                _ => login_prefix.to_string(),
            };
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
            self.logout_prefix = match logout_prefix.chars().next().unwrap() {
                '/' => logout_prefix[1..].to_string(),
                _ => logout_prefix.to_string(),
            };
        } else {
            error!("Logout prefix cannot be empty");
        }
        self
    }

    // No auth behavior
    pub fn no_auth_behavior(&self) -> &NoAuthBehavior {
        &self.no_auth_behavior
    }

    pub fn set_no_auth_behavior(&mut self, no_auth_behavior: NoAuthBehavior) -> &mut Self {
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
    pub fn service_url(&self) -> &str {
        &self.service_url
    }

    pub fn set_service_url(&mut self, service_url: &str) -> &mut Self {
        match Url::parse(service_url) {
            Ok(_) => self.service_url = service_url.to_string(),
            Err(err) => error!("Invalid service url! Error: {:?}", err),
        };
        self
    }

    // Service validate prefix
    pub fn service_validate_prefix(&self) -> &String {
        &self.service_validate_prefix
    }

    pub fn set_service_validate_prefix(&mut self, service_validate_prefix: &str) -> &mut Self {
        if service_validate_prefix.len() != 0 {
            self.service_validate_prefix = match service_validate_prefix.chars().next().unwrap() {
                '/' => service_validate_prefix[1..].to_string(),
                _ => service_validate_prefix.to_string(),
            };
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
            &[("service", &format!("{}", self.service_url()))],
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
            &[("service", &format!("{}", self.service_url()))],
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
                let client = Client::new();
                let mut req = match client.get(Url::parse(&url).unwrap()).send() {
                    Ok(r) => r,
                    Err(err) => {
                        error!("Error while requesting ticket validation! Error: {:?}", err);
                        return None;
                    }
                };
                match req.text() {
                    Ok(t) => Some(t),
                    Err(err) => {
                        error!("Error while decoding response body! Error: {:?}", err);
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

    pub(self) fn parse_saml_response(&self, resp: String) -> (String, HashMap<String, String>) {
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
                ("service", &format!("{}", self.service_url())),
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CasProtocol {
    V2,
    V3,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NoAuthBehavior {
    AuthenticatedOr403,
    AuthenticatedOr404,
    Authenticate,
    ForceAuthentication,
}

#[cfg(test)]
mod tests;
