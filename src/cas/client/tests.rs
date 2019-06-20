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
    assert_eq!(cas_client.service_url, String::new());
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

    cas_client.set_login_prefix("custom_login_path");
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
    cas_client.set_logout_prefix("custom_logout_path");
    assert_eq!(cas_client.logout_prefix, "custom_logout_path");

    cas_client.set_logout_prefix("custom_logout_path");
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

// Service url
#[test]
fn service_url_getter_and_setter() {
    let cas_url = "https://cas.example.org";
    let mut cas_client = CasClient::new(cas_url).unwrap();
    assert_eq!(cas_client.service_url(), "");

    cas_client.set_service_url("https://service.example.org");
    assert_eq!(cas_client.service_url(), "https://service.example.org");

    cas_client.set_service_url("https://service.example.org/");
    assert_eq!(cas_client.service_url(), "https://service.example.org/");
}

#[test]
fn service_url_not_updated_if_service_url_is_invalid() {
    let cas_url = "https://cas.example.org";
    let mut cas_client = CasClient::new(cas_url).unwrap();
    assert_eq!(cas_client.service_url(), "");

    cas_client.set_service_url("service2.example.org");
    assert_eq!(cas_client.service_url(), "");
}

#[test]
fn set_service_url_should_return_self() {
    let cas_url = "https://cas.example.org";
    let mut cas_client = CasClient::new(cas_url).unwrap();

    // Invalid service_url
    let return_value = cas_client.set_service_url("").clone();
    assert_eq!(return_value, cas_client);

    // Valid service_url
    let return_value = cas_client
        .set_service_url("https://service.example.org")
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

    cas_client.set_service_validate_prefix("custom_serviceValidate_path");
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
        Some(String::from("https://cas.example.org/login?service="))
    );
    cas_client.set_service_url("https://service.example.org");
    assert_eq!(
        cas_client.login_url(),
        Some(String::from(
            "https://cas.example.org/login?service=https%3A%2F%2Fservice.example.org"
        ))
    );
    cas_client.set_service_url("https://service.example.org/");
    assert_eq!(
        cas_client.login_url(),
        Some(String::from(
            "https://cas.example.org/login?service=https%3A%2F%2Fservice.example.org%2F"
        ))
    );
    cas_client.set_service_url("https://service.example.org/path");
    assert_eq!(
        cas_client.login_url(),
        Some(String::from(
            "https://cas.example.org/login?service=https%3A%2F%2Fservice.example.org%2Fpath"
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
    cas_client.set_service_url("https://service.example.org");
    assert_eq!(
        cas_client.logout_url(),
        Some(String::from(
            "https://cas.example.org/logout?service=https%3A%2F%2Fservice.example.org"
        ))
    );
    cas_client.set_service_url("https://service.example.org/");
    assert_eq!(
        cas_client.logout_url(),
        Some(String::from(
            "https://cas.example.org/logout?service=https%3A%2F%2Fservice.example.org%2F"
        ))
    );
    cas_client.set_service_url("https://service.example.org/path");
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
            "https://cas.example.org/serviceValidate?service=&ticket="
        ))
    );

    cas_client.set_service_url("https://service.example.org/");
    assert_eq!(
        cas_client.service_validate_url(""),
        Some(String::from(
            "https://cas.example.org/serviceValidate?service=https%3A%2F%2Fservice.example.org%2F&ticket="
        ))
    );

    assert_eq!(
        cas_client.service_validate_url("fake_ticket"),
        Some(String::from(
            "https://cas.example.org/serviceValidate?service=https%3A%2F%2Fservice.example.org%2F&ticket=fake_ticket"
        ))
    );
}

// ################################################################################
// TO ORDER
// ################################################################################
// Getters

// #[test]
// fn should_not_update_login_url_if_url_is_empty() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_login_url = Url::parse(&format!("{}login", cas_client.cas_url()))
//         .unwrap()
//         .to_string();
//     assert_eq!(cas_client.login_url(), default_login_url);
//     cas_client.set_login_url("");
//     assert_eq!(cas_client.login_url(), default_login_url);
// }

// #[test]
// fn should_not_update_login_url_if_url_is_invalid() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_login_url = Url::parse(&format!("{}login", cas_client.cas_url()))
//         .unwrap()
//         .to_string();
//     assert_eq!(cas_client.login_url(), default_login_url);
//     cas_client.set_login_url("cas.example.org/mylogin");
//     assert_eq!(cas_client.login_url(), default_login_url);
// }

// // # set_logout_url
// #[test]
// fn should_return_self_on_set_logout_url() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     // Valid logout_url
//     let return_value = cas_client
//         .set_logout_url("https://cas.example.org/mylogout")
//         .clone();
//     assert_eq!(return_value, cas_client);
//     // Invalid logout_url
//     let return_value = cas_client.set_logout_url("").clone();
//     assert_eq!(return_value, cas_client);
// }

// #[test]
// fn should_update_logout_url() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_logout_url = Url::parse(&format!("{}logout", cas_client.cas_url()))
//         .unwrap()
//         .to_string();
//     let new_logout_url = Url::parse(&format!("{}mylogout", cas_client.cas_url()))
//         .unwrap()
//         .to_string();
//     assert_eq!(cas_client.logout_url(), default_logout_url);
//     cas_client.set_logout_url(&new_logout_url);
//     assert_eq!(cas_client.logout_url(), new_logout_url);
// }

// #[test]
// fn should_not_update_logout_url_if_url_is_empty() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_logout_url = Url::parse(&format!("{}logout", cas_client.cas_url()))
//         .unwrap()
//         .to_string();
//     assert_eq!(cas_client.logout_url(), default_logout_url);
//     cas_client.set_logout_url("");
//     assert_eq!(cas_client.logout_url(), default_logout_url);
// }

// #[test]
// fn should_not_update_logout_url_if_url_is_invalid() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_logout_url = Url::parse(&format!("{}logout", cas_client.cas_url()))
//         .unwrap()
//         .to_string();
//     assert_eq!(cas_client.logout_url(), default_logout_url);
//     cas_client.set_logout_url("cas.example.org/mylogout");
//     assert_eq!(cas_client.logout_url(), default_logout_url);
// }

// // # cas_protocol
// #[test]
// fn should_return_self_on_set_no_auth_behavior() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let return_value = cas_client
//         .set_no_auth_behavior(NoAuthBehavior::AuthenticatedOr403)
//         .clone();
//     assert_eq!(return_value, cas_client);
// }

// #[test]
// fn should_update_no_auth_behavior() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     assert_eq!(cas_client.no_auth_behavior(), &NoAuthBehavior::Authenticate);
//     cas_client.set_no_auth_behavior(NoAuthBehavior::AuthenticatedOr403);
//     assert_eq!(
//         cas_client.no_auth_behavior(),
//         &NoAuthBehavior::AuthenticatedOr403
//     );
// }

// // # set_protocol
// #[test]
// fn should_return_self_on_set_protocol() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let return_value = cas_client.set_protocol(CasProtocol::V2).clone();
//     assert_eq!(return_value, cas_client);
// }

// #[test]
// fn should_update_protocol() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     assert_eq!(cas_client.protocol(), &CasProtocol::V3);
//     cas_client.set_protocol(CasProtocol::V2);
//     assert_eq!(cas_client.protocol(), &CasProtocol::V2);
// }

// // # set_service_url
// #[test]
// fn should_return_self_on_set_service_url() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     // Valid service_url
//     let return_value = cas_client
//         .set_service_url("https://service.example.org")
//         .clone();
//     assert_eq!(return_value, cas_client);
//     // Invalid service_url
//     let return_value = cas_client.set_service_url("").clone();
//     assert_eq!(return_value, cas_client);
// }

// #[test]
// fn should_update_service_url() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_service_url = "";
//     let new_service_url = Url::parse("https://service.example.org")
//         .unwrap()
//         .to_string();
//     assert_eq!(cas_client.service_url(), default_service_url);
//     cas_client.set_service_url(&new_service_url);
//     assert_eq!(cas_client.service_url(), new_service_url);
// }

// #[test]
// fn should_not_update_service_url_if_url_is_empty() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_service_url = "";
//     assert_eq!(cas_client.service_url(), default_service_url);
//     cas_client.set_service_url("");
//     assert_eq!(cas_client.service_url(), default_service_url);
// }

// #[test]
// fn should_not_update_service_url_if_url_is_invalid() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_service_url = "";
//     assert_eq!(cas_client.service_url(), default_service_url);
//     cas_client.set_service_url("service.example.org");
//     assert_eq!(cas_client.service_url(), default_service_url);
// }

// // # set_service_validate_url
// #[test]
// fn should_return_self_on_set_service_validate_url() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     // Valid logout_url
//     let return_value = cas_client
//         .set_service_validate_url("https://cas.example.org/mylogout")
//         .clone();
//     assert_eq!(return_value, cas_client);
//     // Invalid logout_url
//     let return_value = cas_client.set_service_validate_url("").clone();
//     assert_eq!(return_value, cas_client);
// }

// #[test]
// fn should_update_service_validate_url() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_service_validate_url =
//         Url::parse(&format!("{}serviceValidate", cas_client.cas_url()))
//             .unwrap()
//             .to_string();
//     let new_service_validate_url =
//         Url::parse(&format!("{}myserviceValidate", cas_client.cas_url()))
//             .unwrap()
//             .to_string();
//     assert_eq!(
//         cas_client.service_validate_url(),
//         default_service_validate_url
//     );
//     cas_client.set_service_validate_url(&new_service_validate_url);
//     assert_eq!(cas_client.service_validate_url(), new_service_validate_url);
// }

// #[test]
// fn should_not_update_service_validate_url_if_url_is_empty() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_service_validate_url =
//         Url::parse(&format!("{}serviceValidate", cas_client.cas_url()))
//             .unwrap()
//             .to_string();
//     assert_eq!(
//         cas_client.service_validate_url(),
//         default_service_validate_url
//     );
//     cas_client.set_service_validate_url("");
//     assert_eq!(
//         cas_client.service_validate_url(),
//         default_service_validate_url
//     );
// }

// #[test]
// fn should_not_update_service_validate_url_if_url_is_invalid() {
//     let cas_url = "https://cas.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     let default_service_validate_url =
//         Url::parse(&format!("{}serviceValidate", cas_client.cas_url()))
//             .unwrap()
//             .to_string();
//     assert_eq!(
//         cas_client.service_validate_url(),
//         default_service_validate_url
//     );
//     cas_client.set_service_validate_url("cas.example.org/myserviceValidate");
//     assert_eq!(
//         cas_client.service_validate_url(),
//         default_service_validate_url
//     );
// }

// // Public functions
// // # redirect_url

// #[test]
// fn should_return_redirect_url_with_service_url() {
//     let cas_url = "https://cas.example.org";
//     let service_url = "https://service.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     cas_client.set_service_url(service_url);
//     let redirect_url = Url::parse_with_params(
//         &cas_client.cas_url(),
//         &[("service", &format!("{}", cas_client.service_url()))],
//     )
//     .unwrap()
//     .to_string();
//     assert_eq!(cas_client.redirect_url(), Some(redirect_url));
// }

// // # validate_service_ticket
// // ###########
// // BEGIN TODO
// // ###########
// // #[test]
// // fn should_return_cas_user() {
// //     let cas_url = "https://cas.example.org";
// //     let cas_client = CasClient::new(cas_url).unwrap();
// //     let cas_user = CasUser::new("", None);
// //     assert_eq!(
// //         cas_client.validate_service_ticket("fake_ticket"),
// //         Some(cas_user)
// //     );
// // }
// // ###########
// // END TODO
// // ###########

// // Private functions
// #[test]
// fn should_return_service_ticket_validation_url() {
//     let cas_url = "https://cas.example.org";
//     let ticket = "fake_tiket";
//     let service_url = "http://service.example.org";
//     let mut cas_client = CasClient::new(cas_url).unwrap();
//     cas_client.set_service_url(service_url);
//     let redirect_url = Url::parse_with_params(
//         cas_client.service_validate_url(),
//         &[("service", cas_client.service_url()), ("ticket", ticket)],
//     )
//     .unwrap();
//     assert_eq!(
//         cas_client.service_ticket_validation_url(ticket),
//         Some(redirect_url)
//     );
// }
