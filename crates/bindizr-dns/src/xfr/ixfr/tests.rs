use super::normalize_change_name;

#[test]
fn normalize_change_name_expands_relative_name() {
    assert_eq!(
        normalize_change_name("www", "example.com"),
        "www.example.com."
    );
}

#[test]
fn normalize_change_name_expands_apex() {
    assert_eq!(normalize_change_name("@", "example.com."), "example.com.");
}

#[test]
fn normalize_change_name_keeps_fqdn() {
    assert_eq!(
        normalize_change_name("api.example.com.", "example.com"),
        "api.example.com."
    );
}
