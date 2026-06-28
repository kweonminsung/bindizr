use super::*;

#[test]
fn encode_canonical_name_lowercases_key_name() {
    assert_eq!(
        encode_canonical_name("Nsupdate-Key.").unwrap(),
        vec![
            12, b'n', b's', b'u', b'p', b'd', b'a', b't', b'e', b'-', b'k', b'e', b'y', 0,
        ]
    );
}
