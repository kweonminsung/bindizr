use super::encode_dns_name;

#[test]
fn encode_dns_name_writes_single_root_label_for_root_name() {
    let mut encoded = Vec::new();

    encode_dns_name(".", &mut encoded).unwrap();

    assert_eq!(encoded, [0]);
}

#[test]
fn encode_dns_name_writes_labels_and_root_terminator() {
    let mut encoded = Vec::new();

    encode_dns_name("www.example.com.", &mut encoded).unwrap();

    assert_eq!(
        encoded,
        [
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]
    );
}
