use super::SoaMailbox;

#[test]
fn from_email_escapes_local_part() {
    assert_eq!(
        SoaMailbox::from_email(r"host.master\ops@example.com")
            .unwrap()
            .as_str(),
        r"host\.master\\ops.example.com."
    );
    assert!(SoaMailbox::from_email("hostmaster.example.com").is_err());
    assert!(SoaMailbox::from_email("host@@example.com").is_err());
}

#[test]
fn to_email_round_trips() {
    for email in [
        "admin@example.com",
        "first.last@example.com",
        "a.b.c@sub.example.com",
        "back\\slash@example.com",
    ] {
        let mailbox = SoaMailbox::from_email(email).expect("email should convert to mailbox");
        assert_eq!(
            mailbox.to_email().expect("mailbox should convert back"),
            email,
            "round trip failed for mailbox '{mailbox}'"
        );
    }
}

#[test]
fn to_email_handles_plain_stored_mailbox() {
    assert_eq!(
        SoaMailbox::from_encoded("hostmaster.example.com.")
            .to_email()
            .unwrap(),
        "hostmaster@example.com"
    );
    assert_eq!(
        SoaMailbox::from_encoded("hostmaster.example.com")
            .to_email()
            .unwrap(),
        "hostmaster@example.com"
    );
}

#[test]
fn to_email_rejects_invalid_input() {
    assert!(SoaMailbox::from_encoded("no-separator").to_email().is_err());
    assert!(SoaMailbox::from_encoded(".example.com").to_email().is_err());
    assert!(SoaMailbox::from_encoded("dangling\\").to_email().is_err());
}
