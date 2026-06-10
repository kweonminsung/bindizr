use chrono::Utc;

/// Generate next serial number in YYYYMMDDNN format.
pub fn generate_serial(current_serial: Option<i32>) -> i32 {
    let now = Utc::now();
    let date_prefix = now.format("%Y%m%d").to_string().parse::<i32>().unwrap();
    let base_serial = date_prefix * 100;

    // If current serial is from today, increment it. Otherwise, start fresh with today's date.
    match current_serial {
        Some(serial) if serial >= base_serial => serial + 1,
        _ => base_serial,
    }
}
