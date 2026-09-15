/// Assert that a CLI command completed successfully, showing output on failure.
pub(crate) fn assert_cli_success(args: &[&str], output: &std::process::Output) {
    assert!(
        output.status.success(),
        "bindizr {} failed\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Assert that a CLI command failed with the expected error text.
pub(crate) fn assert_cli_failure_contains(
    args: &[&str],
    output: &std::process::Output,
    expected_error: &str,
) {
    assert!(
        !output.status.success(),
        "expected bindizr {} to fail, but it succeeded.\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(expected_error),
        "bindizr {} response did not contain '{expected_error}': {combined}",
        args.join(" ")
    );
}
