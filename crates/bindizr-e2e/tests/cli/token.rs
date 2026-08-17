use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn token_create_rejects_duplicate_name() {
    let app = TestApp::start().await;
    let (name, _) = app.create_api_token().await;

    let output = app.run_cli(&["token", "create", "--name", &name]).await;
    assert!(!output.status.success());
}
