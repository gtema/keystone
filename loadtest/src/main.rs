use std::env;

use goose::prelude::*;

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("LoadtestTransactions").register_transaction(transaction!(loadtest_index)),
        )
        .execute()
        .await?;

    Ok(())
}

async fn loadtest_index(user: &mut GooseUser) -> TransactionResult {
    let token = match env::var("TOKEN") {
        Ok(token) => token,
        Err(_) => "foo".to_string(),
    };

    // Create a Reqwest RequestBuilder object and configure bearer authentication when making
    // a GET request for the index.
    let reqwest_request_builder = user
        .get_request_builder(&GooseMethod::Get, "/v3/users")?
        .header("x-auth-token", token);

    // Add the manually created RequestBuilder and build a GooseRequest object.
    let goose_request = GooseRequest::builder()
        .set_request_builder(reqwest_request_builder)
        .build();

    // Make the actual request.
    user.request(goose_request).await?;

    Ok(())
}
