use http::Uri;
use nio_client::{CheckClient, Namespace, Permission, UserId};
use std::env;

fn perm(p: &str) -> Permission {
    match p {
        "customer.get" => Permission("customer.get"),
        "customer.list" => Permission("customer.list"),
        "customer.update" => Permission("customer.update"),
        _ => Permission("none"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return Err(format!("Usage: {} <namespace> <permission> <userid>", args[0]).into());
    }

    // Extract and validate arguments
    let ns = Namespace(args[1].clone());
    let per = perm(args[2].as_str());
    let userid = UserId(args[3].clone());

    // Read NIO_CHECK_URI from environment at runtime
    let nio_check_uri =
        env::var("NIO_CHECK_URI").map_err(|_| "NIO_CHECK_URI environment variable not set")?;

    // Parse URI with error handling
    let uri: Uri = nio_check_uri
        .parse()
        .map_err(|e| format!("Invalid URI format for NIO_CHECK_URI: {}", e))?;

    // Create CheckClient with error handling
    let mut check_client = CheckClient::create(uri)
        .await
        .map_err(|e| format!("Failed to create CheckClient: {}", e))?;

    // Perform the check with error handling
    let res = check_client
        .list(ns.clone(), per.into(), userid.clone(), None)
        .await
        .map_err(|e| format!("List request failed: {}", e))?;

    for obj in res {
        println!("{}", obj)
    }

    Ok(())
}
