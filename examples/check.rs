// let nio_check_uri = env!("NIO_CHECK_URI");
// let uri = Uri::try_from(nio_check_uri).unwrap();
// let mut check_client = CheckClient::create(uri).await.unwrap();
//
// let ns = Namespace("customer".to_string());
// let obj = Obj("acme".to_string());
// let per = Permission("customer.update");
// //let userid = UserId("734962c4-4c27-4c81-9d5f-7ddd5ae57f42".to_string());
// let userid = UserId("abcdef".to_string());
//
// let res = check_client
//     .check(ns, obj, per, userid.clone(), None)
//     .await
//     .unwrap();
// match res {
//     CheckResult::Ok(p) => println!("ok {}", p.as_str()),
//
//     CheckResult::Forbidden(p) => println!("forbidden {}", p.as_str()),
//     CheckResult::UnknownPutativeUser => println!("unknown user {:?}", userid),
// }

use check_client::auth::CheckResult;
use check_client::{CheckClient, Namespace, Obj, Permission, UserId};
use http::Uri;
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
    if args.len() != 5 {
        return Err(format!(
            "Usage: {} <namespace> <object> <permission> <userid>",
            args[0]
        )
        .into());
    }

    // Extract and validate arguments
    let ns = Namespace(args[1].clone());
    let obj = Obj(args[2].clone());
    let per = perm(args[3].as_str());
    let userid = UserId(args[4].clone());

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
        .check(ns.clone(), obj.clone(), per.clone(), userid.clone(), None)
        .await
        .map_err(|e| format!("Check request failed: {}", e))?;

    // Enhanced output for clarity
    match res {
        CheckResult::Ok(p) => println!(
            "Permission granted: {} for user {} in namespace {} on object {}",
            p.as_str(),
            userid.0,
            ns.0,
            obj.0
        ),
        CheckResult::Forbidden(p) => println!(
            "Permission denied: {} for user {} in namespace {} on object {}",
            p.as_str(),
            userid.0,
            ns.0,
            obj.0
        ),
        CheckResult::UnknownPutativeUser => println!(
            "Unknown user: {} in namespace {} on object {}",
            userid.0, ns.0, obj.0
        ),
    }

    Ok(())
}
