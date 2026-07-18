use http::Uri;
use nio_client::auth::CheckResult;
use nio_client::{CheckClient, Namespace, Obj, Rel, UserId};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return Err(format!("Usage: {} <namespace> <object> <rel> <userid>", args[0]).into());
    }

    let ns = Namespace(args[1].clone());
    let obj = Obj(args[2].clone());
    let rel = Rel(args[3].clone());
    let userid = UserId(args[4].clone());

    let nio_check_uri =
        env::var("NIO_CHECK_URI").map_err(|_| "NIO_CHECK_URI environment variable not set")?;
    let uri: Uri = nio_check_uri
        .parse()
        .map_err(|e| format!("Invalid URI format for NIO_CHECK_URI: {}", e))?;

    let mut check_client = CheckClient::create(uri)
        .await
        .map_err(|e| format!("Failed to create CheckClient: {}", e))?;

    let res = check_client
        .check(ns.clone(), obj.clone(), rel.clone(), userid.clone(), None)
        .await
        .map_err(|e| format!("Check request failed: {}", e))?;

    match res {
        CheckResult::Ok(p) => println!(
            "Granted: {} for user {} in namespace {} on object {}",
            p.as_str(),
            userid.0,
            ns.0,
            obj.0
        ),
        CheckResult::Forbidden(p) => println!(
            "Denied: {} for user {} in namespace {} on object {}",
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
