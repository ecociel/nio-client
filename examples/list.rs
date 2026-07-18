use http::Uri;
use nio_client::{CheckClient, Namespace, Rel, UserId};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return Err(format!("Usage: {} <namespace> <rel> <userid>", args[0]).into());
    }

    let ns = Namespace(args[1].clone());
    let rel = Rel(args[2].clone());
    let userid = UserId(args[3].clone());

    let nio_check_uri =
        env::var("NIO_CHECK_URI").map_err(|_| "NIO_CHECK_URI environment variable not set")?;
    let uri: Uri = nio_check_uri
        .parse()
        .map_err(|e| format!("Invalid URI format for NIO_CHECK_URI: {}", e))?;

    let mut check_client = CheckClient::create(uri)
        .await
        .map_err(|e| format!("Failed to create CheckClient: {}", e))?;

    let res = check_client
        .list(ns, rel, userid, None)
        .await
        .map_err(|e| format!("List request failed: {}", e))?;

    eprintln!("evaluated at ts={}", res.ts.0);
    for obj in res.objs {
        println!("{}", obj)
    }

    Ok(())
}
