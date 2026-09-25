use http::Uri;
use nio_client::{CheckClient, Namespace, Obj, Rel, Tuple, User};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return Err(format!(
            "Usage: {} <namespace> <object> <rel> <userid|allUsers|authenticatedUsers|ns:obj#rel>",
            args[0]
        )
        .into());
    }

    let ns = Namespace(args[1].clone());
    let obj = Obj(args[2].clone());
    let rel = Rel(args[3].clone());
    let sbj: User = args[4].parse()?;

    let nio_check_uri =
        env::var("NIO_CHECK_URI").map_err(|_| "NIO_CHECK_URI environment variable not set")?;
    let uri: Uri = nio_check_uri
        .parse()
        .map_err(|e| format!("Invalid URI format for NIO_CHECK_URI: {}", e))?;

    let mut check_client = CheckClient::create(uri)
        .await
        .map_err(|e| format!("Failed to create CheckClient: {}", e))?;

    let ts = check_client
        .add_one(Tuple::new(ns, obj, rel, sbj))
        .await
        .map_err(|e| format!("Write request failed: {}", e))?;

    println!("committed at ts={}", ts.0);
    Ok(())
}
