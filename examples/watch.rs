use http::Uri;
use nio_client::{CheckClient, Namespace, Timestamp};
use std::env;

/// Tails the changelog for a namespace. Pass a previously received ts to
/// resume; omit it to start from the beginning of the retained log.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 && args.len() != 3 {
        return Err(format!("Usage: {} <namespace> [start-ts]", args[0]).into());
    }

    let ns = Namespace(args[1].clone());
    let start_ts = args
        .get(2)
        .map(|s| Timestamp(s.clone()))
        .unwrap_or_else(Timestamp::empty);

    let nio_check_uri =
        env::var("NIO_CHECK_URI").map_err(|_| "NIO_CHECK_URI environment variable not set")?;
    let uri: Uri = nio_check_uri
        .parse()
        .map_err(|e| format!("Invalid URI format for NIO_CHECK_URI: {}", e))?;

    let mut check_client = CheckClient::create(uri)
        .await
        .map_err(|e| format!("Failed to create CheckClient: {}", e))?;

    let mut stream = check_client
        .watch(ns, start_ts)
        .await
        .map_err(|e| format!("Watch request failed: {}", e))?;

    while let Some(event) = stream.recv().await? {
        if event.updates.is_empty() {
            eprintln!("heartbeat ts={}", event.ts.0);
            continue;
        }
        println!("write committed at ts={}", event.ts.0);
        for update in event.updates {
            let op = if update.deleted { "del" } else { "add" };
            println!("  {} {}", op, update.tuple);
        }
    }

    println!("stream ended");
    Ok(())
}
