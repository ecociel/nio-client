fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/iam.proto");
    println!("cargo:rerun-if-changed=proto/sessions.proto");
    // Server stubs are generated so integration tests can host an in-process
    // mock server; the published library only uses the client side.
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/iam.proto", "proto/sessions.proto"], &["./"])?;
    Ok(())
}
