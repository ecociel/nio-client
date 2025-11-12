fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/iam.proto");
    tonic_build::configure()
        .build_client(true)
        .compile_protos(&["proto/iam.proto"], &["./"])?;
    Ok(())
}
