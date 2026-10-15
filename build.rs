fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Do not rerun for unrelated tests, reports or working-tree files. Cargo's
    // default without an explicit input watches the entire package directory.
    println!("cargo:rerun-if-changed=build.rs");
    // A build script runs on the host, so the target's cfg comes from the environment. The
    // browser build compiles neither protobuf user (both are `not(target_arch = "wasm32")`).
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        return Ok(());
    }
    if std::env::var_os("PROTOC").is_none() {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    {
        println!("cargo:rerun-if-changed=proto/gnmi");
        println!("cargo:rerun-if-env-changed=PROTOC");
        println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");
        let output = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
        tonic_build::configure()
            .codec_path("crate::server::gnmi::codec::BoundedProstCodec")
            .file_descriptor_set_path(output.join("gnmi-descriptors.pb"))
            .compile_protos(
                &["proto/gnmi/github.com/openconfig/gnmi/proto/gnmi/gnmi.proto"],
                &["proto/gnmi"],
            )?;
    }
    {
        println!("cargo:rerun-if-changed=proto/etcd");
        println!("cargo:rerun-if-env-changed=PROTOC");
        println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");
        // Compile proto files using prost-build
        let mut prost_build = prost_build::Config::new();

        prost_build.compile_protos(
            &["proto/etcd/rpc.proto", "proto/etcd/kv.proto"],
            &["proto/etcd"],
        )?;
    }

    Ok(())
}
