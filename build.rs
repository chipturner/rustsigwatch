use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(out_dir);

    println!("cargo:rerun-if-changed=src/bpf/sigwatch.bpf.c");

    let status = std::process::Command::new("clang")
        .args([
            "-g",
            "-O2",
            "-target",
            "bpf",
            "-fno-stack-protector",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include/x86_64-linux-gnu",
            "-I/usr/include",
            "-c",
            "src/bpf/sigwatch.bpf.c",
            "-o",
        ])
        .arg(out_path.join("sigwatch.bpf.o"))
        .status()
        .expect("Failed to compile BPF program");

    if !status.success() {
        panic!("Failed to compile BPF program");
    }
}
