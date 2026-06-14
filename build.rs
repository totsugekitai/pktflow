use std::{env, fs, path::PathBuf};

use cc::Build;
use walkdir::WalkDir;

fn collect_c_files(root: &str) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter(|e| {
            let e = e.as_ref().unwrap();
            let path = e.path();
            path.extension().and_then(|s| s.to_str()) == Some("c")
        })
        .map(|c| c.unwrap().path().to_path_buf())
        .collect()
}

fn gen_compiledb(files: &[PathBuf], dpdk_incs: &[PathBuf], other_flags: &[&str]) {
    let root = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let mut entries = Vec::new();

    for file in files {
        let file = file.to_str().unwrap();
        let mut cmd = String::from("clang");

        for inc in dpdk_incs {
            cmd.push_str(&format!(" -isystem{}", inc.to_str().unwrap()));
        }
        for flag in other_flags {
            cmd.push_str(&format!(" {}", flag));
        }
        cmd.push_str(&format!(" -c {}", file));
        entries.push(format!(
            r#"  {{
    "directory": "{}",
    "command": "{}",
    "file": "{}"
  }}"#,
            root, cmd, file
        ));
    }

    let json = format!("[\n{}\n]", entries.join(",\n"));
    fs::write("compile_commands.json", json).unwrap();
}

const DPDK_C_SRCS_PATH: &str = "src/backend/dpdk/adapter";

fn build_dpdk_adapter() {
    println!("cargo:rerun-if-changed={}", DPDK_C_SRCS_PATH);

    let mut build = Build::new();

    // Search DPDK
    let dpdk = pkg_config::Config::new().probe("libdpdk").unwrap();
    let dpdk_incs = dpdk.include_paths;
    for inc in &dpdk_incs {
        build.flag(format!("-isystem{}", inc.to_str().unwrap()));
        // build.include(inc);
    }

    // Search src/dpdk/*.c
    let dpdk_c_srcs = collect_c_files(DPDK_C_SRCS_PATH);

    // Compile
    for c in &dpdk_c_srcs {
        build.file(c);
        println!("cargo:rerun-if-changed={}", c.to_str().unwrap());
    }
    // -mssse3 is for DPDK
    // -D_GNU_SOURCE: DPDK headers use POSIX/GNU functions (e.g. strnlen in
    // rte_string_fns.h) that glibc hides under strict -std=c2x
    let flags = vec![
        "-std=c2x",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Wextra",
        "-mssse3",
        "-g",
        "-O2",
        "-Werror",
    ];
    build.flags(&flags);
    build.compile("dpdk_adapter");

    gen_compiledb(&dpdk_c_srcs, &dpdk_incs, &flags);
}

fn binding() {
    let bindings = bindgen::Builder::default()
        .header(format!("{}/dpdk_api.h", DPDK_C_SRCS_PATH))
        .allowlist_function("dpdk_.*")
        .allowlist_type("dpdk_.*")
        .allowlist_var("DPDK_.*")
        .clang_arg("-std=c2x")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();
}

fn main() {
    build_dpdk_adapter();
    binding();
}
