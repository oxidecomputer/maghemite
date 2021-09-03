// Copyright 2021 Oxide Computer Company
//
// Derived from https://github.com/oxidecomputer/libscf-sys/blob/main/build.rs

use bindgen;
use std::env;
use std::path::PathBuf;

fn main() {
    #[cfg(not(target_os = "illumos"))]
    compile_error!("libdladm-sys is only supported on illumos");

    println!("cargo:rustc-link-lib=dladm");
    println!("cargo:rustc-link-lib=ipadm");
    println!("cargo:rerun-if-changed=wrapper.h");

    if let Err(_) = env::var("LIBCLANG_PATH") {
        env::set_var("LIBCLANG_PATH", "/opt/ooce/clang-11.0/lib");
    }

    let illumos_src_path = match env::var("ILLUMOS_SRC") {
        Err(_) => {
            println!("illumos path not set, using system libraries");
            println!("this will not work outside ry's personal illumos build");
            println!("https://github.com/oxidecomputer/illumos-gate/tree/netapis");
            "".to_string()
        }
        Ok(path) => path.to_string(),
    };

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    if illumos_src_path != "" {
        let bindings = bindgen::Builder::default()
            .header("wrapper.h")
            .clang_arg(format!("-I{}/usr/src/uts/common", illumos_src_path))
            .clang_arg(format!(
                    "-I{}/usr/src/lib/libdladm/common", illumos_src_path))
            .clang_arg(format!(
                    "-I{}/usr/src/lib/libipadm/common", illumos_src_path))
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("unable to generate bindings");

        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("unable to write bindings");
    } else {
        let bindings = bindgen::Builder::default()
            .header("wrapper.h")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("unable to generate bindings");

        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("unable to write bindings");

    }
}
