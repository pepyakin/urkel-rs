use std::path::Path;
use std::process;

fn main() {
    println!("cargo:rerun-if-changed=liburkel");

    let cmake_lists = Path::new("liburkel/CMakeLists.txt");
    if !cmake_lists.exists() {
        eprintln!(
            "{} doesn't exist. Perhaps, you need to update git submodules?\n\nTry\n\n\t\
git submodule update --init --recursive",
            cmake_lists.display(),
        );
        process::exit(1);
    }

    let mut cfg = cmake::Config::new("liburkel");
    let dst = cfg.build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=urkel");
}
