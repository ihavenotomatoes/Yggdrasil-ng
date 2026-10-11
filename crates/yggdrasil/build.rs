fn main() {
    println!("cargo:rerun-if-env-changed=YGGDRASIL_CONFIG_DIR");
    println!("cargo:rerun-if-env-changed=YGGDRASIL_ROUTES_CACHE_DIR");

    if let Ok(dir) = std::env::var("YGGDRASIL_CONFIG_DIR") {
        if !dir.is_empty() {
            println!("cargo:rustc-env=YGGDRASIL_CONFIG_DIR={}", dir);
        }
    }
    if let Ok(dir) = std::env::var("YGGDRASIL_ROUTES_CACHE_DIR") {
        if !dir.is_empty() {
            println!("cargo:rustc-env=YGGDRASIL_ROUTES_CACHE_DIR={}", dir);
        }
    }
}