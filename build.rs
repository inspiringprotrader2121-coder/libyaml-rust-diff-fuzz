use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=vendor/libyaml/include/yaml.h");
    println!("cargo:rerun-if-changed=vendor/libyaml/src/scanner.c");

    // Compile upstream C libyaml scanner + reader with AddressSanitizer enabled
    // so any heap buffer overflow or use-after-free in FFI boundary is caught immediately.
    cc::Build::new()
        .files([
            "vendor/libyaml/src/api.c",
            "vendor/libyaml/src/reader.c",
            "vendor/libyaml/src/scanner.c",
        ])
        .include("vendor/libyaml/include")
        .include("vendor/libyaml/src")
        .define("YAML_DECLARE_STATIC", None)
        .define("HAVE_CONFIG_H", None)
        .flag_if_supported("-fsanitize=address")
        .flag_if_supported("-fno-omit-frame-pointer")
        .flag_if_supported("-g")
        .warnings(false)
        .compile("yaml_c_ref");

    // Generate FFI bindings for yaml_parser_t and yaml_token_t state machine
    let bindings = bindgen::Builder::default()
        .header("vendor/libyaml/include/yaml.h")
        .allowlist_function("yaml_parser_initialize")
        .allowlist_function("yaml_parser_delete")
        .allowlist_function("yaml_parser_set_input_string")
        .allowlist_function("yaml_parser_scan")
        .allowlist_function("yaml_parser_fetch_more_tokens")
        .allowlist_function("yaml_token_delete")
        .allowlist_type("yaml_parser_t")
        .allowlist_type("yaml_token_t")
        .allowlist_type("yaml_token_type_t")
        .derive_debug(true)
        .generate()
        .expect("Unable to generate bindgen FFI bindings for yaml.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings.rs");
}
