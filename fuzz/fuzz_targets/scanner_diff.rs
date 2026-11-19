#![no_main]
use libfuzzer_sys::fuzz_target;
use libyaml_rust_diff_fuzz::{ffi, Scanner, StructuredYamlChunk};
use std::mem::MaybeUninit;

// Structure-aware differential fuzz target comparing upstream C `yaml_parser_scan`
// (compiled with AddressSanitizer) against the Rust `Scanner` token stream.
// For forkserver isolation across stateful C runs, execute with:
//   RUSTFLAGS="-Zsanitizer=address" cargo +nightly fuzz run scanner_diff -- -fork=1
fuzz_target!(|chunks: Vec<StructuredYamlChunk>| {
    let data = StructuredYamlChunk::to_bytes(&chunks);

    unsafe {
        let mut c_parser = MaybeUninit::<ffi::yaml_parser_t>::zeroed();
        assert_eq!(
            ffi::yaml_parser_initialize(c_parser.as_mut_ptr()),
            1,
            "yaml_parser_initialize failed"
        );
        let c_parser = c_parser.assume_init_mut();
        ffi::yaml_parser_set_input_string(c_parser, data.as_ptr(), data.len());

        let mut rust_scanner = Scanner::new(&data);

        loop {
            let mut c_tok = MaybeUninit::<ffi::yaml_token_t>::zeroed();
            let c_ok = ffi::yaml_parser_scan(c_parser, c_tok.as_mut_ptr());
            let r_res = rust_scanner.scan_next_token();

            assert_eq!(
                c_ok == 1,
                r_res.is_ok(),
                "Differential status mismatch on input bytes: {:02x?}",
                data
            );
            if c_ok != 1 {
                break;
            }

            let c_tok = c_tok.assume_init_mut();
            let r_tok = r_res.unwrap();
            assert_eq!(
                c_tok.type_,
                r_tok.token_type as u32,
                "Differential token_type mismatch on input bytes: {:02x?}",
                data
            );

            let done = c_tok.type_ == ffi::yaml_token_type_e_YAML_STREAM_END_TOKEN;
            ffi::yaml_token_delete(c_tok);
            if done {
                break;
            }
        }

        ffi::yaml_parser_delete(c_parser);
    }
});
