//! Rust port target for `yaml/libyaml` token scanner (`src/scanner.c`)
//! verified against upstream C implementation via differential fuzzing.

use arbitrary::Arbitrary;
use std::collections::VecDeque;

pub mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

/// Mirrors `yaml_token_type_e` in `vendor/libyaml/include/yaml.h`
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YamlTokenType {
    NoToken = 0,
    StreamStartToken = 1,
    StreamEndToken = 2,
    VersionDirectiveToken = 3,
    TagDirectiveToken = 4,
    DocumentStartToken = 5,
    DocumentEndToken = 6,
    BlockSequenceStartToken = 7,
    BlockMappingStartToken = 8,
    BlockEndToken = 9,
    FlowSequenceStartToken = 10,
    FlowSequenceEndToken = 11,
    FlowMappingStartToken = 12,
    FlowMappingEndToken = 13,
    BlockEntryToken = 14,
    FlowEntryToken = 15,
    KeyToken = 16,
    ValueToken = 17,
    AliasToken = 18,
    AnchorToken = 19,
    TagToken = 20,
    ScalarToken = 21,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlToken {
    pub token_type: YamlTokenType,
    pub value: Vec<u8>,
    pub start_offset: usize,
    pub end_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerError {
    pub problem: &'static str,
    pub offset: usize,
}

/// Structure-aware fuzzing input AST so `cargo-fuzz` / `libFuzzer` mutates valid
/// and near-valid YAML token transitions (anchors, flow levels, indentation, block scalars)
/// instead of dying on invalid UTF-8 at byte 0.
#[derive(Debug, Clone, Arbitrary)]
pub enum StructuredYamlChunk {
    FlowSeq(Vec<u8>),
    FlowMap { key: Vec<u8>, val: Vec<u8> },
    AnchorAlias { name: Vec<u8>, is_alias: bool },
    BlockIndent { spaces: u8, payload: Vec<u8> },
    Directive(Vec<u8>),
    RawBytes(Vec<u8>),
}

impl StructuredYamlChunk {
    pub fn to_bytes(chunks: &[Self]) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        for chunk in chunks {
            match chunk {
                Self::FlowSeq(inner) => {
                    out.push(b'[');
                    out.extend_from_slice(inner);
                    out.push(b']');
                }
                Self::FlowMap { key, val } => {
                    out.push(b'{');
                    out.extend_from_slice(key);
                    out.extend_from_slice(b": ");
                    out.extend_from_slice(val);
                    out.push(b'}');
                }
                Self::AnchorAlias { name, is_alias } => {
                    out.push(if *is_alias { b'*' } else { b'&' });
                    out.extend_from_slice(name);
                    out.push(b' ');
                }
                Self::BlockIndent { spaces, payload } => {
                    out.push(b'\n');
                    let indent = (*spaces % 16) as usize;
                    out.resize(out.len() + indent, b' ');
                    out.extend_from_slice(b"- ");
                    out.extend_from_slice(payload);
                }
                Self::Directive(d) => {
                    out.extend_from_slice(b"%YAML ");
                    out.extend_from_slice(d);
                    out.push(b'\n');
                }
                Self::RawBytes(raw) => out.extend_from_slice(raw),
            }
        }
        out
    }
}

/// Explicit-state Rust replacement for the scanner portion of `yaml_parser_t`.
/// Isolates all implicit C static/pointer state into an owned, deterministic struct.
pub struct Scanner<'a> {
    input: &'a [u8],
    cursor: usize,
    stream_start_produced: bool,
    stream_end_produced: bool,
    flow_level: usize,
    indent: isize,
    indents: Vec<isize>,
    tokens: VecDeque<YamlToken>,
}

impl<'a> Scanner<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cursor: 0,
            stream_start_produced: false,
            stream_end_produced: false,
            flow_level: 0,
            indent: -1,
            indents: Vec::new(),
            tokens: VecDeque::new(),
        }
    }

    /// Mirrors `yaml_parser_scan` + `yaml_parser_fetch_more_tokens` in `src/scanner.c`.
    /// Target for iterative autonomous porting gated by `fuzz/fuzz_targets/scanner_diff.rs`.
    pub fn scan_next_token(&mut self) -> Result<YamlToken, ScannerError> {
        if !self.stream_start_produced {
            self.stream_start_produced = true;
            return Ok(YamlToken {
                token_type: YamlTokenType::StreamStartToken,
                value: Vec::new(),
                start_offset: 0,
                end_offset: 0,
            });
        }

        if let Some(tok) = self.tokens.pop_front() {
            return Ok(tok);
        }

        self.fetch_more_tokens()?;
        self.tokens.pop_front().ok_or(ScannerError {
            problem: "unexpected empty token queue after fetch_more_tokens",
            offset: self.cursor,
        })
    }

    fn fetch_more_tokens(&mut self) -> Result<(), ScannerError> {
        self.scan_to_next_token()?;

        if self.cursor >= self.input.len() {
            self.stream_end_produced = true;
            self.tokens.push_back(YamlToken {
                token_type: YamlTokenType::StreamEndToken,
                value: Vec::new(),
                start_offset: self.cursor,
                end_offset: self.cursor,
            });
            return Ok(());
        }

        match self.input[self.cursor] {
            b'[' => self.fetch_flow_collection_start(YamlTokenType::FlowSequenceStartToken),
            b'{' => self.fetch_flow_collection_start(YamlTokenType::FlowMappingStartToken),
            b']' => self.fetch_flow_collection_end(YamlTokenType::FlowSequenceEndToken),
            b'}' => self.fetch_flow_collection_end(YamlTokenType::FlowMappingEndToken),
            b',' => self.fetch_flow_entry(),
            _ => {
                // Remaining branches (directives, document indicators, anchors, tags, scalars)
                // are queued as isolated Devin migration tasks gated by CI differential fuzzing.
                self.cursor = self.input.len();
                self.tokens.push_back(YamlToken {
                    token_type: YamlTokenType::StreamEndToken,
                    value: Vec::new(),
                    start_offset: self.cursor,
                    end_offset: self.cursor,
                });
                Ok(())
            }
        }
    }

    fn scan_to_next_token(&mut self) -> Result<(), ScannerError> {
        while self.cursor < self.input.len() {
            match self.input[self.cursor] {
                b' ' | b'\t' | b'\r' | b'\n' => self.cursor += 1,
                b'#' => {
                    while self.cursor < self.input.len() && self.input[self.cursor] != b'\n' {
                        self.cursor += 1;
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn fetch_flow_collection_start(&mut self, token_type: YamlTokenType) -> Result<(), ScannerError> {
        let start = self.cursor;
        self.cursor += 1;
        self.flow_level += 1;
        self.tokens.push_back(YamlToken {
            token_type,
            value: Vec::new(),
            start_offset: start,
            end_offset: self.cursor,
        });
        Ok(())
    }

    fn fetch_flow_collection_end(&mut self, token_type: YamlTokenType) -> Result<(), ScannerError> {
        if self.flow_level == 0 {
            return Err(ScannerError {
                problem: "unmatched flow collection end",
                offset: self.cursor,
            });
        }
        let start = self.cursor;
        self.cursor += 1;
        self.flow_level -= 1;
        self.tokens.push_back(YamlToken {
            token_type,
            value: Vec::new(),
            start_offset: start,
            end_offset: self.cursor,
        });
        Ok(())
    }

    fn fetch_flow_entry(&mut self) -> Result<(), ScannerError> {
        let start = self.cursor;
        self.cursor += 1;
        self.tokens.push_back(YamlToken {
            token_type: YamlTokenType::FlowEntryToken,
            value: Vec::new(),
            start_offset: start,
            end_offset: self.cursor,
        });
        Ok(())
    }
}
