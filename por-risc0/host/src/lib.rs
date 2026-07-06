//! `host` library: shared code for the `prover` binary and the `por_verify` /
//! `verifier` binaries.
//!
//! - [`attest`]: TLSNotary MPC-TLS attestation of a block header (used by the prover).
//! - [`verify`]: Risc0 receipt + journal decode, TLSNotary presentation binding, policy,
//!   and Kurier submission (used by the `por_verify` CLI and the `verifier` service).
//!
//! Extracting these into a lib is what lets the offline CLI and the HTTP service reuse the
//! exact same verification logic instead of two copies drifting apart.

pub mod attest;
pub mod verify;
