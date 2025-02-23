//! A runtime component for user-defined logic that authorizes or rejects executables and queries based on the authority’s permissions.
//!
//! This is a reduced version of the executor, responsible only for permission validation, without handling instruction definitions or executions.

#![allow(missing_docs)] // SATO disallow
#![allow(dead_code)] // SATO disallow
#![allow(missing_copy_implementations)] // SATO disallow

// SATO implement an equivalent logic to the following in wasm

pub struct DefaultAuthorizer;

trait Authorizer {
    // TODO
}

impl Authorizer for DefaultAuthorizer {
    // TODO
}
