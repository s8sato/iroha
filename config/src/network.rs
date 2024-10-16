//! Module for network-related configuration and structs
#![allow(clippy::std_instead_of_core)]
use iroha_config_base::derive::{Documented, LoadFromEnv, Proxy};
use serde::{Deserialize, Serialize};

const DEFAULT_ACTOR_CHANNEL_CAPACITY: u32 = 100;

/// Network Configuration parameters
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Documented, Proxy, LoadFromEnv,
)]
#[serde(default)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "IROHA_NETWORK_")]
pub struct Configuration {
    /// Buffer capacity of actor's MPSC channel
    pub actor_channel_capacity: u32,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            actor_channel_capacity: DEFAULT_ACTOR_CHANNEL_CAPACITY,
        }
    }
}
