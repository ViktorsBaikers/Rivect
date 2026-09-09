//! Rivect runtime library. One executable, one owner, one state store.

pub mod commands;
pub mod config;
pub mod contracts;
pub mod controller;
pub mod executor;
pub mod model;
pub mod owner;
pub mod policy;
pub mod providers;
pub mod resources;
pub mod state;
pub mod tools;
pub mod ui;
pub mod verification;

pub const BUILD_ATTEMPT_ID: &str = "slice001-20260909T180108Z-retry";
