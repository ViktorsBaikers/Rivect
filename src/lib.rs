//! Rivect runtime library. One executable, one owner, one state store.

pub mod actions;
pub mod commands;
pub mod config;
pub mod context;
pub mod contracts;
pub mod controller;
pub mod executor;
pub mod identity;
pub mod index;
pub mod instructions;
pub mod learning;
pub mod lsp;
pub mod mcp;
pub mod model;
pub mod owner;
pub mod policy;
pub mod procedure;
pub mod providers;
pub mod resources;
pub mod scheduler;
pub mod state;
pub mod supervisor;
pub mod tools;
pub mod ui;
pub mod update;
pub mod verification;

pub const BUILD_ATTEMPT_ID: &str = "slice001-20260909T180108Z-retry";
