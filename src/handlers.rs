//! # Handlers
//!
//! This module contains the DWN message handlers — one for each
//! interface/method message.

pub mod messages_query;
pub mod messages_read;
pub mod messages_subscribe;
pub mod protocols_configure;
pub mod protocols_query;
pub mod records_delete;
pub mod records_query;
pub mod records_read;
pub mod records_subscribe;
pub mod records_write;
pub mod verify_grant;
pub mod verify_protocol;
