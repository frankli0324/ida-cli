//! Analysis handlers - load_debug_info API removed in idalib 0.9.0

use crate::error::ToolError;
use idalib::IDB;
use serde_json::Value;

const NOT_SUPPORTED: &str = "Debug info loading API removed in idalib 0.9.0";

pub fn handle_load_debug_info(
    _idb: &Option<IDB>,
    _path: Option<&str>,
    _verbose: bool,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_analysis_status(_idb: &Option<IDB>) -> Result<Value, ToolError> {
    // Return a default status since auto_is_ok and auto_state are not available
    Ok(serde_json::json!({
        "auto_enabled": false,
        "auto_is_ok": false,
        "auto_state": "unknown",
        "auto_state_id": -1,
        "analysis_running": false,
    }))
}
