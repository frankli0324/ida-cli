//! Script handlers - run_python API removed in idalib 0.9.0

use crate::error::ToolError;
use idalib::IDB;
use serde_json::Value;

const NOT_SUPPORTED: &str = "Script execution API removed in idalib 0.9.0";

pub fn handle_run_python_snippet(
    _idb: &Option<IDB>,
    _code: &str,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_run_script(_idb: &Option<IDB>, _code: &str) -> Result<serde_json::Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}
