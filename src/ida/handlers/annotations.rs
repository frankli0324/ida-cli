//! Comment and rename handlers using FFI functions.

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_set_comments(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: u64,
    comment: &str,
    repeatable: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    if repeatable {
        db.set_cmt_with(addr, comment, true)?;
    } else {
        db.set_cmt(addr, comment)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "repeatable": repeatable,
        "comment": comment,
    }))
}

pub fn handle_set_function_comment(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    comment: &str,
    repeatable: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, 0)?;
    if repeatable {
        db.set_func_cmt_with(addr, comment, true)?;
    } else {
        db.set_func_cmt(addr, comment)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "comment": comment,
        "repeatable": repeatable,
    }))
}

pub fn handle_rename(
    _idb: &Option<IDB>,
    _addr: Option<u64>,
    _current_name: Option<&str>,
    _name: &str,
    _flags: i32,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(
        "Rename functionality temporarily unavailable".to_string(),
    ))
}

pub fn handle_batch_rename(
    _idb: &Option<IDB>,
    _entries: Vec<(Option<u64>, Option<String>, String, i32)>,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(
        "Batch rename temporarily unavailable".to_string(),
    ))
}

pub fn handle_rename_lvar(
    _idb: &Option<IDB>,
    _addr: u64,
    _idx: usize,
    _name: &str,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(
        "Local variable rename temporarily unavailable".to_string(),
    ))
}

pub fn handle_set_lvar_type(
    _idb: &Option<IDB>,
    _addr: u64,
    _idx: usize,
    _type_str: &str,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(
        "Local variable type set temporarily unavailable".to_string(),
    ))
}

pub fn handle_set_decompiler_comment(
    _idb: &Option<IDB>,
    _func_addr: u64,
    _comment: &str,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(
        "Decompiler comment set temporarily unavailable".to_string(),
    ))
}
