//! Disassembly and decompilation handlers.

use crate::disasm::generate_disasm_line;
use crate::error::ToolError;
use idalib::{Address, IDB};
use serde_json::{json, Value};

pub fn handle_disasm_by_name(
    idb: &Option<IDB>,
    name: &str,
    count: usize,
) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    for (_id, func) in db.functions() {
        if let Some(func_name) = func.name() {
            if func_name == name || func_name.contains(name) {
                let addr = func.start_address();
                return handle_disasm(idb, addr, count);
            }
        }
    }

    Err(ToolError::FunctionNameNotFound(name.to_string()))
}

pub fn handle_disasm(idb: &Option<IDB>, addr: u64, count: usize) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let mut lines = Vec::with_capacity(count);
    let mut current_addr: Address = addr;

    for _ in 0..count {
        // Get disassembly line
        if let Some(line) = generate_disasm_line(db, current_addr) {
            lines.push(format!("{:#x}:\t{}", current_addr, line));
        } else {
            // No more valid instructions
            break;
        }

        // Get instruction at current address to find next
        if let Some(insn) = db.insn_at(current_addr) {
            current_addr += insn.len() as u64;
        } else {
            // Move to next head
            if let Some(next) = db.next_head(current_addr) {
                if next <= current_addr {
                    break; // Prevent infinite loop
                }
                current_addr = next;
            } else {
                break;
            }
        }
    }

    if lines.is_empty() {
        return Err(ToolError::AddressOutOfRange(addr));
    }

    Ok(lines.join("\n"))
}

pub fn handle_disasm_function_at(
    idb: &Option<IDB>,
    addr: u64,
    count: usize,
) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;
    let start = func.start_address();
    let end = func.end_address();

    let mut lines = Vec::new();
    let mut current_addr: Address = start;

    while current_addr < end && lines.len() < count {
        if let Some(line) = generate_disasm_line(db, current_addr) {
            lines.push(format!("{:#x}:\t{}", current_addr, line));
        } else {
            break;
        }

        if let Some(insn) = db.insn_at(current_addr) {
            current_addr += insn.len() as u64;
        } else if let Some(next) = db.next_head(current_addr) {
            if next <= current_addr {
                break;
            }
            current_addr = next;
        } else {
            break;
        }
    }

    if lines.is_empty() {
        return Err(ToolError::AddressOutOfRange(addr));
    }

    Ok(lines.join("\n"))
}

pub fn handle_decompile(idb: &Option<IDB>, addr: u64) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    // Check if decompiler is available
    if !db.decompiler_available() {
        return Err(ToolError::DecompilerUnavailable);
    }

    // Find the function at this address
    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    // Decompile function
    let cfunc = db
        .decompile(&func)
        .map_err(|e| ToolError::IdaError(e.to_string()))?;

    // Get the pseudocode as string
    Ok(cfunc.pseudocode())
}

/// Search decompiled pseudocode of all functions for a text pattern.
/// Runs entirely on the main thread — no cross-thread overhead per function.
pub fn handle_search_pseudocode(
    idb: &Option<IDB>,
    pattern: &str,
    limit: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    if !db.decompiler_available() {
        return Err(ToolError::DecompilerUnavailable);
    }

    let mut matches = Vec::new();
    let mut total_searched = 0usize;
    let mut errors = 0usize;

    for (_id, func) in db.functions() {
        total_searched += 1;
        let addr = func.start_address();
        let name = func.name().unwrap_or_else(|| format!("sub_{:x}", addr));

        match db.decompile(&func) {
            Ok(cfunc) => {
                let pseudocode = cfunc.pseudocode();
                if pseudocode.contains(pattern) {
                    matches.push(json!({
                        "address": format!("{:#x}", addr),
                        "name": name,
                        "pseudocode": pseudocode,
                    }));
                    if matches.len() >= limit {
                        break;
                    }
                }
            }
            Err(_) => {
                errors += 1;
            }
        }
    }

    Ok(json!({
        "pattern": pattern,
        "matches": matches,
        "total_searched": total_searched,
        "decompile_errors": errors,
    }))
}

/// Get decompiled pseudocode statements at a specific address or address range.
pub fn handle_pseudocode_at(
    _idb: &Option<IDB>,
    _addr: u64,
    _end_addr: Option<u64>,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(
        "Pseudocode statement API (statements_at, has_eamap) removed in idalib 0.9.0"
            .to_string(),
    ))
}

const DECOMPILE_STRUCTURED_PY: &str = include_str!("../../../scripts/decompile_structured.py");

pub fn decompile_structured_script(
    addr: u64,
    max_depth: u32,
    include_types: bool,
    include_addresses: bool,
) -> String {
    format!(
        "EA = {addr:#x}\nMAX_DEPTH = {max_depth}\nINCLUDE_TYPES = {include_types}\nINCLUDE_ADDRESSES = {include_addresses}\n{body}",
        addr = addr,
        max_depth = max_depth,
        include_types = if include_types { "True" } else { "False" },
        include_addresses = if include_addresses { "True" } else { "False" },
        body = DECOMPILE_STRUCTURED_PY,
    )
}
