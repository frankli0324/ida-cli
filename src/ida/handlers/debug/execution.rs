//! IDAPython script generators for execution control operations.

/// Generate a script to continue execution until next event.
pub fn generate_continue_script(timeout: u64) -> String {
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot continue: state={{state}}, need DSTATE_SUSP(-1)")
else:
    ida_dbg.continue_process()
    code = ida_dbg.wait_for_next_event(WFNE_CONT | WFNE_SUSP | WFNE_SILENT, {timeout})
    evt = ida_dbg.get_debug_event()
    ip = safe_hex(ida_dbg.get_ip_val())
    make_result(True, {{
        "event_code": code,
        "ip": ip,
        "state": ida_dbg.get_process_state(),
        "event_id": evt.eid() if evt else None,
    }})
"#,
        timeout = timeout,
    );
    super::build_script(&body)
}

/// Generate a script to step into the next instruction.
pub fn generate_step_into_script(timeout: u64) -> String {
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot step into: state={{state}}, need DSTATE_SUSP(-1)")
else:
    ok = ida_dbg.step_into()
    if not ok:
        make_result(False, error="step_into() returned False")
    else:
        code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
        ip = safe_hex(ida_dbg.get_ip_val())
        make_result(True, {{"event_code": code, "ip": ip, "state": ida_dbg.get_process_state(), "step_ok": ok}})
"#,
        timeout = timeout,
    );
    super::build_script(&body)
}

/// Generate a script to step over the next instruction.
pub fn generate_step_over_script(timeout: u64) -> String {
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot step over: state={{state}}, need DSTATE_SUSP(-1)")
else:
    ok = ida_dbg.step_over()
    if not ok:
        make_result(False, error="step_over() returned False")
    else:
        code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
        ip = safe_hex(ida_dbg.get_ip_val())
        make_result(True, {{"event_code": code, "ip": ip, "state": ida_dbg.get_process_state(), "step_ok": ok}})
"#,
        timeout = timeout,
    );
    super::build_script(&body)
}

/// Generate a script to step until the current function returns.
pub fn generate_step_until_ret_script(timeout: u64) -> String {
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot step until ret: state={{state}}, need DSTATE_SUSP(-1)")
else:
    ok = ida_dbg.step_until_ret()
    if not ok:
        make_result(False, error="step_until_ret() returned False")
    else:
        code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
        ip = safe_hex(ida_dbg.get_ip_val())
        make_result(True, {{"event_code": code, "ip": ip, "state": ida_dbg.get_process_state(), "step_ok": ok}})
"#,
        timeout = timeout,
    );
    super::build_script(&body)
}

/// Generate a script to run to a specific address.
pub fn generate_run_to_script(address: u64, timeout: u64) -> String {
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != -1:
    make_result(False, error=f"Cannot run_to: state={{state}}, need DSTATE_SUSP(-1)")
else:
    ok = ida_dbg.run_to({address})
    if not ok:
        make_result(False, error="run_to() returned False")
    else:
        code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
        ip = safe_hex(ida_dbg.get_ip_val())
        make_result(True, {{"event_code": code, "ip": ip, "state": ida_dbg.get_process_state(), "run_ok": ok}})
"#,
        address = address,
        timeout = timeout,
    );
    super::build_script(&body)
}
