//! IDAPython script generators for process and debugger loading operations.

/// Generate a script to load a debugger module.
pub fn generate_load_debugger_script(debugger_name: &str, is_remote: bool) -> String {
    let is_remote_py = if is_remote { "True" } else { "False" };
    let body = format!(
        r#"
if ida_dbg.dbg_is_loaded():
    make_result(True, {{"already_loaded": True, "debugger": "{debugger_name}"}})
else:
    ok = ida_dbg.load_debugger("{debugger_name}", {is_remote_py})
    if ok:
        ida_dbg.set_debugger_options(0)
        make_result(True, {{"loaded": True, "debugger": "{debugger_name}"}})
    else:
        make_result(False, error="Failed to load debugger '{debugger_name}'")
"#,
        debugger_name = debugger_name,
        is_remote_py = is_remote_py,
    );
    super::build_script(&body)
}

/// Generate a script to start the process under the debugger.
pub fn generate_start_process_script(
    path: Option<&str>,
    args: Option<&str>,
    start_dir: Option<&str>,
    timeout: u64,
) -> String {
    let path_py = match path {
        Some(p) => format!("\"{}\"", p.replace('"', "\\\"")),
        None => "None".to_string(),
    };
    let args_py = match args {
        Some(a) => format!("\"{}\"", a.replace('"', "\\\"")),
        None => "None".to_string(),
    };
    let dir_py = match start_dir {
        Some(d) => format!("\"{}\"", d.replace('"', "\\\"")),
        None => "None".to_string(),
    };
    let body = format!(
        r#"
import platform
if not ida_dbg.dbg_is_loaded():
    dbg_name = {{"Darwin": "mac", "Linux": "linux", "Windows": "win32"}}.get(platform.system(), "gdb")
    ida_dbg.load_debugger(dbg_name, False)
    ida_dbg.set_debugger_options(0)
state = ida_dbg.get_process_state()
if state != 0:
    make_result(False, error=f"Cannot start: process state is {{state}}, need DSTATE_NOTASK(0)")
else:
    ret = ida_dbg.start_process({path_py}, {args_py}, {dir_py})
    if ret == 1:
        code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
        ip = safe_hex(ida_dbg.get_ip_val())
        make_result(True, {{"event_code": code, "ip": ip, "state": ida_dbg.get_process_state()}})
    elif ret == 0:
        make_result(False, error="start_process cancelled")
    else:
        make_result(False, error=f"start_process failed with code {{ret}}")
"#,
        path_py = path_py,
        args_py = args_py,
        dir_py = dir_py,
        timeout = timeout,
    );
    super::build_script(&body)
}

/// Generate a script to attach to a running process by PID.
pub fn generate_attach_process_script(pid: Option<u64>, timeout: u64) -> String {
    let pid_py = match pid {
        Some(p) => p.to_string(),
        None => "None".to_string(),
    };
    let body = format!(
        r#"
state = ida_dbg.get_process_state()
if state != 0:
    make_result(False, error=f"Cannot attach: state={{state}}, need DSTATE_NOTASK(0)")
else:
    ret = ida_dbg.attach_process({pid_py}, -1)
    if ret == 1:
        code = ida_dbg.wait_for_next_event(WFNE_SUSP | WFNE_SILENT, {timeout})
        ip = safe_hex(ida_dbg.get_ip_val())
        make_result(True, {{"event_code": code, "ip": ip, "pid": {pid_py}}})
    else:
        make_result(False, error=f"attach_process returned {{ret}}")
"#,
        pid_py = pid_py,
        timeout = timeout,
    );
    super::build_script(&body)
}

/// Generate a script to detach from the current process.
pub fn generate_detach_process_script() -> String {
    let body = r#"
state = ida_dbg.get_process_state()
if state == 0:
    make_result(False, error="No active process to detach from")
else:
    ok = ida_dbg.detach_process()
    make_result(ok, {"detached": ok})
"#;
    super::build_script(body)
}

/// Generate a script to terminate the debugged process.
pub fn generate_exit_process_script() -> String {
    let body = r#"
state = ida_dbg.get_process_state()
if state == 0:
    make_result(False, error="No active process to exit")
else:
    ok = ida_dbg.exit_process()
    make_result(ok, {"exited": ok})
"#;
    super::build_script(body)
}

/// Generate a script to query current debugger and process state.
pub fn generate_get_state_script() -> String {
    let body = r#"
state = ida_dbg.get_process_state()
state_names = {-1: "DSTATE_SUSP", 0: "DSTATE_NOTASK", 1: "DSTATE_RUN"}
data = {
    "state": state,
    "state_name": state_names.get(state, "unknown"),
    "debugger_loaded": ida_dbg.dbg_is_loaded(),
    "is_debugger_on": ida_dbg.is_debugger_on(),
    "thread_count": ida_dbg.get_thread_qty(),
}
if state == -1:
    data["ip"] = safe_hex(ida_dbg.get_ip_val())
    data["sp"] = safe_hex(ida_dbg.get_sp_val())
    data["current_thread"] = ida_dbg.get_current_thread()
make_result(True, data)
"#;
    super::build_script(body)
}
