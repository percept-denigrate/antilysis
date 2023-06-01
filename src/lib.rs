//! # Antilysis
//!
//! Library to detect analysis on windows to protect your program from it. 
//! Anti-VM, anti-sandbox, anti-analyzing.

use sysinfo::{ProcessExt, System, SystemExt};

/// Returns whether or not any sign of analysis environment is present.
/// Is true if processes() or sandbox() is true.
/// 
/// Use:
/// ```
/// use std::process;
/// 
/// if antilysis::detected(){
///     process::exit(0);
/// }
/// ```
pub fn detected() -> bool{
    return processes() || sandbox();
}

/// Returns whether or not suspicious processes have been found. Includes analyzers (wireshark, process explorer, etc...) and VM guest processes.
/// 
/// Use:
/// ```
/// use std::process;
/// 
/// if antilysis::processes(){
///     process::exit(0);
/// }
/// ```
pub fn processes() -> bool{
    let analyzers = vec![
        "Wireshark.exe",
        "procexp64.exe",
        "procexp.exe",
        "Procmon.exe",
        "Procmon64.exe",
        "pestudio.exe",
        "KsDumper.exe",
        "prl_cc.exe",
        "prl_tools.exe"
    ];

    let vms = vec![
        "VBoxTray.exe",
        "VBoxService.exe",
        "VMwareUser.exe",
        "vmtoolsd.exe",
        "VMwareTray.exe",
        "vmsrvc.exe",
        "VGAuthService.exe"
    ];

    let s = System::new_all();
    for (_pid, process) in s.processes() {
        if analyzers.contains(&process.name()) || vms.contains(&process.name()) {
            return true;
        }
    }
    return false;
}

/// Returns whether or not any common sandbox artifact is present.
/// 
/// Use:
/// ```
/// use std::process;
/// 
/// if antilysis::sandbox(){
///     process::exit(0);
/// }
/// ```
pub fn sandbox() -> bool{
    let sys = System::new_all();
    let windows_version = sys.os_version().unwrap().chars().next().unwrap();
    if windows_version == '0' {
        return true;
    }
    let host = sys.host_name().unwrap().to_lowercase();
    if host == "john-pc"{
        return true;
    }
    return false;
}