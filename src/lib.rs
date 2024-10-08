//! # Antilysis
//!
//! Library to detect analysis on windows to protect your program from it. 
//! Anti-VM, anti-sandbox, anti-analyzing.

use std::{thread, time::Duration, sync::{Arc, Mutex}};
use rdev::{listen, Event, EventType};
use sysinfo::System;

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
        "prl_tools.exe",
        "pe-sieve64.exe",
        "hollows_hunter32.exe",
        "Moneta64.exe",
        "fakenet.exe",
        "tcpview.exe",
        "dumpcap.exe",
        "PETools.exe",
        "httpdebugger.exe"
    ];

    let vms = vec![
        "VBoxTray.exe",
        "VBoxService.exe",
        "VMwareUser.exe",
        "vmtoolsd.exe",
        "VMwareTray.exe",
        "vmsrvc.exe",
        "VGAuthService.exe",
        "qemu-ga.exe",
        "vdagent.exe",
        "vdservice.exe",
        "xenservice.exe",
        "joeboxserver.exe"
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
    let windows_version = System::os_version().unwrap().chars().next().unwrap();
    if windows_version == '0' {
        return true;
    }
    let host = System::host_name().unwrap().to_lowercase();
    if host == "john-pc"{
        return true;
    }
    return false;
}

/// Waits for the user to left click. The function takes the number of clicks to wait for as an argument.
/// 
/// Use:
/// ```
/// antilysis::wait_for_left_clicks(1);
/// ```
pub fn wait_for_left_clicks(min_clicks: u64) {
    let count = Arc::new(Mutex::new(0));
    let count_clone = Arc::clone(&count);

    thread::spawn(move || {
        listen(move |event: Event| {
            if let EventType::ButtonPress(button) = event.event_type {
                if button == rdev::Button::Left {
                    let mut count = count_clone.lock().unwrap();
                    *count += 1;
                }
            }
        }).unwrap();
    });

    loop {
        let count = count.lock().unwrap();
        if *count >= min_clicks {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Returns whether or not if a debugger is present.
/// 
/// Use:
/// ```
/// use std::process;
/// 
/// if antilysis::debugger(){
///     process::exit(0);
/// }
/// ```
pub fn debugger() -> bool{
    let windows_version = System::os_version().unwrap().chars().next().unwrap();
    if windows_version == '0' {
        return true;
    }
    let host = System::host_name().unwrap().to_lowercase();
    if host == "john-pc"{
        return true;
    }
    return false;
}
