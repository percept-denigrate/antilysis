//! # Antilysis
//!
//! Library to detect analysis on windows to protect your program from it. 
//! Anti-VM, anti-sandbox, anti-analyzing.

use std::{thread, time, sync::{Arc, Mutex}, ptr, path::Path};
use rdev::{listen, Event, EventType};
use sysinfo::System;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::debugapi::{CheckRemoteDebuggerPresent, IsDebuggerPresent};
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::iphlpapi::GetAdaptersAddresses;
use winapi::um::iptypes::{GAA_FLAG_INCLUDE_ALL_INTERFACES, IP_ADAPTER_ADDRESSES};
use winapi::um::winnt::{GENERIC_READ, FILE_ATTRIBUTE_NORMAL};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::shared::minwindef::{BOOL, PBOOL};
use winapi::shared::ntdef::{HANDLE, ULONG};
use winapi::shared::ws2def::AF_UNSPEC;
use ntapi::ntpsapi::{NtSetInformationThread, ThreadHideFromDebugger};
use ntp::formats::timestamp::TimestampFormat;

/// Returns whether or not any sign of analysis environment is present.
/// Is true if one of the following is true: processes(), is_debugger_present(), comparaison_known_mac_addr(), vm_file_detected(), sandbox().
/// 
/// Use:
/// ```
/// use std::process;
/// 
/// match antilysis::detected(){
///     Some(true) => process::exit(0),
///     _ => {}
/// }
/// ```
pub fn detected() -> Option<bool>{
    return Some(processes() || sandbox()? || is_debugger_present() || comparaison_known_mac_addr()? || vm_file_detected());
}

/// Returns whether or not suspicious processes have been found. Includes analyzers (wireshark, process explorer, etc...) VM guest processes and debuggers processes.
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

    let debuggers = vec![
        "WinDbg.exe",
        "devenv.exe", // Visual Studio Debugger
        "drwtsn32.exe", // Dr. Watson
        "ollydbg.exe",
        "x64dbg.exe",
        "gdb.exe", // gdb via WSL
        "dbgview.exe", // DebugView
        "procdump.exe", // ProcDump
        "ntsd.exe", // NTSD (Console version of WinDbg)
        "windbgX.exe", // WinDbg Preview
    ];

    let s = System::new_all();
    for (_pid, process) in s.processes() {
        if analyzers.contains(&process.name()) || vms.contains(&process.name()) || debuggers.contains(&process.name()) {
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
/// match antilysis::sandbox(){
///     Some(true) => process::exit(0),
///     _ => {}
/// }
/// ```
pub fn sandbox() -> Option<bool> {
    let windows_version = System::os_version()?.chars().next()?;
    if windows_version == '0' {
        return Some(true);
    }
    let host = System::host_name()?.to_lowercase();
    if host == "john-pc" {
        return Some(true);
    }
    Some(false)
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

/// Returns whether or not a debugger is present.
/// 
/// Use:
/// ```
/// use std::process;
/// 
/// if antilysis::is_debugger_present(){
///     process::exit(0);
/// }
/// ```
pub fn is_debugger_present() -> bool{
    let mut ispresent: BOOL = 0;
    let h_process = unsafe { GetCurrentProcess() };
    let device_name = "\\\\.\\NTICE\0".as_ptr() as *const i8;
    unsafe {
        IsDebuggerPresent() != 0 && 
        CheckRemoteDebuggerPresent(h_process, &mut ispresent as PBOOL) != 0 && 
        ispresent != 0 &&
        CreateFileA(
            device_name,
            GENERIC_READ,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        ) != INVALID_HANDLE_VALUE
    }
}

/// Returns whether or not any VM specific files (Virtual Box and Vmware) are present.
/// 
/// Use:
/// ```
/// use std::process;
/// 
/// if antilysis::vm_file_detected(){
///     process::exit(0);
/// }
/// ```
pub fn vm_file_detected() -> bool{
    let file_paths = vec![
        "C:\\windows\\System32\\Drivers\\Vmmouse.sys",
        "C:\\windows\\System32\\Drivers\\vm3dgl.dll",
        "C:\\windows\\System32\\Drivers\\vmdum.dll",
        "C:\\windows\\System32\\Drivers\\vm3dver.dll",
        "C:\\windows\\System32\\Drivers\\vmtray.dll",
        "C:\\windows\\System32\\Drivers\\VMToolsHook.dll",
        "C:\\windows\\System32\\Drivers\\vmmousever.dll",
        "C:\\windows\\System32\\Drivers\\vmhgfs.dll",
        "C:\\windows\\System32\\Drivers\\vmGuestLib.dll",
        "C:\\windows\\System32\\Drivers\\VmGuestLibJava.dll",
        "C:\\windows\\System32\\Drivers\\VBoxMouse.sys",
        "C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
        "C:\\windows\\System32\\Drivers\\VBoxSF.sys",
        "C:\\windows\\System32\\Drivers\\VBoxVideo.sys",
        "C:\\windows\\System32\\vboxdisp.dll",
        "C:\\windows\\System32\\vboxhook.dll",
        "C:\\windows\\System32\\vboxmrxnp.dll",
        "C:\\windows\\System32\\vboxogl.dll",
        "C:\\windows\\System32\\vboxoglarrayspu.dll",
        "C:\\windows\\System32\\vboxoglcrutil.dll",
        "C:\\windows\\System32\\vboxoglerrorspu.dll",
        "C:\\windows\\System32\\vboxoglfeedbackspu.dll",
        "C:\\windows\\System32\\vboxoglpackspu.dll",
        "C:\\windows\\System32\\vboxoglpassthroughspu.dll",
        "C:\\windows\\System32\\vboxservice.exe",
        "C:\\windows\\System32\\vboxtray.exe",
        "C:\\windows\\System32\\VBoxControl.exe",
    ];
    for path in file_paths { if Path::new(path).exists() { return true; } } 
    return false;
}

/// Returns if the mac addresses indicates a VM running with Virtual Box or VMware.
/// 
/// Use:
/// ```
/// use std::process;
/// 
/// match antilysis::comparaison_known_mac_addr(){
///     Some(true) => process::exit(0),
///     _ => {}
/// }
/// ```
pub fn comparaison_known_mac_addr() -> Option<bool> {
    let known_mac_addr: Vec<[u8; 6]> = vec![
        [0x00, 0x05, 0x69, 0x00, 0x00, 0x00], // 00:05:69 Vmware
        [0x00, 0x0C, 0x29, 0x00, 0x00, 0x00], // 00:0C:29 Vmware
        [0x00, 0x1C, 0x14, 0x00, 0x00, 0x00], // 00:1C:14 Vmware
        [0x00, 0x50, 0x56, 0x00, 0x00, 0x00], // 00:50:56 Vmware
        [0x08, 0x00, 0x27, 0x00, 0x00, 0x00], // 08:00:27 Virtual Box
    ];

    unsafe {
        let mut out_buf_len: ULONG = 0;
        GetAdaptersAddresses(AF_UNSPEC.try_into().ok()?, GAA_FLAG_INCLUDE_ALL_INTERFACES, ptr::null_mut(), ptr::null_mut(), &mut out_buf_len);
        let mut buffer: Vec<u8> = vec![0; out_buf_len as usize];
        let adapters_ptr: *mut IP_ADAPTER_ADDRESSES = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES;
        let result = GetAdaptersAddresses(AF_UNSPEC.try_into().ok()?, GAA_FLAG_INCLUDE_ALL_INTERFACES, ptr::null_mut(), adapters_ptr, &mut out_buf_len);
        if result == 0 {
            let mut current_adapter = adapters_ptr;
            while !current_adapter.is_null() {
                let adapter = &*current_adapter;
                for i in 0..known_mac_addr.len() {
                    if (known_mac_addr[i][0] == adapter.PhysicalAddress[0]) &&
                    (known_mac_addr[i][1] == adapter.PhysicalAddress[1]) &&
                    (known_mac_addr[i][2] == adapter.PhysicalAddress[2]) {
                        return Some(true);
                    }
                }
                current_adapter = adapter.Next;
            }
        } else {
            return Some(false);
        }
        return Some(false);
    }
}
/// Tries to hide the current thread for debuggers.
/// 
/// Use:
/// ```
/// antilysis::attempt_hide_thread();
/// ```
pub fn attempt_hide_thread() {
    const NT_CURRENT_THREAD: HANDLE = -2i32 as HANDLE;
    unsafe {
        let _status = NtSetInformationThread(
            NT_CURRENT_THREAD,
            ThreadHideFromDebugger,
            ptr::null_mut(),
            0,
        );
    }
}

fn ntp_time() -> Option<TimestampFormat> {
    let address = "0.pool.ntp.org:123";
    let response: ntp::packet::Packet = ntp::request(address).ok()?;
    Some(response.transmit_time)
}

/// Makes the process sleep and times the sleep using NTP. This checks if the pogram is being run in a sandbox that patches sleep functions.
/// 
/// Use:
/// ```
/// use std::process;
/// 
/// match antilysis::secure_sleep(){
///     Some(true) => process::exit(0),
///     _ => {}
/// }
/// ```
pub fn secure_sleep(n: u32) -> Option<bool>{
    let before = ntp_time()?;
    thread::sleep(time::Duration::from_millis((n * 1000).into()));
    let after = ntp_time()?;
    let diff = after.sec - before.sec;
    Some(diff < n)
}