extern crate antilysis;

// This file is used to create a binary that will test the library's function.
// The binary is meant to be compiled, then executed in different environments and under different conditions.

fn main() {
    println!("Processes: {}", antilysis::processes());
    println!("Sandbox: {}", antilysis::sandbox().unwrap());
    println!("VM files: {}", antilysis::vm_file_detected());
    println!("Debugger: {}", antilysis::is_debugger_present());
    println!("Detected: {}", antilysis::detected().unwrap());
    println!("Known MAC address: {}", antilysis::comparaison_known_mac_addr().unwrap());

    println!("Attempt at hiding thread...");
    antilysis::attempt_hide_thread();
    println!("Done");

    antilysis::wait_for_left_clicks(2);
    println!("Left click");

    println!("Sleep patched: {}", antilysis::secure_sleep(2).unwrap());
}
