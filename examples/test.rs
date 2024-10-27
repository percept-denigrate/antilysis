extern crate antilysis;

// This file is used to create a binary that will test the library's function.
// The binary is meant to be compiled, then executed in different environments and under different conditions.

fn main() {
    println!("Processes: {}", antilysis::processes());
    println!("Sandbox: {}", antilysis::sandbox());
    println!("File: {}", antilysis::vm_file_detected());
    println!("Detected: {}", antilysis::detected());
    println!("Known MAC address: {}", antilysis::comparaison_known_mac_addr());

    
    antilysis::wait_for_left_clicks(2);
    println!("Left click");

}
