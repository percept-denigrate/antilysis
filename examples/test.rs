extern crate antilysis;

// This file is used to create a binary that will test the library's function.
// The binary is meant to be compiled, then executed in different environments and under different conditions.

fn main() {
    println!("Processes: {}", antilysis::processes());
    println!("Sandbox: {}", antilysis::sandbox());
    println!("Detected: {}", antilysis::detected());
<<<<<<< HEAD
}
=======
    antilysis::wait_for_left_click();
    println!("Left click");
}
>>>>>>> 3cc8ff9 (wait for left click)
