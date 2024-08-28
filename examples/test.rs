extern crate antilysis;

fn main() {
    println!("Processes: {}", antilysis::processes());
    println!("Sandbox: {}", antilysis::sandbox());
    println!("Detected: {}", antilysis::detected());
}