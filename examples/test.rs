extern crate antilysis;

fn main() {
    println!("Processes: {}", antilysis::processes());
    println!("Sandbox: {}", antilysis::sandbox());
    println!("Detected: {}", antilysis::detected());
    antilysis::wait_for_left_click(2);
    println!("Left click");
}