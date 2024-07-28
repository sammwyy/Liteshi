mod inside_vm;

fn main() {
    let is_vm = inside_vm::inside_vm();
    println!("Is inside VM? {}", is_vm);
}
