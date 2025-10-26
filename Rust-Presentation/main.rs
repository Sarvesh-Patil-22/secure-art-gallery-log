// Rust

fn main() {
    
    
    // Out of bounds caught during compile
    let v = [1,2,3];
    let x = v[10]; // Error out of bounds, change 10 to a valid array element to compile
    println!("x= {}",x);
    
    // mutable vs immutable
    // let y = 1; // Immutable by default
    let /*mut*/ y = 1; // need mut to be mutable, add mut to compile
    y=15+y;
    println!("y= {}", y);


    // Ownership example
    let v = vec![1, 2, 3];
    let v2 = v;          // ownership moved
    println!("v= {:?}", v); // compile error: used after moved, comment out to compile
    println!("v2= {:?}", v2);

    // Unintialized variables
    let k: i32;
    println!("{}", k); // compile error, comment out to compile
    k = 10;
    println!("k= {}", k);
    
}