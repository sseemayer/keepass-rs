#[no_mangle]
#[repr(C)]
pub enum MyEnum {
    Moi,
    Toi,
}

#[no_mangle]
pub static MY_STATIC: i32 = 42;

#[no_mangle]
pub extern "C" fn call_from_c() {
    println!("Just called a Rust function from C!");
}
