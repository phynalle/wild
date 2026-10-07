#[repr(C)]
pub struct Position {
    pub file: i32,
    pub rank: i32,
}

#[unsafe(no_mangle)]
pub static mut EXPORTED_VALUE: i32 = 17;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn evaluate(position: Position, bias: i32) -> i32 {
    let weighted = position.file * 8 + position.rank;
    weighted + bias
}

thread_local! {
    static COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[unsafe(no_mangle)]
pub extern "C" fn tls_count() -> u32 {
    COUNTER.with(|value| {
        value.set(value.get() + 1);
        value.get()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn panic_is_caught() -> bool {
    std::panic::catch_unwind(|| panic!("DLL unwind fixture")).is_err()
}
