#[repr(C)]
struct Position {
    file: i32,
    rank: i32,
}

#[link(name = "development_dll")]
unsafe extern "C" {
    fn evaluate(position: Position, bias: i32) -> i32;
    fn tls_count() -> u32;
    static mut EXPORTED_VALUE: i32;
}

#[inline(never)]
fn calculate(file: i32) -> i32 {
    let position = Position { file, rank: 3 };
    let bias = 4;
    unsafe { evaluate(position, bias) }
}

fn main() {
    let value = calculate(5);
    assert_eq!(value, 47);
    unsafe {
        let initial = EXPORTED_VALUE;
        assert_eq!(initial, 17);
        EXPORTED_VALUE = 23;
        let updated = EXPORTED_VALUE;
        assert_eq!(updated, 23);
        assert_eq!(tls_count(), 1);
        assert_eq!(tls_count(), 2);
    }
    std::thread::spawn(|| unsafe { assert_eq!(tls_count(), 1); }).join().unwrap();
    println!("DLL development fixture passed");
}
