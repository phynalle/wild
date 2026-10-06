use std::cell::Cell;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
static DROPS: AtomicU32 = AtomicU32::new(0);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}
thread_local! { static VALUE: Cell<u32> = const { Cell::new(7) }; }
thread_local! { static GUARD: Guard = const { Guard }; }
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                GUARD.with(|_| {});
                VALUE.with(|v| {
                    assert_eq!(v.get(), 7);
                    v.set(i);
                });
                assert!(std::panic::catch_unwind(|| panic!("expected unwind")).is_err());
                VALUE.with(|v| assert_eq!(v.get(), i));
                i * i
            })
        })
        .collect();
    assert_eq!(
        handles.into_iter().map(|h| h.join().unwrap()).sum::<u32>(),
        140
    );
    assert_eq!(DROPS.load(Ordering::SeqCst), 8);
    VALUE.with(|v| assert_eq!(v.get(), 7));
    let path = std::env::temp_dir().join(format!("wild-coff-{}.txt", std::process::id()));
    std::fs::write(&path, b"wild bootstrap runtime").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"wild bootstrap runtime");
    std::fs::remove_file(path).unwrap();
    println!("COFF runtime OK");
}
