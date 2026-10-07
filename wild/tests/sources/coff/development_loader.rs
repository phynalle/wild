use std::ffi::{c_char, c_void};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
}

#[repr(C)]
struct Position {
    file: i32,
    rank: i32,
}

fn main() {
    let path = std::env::args().nth(1).expect("DLL path");
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    for _ in 0..3 {
        unsafe {
            let module = LoadLibraryW(path.as_ptr());
            assert!(!module.is_null());
            let evaluate = GetProcAddress(module, c"evaluate".as_ptr());
            let tls = GetProcAddress(module, c"tls_count".as_ptr());
            let unwind = GetProcAddress(module, c"panic_is_caught".as_ptr());
            let data = GetProcAddress(module, c"EXPORTED_VALUE".as_ptr());
            assert!(!evaluate.is_null() && !tls.is_null() && !unwind.is_null() && !data.is_null());
            let evaluate: extern "C" fn(Position, i32) -> i32 = std::mem::transmute(evaluate);
            let tls: extern "C" fn() -> u32 = std::mem::transmute(tls);
            let unwind: extern "C" fn() -> bool = std::mem::transmute(unwind);
            assert_eq!(evaluate(Position { file: 5, rank: 3 }, 4), 47);
            assert_eq!(*data.cast::<i32>(), 17);
            *data.cast::<i32>() = 23;
            assert_eq!(tls(), 1);
            assert_eq!(tls(), 2);
            std::thread::spawn(move || assert_eq!(tls(), 1)).join().unwrap();
            assert!(unwind());
            assert_ne!(FreeLibrary(module), 0);
        }
    }
    println!("DLL load/unload, data, TLS and unwind passed");
}
