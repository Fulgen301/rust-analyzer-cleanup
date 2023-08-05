use std::ffi::c_void;
use std::hash::{BuildHasher, Hasher};
use std::path::Path;

use windows::core::HRESULT;
use windows::Win32::Foundation::{BOOL, E_FAIL, HMODULE, WIN32_ERROR};
use windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

fn map_io_error(error: std::io::Error) -> HRESULT {
    error
        .raw_os_error()
        .map_or(E_FAIL, |code| WIN32_ERROR(code as u32).to_hresult())
}

fn clean_tmp_paths() -> windows::core::Result<()> {
    let tmp_path = std::env::var("TMP").map_err(|_| E_FAIL)?;

    for path in Path::new(&tmp_path).read_dir().map_err(map_io_error)? {
        match path {
            Err(_) => continue,
            Ok(entry) => {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("rust-analyzer-")
                {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
    }

    Ok(())
}

fn set_tmp_path() -> windows::core::Result<()> {
    let tmp_path = std::env::var("TMP").map_err(|_| E_FAIL)?;

    let hash = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();

    let name = format!("rust-analyzer-{}", hash);

    let new_tmp_path = Path::new(&tmp_path).join(name);

    std::fs::create_dir(&new_tmp_path).map_err(map_io_error)?;

    std::env::set_var("TMP", new_tmp_path);

    Ok(())
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(module: HMODULE, reason: u32, _reserved: *const c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(module);

        let _ = clean_tmp_paths();
        let _ = set_tmp_path();

        // Always return 0 so that the DLL gets unloaded again
        BOOL(0)
    } else {
        BOOL(1)
    }
}
