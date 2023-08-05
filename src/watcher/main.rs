use std::{ffi::c_void, path::Path, sync::atomic::AtomicIsize};

use windows::{
    core::{implement, ComInterface, BSTR, HRESULT, HSTRING, PCWSTR},
    s, w,
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, BOOL, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, E_FAIL,
            HANDLE, HMODULE, MAX_PATH,
        },
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket,
                CoUninitialize, CLSCTX_INPROC_SERVER, CLSCTX_LOCAL_SERVER, COINIT,
                COINIT_DISABLE_OLE1DDE, COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, VARIANT,
            },
            Console::SetConsoleCtrlHandler,
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress},
            Memory::{
                VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
            },
            Ole::{VariantClear, VariantInit},
            Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE},
            Threading::{
                CreateEventW, CreateMutexW, CreateRemoteThread, OpenProcess, SetEvent,
                WaitForSingleObject, INFINITE, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION,
                PROCESS_VM_WRITE,
            },
            Wmi::{
                IUnsecuredApartment, IWbemClassObject, IWbemLocator, IWbemObjectSink,
                IWbemObjectSink_Impl, UnsecuredApartment, WbemLocator, WBEM_FLAG_SEND_STATUS,
            },
        },
    },
};

struct OwnedHandle(HANDLE);

impl From<HANDLE> for OwnedHandle {
    fn from(handle: HANDLE) -> Self {
        Self(handle)
    }
}

impl From<OwnedHandle> for HANDLE {
    fn from(handle: OwnedHandle) -> Self {
        handle.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct Apartment();

impl Apartment {
    pub fn new(flags: COINIT) -> windows::core::Result<Self> {
        unsafe {
            CoInitializeEx(None, flags)?;
        }

        Ok(Self())
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

struct Variant(VARIANT);

impl Variant {
    pub fn new() -> Self {
        Self(unsafe { VariantInit() })
    }

    pub unsafe fn as_mut_ptr(&mut self) -> *mut VARIANT {
        &mut self.0
    }
}

impl Drop for Variant {
    fn drop(&mut self) {
        unsafe {
            let _ = VariantClear(&mut self.0);
        }
    }
}

impl std::ops::Deref for Variant {
    type Target = VARIANT;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Variant {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

struct VirtualMemoryInProcess {
    process: HANDLE,
    memory: *mut c_void,
}

impl VirtualMemoryInProcess {
    pub fn new(process: HANDLE, memory: *mut c_void) -> windows::core::Result<Self> {
        if memory.is_null() {
            return Err(windows::core::Error::from_win32());
        } else {
            Ok(Self { process, memory })
        }
    }

    pub fn get(&self) -> *mut c_void {
        self.memory
    }
}

impl Drop for VirtualMemoryInProcess {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFreeEx(self.process, self.memory, 0, MEM_RELEASE);
        }
    }
}

fn get_module_path(module: HMODULE) -> windows::core::Result<String> {
    let mut buffer = vec![0u16; MAX_PATH as usize];

    loop {
        let actual_size = unsafe { GetModuleFileNameW(module, buffer.as_mut_slice()) };

        let last_error = unsafe { GetLastError() };
        match last_error {
            ERROR_SUCCESS => {
                buffer.resize(actual_size as usize + 1, 0u16);
                break String::from_utf16(buffer.as_slice()).map_err(|e| e.into());
            }
            ERROR_INSUFFICIENT_BUFFER => buffer.resize(buffer.len() * 2, 0u16),
            _ => {
                break Err(windows::core::Error::from_win32());
            }
        }
    }
}

#[implement(IWbemObjectSink)]
struct EventSink {}

impl EventSink {
    pub fn new() -> Self {
        Self {}
    }

    fn get(object: &IWbemClassObject, name: PCWSTR) -> windows::core::Result<Variant> {
        let mut variant = Variant::new();

        unsafe { object.Get(name, 0, variant.as_mut_ptr(), None, None)? };

        Ok(variant)
    }

    fn bstr_equal(object: &IWbemClassObject, name: PCWSTR, string: PCWSTR) -> bool {
        Self::get(object, name).map_or(false, |variant| unsafe {
            variant.Anonymous.Anonymous.Anonymous.bstrVal.as_wide() == string.as_wide()
        })
    }

    fn handle_event(&self, object: &IWbemClassObject) -> windows::core::Result<()> {
        if Self::bstr_equal(object, w!("__Class"), w!("__InstanceCreationEvent")) {
            let target_instance: IWbemClassObject = unsafe {
                Self::get(object, w!("TargetInstance"))?
                    .Anonymous
                    .Anonymous
                    .Anonymous
                    .punkVal
                    .as_ref()
                    .ok_or(E_FAIL)?
                    .cast()?
            };

            if Self::bstr_equal(&target_instance, w!("Name"), w!("rust-analyzer.exe")) {
                self.inject_dll(target_instance)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn inject_dll(&self, process: IWbemClassObject) -> windows::core::Result<()> {
        unsafe {
            let process_id = Self::get(&process, w!("ProcessId"))?
                .Anonymous
                .Anonymous
                .Anonymous
                .uintVal;

            let handle: OwnedHandle = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                false,
                process_id,
            )?
            .into();

            let load_library = GetProcAddress(GetModuleHandleW(w!("kernel32"))?, s!("LoadLibraryW"))
                .ok_or(E_FAIL)?
                as *const extern "system" fn(PCWSTR) -> HMODULE;

            let module_path_string = get_module_path(Default::default())?;

            let module_path: HSTRING = Path::new(&module_path_string)
                .parent()
                .ok_or(E_FAIL)?
                .join("rust_analyzer_cleanup.dll")
                .to_str()
                .ok_or(E_FAIL)?
                .into();

            let memory_size = (module_path.len() + 1) * std::mem::size_of::<u16>();
            let memory = VirtualMemoryInProcess::new(
                handle.0,
                VirtualAllocEx(
                    handle.0,
                    None,
                    memory_size,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                ),
            )?;

            if !WriteProcessMemory(
                handle.0,
                memory.get(),
                module_path.as_ptr() as _,
                memory_size,
                None,
            )
            .as_bool()
            {
                return Err(windows::core::Error::from_win32());
            }

            let thread = CreateRemoteThread(
                handle.0,
                None,
                0,
                Some(std::mem::transmute(load_library)),
                Some(memory.get()),
                0,
                None,
            )?;

            WaitForSingleObject(thread, INFINITE);
        }

        Ok(())
    }
}

impl IWbemObjectSink_Impl for EventSink {
    #[allow(non_snake_case)]
    fn Indicate(
        &self,
        object_count: i32,
        object_array: *const Option<IWbemClassObject>,
    ) -> windows::core::Result<()> {
        let objects = unsafe { std::slice::from_raw_parts(object_array, object_count as usize) };

        for object in objects {
            match object {
                Some(object) => self.handle_event(object)?,
                None => continue,
            };
        }

        Ok(())
    }

    #[allow(non_snake_case)]
    fn SetStatus(
        &self,
        _flags: i32,
        _hresult: HRESULT,
        _strparam: &BSTR,
        _pobjparam: Option<&IWbemClassObject>,
    ) -> ::windows::core::Result<()> {
        Ok(())
    }
}

static mut EVENT: AtomicIsize = AtomicIsize::new(0);

unsafe extern "system" fn console_ctrl_handler(_: u32) -> BOOL {
    SetEvent(HANDLE(EVENT.load(std::sync::atomic::Ordering::Acquire)));
    BOOL(1)
}

pub fn main() -> windows::core::Result<()> {
    //let mutex = unsafe { OwnedHandle::from_raw_handle() };

    let _startup_mutex =
        unsafe { OwnedHandle::from(CreateMutexW(None, true, w!("rust-analyzer-cleanup"))?) };

    let _apartment = Apartment::new(COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE)?;

    unsafe {
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )?;

        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        let services =
            locator.ConnectServer(&BSTR::from("ROOT\\CIMV2"), None, None, None, 0, None, None)?;

        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )?;

        let unsecured_apartment: IUnsecuredApartment =
            CoCreateInstance(&UnsecuredApartment, None, CLSCTX_LOCAL_SERVER)?;

        let event_sink: IWbemObjectSink = EventSink::new().into();
        let stub_sink: IWbemObjectSink =
            unsecured_apartment.CreateObjectStub(&event_sink)?.cast()?;

        services.ExecNotificationQueryAsync(
            &BSTR::from("WQL"),
            &BSTR::from("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
            WBEM_FLAG_SEND_STATUS.0,
            None,
            &stub_sink,
        )?;

        let event: OwnedHandle = CreateEventW(None, false, false, None)?.into();

        EVENT.store(event.0 .0, std::sync::atomic::Ordering::Release);

        SetConsoleCtrlHandler(Some(console_ctrl_handler), true);

        WaitForSingleObject(event.0, INFINITE);

        services.CancelAsyncCall(&stub_sink)?;
    }

    Ok(())
}
