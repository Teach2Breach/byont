use byont::*;
use winapi::shared::ntdef::{LARGE_INTEGER, PLARGE_INTEGER};

fn main() {
    println!("Starting...");
    
    // Example 1: Get the clean NTDLL bytes (using the new generic function)
    println!("=== Loading NTDLL ===");
    let clean_ntdll = match get_clean_dll("ntdll") {
        Some(dll) => dll,
        None => {
            println!("Failed to get clean NTDLL");
            return;
        }
    };
    
    // Example 2: Get the clean KERNEL32 bytes
    println!("=== Loading KERNEL32 ===");
    let clean_kernel32 = match get_clean_dll("kernel32") {
        Some(dll) => dll,
        None => {
            println!("Failed to get clean KERNEL32");
            return;
        }
    };
    
    // Process NTDLL
    println!("=== Processing NTDLL ===");
    let (ntdll_memory, ntdll_size) = match allocate_executable_memory(&clean_ntdll) {
        Some(result) => result,
        None => {
            println!("Failed to allocate memory for NTDLL");
            return;
        }
    };
    
    // Copy security directory for NTDLL
    if let None = copy_security_directory_raw(ntdll_memory, ntdll_size, "ntdll") {
        println!("Warning: Failed to copy security directory for NTDLL");
    }
    
    // Verify security directory for NTDLL
    if let None = verify_security_directory_raw(ntdll_memory, ntdll_size) {
        println!("Warning: Failed to verify security directory for NTDLL");
    }
    
    // Apply relocations for NTDLL
    let (ntdll_clean_base, _ntdll_base, _ntdll_delta) = match apply_relocations_raw(ntdll_memory, ntdll_size) {
        Some(result) => result,
        None => {
            println!("Failed to apply relocations for NTDLL");
            free_executable_memory(ntdll_memory);
            return;
        }
    };
    
    // Process KERNEL32
    println!("=== Processing KERNEL32 ===");
    let (kernel32_memory, kernel32_size) = match allocate_executable_memory(&clean_kernel32) {
        Some(result) => result,
        None => {
            println!("Failed to allocate memory for KERNEL32");
            free_executable_memory(ntdll_memory);
            return;
        }
    };
    
    // Copy security directory for KERNEL32
    if let None = copy_security_directory_raw(kernel32_memory, kernel32_size, "kernel32") {
        println!("Warning: Failed to copy security directory for KERNEL32");
    }
    
    // Verify security directory for KERNEL32
    if let None = verify_security_directory_raw(kernel32_memory, kernel32_size) {
        println!("Warning: Failed to verify security directory for KERNEL32");
    }
    
    // Apply relocations for KERNEL32
    let (_kernel32_clean_base, _kernel32_base, _kernel32_delta) = match apply_relocations_raw(kernel32_memory, kernel32_size) {
        Some(result) => result,
        None => {
            println!("Failed to apply relocations for KERNEL32");
            free_executable_memory(ntdll_memory);
            free_executable_memory(kernel32_memory);
            return;
        }
    };

    //note that kernel32 functions are not supported by this library at this time, only ntdll functions are supported
    
    println!("Kernel32 functions are not supported by this library at this time, only ntdll functions are supported");
    
    // Test NTDLL functions
    println!("=== Testing NTDLL Functions ===");
    
    // Test RtlGetNtVersionNumbers from NTDLL
    println!("Looking for RtlGetNtVersionNumbers in NTDLL...");
    let version_numbers_result = get_function_from_raw_dll(ntdll_memory, std::ptr::null(), "RtlGetNtVersionNumbers");
    let version_numbers_address = match version_numbers_result {
        Some((addr, _)) => {
            println!("Found RtlGetNtVersionNumbers at offset: {:#x}", addr - ntdll_clean_base);
            Some(addr)
        },
        None => {
            println!("Failed to find RtlGetNtVersionNumbers in NTDLL");
            None
        }
    };
    
    // Test NtDelayExecution from NTDLL
    println!("Looking for NtDelayExecution in NTDLL...");
    let delay_execution_result = get_function_from_raw_dll(ntdll_memory, std::ptr::null(), "NtDelayExecution");
    let delay_execution_address = match delay_execution_result {
        Some((addr, _)) => {
            println!("Found NtDelayExecution at offset: {:#x}", addr - ntdll_clean_base);
            Some(addr)
        },
        None => {
            println!("Failed to find NtDelayExecution in NTDLL");
            None
        }
    };
    
    
    // Execute NtDelayExecution test if found
    if let Some(delay_execution_addr) = delay_execution_address {
        println!("=== NtDelayExecution Test Starting ===");
        
        type NtDelayExecutionFn = unsafe extern "system" fn(u8, PLARGE_INTEGER) -> i32;
        let nt_delay_execution: NtDelayExecutionFn = unsafe { std::mem::transmute(delay_execution_addr) };
        
        println!("Testing with 3-second delay...");
        let three_seconds_ns = -30_000_000i64; // 3 seconds in nanoseconds, divided by 100
        let mut three_sec_delay: LARGE_INTEGER = unsafe { std::mem::zeroed() };
        
        unsafe {
            let ptr = &mut three_sec_delay as *mut LARGE_INTEGER as *mut i64;
            *ptr = three_seconds_ns;
        }
        
        let start_time_three = std::time::Instant::now();
        let status_three = unsafe { nt_delay_execution(0, &mut three_sec_delay) };
        let elapsed_three = start_time_three.elapsed();
        
        println!("NtDelayExecution (3-second delay) returned: {}", status_three);
        println!("Actual elapsed time: {:?}", elapsed_three);
        
        if status_three == 0 {
            println!("NtDelayExecution (3-second delay) succeeded!");
        } else {
            println!("NtDelayExecution (3-second delay) failed with status: {:#x}", status_three);
        }
        
        println!("=== NtDelayExecution Test Complete ===");
    } else {
        println!("NtDelayExecution function not found, skipping test");
    }
    
    // Execute RtlGetNtVersionNumbers test if found
    if let Some(version_numbers_addr) = version_numbers_address {
        println!("=== RtlGetNtVersionNumbers Test Starting ===");
        println!("Trying RtlGetNtVersionNumbers...");
        
        type RtlGetNtVersionNumbersFn = unsafe extern "system" fn(*mut u32, *mut u32, *mut u32);
        let rtl_get_nt_version_numbers: RtlGetNtVersionNumbersFn = unsafe { std::mem::transmute(version_numbers_addr) };
        
        let mut major = 0u32;
        let mut minor = 0u32;
        let mut build = 0u32;
        
        unsafe { rtl_get_nt_version_numbers(&mut major, &mut minor, &mut build) };
        
        // Convert build number to proper format (remove high bits)
        let actual_build = build & 0xFFFF;
        println!("Windows version from clean NTDLL: {}.{}.{}", major, minor, actual_build);
        println!("=== RtlGetNtVersionNumbers Test Complete ===");
    }
    
    // Free the allocated memory
    println!("Freeing allocated memory...");
    free_executable_memory(ntdll_memory);
    free_executable_memory(kernel32_memory);
    
    println!("Execution completed successfully");
}
