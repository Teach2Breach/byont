use byont::*;
use winapi::shared::ntdef::{LARGE_INTEGER, PLARGE_INTEGER};

#[macro_use]
extern crate litcrypt;

use_litcrypt!();

fn main() {
    println!("Starting...");
    
    // Get the clean DLL bytes
    let clean_dll = match get_clean_ntdll() {
        Some(dll) => dll,
        None => {
            println!("Failed to get clean NTDLL");
            return;
        }
    };
    
    // Allocate executable memory and copy the DLL into it
    let (memory, size) = match allocate_executable_memory(&clean_dll) {
        Some(result) => result,
        None => {
            println!("Failed to allocate memory for DLL");
            return;
        }
    };
    
    // Copy security directory
    if let None = copy_security_directory_raw(memory, size) {
        println!("Warning: Failed to copy security directory");
    }
    
    // Verify security directory
    if let None = verify_security_directory_raw(memory, size) {
        println!("Warning: Failed to verify security directory");
    }
    
    // Apply relocations
    let (clean_base, _ntdll_base, _delta) = match apply_relocations_raw(memory, size) {
        Some(result) => result,
        None => {
            println!("Failed to apply relocations");
            free_executable_memory(memory);
            return;
        }
    };
    
    // Let's also try RtlGetNtVersionNumbers which might be simpler
    println!("Looking for RtlGetNtVersionNumbers...");
    let version_numbers_address = match get_function_from_raw_dll(memory, std::ptr::null(), "RtlGetNtVersionNumbers") {
        Some(addr) => {
            println!("Found RtlGetNtVersionNumbers at offset: {:#x}", addr - clean_base);
            Some(addr)
        },
        None => {
            println!("Failed to find RtlGetNtVersionNumbers");
            None
        }
    };
    
    // Let's try NtDelayExecution which might have different dependencies
    println!("Looking for NtDelayExecution...");
    let delay_execution_address = match get_function_from_raw_dll(memory, std::ptr::null(), "NtDelayExecution") {
        Some(addr) => {
            println!("Found NtDelayExecution at offset: {:#x}", addr - clean_base);
            Some(addr)
        },
        None => {
            println!("Failed to find NtDelayExecution");
            None
        }
    };
        
        // Try NtDelayExecution if we found it
        if let Some(delay_execution_addr) = delay_execution_address {
            println!("=== NtDelayExecution Test Starting ===");
            //println!("Trying NtDelayExecution with zero delay first...");
            
            type NtDelayExecutionFn = unsafe extern "system" fn(u8, PLARGE_INTEGER) -> i32;
            let nt_delay_execution: NtDelayExecutionFn = unsafe { std::mem::transmute(delay_execution_addr) };
            
            // Now let's try the 3-second delay with the corrected value
            println!("Testing with 3-second delay...");
            let three_seconds_ns = -30_000_000i64; // 3 seconds in nanoseconds, divided by 100
            let mut three_sec_delay: LARGE_INTEGER = unsafe { std::mem::zeroed() };
            
            unsafe {
                let ptr = &mut three_sec_delay as *mut LARGE_INTEGER as *mut i64;
                *ptr = three_seconds_ns;
            }
            
            // Debug: Let's see what value we actually set

            //let ptr = &three_sec_delay as *const LARGE_INTEGER as *const i64;
            //println!("Set LARGE_INTEGER value for 3s: {}", *ptr);
            
            
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
            //println!("Note: NtDelayExecution is working correctly with proper time units.");
            //println!("3-second delay completed successfully from manually loaded clean NTDLL.");
        } else {
            println!("NtDelayExecution function not found, skipping test");
        }
        
        // Try RtlGetNtVersionNumbers if we found it
        if let Some(version_numbers_addr) = version_numbers_address {
            println!("=== RtlGetNtVersionNumbers Test Starting ===");
            println!("Trying RtlGetNtVersionNumbers...");
            
            type RtlGetNtVersionNumbersFn = unsafe extern "system" fn(*mut u32, *mut u32, *mut u32);
            let rtl_get_nt_version_numbers: RtlGetNtVersionNumbersFn = unsafe { std::mem::transmute(version_numbers_addr) };
            
            let mut major = 0u32;
            let mut minor = 0u32;
            let mut build = 0u32;
            
            //println!("Before RtlGetNtVersionNumbers: major={}, minor={}, build={}", major, minor, build);
            unsafe { rtl_get_nt_version_numbers(&mut major, &mut minor, &mut build) };
            //println!("After RtlGetNtVersionNumbers: major={}, minor={}, build={}", major, minor, build);
            
            // Convert build number to proper format (remove high bits)
            let actual_build = build & 0xFFFF;
            println!("Windows version from clean DLL: {}.{}.{}", major, minor, actual_build);
            println!("=== RtlGetNtVersionNumbers Test Complete ===");
        }
    
    
    // Free the allocated memory
    println!("Freeing allocated memory...");
    free_executable_memory(memory);
    
    println!("Execution completed successfully");
}
