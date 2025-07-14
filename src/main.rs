use byont::*;
use winapi::shared::ntdef::{LARGE_INTEGER, PLARGE_INTEGER};

fn main() {
    println!("=== Byont - Clean DLL Loader Demo ===");
    println!("Starting...");
    
    // Example 1: Get the clean NTDLL bytes (using the new generic function)
    println!("\n=== Loading NTDLL ===");
    let clean_ntdll = match get_clean_dll("ntdll") {
        Some(dll) => {
            println!("✅ Successfully downloaded clean NTDLL: {} bytes", dll.len());
            dll
        },
        None => {
            println!("❌ Failed to get clean NTDLL");
            return;
        }
    };
    
    // Example 2: Get the clean KERNEL32 bytes
    println!("\n=== Loading KERNEL32 ===");
    let clean_kernel32 = match get_clean_dll("kernel32") {
        Some(dll) => {
            println!("✅ Successfully downloaded clean KERNEL32: {} bytes", dll.len());
            dll
        },
        None => {
            println!("❌ Failed to get clean KERNEL32");
            return;
        }
    };
    
    // Process NTDLL
    println!("\n=== Processing NTDLL ===");
    let (ntdll_memory, ntdll_size) = match allocate_executable_memory(&clean_ntdll) {
        Some(result) => {
            println!("✅ Allocated memory for NTDLL at {:p} with size {:#x}", result.0, result.1);
            result
        },
        None => {
            println!("❌ Failed to allocate memory for NTDLL");
            return;
        }
    };
    
    // Copy security directory for NTDLL
    match copy_security_directory_raw(ntdll_memory, ntdll_size, "ntdll") {
        Some(_) => println!("✅ Security directory copied for NTDLL"),
        None => println!("⚠️  Warning: Failed to copy security directory for NTDLL"),
    }
    
    // Verify security directory for NTDLL
    match verify_security_directory_raw(ntdll_memory, ntdll_size) {
        Some(_) => println!("✅ Security directory verified for NTDLL"),
        None => println!("⚠️  Warning: Failed to verify security directory for NTDLL"),
    }
    
    // Apply relocations for NTDLL
    let (ntdll_clean_base, _ntdll_base, _ntdll_delta) = match apply_relocations_raw(ntdll_memory, ntdll_size) {
        Some(result) => {
            println!("✅ Relocations applied for NTDLL");
            result
        },
        None => {
            println!("❌ Failed to apply relocations for NTDLL");
            free_executable_memory(ntdll_memory);
            return;
        }
    };
    
    // Process KERNEL32
    println!("\n=== Processing KERNEL32 ===");
    let (kernel32_memory, kernel32_size) = match allocate_executable_memory(&clean_kernel32) {
        Some(result) => {
            println!("✅ Allocated memory for KERNEL32 at {:p} with size {:#x}", result.0, result.1);
            result
        },
        None => {
            println!("❌ Failed to allocate memory for KERNEL32");
            free_executable_memory(ntdll_memory);
            return;
        }
    };
    
    // Copy security directory for KERNEL32
    match copy_security_directory_raw(kernel32_memory, kernel32_size, "kernel32") {
        Some(_) => println!("✅ Security directory handled for KERNEL32"),
        None => println!("⚠️  Warning: Failed to handle security directory for KERNEL32"),
    }
    
    // Verify security directory for KERNEL32
    match verify_security_directory_raw(kernel32_memory, kernel32_size) {
        Some(_) => println!("✅ Security directory verified for KERNEL32"),
        None => println!("⚠️  Warning: Failed to verify security directory for KERNEL32"),
    }
    
    // Apply relocations for KERNEL32
    let (kernel32_clean_base, _kernel32_base, _kernel32_delta) = match apply_relocations_raw(kernel32_memory, kernel32_size) {
        Some(result) => {
            println!("✅ Relocations applied for KERNEL32");
            result
        },
        None => {
            println!("❌ Failed to apply relocations for KERNEL32");
            free_executable_memory(ntdll_memory);
            free_executable_memory(kernel32_memory);
            return;
        }
    };
    
    // Test NTDLL functions
    println!("\n=== Testing NTDLL Functions ===");
    
    // Test RtlGetNtVersionNumbers from NTDLL
    println!("🔍 Looking for RtlGetNtVersionNumbers in NTDLL...");
    let version_numbers_result = get_function_from_raw_dll(ntdll_memory, std::ptr::null(), "RtlGetNtVersionNumbers");
    let version_numbers_address = match version_numbers_result {
        Some((addr, is_forwarder)) => {
            if is_forwarder {
                println!("⚠️  RtlGetNtVersionNumbers is a forwarded export");
                None
            } else {
                println!("✅ Found RtlGetNtVersionNumbers at offset: {:#x}", addr - ntdll_clean_base);
                Some(addr)
            }
        },
        None => {
            println!("❌ Failed to find RtlGetNtVersionNumbers in NTDLL");
            None
        }
    };
    
    // Test NtDelayExecution from NTDLL
    println!("🔍 Looking for NtDelayExecution in NTDLL...");
    let delay_execution_result = get_function_from_raw_dll(ntdll_memory, std::ptr::null(), "NtDelayExecution");
    let delay_execution_address = match delay_execution_result {
        Some((addr, is_forwarder)) => {
            if is_forwarder {
                println!("⚠️  NtDelayExecution is a forwarded export");
                None
            } else {
                println!("✅ Found NtDelayExecution at offset: {:#x}", addr - ntdll_clean_base);
                Some(addr)
            }
        },
        None => {
            println!("❌ Failed to find NtDelayExecution in NTDLL");
            None
        }
    };
    
    // Test KERNEL32 functions
    println!("\n=== Kernel32 functions not yet supported ===");
    
    // Free the allocated memory
    println!("\n=== Cleanup ===");
    println!("🗑️  Freeing allocated memory...");
    free_executable_memory(ntdll_memory);
    free_executable_memory(kernel32_memory);
    
    println!("\n✅ Execution completed successfully!");
    println!("=== Demo Complete ===");
}
