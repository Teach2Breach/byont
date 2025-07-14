# Byont - Clean DLL Loader

A Rust-based library for dynamically loading clean copies of Windows DLLs from Microsoft's symbol servers and executing functions from the clean DLLs in memory. This project demonstrates techniques for bypassing DLL hooking and EDR (Endpoint Detection and Response) systems by loading pristine copies of system DLLs.

## Overview

Byont downloads clean copies of Windows DLLs (such as `ntdll.dll`, `kernel32.dll`, etc.) directly from Microsoft's symbol servers, loads them into executable memory, applies proper relocations, and allows execution of functions from the clean DLLs. This is useful for:

- **Security Research**: Testing EDR evasion techniques
- **Malware Analysis**: Understanding DLL hooking detection methods
- **System Administration**: Bypassing problematic DLL hooks
- **Educational Purposes**: Learning about PE file loading and Windows internals

## Features

- **Clean DLL Download**: Automatically downloads pristine Windows DLLs from Microsoft symbol servers
- **Multi-DLL Support**: Supports loading any DLL available on Microsoft's symbol servers (ntdll, kernel32, user32, etc.)
- **Memory Loading**: Loads DLLs into executable memory with proper PE parsing
- **Relocation Support**: Applies base relocations for proper function execution
- **Security Directory**: Preserves and verifies digital signatures
- **Function Resolution**: Locates and executes functions from the clean DLLs
- **Manual PE Loading**: Bypasses LoadLibrary for complete control over the loading process
- **Clean Library API**: Silent operation suitable for integration into other tools
- **Demo Application**: Comprehensive example showing the library's capabilities

## Current Limitations

**Function Execution Support:**
- `ntdll.dll` - Native API functions (✅ **Function execution supported**)
- `kernel32.dll` - Kernel32 API functions (⚠️ **Load only - function execution not yet supported**)
- `user32.dll` - User interface functions (⚠️ **Load only - function execution not yet supported**)
- `advapi32.dll` - Advanced Windows 32 API functions (⚠️ **Load only - function execution not yet supported**)
- And many more system DLLs (⚠️ **Load only - function execution not yet supported**)

**Note**: While Byont can successfully download, load, and resolve exports from any Windows system DLL, only ntdll.dll functions can be safely called from the manually loaded image. Other DLLs require Windows loader initialization and import resolution, which are not currently implemented.

## How It Works

1. **Symbol Information Extraction**: Extracts timestamp and size from the currently loaded target DLL
2. **Clean DLL Download**: Downloads a pristine copy from Microsoft's symbol servers using the extracted information
3. **Memory Allocation**: Allocates executable memory based on the PE header's `SizeOfImage`
4. **PE Loading**: Copies the DLL into memory and applies base relocations
5. **Security Verification**: Copies and verifies the security directory (digital signatures)
6. **Function Execution**: Locates and executes functions from the clean DLL

**Supported DLLs**: The tool can download and load any DLL available on Microsoft's symbol servers, including:
- `ntdll.dll` - Native API functions (✅ **Function execution supported**)
- `kernel32.dll` - Kernel32 API functions (⚠️ **Load only - function execution not yet supported**)
- `user32.dll` - User interface functions (⚠️ **Load only - function execution not yet supported**)
- `advapi32.dll` - Advanced Windows 32 API functions (⚠️ **Load only - function execution not yet supported**)
- And many more system DLLs (⚠️ **Load only - function execution not yet supported**)

**Note**: While Byont can successfully download, load, and resolve exports from any Windows system DLL, only ntdll.dll functions can be safely called from the manually loaded image. Other DLLs require Windows loader initialization and import resolution, which are not currently implemented.

## Prerequisites

- **Windows 10/11** (x64)
- **Rust** (latest stable version)
- **Internet connection** (for downloading from Microsoft symbol servers)

## Building

### Standard Build
```bash
cargo build --release
```

### Static Build (Recommended for distribution)
```bash
cargo rustc --release --bin byont -- -C target-feature=+crt-static
```

## Usage

### Demo Application
```bash
./target/release/byont.exe
```

### Library Usage
```rust
use byont::*;

// Download and load a clean DLL
let clean_ntdll = get_clean_dll("ntdll")?;

// Allocate executable memory
let (memory, size) = allocate_executable_memory(&clean_ntdll)?;

// Apply relocations
let (base, _, _) = apply_relocations_raw(memory, size)?;

// Find and call a function
if let Some((func_addr, is_forwarder)) = get_function_from_raw_dll(memory, std::ptr::null(), "NtDelayExecution") {
    if !is_forwarder {
        // Call the function
        let func: unsafe extern "system" fn(u8, *mut LARGE_INTEGER) -> i32 = 
            std::mem::transmute(func_addr);
        // ... use the function
    }
}

// Clean up
free_executable_memory(memory);
```

### Example Output
```
=== Byont - Clean DLL Loader Demo ===
Starting...

=== Loading NTDLL ===
✅ Successfully downloaded clean NTDLL: 2521984 bytes

=== Loading KERNEL32 ===
✅ Successfully downloaded clean KERNEL32: 836120 bytes

=== Processing NTDLL ===
✅ Allocated memory for NTDLL at 0x129e53c0000 with size 0x268000
✅ Security directory copied for NTDLL
✅ Security directory verified for NTDLL
✅ Relocations applied for NTDLL

=== Processing KERNEL32 ===
✅ Allocated memory for KERNEL32 at 0x129e5630000 with size 0xcc218
✅ Security directory handled for KERNEL32
✅ Security directory verified for KERNEL32
✅ Relocations applied for KERNEL32

=== Testing NTDLL Functions ===
🔍 Looking for RtlGetNtVersionNumbers in NTDLL...
✅ Found RtlGetNtVersionNumbers at offset: 0x115d60
🔍 Looking for NtDelayExecution in NTDLL...
✅ Found NtDelayExecution at offset: 0x162440

=== Kernel32 functions not yet supported ===

=== Cleanup ===
🗑️  Freeing allocated memory...

✅ Execution completed successfully!
=== Demo Complete ===
```

## API Functions

### Core Functions

- `get_clean_dll(dll_name)` - Downloads clean DLL from Microsoft symbol servers (supports any DLL like "ntdll", "kernel32", etc.)
- `get_clean_ntdll()` - Downloads clean NTDLL (backward compatibility wrapper)
- `allocate_executable_memory()` - Allocates executable memory for DLL loading
- `apply_relocations_raw()` - Applies base relocations to the loaded DLL
- `get_function_from_raw_dll()` - Locates functions in the loaded DLL (returns `Option<(address, is_forwarder)>`)
- `copy_security_directory_raw()` - Preserves digital signatures
- `verify_security_directory_raw()` - Verifies digital signatures
- `free_executable_memory()` - Frees allocated memory

### Library Design

The library is designed to be silent and suitable for integration into other tools:
- **No print statements** in library functions
- **Clean error handling** with `Option<T>` return types
- **Comprehensive demo** in `main.rs` showing all capabilities
- **Forwarder detection** to avoid calling invalid functions

## Security Considerations

⚠️ **WARNING**: This tool is designed for security research and educational purposes only.

### Legal and Ethical Use
- **Authorized Testing Only**: Only use on systems you own or have explicit permission to test
- **Research Purposes**: Intended for security research, malware analysis, and educational use
- **Compliance**: Ensure compliance with local laws and organizational policies

### Technical Risks
- **Memory Manipulation**: Involves low-level memory operations that could crash the system
- **DLL Injection**: May trigger security software alerts
- **Network Access**: Downloads files from external servers
- **Privilege Escalation**: Could potentially be used for privilege escalation

### Mitigation
- **Sandboxed Environment**: Test in isolated virtual machines
- **Security Software**: May need to temporarily disable security software for testing
- **Backup**: Ensure important data is backed up before testing

## Dependencies

- **winapi**: Windows API bindings
- **ntapi**: Native Windows API bindings
- **reqwest**: HTTP client for downloading DLLs
- **noldr**: PE loading and parsing utilities

## Troubleshooting

### Common Issues

1. **Download Failures**
   - Check internet connectivity
   - Verify Microsoft symbol server accessibility
   - Ensure firewall allows HTTPS connections

2. **Memory Allocation Failures**
   - Run with administrator privileges
   - Check available system memory
   - Disable security software temporarily

3. **Function Resolution Failures**
   - Verify DLL integrity after download
   - Check relocation application success
   - Ensure proper memory protection settings

### Debug Information

The demo application provides comprehensive output. For library usage, check return values:
```rust
match get_clean_dll("ntdll") {
    Some(dll) => println!("Success: {} bytes", dll.len()),
    None => println!("Failed to download DLL"),
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is" without warranty. The authors are not responsible for any damage or legal issues arising from its use. Use at your own risk and ensure compliance with applicable laws and regulations.

## Acknowledgments

- Microsoft for providing symbol servers
- The Rust community for excellent tooling
- Security researchers who pioneered these techniques

