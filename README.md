# Byont - Bring Your Own NTDLL

A Rust-based tool for demonstrating how to dynamically loading clean copies of `ntdll.dll` from Microsoft's symbol servers and executing functions from the clean DLL in memory. This project demonstrates techniques for bypassing DLL hooking and EDR (Endpoint Detection and Response) systems by loading pristine copies of system DLLs.

note - some functions in the target dll may have additional dependencies and fail. this is an experimental tool demo

## Overview

Byont downloads clean copies of `ntdll.dll` directly from Microsoft's symbol servers, loads them into executable memory, applies proper relocations, and allows execution of functions from the clean DLL. Could also be used for kernel32 and any other dlls available on the Microsoft symbols server. This is useful for:

- **Security Research**: Testing EDR evasion techniques
- **Malware Analysis**: Understanding DLL hooking detection methods
- **Educational Purposes**: Learning about PE file loading and Windows internals

## Features

- **Clean DLL Download**: Automatically downloads pristine `ntdll.dll` from Microsoft symbol servers
- **Memory Loading**: Loads DLL into executable memory with proper PE parsing
- **Relocation Support**: Applies base relocations for proper function execution
- **Security Directory**: Preserves and verifies digital signatures
- **Function Resolution**: Locates and executes functions from the clean DLL

## How It Works

1. **Symbol Information Extraction**: Extracts timestamp and size from the currently loaded `ntdll.dll`
2. **Clean DLL Download**: Downloads a pristine copy from Microsoft's symbol servers using the extracted information
3. **Memory Allocation**: Allocates executable memory based on the PE header's `SizeOfImage`
4. **PE Loading**: Copies the DLL into memory and applies base relocations
5. **Security Verification**: Copies and verifies the security directory (digital signatures)
6. **Function Execution**: Locates and executes functions from the clean DLL

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

### Basic Execution
```bash
./target/release/byont.exe
```

### Example Output
(There's a lot of print statements, for educational purposes. Clean them up or wait for my opsec branch to be released with that and other enhancements.)
```
Starting...
Attempting download from: https://msdl.microsoft.com/download/symbols/ntdll.dll/9194561F265000/ntdll.dll
Successfully downloaded clean NTDLL: 2513744 bytes
File size: 0x265b50, Virtual size: 0x265000, Allocation size: 0x265b50
Allocated memory at 0x13f2d1f0000 with size 2513744
Copying security directory from 0x7ffe833de000 with size 0x7b50
Security directory copied successfully
Certificate found:
  Length: 0x630069
  Revision: 0x79
  Type: 0x20
Clean DLL at: 0x13f2d1f0000, Expected base: 0x180000000, Delta: 0x13dad1f0000
Processing relocations at RVA 2506752, Size: 1776
Memory protection changed to PAGE_READWRITE for relocations
Relocation directory: VA=0x264000, Size=0x6f0
Memory size: 0x265b50, Initial offset: 0x264000
End offset: 0x2646f0
Relocations completed successfully
Setting memory protection for 15 sections
Memory protection changed to PAGE_EXECUTE_READ for entire DLL
Looking for RtlGetNtVersionNumbers...
Clean DLL base: 0x13f2d1f0000
DOS header e_lfanew: 0xe0
Export directory RVA: 0x1b7fc0
Export directory at: 0x13f2d3a7fc0
Number of names: 2514
Names array at: 0x13f2d3aa734
Functions array at: 0x13f2d3a7fe8
Ordinals array at: 0x13f2d3ace7c
Searching for function: RtlGetNtVersionNumbers
Found function 'RtlGetNtVersionNumbers' at index 1109
Ordinal: 1110
Function RVA: 0x115e10
Function address in clean copy: 0x13f2d305e10
First 16 bytes of function: [65, 4C, 8B, 0C, 25, 60, 00, 00, 00, 48, 85, C9, 74, 09, 41, 8B]
Memory protection at function address: 0x20
Found RtlGetNtVersionNumbers at offset: 0x115e10
Looking for NtDelayExecution...
Clean DLL base: 0x13f2d1f0000
DOS header e_lfanew: 0xe0
Export directory RVA: 0x1b7fc0
Export directory at: 0x13f2d3a7fc0
Number of names: 2514
Names array at: 0x13f2d3aa734
Functions array at: 0x13f2d3a7fe8
Ordinals array at: 0x13f2d3ace7c
Searching for function: NtDelayExecution
Found function 'NtDelayExecution' at index 330
Ordinal: 331
Function RVA: 0x162170
Function address in clean copy: 0x13f2d352170
First 16 bytes of function: [4C, 8B, D1, B8, 34, 00, 00, 00, F6, 04, 25, 08, 03, FE, 7F, 01]
Memory protection at function address: 0x20
Found NtDelayExecution at offset: 0x162170
=== NtDelayExecution Test Starting ===
Testing with 3-second delay...
NtDelayExecution (3-second delay) returned: 0
Actual elapsed time: 3.0001196s
NtDelayExecution (3-second delay) succeeded!
=== NtDelayExecution Test Complete ===
=== RtlGetNtVersionNumbers Test Starting ===
Trying RtlGetNtVersionNumbers...
Windows version from clean DLL: 10.0.26100
=== RtlGetNtVersionNumbers Test Complete ===
Freeing allocated memory...
Execution completed successfully
```

## API Functions

### Core Functions

- `get_clean_ntdll()` - Downloads clean NTDLL from Microsoft symbol servers
- `allocate_executable_memory()` - Allocates executable memory for DLL loading
- `apply_relocations_raw()` - Applies base relocations to the loaded DLL
- `get_function_from_raw_dll()` - Locates functions in the loaded DLL
- `copy_security_directory_raw()` - Preserves digital signatures
- `verify_security_directory_raw()` - Verifies digital signatures

### Test Functions

The demo includes tests for:
- `NtDelayExecution` - Tests timing functions
- `RtlGetNtVersionNumbers` - Tests version information retrieval

