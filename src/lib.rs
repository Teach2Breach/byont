#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

#[macro_use]
extern crate litcrypt;

use_litcrypt!();

use winapi::shared::ntdef::{UNICODE_STRING, PVOID, ULONG};
use winapi::um::winnt::{
    IMAGE_DEBUG_DIRECTORY,
    IMAGE_DEBUG_TYPE_CODEVIEW,
    IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DOS_HEADER,
    IMAGE_NT_HEADERS,
    IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_BASE_RELOCATION,
    IMAGE_REL_BASED_DIR64,
    IMAGE_REL_BASED_HIGHLOW,
    IMAGE_DIRECTORY_ENTRY_SECURITY,
    PAGE_EXECUTE_READ,
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE_READWRITE,
    MEM_RELEASE,
};

//maybe swap this out with a better method in the future
use ntapi::ntldr::LdrGetDllHandle;

use noldr::{get_dll_address, get_teb, IMAGE_EXPORT_DIRECTORY};

use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};

#[derive(Debug)]
pub struct PeInfo {
    pub timestamp: u32,
    pub size: u32,
    pub pdb_name: String,
    pub guid: String,
    pub age: u32,
}

#[repr(C)]
struct RSDS_DEBUG_FORMAT {
    Rsds: u32,
    Guid: GUID,
    Age: u32,
    PdbFileName: [u8; 260],  // Adjust size as needed
}

#[repr(C)]
struct GUID {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [u8; 8],
}

#[repr(C)]
pub struct WIN_CERTIFICATE {
    pub length: u32,
    pub revision: u16,
    pub certificate_type: u16,
}

fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn get_ntdll_symbol_info() -> Option<PeInfo> {
    unsafe {
        let dll_name = wide_string(&lc!("ntdll.dll"));
        let name_len = (dll_name.len() - 1) * 2;  // exclude null terminator, but multiply by 2 for wide chars
        let mut unicode_name = UNICODE_STRING {
            Length: name_len as u16,
            MaximumLength: (dll_name.len() * 2) as u16,  // include space for null terminator
            Buffer: dll_name.as_ptr() as *mut _,
        };

        //println!("String length: {}, Maximum length: {}", name_len, dll_name.len() * 2);
        //println!("Buffer contents: {:?}", dll_name);

        let mut ntdll: PVOID = std::ptr::null_mut();
        let status = LdrGetDllHandle(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut unicode_name,
            &mut ntdll
        );
        
        if status != 0 {
            println!("LdrGetDllHandle failed with status: {:#x}", status);
            return None;
        }

        if ntdll.is_null() {
            println!("LdrGetDllHandle returned null handle");
            return None;
        }
        
        let dos_header = ntdll as *const IMAGE_DOS_HEADER;
        let nt_headers = (ntdll as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        
        // Get timestamp and size from PE header
        let timestamp = (*nt_headers).FileHeader.TimeDateStamp;
        let size = (*nt_headers).OptionalHeader.SizeOfImage;

        // Find debug directory
        let debug_dir = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG as usize];
        let debug_rva = debug_dir.VirtualAddress;
        
        if debug_rva != 0 {
            let debug_entry = (ntdll as usize + debug_rva as usize) as *const IMAGE_DEBUG_DIRECTORY;
            if (*debug_entry).Type == IMAGE_DEBUG_TYPE_CODEVIEW {
                let pdb_info = (ntdll as usize + (*debug_entry).AddressOfRawData as usize) as *const RSDS_DEBUG_FORMAT;
                
                // Extract PDB GUID
                let guid = format!("{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    (*pdb_info).Guid.Data1,
                    (*pdb_info).Guid.Data2,
                    (*pdb_info).Guid.Data3,
                    (*pdb_info).Guid.Data4[0],
                    (*pdb_info).Guid.Data4[1],
                    (*pdb_info).Guid.Data4[2],
                    (*pdb_info).Guid.Data4[3],
                    (*pdb_info).Guid.Data4[4],
                    (*pdb_info).Guid.Data4[5],
                    (*pdb_info).Guid.Data4[6],
                    (*pdb_info).Guid.Data4[7]
                );

                let pdb_name = std::ffi::CStr::from_ptr((*pdb_info).PdbFileName.as_ptr() as *const i8)
                    .to_string_lossy()
                    .into_owned();

                return Some(PeInfo {
                    timestamp,
                    size,
                    pdb_name,
                    guid,
                    age: (*pdb_info).Age,
                });
            }
        }
        None
    }
}

pub fn get_clean_ntdll() -> Option<Vec<u8>> {
    let pe_info = get_ntdll_symbol_info()?;
    
    // Build symbol path for DLL download
    // Format: https://msdl.microsoft.com/download/symbols/ntdll.dll/HASH/ntdll.dll
    let symbol_path = format!(
        "https://msdl.microsoft.com/download/symbols/ntdll.dll/{:X}{:X}/ntdll.dll", 
        pe_info.timestamp,
        pe_info.size
    );

    println!("{}: {}", lc!("Attempting download from"), symbol_path);

    //consider using a better method in the future
    // Create blocking HTTP client with longer timeout
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .ok()?;

    // Try download with retry logic
    let mut retries = 3;
    let mut response = None;
    
    while retries > 0 {
        match client.get(&symbol_path).send() {
            Ok(resp) => {
                if resp.status().is_success() {
                    response = Some(resp);
                    break;
                }
                println!("{}: {} (attempts remaining: {})", 
                    lc!("Download failed with status"),
                    resp.status(),
                    retries - 1
                );
            }
            Err(e) => {
                println!("{}: {} (attempts remaining: {})",
                    lc!("Download error"),
                    e,
                    retries - 1
                );
            }
        }
        retries -= 1;
        if retries > 0 {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    let response = response?;

    // Get the bytes
    let clean_dll = match response.bytes() {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            println!("{}: {}", lc!("Failed to read response bytes"), e);
            return None;
        }
    };

    // Verify the downloaded DLL
    unsafe {
        // Check if it's a valid PE file
        if clean_dll.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
            println!("{}", lc!("Downloaded file too small"));
            return None;
        }

        let dos_header = clean_dll.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D { // "MZ" signature
            println!("{}", lc!("Invalid DOS header signature"));
            return None;
        }

        // Verify PE header
        let nt_headers = (clean_dll.as_ptr() as usize + (*dos_header).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;
        if (*nt_headers).Signature != 0x4550 { // "PE" signature
            println!("{}", lc!("Invalid PE signature"));
            return None;
        }

        // Verify timestamp matches
        if (*nt_headers).FileHeader.TimeDateStamp != pe_info.timestamp {
            println!("{}", lc!("Timestamp mismatch in downloaded file"));
            return None;
        }
    }

    println!("{}: {} bytes", lc!("Successfully downloaded clean NTDLL"), clean_dll.len());
    Some(clean_dll)
}

pub fn apply_relocations(dll_bytes: &mut std::pin::Pin<Vec<u8>>) -> Option<(usize, *const std::ffi::c_void, *const std::ffi::c_void)> {
    let teb = get_teb();
    let ntdll_base = get_dll_address("ntdll.dll".to_string(), teb)?;
    let clean_dll_base = dll_bytes.as_ptr() as usize;
    let delta;
    
    unsafe {
        let dos_header = dll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt_headers = (dll_bytes.as_ptr() as usize + (*dos_header).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;
        
        // Get the expected base from PE header
        let expected_base = (*nt_headers).OptionalHeader.ImageBase as usize;
        delta = clean_dll_base.wrapping_sub(expected_base);

        println!("Clean DLL at: {:p}, Expected base: {:p}, Delta: {:p}", 
            clean_dll_base as *const u8,
            expected_base as *const u8,
            delta as *const u8);

        // Get relocation directory
        let reloc_dir = &(*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
            println!("No relocation directory found");
            return None;
        }

        println!("Processing relocations at RVA {:#?}, Size: {:#?}", 
            reloc_dir.VirtualAddress, reloc_dir.Size);

        let mut offset = reloc_dir.VirtualAddress as usize;
        let end_offset = offset + reloc_dir.Size as usize;

        println!("Relocation directory: VA={:#x}, Size={:#x}", reloc_dir.VirtualAddress, reloc_dir.Size);
        println!("Memory size: {:#x}, Initial offset: {:#x}", dll_bytes.len(), offset);
        println!("End offset: {:#x}", end_offset);

        // Before the loop
        if offset >= dll_bytes.len() {
            println!("CRASH POINT: Initial offset {:#x} >= size {:#x}", offset, dll_bytes.len());
            return None;
        }

        // Process each relocation block
        while offset < end_offset {
            if offset >= dll_bytes.len() {
                println!("Relocation offset {:#x} exceeds buffer size {:#x}", offset, dll_bytes.len());
                break;
            }

            let block = (dll_bytes.as_ptr() as usize + offset) as *const IMAGE_BASE_RELOCATION;
            if block.is_null() {
                println!("Null relocation block pointer at offset {:#x}", offset);
                break;
            }

            if (*block).SizeOfBlock == 0 || offset + (*block).SizeOfBlock as usize > dll_bytes.len() {
                println!("Invalid relocation block at offset {:#x}", offset);
                break;
            }

            let entries_start = offset + std::mem::size_of::<IMAGE_BASE_RELOCATION>();
            let num_entries = ((*block).SizeOfBlock as usize - std::mem::size_of::<IMAGE_BASE_RELOCATION>()) / 2;
            
            // Bounds check
            if entries_start + (num_entries * 2) > dll_bytes.len() {
                break;
            }

            let entries = (dll_bytes.as_ptr() as usize + entries_start) as *const u16;

            for i in 0..num_entries {
                let entry = *entries.add(i);
                let reloc_type = (entry >> 12) as u32;
                let reloc_offset = (entry & 0xFFF) as usize;

                let rva = (*block).VirtualAddress as usize + reloc_offset;
                if rva >= dll_bytes.len() {
                    continue;
                }

                match reloc_type {
                    x if x == IMAGE_REL_BASED_DIR64.into() => {
                        let addr = dll_bytes.as_mut_ptr() as usize + rva;
                        let ptr = addr as *mut u64;
                        *ptr = ptr.read().wrapping_add(delta as u64);
                    },
                    x if x == IMAGE_REL_BASED_HIGHLOW.into() => {
                        let addr = dll_bytes.as_mut_ptr() as usize + rva;
                        let ptr = addr as *mut u32;
                        *ptr = ptr.read().wrapping_add(delta as u32);
                    },
                    _ => {}
                }
            }

            offset += (*block).SizeOfBlock as usize;
        }

        println!("Relocations completed successfully");

        // Set memory to executable after relocations
        use winapi::um::memoryapi::VirtualProtect;
        
        let mut old_protect: ULONG = 0;
        if VirtualProtect(
            dll_bytes.as_mut_ptr() as *mut _,
            dll_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect
        ) == 0 {
            println!("Failed to make memory executable");
            return None;
        }
        println!("Memory protection changed to PAGE_EXECUTE_READ");
    }

    Some((clean_dll_base, ntdll_base, delta as *const std::ffi::c_void))
}

pub fn get_function_from_clean_dll(clean_dll: &std::pin::Pin<Vec<u8>>, _delta: *const std::ffi::c_void, function_name: &str) -> Option<usize> {
    unsafe {
        // Parse PE structure
        let dos_header = clean_dll.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt_headers = (clean_dll.as_ptr() as usize + (*dos_header).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;
        
        println!("Clean DLL base: {:p}", clean_dll.as_ptr());
        println!("DOS header e_lfanew: {:#x}", (*dos_header).e_lfanew);
        
        // Get export directory
        let optional_header = &(*nt_headers).OptionalHeader;
        let export_directory_rva = optional_header.DataDirectory[0].VirtualAddress as usize;
        
        println!("Export directory RVA: {:#x}", export_directory_rva);
        
        // Get export directory
        let export_directory = (clean_dll.as_ptr() as usize + export_directory_rva) 
            as *const IMAGE_EXPORT_DIRECTORY;
        
        println!("Export directory at: {:p}", export_directory);
        println!("Number of names: {}", (*export_directory).NumberOfNames);
        
        // Get arrays of names, functions and ordinals
        let names = (clean_dll.as_ptr() as usize + (*export_directory).AddressOfNames as usize) 
            as *const u32;
        let functions = (clean_dll.as_ptr() as usize + (*export_directory).AddressOfFunctions as usize) 
            as *const u32;
        let ordinals = (clean_dll.as_ptr() as usize + (*export_directory).AddressOfNameOrdinals as usize) 
            as *const u16;

        println!("Names array at: {:p}", names);
        println!("Functions array at: {:p}", functions);
        println!("Ordinals array at: {:p}", ordinals);
        
        println!("Searching for function: {}", function_name);

        // Search for the function
        for i in 0..(*export_directory).NumberOfNames {
            let name_rva = *names.offset(i as isize);
            let name = (clean_dll.as_ptr() as usize + name_rva as usize) as *const i8;
            let name_str = std::ffi::CStr::from_ptr(name).to_str().unwrap_or("");
            
            if name_str == function_name {
                let ordinal = *ordinals.offset(i as isize) as usize;
                let function_rva = *functions.offset(ordinal as isize);
                let function_addr = clean_dll.as_ptr() as usize + function_rva as usize;
                
                println!("Found function '{}' at index {}", function_name, i);
                println!("Ordinal: {}", ordinal);
                println!("Function RVA: {:#x}", function_rva);
                println!("Function address in clean copy: {:p}", function_addr as *const u8);
                
                return Some(function_addr);
            }
        }
        
        println!("Function '{}' not found in export directory", function_name);
    }
    None
}

pub fn copy_security_directory(dll_bytes: &mut std::pin::Pin<Vec<u8>>) -> Option<()> {
    unsafe {
        let teb = get_teb();
        let ntdll_base = get_dll_address("ntdll.dll".to_string(), teb)?;

        // Get security directory from original NTDLL
        let orig_dos = ntdll_base as *const IMAGE_DOS_HEADER;
        let orig_nt = (ntdll_base as usize + (*orig_dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let sec_dir = &(*orig_nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY as usize];

        if sec_dir.VirtualAddress == 0 || sec_dir.Size == 0 {
            println!("No security directory found in original NTDLL");
            return None;
        }

        // Get location in our clean DLL
        let dos_header = dll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt_headers = (dll_bytes.as_ptr() as usize + (*dos_header).e_lfanew as usize) 
            as *mut IMAGE_NT_HEADERS;

        println!("Copying security directory from {:p} with size {:#x}", 
            (ntdll_base as usize + sec_dir.VirtualAddress as usize) as *const u8,
            sec_dir.Size);

        // Copy the security directory
        std::ptr::copy_nonoverlapping(
            (ntdll_base as usize + sec_dir.VirtualAddress as usize) as *const u8,
            (dll_bytes.as_mut_ptr() as usize + sec_dir.VirtualAddress as usize) as *mut u8,
            sec_dir.Size as usize
        );

        // Update our PE headers to point to the security directory
        (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY as usize] = *sec_dir;

        println!("Security directory copied successfully");
        Some(())
    }
}

pub fn verify_security_directory(dll_bytes: &std::pin::Pin<Vec<u8>>) -> Option<()> {
    unsafe {
        // Get security directory from our clean DLL
        let dos_header = dll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt_headers = (dll_bytes.as_ptr() as usize + (*dos_header).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;
        let sec_dir = &(*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY as usize];

        if sec_dir.VirtualAddress == 0 || sec_dir.Size == 0 {
            println!("No security directory found in clean DLL");
            return None;
        }

        // Get pointer to certificate data
        let cert_data = (dll_bytes.as_ptr() as usize + sec_dir.VirtualAddress as usize) 
            as *const WIN_CERTIFICATE;

        println!("Certificate found:");
        println!("  Length: {:#x}", (*cert_data).length);
        println!("  Revision: {:#x}", (*cert_data).revision);
        println!("  Type: {:#x}", (*cert_data).certificate_type);

        Some(())
    }
}

// Function to allocate executable memory and copy the DLL into it
pub fn allocate_executable_memory(dll_bytes: &[u8]) -> Option<(*mut u8, usize)> {
    unsafe {
        // Allocate memory with proper alignment
        let size = dll_bytes.len();
        let memory = VirtualAlloc(
            std::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        ) as *mut u8;
        
        if memory.is_null() {
            println!("Failed to allocate memory for DLL");
            return None;
        }
        
        println!("Allocated memory at {:p} with size {}", memory, size);
        
        // Copy DLL bytes to allocated memory
        std::ptr::copy_nonoverlapping(
            dll_bytes.as_ptr(),
            memory,
            size
        );
        
        Some((memory, size))
    }
}

// Function to free allocated memory
pub fn free_executable_memory(memory: *mut u8) {
    unsafe {
        if !memory.is_null() {
            VirtualFree(memory as *mut _, 0, MEM_RELEASE);
        }
    }
}

pub fn apply_relocations_raw(memory: *mut u8, size: usize) -> Option<(usize, *const std::ffi::c_void, *const std::ffi::c_void)> {
    let teb = get_teb();
    let ntdll_base = get_dll_address("ntdll.dll".to_string(), teb)?;
    let clean_dll_base = memory as usize;
    let delta;
    
    unsafe {
        let dos_header = memory as *const IMAGE_DOS_HEADER;
        let nt_headers = (memory as usize + (*dos_header).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;
        
        // Get the expected base from PE header
        let expected_base = (*nt_headers).OptionalHeader.ImageBase as usize;
        delta = clean_dll_base.wrapping_sub(expected_base);

        println!("Clean DLL at: {:p}, Expected base: {:p}, Delta: {:p}", 
            clean_dll_base as *const u8,
            expected_base as *const u8,
            delta as *const u8);

        // Get relocation directory
        let reloc_dir = &(*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 {
            println!("No relocation directory found");
            return None;
        }

        println!("Processing relocations at RVA {:#?}, Size: {:#?}", 
            reloc_dir.VirtualAddress, reloc_dir.Size);

        // First, make sure the memory is writable before applying relocations
        use winapi::um::memoryapi::VirtualProtect;
        let mut old_protect: ULONG = 0;
        if VirtualProtect(
            memory as *mut _,
            size,
            PAGE_READWRITE,
            &mut old_protect
        ) == 0 {
            println!("Failed to make memory writable for relocations: {}", 
                std::io::Error::last_os_error());
            return None;
        }
        println!("Memory protection changed to PAGE_READWRITE for relocations");

        let mut offset = reloc_dir.VirtualAddress as usize;
        let end_offset = offset + reloc_dir.Size as usize;

        println!("Relocation directory: VA={:#x}, Size={:#x}", reloc_dir.VirtualAddress, reloc_dir.Size);
        println!("Memory size: {:#x}, Initial offset: {:#x}", size, offset);
        println!("End offset: {:#x}", end_offset);

        // Before the loop
        if offset >= size {
            println!("CRASH POINT: Initial offset {:#x} >= size {:#x}", offset, size);
            return None;
        }

        // Process each relocation block
        while offset < end_offset {
            if offset >= size {
                println!("Relocation offset {:#x} exceeds buffer size {:#x}", offset, size);
                break;
            }

            let block = (memory as usize + offset) as *const IMAGE_BASE_RELOCATION;
            if block.is_null() {
                println!("Null relocation block pointer at offset {:#x}", offset);
                break;
            }

            if (*block).SizeOfBlock == 0 || offset + (*block).SizeOfBlock as usize > size {
                println!("Invalid relocation block at offset {:#x}", offset);
                break;
            }

            let entries_start = offset + std::mem::size_of::<IMAGE_BASE_RELOCATION>();
            let num_entries = ((*block).SizeOfBlock as usize - std::mem::size_of::<IMAGE_BASE_RELOCATION>()) / 2;
            
            // Bounds check
            if entries_start + (num_entries * 2) > size {
                println!("Relocation entries exceed buffer size");
                break;
            }

            //println!("Processing relocation block at VA {:#x} with {} entries", 
                //(*block).VirtualAddress, num_entries);

            let entries = (memory as usize + entries_start) as *const u16;

            for i in 0..num_entries {
                let entry = *entries.add(i);
                let reloc_type = (entry >> 12) as u32;
                let reloc_offset = (entry & 0xFFF) as usize;

                let rva = (*block).VirtualAddress as usize + reloc_offset;
                if rva >= size {
                    println!("Relocation RVA {:#x} exceeds buffer size", rva);
                    continue;
                }

                match reloc_type {
                    x if x == IMAGE_REL_BASED_DIR64.into() => {
                        let addr = memory as usize + rva;
                        let ptr = addr as *mut u64;
                        let old_value = *ptr;
                        *ptr = old_value.wrapping_add(delta as u64);
                        //println!("Applied DIR64 relocation at RVA {:#x}: {:#x} -> {:#x}", 
                           // rva, old_value, *ptr);
                    },
                    x if x == IMAGE_REL_BASED_HIGHLOW.into() => {
                        let addr = memory as usize + rva;
                        let ptr = addr as *mut u32;
                        let old_value = *ptr;
                        *ptr = old_value.wrapping_add(delta as u32);
                        //println!("Applied HIGHLOW relocation at RVA {:#x}: {:#x} -> {:#x}", 
                            //rva, old_value, *ptr);
                    },
                    0 => {}, // IMAGE_REL_BASED_ABSOLUTE - skip
                    _ => {
                        println!("Unsupported relocation type: {}", reloc_type);
                    }
                }
            }

            offset += (*block).SizeOfBlock as usize;
        }

        println!("Relocations completed successfully");

        // Set memory to executable after relocations
        use winapi::um::winnt::{IMAGE_SECTION_HEADER, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, 
                               PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READWRITE};
        
        // Get section headers
        let section_count = (*nt_headers).FileHeader.NumberOfSections;
        let first_section = (memory as usize + 
            (*dos_header).e_lfanew as usize + 
            std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;
        
        println!("Setting memory protection for {} sections", section_count);
        
        // Set appropriate protection for each section
        for i in 0..section_count {
            let section = first_section.add(i as usize);
            let section_start = memory as usize + (*section).VirtualAddress as usize;
            
            // Use SizeOfRawData instead of Misc.VirtualSize to avoid the union access issue
            let section_size = (*section).SizeOfRawData as usize;
            let characteristics = (*section).Characteristics;
            
            // Skip empty sections
            if section_size == 0 {
                continue;
            }
            
            // Determine protection based on section characteristics
            let protection = if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_READ
                }
            } else if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                PAGE_READWRITE
            } else {
                PAGE_READONLY
            };
            
            let mut old_protect: ULONG = 0;
            if VirtualProtect(
                section_start as *mut _,
                section_size,
                protection,
                &mut old_protect
            ) == 0 {
                println!("Failed to set protection for section {}: {}", 
                    i, std::io::Error::last_os_error());
            } else {
                //println!("Set protection {:#x} for section {} at {:p} with size {:#x}", 
                    //protection, i, section_start as *const u8, section_size);
            }
        }
        
        // Also set the entire DLL to executable as a fallback
        let mut old_protect: ULONG = 0;
        if VirtualProtect(
            memory as *mut _,
            size,
            PAGE_EXECUTE_READ,
            &mut old_protect
        ) == 0 {
            println!("Failed to make entire memory executable: {}", 
                std::io::Error::last_os_error());
            return None;
        }
        println!("Memory protection changed to PAGE_EXECUTE_READ for entire DLL");
    }

    Some((clean_dll_base, ntdll_base, delta as *const std::ffi::c_void))
}

pub fn get_function_from_raw_dll(memory: *const u8, _delta: *const std::ffi::c_void, function_name: &str) -> Option<usize> {
    unsafe {
        // Parse PE structure
        let dos_header = memory as *const IMAGE_DOS_HEADER;
        let nt_headers = (memory as usize + (*dos_header).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;
        
        println!("Clean DLL base: {:p}", memory);
        println!("DOS header e_lfanew: {:#x}", (*dos_header).e_lfanew);
        
        // Get export directory
        let optional_header = &(*nt_headers).OptionalHeader;
        let export_directory_rva = optional_header.DataDirectory[0].VirtualAddress as usize;
        
        println!("Export directory RVA: {:#x}", export_directory_rva);
        
        // Get export directory
        let export_directory = (memory as usize + export_directory_rva) 
            as *const IMAGE_EXPORT_DIRECTORY;
        
        println!("Export directory at: {:p}", export_directory);
        println!("Number of names: {}", (*export_directory).NumberOfNames);
        
        // Get arrays of names, functions and ordinals
        let names = (memory as usize + (*export_directory).AddressOfNames as usize) 
            as *const u32;
        let functions = (memory as usize + (*export_directory).AddressOfFunctions as usize) 
            as *const u32;
        let ordinals = (memory as usize + (*export_directory).AddressOfNameOrdinals as usize) 
            as *const u16;

        println!("Names array at: {:p}", names);
        println!("Functions array at: {:p}", functions);
        println!("Ordinals array at: {:p}", ordinals);
        
        println!("Searching for function: {}", function_name);

        // Search for the function
        for i in 0..(*export_directory).NumberOfNames {
            let name_rva = *names.offset(i as isize);
            let name = (memory as usize + name_rva as usize) as *const i8;
            let name_str = std::ffi::CStr::from_ptr(name).to_str().unwrap_or("");
            
            if name_str == function_name {
                let ordinal = *ordinals.offset(i as isize) as usize;
                let function_rva = *functions.offset(ordinal as isize);
                let function_addr = memory as usize + function_rva as usize;
                
                println!("Found function '{}' at index {}", function_name, i);
                println!("Ordinal: {}", ordinal);
                println!("Function RVA: {:#x}", function_rva);
                println!("Function address in clean copy: {:p}", function_addr as *const u8);
                
                // Verify the function address is within the DLL's memory range
                let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
                if function_rva as usize >= image_size {
                    println!("WARNING: Function RVA {:#x} exceeds image size {:#x}", function_rva, image_size);
                }
                
                // Check if the function is forwarded
                let export_dir_start = export_directory_rva;
                let export_dir_end = export_dir_start + optional_header.DataDirectory[0].Size as usize;
                
                if (function_rva as usize) >= export_dir_start && (function_rva as usize) < export_dir_end {
                    // This is a forwarded export
                    let forward_str = std::ffi::CStr::from_ptr((memory as usize + function_rva as usize) as *const i8)
                        .to_str()
                        .unwrap_or("");
                    println!("Function is forwarded to: {}", forward_str);
                    
                    // For now, we'll just return the address of the forwarded name string
                    // In a real implementation, you'd want to resolve the forwarded function
                    return Some(function_addr);
                }
                
                // Check the first few bytes of the function to make sure it looks like code
                let bytes = std::slice::from_raw_parts(function_addr as *const u8, 16);
                println!("First 16 bytes of function: {:02X?}", bytes);
                
                // Verify memory protection at function address
                use winapi::um::memoryapi::VirtualQuery;
                use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ};
                
                let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let result = VirtualQuery(
                    function_addr as *const _,
                    &mut mem_info as *mut _ as *mut _,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
                );
                
                if result != 0 {
                    println!("Memory protection at function address: {:#x}", mem_info.Protect);
                    if mem_info.Protect & PAGE_EXECUTE_READ == 0 {
                        println!("WARNING: Function memory is not executable!");
                    }
                }
                
                return Some(function_addr);
            }
        }
        
        println!("Function '{}' not found in export directory", function_name);
    }
    None
}

pub fn copy_security_directory_raw(memory: *mut u8, _size: usize) -> Option<()> {
    unsafe {
        let teb = get_teb();
        let ntdll_base = get_dll_address("ntdll.dll".to_string(), teb)?;

        // Get security directory from original NTDLL
        let orig_dos = ntdll_base as *const IMAGE_DOS_HEADER;
        let orig_nt = (ntdll_base as usize + (*orig_dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let sec_dir = &(*orig_nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY as usize];

        if sec_dir.VirtualAddress == 0 || sec_dir.Size == 0 {
            println!("No security directory found in original NTDLL");
            return None;
        }

        // Get location in our clean DLL
        let dos_header = memory as *const IMAGE_DOS_HEADER;
        let nt_headers = (memory as usize + (*dos_header).e_lfanew as usize) 
            as *mut IMAGE_NT_HEADERS;

        println!("Copying security directory from {:p} with size {:#x}", 
            (ntdll_base as usize + sec_dir.VirtualAddress as usize) as *const u8,
            sec_dir.Size);

        // Copy the security directory
        std::ptr::copy_nonoverlapping(
            (ntdll_base as usize + sec_dir.VirtualAddress as usize) as *const u8,
            (memory as usize + sec_dir.VirtualAddress as usize) as *mut u8,
            sec_dir.Size as usize
        );

        // Update our PE headers to point to the security directory
        (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY as usize] = *sec_dir;

        println!("Security directory copied successfully");
        Some(())
    }
}

pub fn verify_security_directory_raw(memory: *const u8, _size: usize) -> Option<()> {
    unsafe {
        // Get security directory from our clean DLL
        let dos_header = memory as *const IMAGE_DOS_HEADER;
        let nt_headers = (memory as usize + (*dos_header).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;
        let sec_dir = &(*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY as usize];

        if sec_dir.VirtualAddress == 0 || sec_dir.Size == 0 {
            println!("No security directory found in clean DLL");
            return None;
        }

        // Get pointer to certificate data
        let cert_data = (memory as usize + sec_dir.VirtualAddress as usize) 
            as *const WIN_CERTIFICATE;

        println!("Certificate found:");
        println!("  Length: {:#x}", (*cert_data).length);
        println!("  Revision: {:#x}", (*cert_data).revision);
        println!("  Type: {:#x}", (*cert_data).certificate_type);

        Some(())
    }
}

