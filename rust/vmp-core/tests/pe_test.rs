use std::fs;
use vmp_core::pe::{PeFile, SectionList, ImportList, ExportList, PeModifier};

#[test]
fn test_pe_file_loading() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";

    println!("Loading PE file: {}", path);

    let pe_file = PeFile::load(path).expect("Failed to load PE file");

    println!("PE File loaded successfully!");
    println!("  Is 64-bit: {}", pe_file.is_64bit());
    println!("  Image Base: 0x{:X}", pe_file.image_base());
    println!("  Entry Point: 0x{:X}", pe_file.entry_point());

    if let Some(pe) = pe_file.pe() {
        println!("  Number of sections: {}", pe.sections.len());

        if !pe.imports.is_empty() {
            println!("  Number of imports: {}", pe.imports.len());
        }

        if !pe.exports.is_empty() {
            println!("  Number of exports: {}", pe.exports.len());
        }
    }
}

#[test]
fn test_section_parsing() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";

    let pe_file = PeFile::load(path).expect("Failed to load PE file");

    if let Some(pe) = pe_file.pe() {
        let sections = SectionList::from_goblin(&pe.sections);

        println!("\nSections:");
        for (i, section) in sections.iter().enumerate() {
            println!("  [{}] {}", i, section.name);
            println!("      Virtual Address: 0x{:X}", section.virtual_address);
            println!("      Virtual Size: 0x{:X}", section.virtual_size);
            println!("      Raw Address: 0x{:X}", section.raw_address);
            println!("      Raw Size: 0x{:X}", section.raw_size);
            println!("      Is Code: {}", section.is_code());
            println!("      Is Readable: {}", section.is_readable());
            println!("      Is Writable: {}", section.is_writable());
            println!("      Is Executable: {}", section.is_executable());
        }
    }
}

#[test]
fn test_import_parsing() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";

    let pe_file = PeFile::load(path).expect("Failed to load PE file");

    if let Some(pe) = pe_file.pe() {
        if let Some(ref import_data) = pe.import_data {
            let import_list = ImportList::from_goblin(import_data);

            println!("\nImports:");
            for import in import_list.iter() {
                println!("  DLL: {}", import.dll_name);
                println!("    Functions: {}", import.functions.len());
                for func in &import.functions {
                    println!("      - {} (0x{:X})", func.display_name(), func.address);
                }
            }
        } else {
            println!("No imports found");
        }
    }
}

#[test]
fn test_export_parsing() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";

    let pe_file = PeFile::load(path).expect("Failed to load PE file");

    if let Some(pe) = pe_file.pe() {
        if let Some(ref export_data) = pe.export_data {
            let export_list = ExportList::from_goblin(Some(export_data));

            println!("\nExports:");
            if let Some(export_dir) = export_list.first() {
                println!("  DLL Name: {}", export_dir.dll_name);
                println!("  Number of exports: {}", export_dir.functions.len());

                for export in &export_dir.functions {
                    println!("    - {} (Ordinal: {}, Address: 0x{:X})",
                        export.display_name(),
                        export.ordinal,
                        export.address
                    );
                }
            }
        } else {
            println!("No exports found (this is normal for EXE files)");
        }
    }
}

#[test]
fn test_rva_conversion() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";

    let pe_file = PeFile::load(path).expect("Failed to load PE file");

    if let Some(pe) = pe_file.pe() {
        let entry_point = pe.entry as u64;
        println!("\nRVA Conversion Test:");
        println!("  Entry Point RVA: 0x{:X}", entry_point);

        if let Some(offset) = pe_file.rva_to_offset(entry_point) {
            println!("  Entry Point Offset: 0x{:X}", offset);

            if let Some(back_to_rva) = pe_file.offset_to_rva(offset) {
                println!("  Back to RVA: 0x{:X}", back_to_rva);
                assert_eq!(entry_point, back_to_rva, "RVA conversion round-trip failed");
            }
        } else {
            println!("  Could not convert entry point RVA to offset");
        }
    }
}

#[test]
fn test_pe_modification() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";
    let output_path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1_modified.exe";

    println!("\nPE Modification Test:");

    let data = fs::read(path).expect("Failed to read PE file");
    let is_64bit = vmp_core::pe::utils::is_64bit(&data).unwrap_or(false);

    let mut modifier = PeModifier::new(data, is_64bit);

    println!("  Stripping debug info...");
    modifier.strip_debug_info().expect("Failed to strip debug info");

    println!("  Updating checksum...");
    let checksum = modifier.update_checksum().expect("Failed to update checksum");
    println!("  New checksum: 0x{:X}", checksum);

    println!("  Adding test section...");
    let section_va = modifier.add_section(".vmp", 0x1000, 0x60000020)
        .expect("Failed to add section");
    println!("  New section VA: 0x{:X}", section_va);

    fs::write(output_path, modifier.data()).expect("Failed to write modified PE");
    println!("  Modified PE saved to: {}", output_path);
}

#[test]
fn test_pe_utils() {
    let path = r"E:\VMPScker\bin\64\Ultimate\ConsoleApplication1.exe";

    let data = fs::read(path).expect("Failed to read PE file");

    println!("\nPE Utils Test:");
    println!("  Is PE: {}", vmp_core::pe::utils::is_pe(&data));
    println!("  Is 64-bit: {:?}", vmp_core::pe::utils::is_64bit(&data));
    println!("  Image Base: 0x{:X?}", vmp_core::pe::utils::get_image_base(&data));
    println!("  Entry Point: 0x{:X?}", vmp_core::pe::utils::get_entry_point(&data));
    println!("  Section Count: {:?}", vmp_core::pe::utils::get_section_count(&data));
}
