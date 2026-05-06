//! Comprehensive comparison tests between Rust implementation and C++ original
//! Tests all core/files functionality to ensure complete implementation

use vmp_core::core::*;
use vmp_core::core::types::*;

/// Test all OperandSize variants match C++ enum
#[test]
fn test_operand_size_matches_cpp() {
    // C++: osByte=0, osWord=1, osDWord=2, osQWord=3, osTByte=4, osOWord=5, osXMMWord=6, osYMMWord=7, osFWord=8
    assert_eq!(OperandSize::Byte as u8, 0);
    assert_eq!(OperandSize::Word as u8, 1);
    assert_eq!(OperandSize::DWord as u8, 2);
    assert_eq!(OperandSize::QWord as u8, 3);
    assert_eq!(OperandSize::TByte as u8, 4);
    assert_eq!(OperandSize::OWord as u8, 5);
    assert_eq!(OperandSize::XmmWord as u8, 6);
    assert_eq!(OperandSize::YmmWord as u8, 7);
    assert_eq!(OperandSize::FWord as u8, 8);
    
    // Test size calculations
    assert_eq!(OperandSize::Byte.size_in_bytes(), 1);
    assert_eq!(OperandSize::Word.size_in_bytes(), 2);
    assert_eq!(OperandSize::DWord.size_in_bytes(), 4);
    assert_eq!(OperandSize::QWord.size_in_bytes(), 8);
    assert_eq!(OperandSize::TByte.size_in_bytes(), 10);
    assert_eq!(OperandSize::OWord.size_in_bytes(), 16);
    assert_eq!(OperandSize::XmmWord.size_in_bytes(), 16);
    assert_eq!(OperandSize::YmmWord.size_in_bytes(), 32);
    assert_eq!(OperandSize::FWord.size_in_bytes(), 6);
    
    // Stack promotion: bytes are promoted to words
    assert_eq!(OperandSize::Byte.stack_size(), 2);
    assert_eq!(OperandSize::DWord.stack_size(), 4);
}

/// Test MemoryTypeFlags match C++ enum values
#[test]
fn test_memory_type_flags_matches_cpp() {
    // C++: mtNone=0x0, mtReadable=0x1, mtExecutable=0x2, mtWritable=0x4, 
    //      mtNotDiscardable=0x8, mtDiscardable=0x10, mtNotPaged=0x20, mtShared=0x40, mtSolid=0x80
    assert_eq!(MemoryTypeFlags::NONE.bits(), 0x0);
    assert_eq!(MemoryTypeFlags::READABLE.bits(), 0x1);
    assert_eq!(MemoryTypeFlags::EXECUTABLE.bits(), 0x2);
    assert_eq!(MemoryTypeFlags::WRITABLE.bits(), 0x4);
    assert_eq!(MemoryTypeFlags::NOT_DISCARDABLE.bits(), 0x8);
    assert_eq!(MemoryTypeFlags::DISCARDABLE.bits(), 0x10);
    assert_eq!(MemoryTypeFlags::NOT_PAGED.bits(), 0x20);
    assert_eq!(MemoryTypeFlags::SHARED.bits(), 0x40);
    assert_eq!(MemoryTypeFlags::SOLID.bits(), 0x80);
}

/// Test ApiType matches C++ enum
#[test]
fn test_api_type_matches_cpp() {
    // C++: atNone=0, atBegin=1, atEnd=2, atIsVirtualMachinePresent=3, ...
    assert_eq!(ApiType::None as u8, 0);
    assert_eq!(ApiType::Begin as u8, 1);
    assert_eq!(ApiType::End as u8, 2);
    assert_eq!(ApiType::IsVirtualMachinePresent as u8, 3);
    assert_eq!(ApiType::IsDebuggerPresent as u8, 4);
    assert_eq!(ApiType::IsValidImageCrc as u8, 5);
    assert_eq!(ApiType::DecryptStringA as u8, 6);
    assert_eq!(ApiType::DecryptStringW as u8, 7);
    assert_eq!(ApiType::FreeString as u8, 8);
    assert_eq!(ApiType::ActivateLicense as u8, 9);
    assert_eq!(ApiType::DeactivateLicense as u8, 10);
    assert_eq!(ApiType::GetOfflineActivationString as u8, 11);
    assert_eq!(ApiType::GetOfflineDeactivationString as u8, 12);
    assert_eq!(ApiType::SetSerialNumber as u8, 13);
    assert_eq!(ApiType::GetSerialNumberState as u8, 14);
    assert_eq!(ApiType::GetSerialNumberData as u8, 15);
    assert_eq!(ApiType::GetCurrentHwid as u8, 16);
    assert_eq!(ApiType::LoadResource as u8, 17);
    assert_eq!(ApiType::FindResourceA as u8, 18);
    assert_eq!(ApiType::FindResourceExA as u8, 19);
    assert_eq!(ApiType::FindResourceW as u8, 20);
    assert_eq!(ApiType::FindResourceExW as u8, 21);
    assert_eq!(ApiType::LoadStringA as u8, 22);
    assert_eq!(ApiType::LoadStringW as u8, 23);
    assert_eq!(ApiType::EnumResourceNamesA as u8, 24);
    assert_eq!(ApiType::EnumResourceNamesW as u8, 25);
    assert_eq!(ApiType::EnumResourceLanguagesA as u8, 26);
    assert_eq!(ApiType::EnumResourceLanguagesW as u8, 27);
    assert_eq!(ApiType::EnumResourceTypesA as u8, 28);
    assert_eq!(ApiType::EnumResourceTypesW as u8, 29);
    assert_eq!(ApiType::DecryptBuffer as u8, 30);
    assert_eq!(ApiType::RuntimeInit as u8, 31);
    assert_eq!(ApiType::LoaderData as u8, 32);
    assert_eq!(ApiType::IsProtected as u8, 33);
    assert_eq!(ApiType::SetupImage as u8, 34);
    assert_eq!(ApiType::FreeImage as u8, 35);
    assert_eq!(ApiType::CalcCrc as u8, 36);
    assert_eq!(ApiType::Random as u8, 37);
    assert_eq!(ApiType::BoxPointer as u8, 38);
    assert_eq!(ApiType::UnboxPointer as u8, 39);
}

/// Test ImportOptions flags match C++
#[test]
fn test_import_options_matches_cpp() {
    // C++: ioNone=0x0000, ioNoReturn=0x0001, ioHasDataReference=0x0002, ioNative=0x0004,
    //      ioHasCompilationType=0x0008, ioLockToKey=0x0010, ioFromRuntime=0x0020,
    //      ioNoReferences=0x0040, ioIsRelative=0x0080, ioHasDirectReference=0x0100, ioHasCallPrefix=0x0200
    assert_eq!(ImportOptions::NONE.bits(), 0x0000);
    assert_eq!(ImportOptions::NO_RETURN.bits(), 0x0001);
    assert_eq!(ImportOptions::HAS_DATA_REFERENCE.bits(), 0x0002);
    assert_eq!(ImportOptions::NATIVE.bits(), 0x0004);
    assert_eq!(ImportOptions::HAS_COMPILATION_TYPE.bits(), 0x0008);
    assert_eq!(ImportOptions::LOCK_TO_KEY.bits(), 0x0010);
    assert_eq!(ImportOptions::FROM_RUNTIME.bits(), 0x0020);
    assert_eq!(ImportOptions::NO_REFERENCES.bits(), 0x0040);
    assert_eq!(ImportOptions::IS_RELATIVE.bits(), 0x0080);
    assert_eq!(ImportOptions::HAS_DIRECT_REFERENCE.bits(), 0x0100);
    assert_eq!(ImportOptions::HAS_CALL_PREFIX.bits(), 0x0200);
}

/// Test RuntimeOptions flags match C++
#[test]
fn test_runtime_options_matches_cpp() {
    // C++: roNone=0, roHWID=0x0001, roKey=0x0002, roResources=0x0004, roStrings=0x0008,
    //      roBundler=0x0010, roRegistry=0x0020, roActivation=0x0040, roMemoryProtection=0x0080
    assert_eq!(RuntimeOptions::NONE.bits(), 0x0000);
    assert_eq!(RuntimeOptions::HWID.bits(), 0x0001);
    assert_eq!(RuntimeOptions::KEY.bits(), 0x0002);
    assert_eq!(RuntimeOptions::RESOURCES.bits(), 0x0004);
    assert_eq!(RuntimeOptions::STRINGS.bits(), 0x0008);
    assert_eq!(RuntimeOptions::BUNDLER.bits(), 0x0010);
    assert_eq!(RuntimeOptions::REGISTRY.bits(), 0x0020);
    assert_eq!(RuntimeOptions::ACTIVATION.bits(), 0x0040);
    assert_eq!(RuntimeOptions::MEMORY_PROTECTION.bits(), 0x0080);
}

/// Test CompilationType matches C++
#[test]
fn test_compilation_type_matches_cpp() {
    // C++: ctVirtualization=0, ctMutation=1, ctUltra=2, ctNone=0xFF
    assert_eq!(CompilationType::Virtualization as u8, 0);
    assert_eq!(CompilationType::Mutation as u8, 1);
    assert_eq!(CompilationType::Ultra as u8, 2);
    assert_eq!(CompilationType::None as u8, 0xFF);
}

/// Test FixupType matches C++
#[test]
fn test_fixup_type_matches_cpp() {
    // C++: ftUnknown=0, ftHigh=1, ftLow=2, ftHighLow=3
    assert_eq!(FixupType::Unknown as u8, 0);
    assert_eq!(FixupType::High as u8, 1);
    assert_eq!(FixupType::Low as u8, 2);
    assert_eq!(FixupType::HighLow as u8, 3);
}

/// Test ObjectType matches C++
#[test]
fn test_object_type_matches_cpp() {
    // C++: otCode=0, otData=1, otExport=2, otMarker=3, otAPIMarker=4, otImport=5, otString=6, otUnknown=7
    assert_eq!(ObjectType::Code as u8, 0);
    assert_eq!(ObjectType::Data as u8, 1);
    assert_eq!(ObjectType::Export as u8, 2);
    assert_eq!(ObjectType::Marker as u8, 3);
    assert_eq!(ObjectType::ApiMarker as u8, 4);
    assert_eq!(ObjectType::Import as u8, 5);
    assert_eq!(ObjectType::String as u8, 6);
    assert_eq!(ObjectType::Unknown as u8, 7);
    
    // Test is_code() method
    assert!(ObjectType::Code.is_code());
    assert!(ObjectType::Marker.is_code());
    assert!(ObjectType::ApiMarker.is_code());
    assert!(ObjectType::String.is_code());
    assert!(ObjectType::Export.is_code());
    assert!(!ObjectType::Data.is_code());
    assert!(!ObjectType::Import.is_code());
}

/// Test CompilerFunctionType matches C++
#[test]
fn test_compiler_function_type_matches_cpp() {
    // C++: cfNone=0, cfBaseRegistr=1, cfGetBaseRegistr=2, cfDllFunctionCall=3, ...
    assert_eq!(CompilerFunctionType::None as u8, 0);
    assert_eq!(CompilerFunctionType::BaseRegister as u8, 1);
    assert_eq!(CompilerFunctionType::GetBaseRegister as u8, 2);
    assert_eq!(CompilerFunctionType::DllFunctionCall as u8, 3);
    assert_eq!(CompilerFunctionType::CxxSeh as u8, 4);
    assert_eq!(CompilerFunctionType::CxxSeh3 as u8, 5);
    assert_eq!(CompilerFunctionType::CxxSeh4 as u8, 6);
    assert_eq!(CompilerFunctionType::Seh4Prolog as u8, 7);
    assert_eq!(CompilerFunctionType::Vb6Seh as u8, 8);
    assert_eq!(CompilerFunctionType::InitBcbSeh as u8, 9);
    assert_eq!(CompilerFunctionType::BcbSeh as u8, 10);
    assert_eq!(CompilerFunctionType::RelocatorMinGW as u8, 11);
    assert_eq!(CompilerFunctionType::PatchImport as u8, 12);
    assert_eq!(CompilerFunctionType::JmpFunction as u8, 13);
}

/// Test SDK imports table matches C++
#[test]
fn test_sdk_imports_table_matches_cpp() {
    // Verify all SDK imports are present
    let sdk_names: Vec<&str> = SDK_IMPORTS.iter().map(|i| i.name).collect();
    
    assert!(sdk_names.contains(&"VMProtectBegin"));
    assert!(sdk_names.contains(&"VMProtectBeginVirtualization"));
    assert!(sdk_names.contains(&"VMProtectBeginMutation"));
    assert!(sdk_names.contains(&"VMProtectBeginUltra"));
    assert!(sdk_names.contains(&"VMProtectBeginVirtualizationLockByKey"));
    assert!(sdk_names.contains(&"VMProtectBeginUltraLockByKey"));
    assert!(sdk_names.contains(&"VMProtectEnd"));
    assert!(sdk_names.contains(&"VMProtectIsProtected"));
    assert!(sdk_names.contains(&"VMProtectIsVirtualMachinePresent"));
    assert!(sdk_names.contains(&"VMProtectIsDebuggerPresent"));
    assert!(sdk_names.contains(&"VMProtectIsValidImageCRC"));
    assert!(sdk_names.contains(&"VMProtectDecryptStringA"));
    assert!(sdk_names.contains(&"VMProtectDecryptStringW"));
    assert!(sdk_names.contains(&"VMProtectFreeString"));
    assert!(sdk_names.contains(&"VMProtectSetSerialNumber"));
    assert!(sdk_names.contains(&"VMProtectGetSerialNumberState"));
    assert!(sdk_names.contains(&"VMProtectGetSerialNumberData"));
    assert!(sdk_names.contains(&"VMProtectGetCurrentHWID"));
    assert!(sdk_names.contains(&"VMProtectActivateLicense"));
    assert!(sdk_names.contains(&"VMProtectDeactivateLicense"));
    assert!(sdk_names.contains(&"VMProtectGetOfflineActivationString"));
    assert!(sdk_names.contains(&"VMProtectGetOfflineDeactivationString"));
}

/// Test SDK info lookup
#[test]
fn test_get_sdk_info_matches_cpp() {
    // Test VMProtectBegin
    let info = get_sdk_info("VMProtectBegin").unwrap();
    assert_eq!(info.api_type, ApiType::Begin);
    assert_eq!(info.compilation_type, CompilationType::None);
    
    // Test VMProtectBeginVirtualization
    let info = get_sdk_info("VMProtectBeginVirtualization").unwrap();
    assert_eq!(info.api_type, ApiType::Begin);
    assert_eq!(info.compilation_type, CompilationType::Virtualization);
    assert!(info.options.contains(ImportOptions::HAS_COMPILATION_TYPE));
    
    // Test VMProtectBeginUltra
    let info = get_sdk_info("VMProtectBeginUltra").unwrap();
    assert_eq!(info.compilation_type, CompilationType::Ultra);
    
    // Test case insensitive
    let info = get_sdk_info("vmprotectbegin").unwrap();
    assert_eq!(info.api_type, ApiType::Begin);
    
    // Test unknown function
    assert!(get_sdk_info("UnknownFunction").is_none());
}

/// Test API runtime options match C++ logic
#[test]
fn test_api_runtime_options_matches_cpp() {
    // SetSerialNumber, GetSerialNumberState, GetSerialNumberData, etc. should return KEY
    assert!(get_api_runtime_options(ApiType::SetSerialNumber).contains(RuntimeOptions::KEY));
    assert!(get_api_runtime_options(ApiType::GetSerialNumberState).contains(RuntimeOptions::KEY));
    assert!(get_api_runtime_options(ApiType::GetSerialNumberData).contains(RuntimeOptions::KEY));
    
    // GetCurrentHwid should return HWID
    assert!(get_api_runtime_options(ApiType::GetCurrentHwid).contains(RuntimeOptions::HWID));
    
    // ActivateLicense/DeactivateLicense should return KEY | ACTIVATION
    let opts = get_api_runtime_options(ApiType::ActivateLicense);
    assert!(opts.contains(RuntimeOptions::KEY));
    assert!(opts.contains(RuntimeOptions::ACTIVATION));
    
    // Others should return NONE
    assert_eq!(get_api_runtime_options(ApiType::Begin), RuntimeOptions::NONE);
    assert_eq!(get_api_runtime_options(ApiType::IsDebuggerPresent), RuntimeOptions::NONE);
}

/// Test API SDK options match C++ logic
#[test]
fn test_api_sdk_options_matches_cpp() {
    // IsValidImageCrc should return MEMORY_PROTECTION
    assert!(get_api_sdk_options(ApiType::IsValidImageCrc).contains(CompileFlags::MEMORY_PROTECTION));
    
    // IsVirtualMachinePresent should return CHECK_VIRTUAL_MACHINE
    assert!(get_api_sdk_options(ApiType::IsVirtualMachinePresent).contains(CompileFlags::CHECK_VIRTUAL_MACHINE));
    
    // IsDebuggerPresent should return CHECK_DEBUGGER
    assert!(get_api_sdk_options(ApiType::IsDebuggerPresent).contains(CompileFlags::CHECK_DEBUGGER));
    
    // Others should return NONE
    assert_eq!(get_api_sdk_options(ApiType::Begin), CompileFlags::NONE);
    assert_eq!(get_api_sdk_options(ApiType::SetSerialNumber), CompileFlags::NONE);
}

/// Test ImportInfo encode/decode matches C++
#[test]
fn test_import_info_encode_decode_matches_cpp() {
    let info = ImportInfo {
        api_type: ApiType::Begin,
        name: "Test",
        options: ImportOptions::HAS_COMPILATION_TYPE | ImportOptions::LOCK_TO_KEY,
        compilation_type: CompilationType::Virtualization,
    };
    
    let encoded = info.encode();
    
    // C++: (compilation_type << 16) | (options << 8) | type
    // compilation_type=0, options=0x18 (0x08 | 0x10), type=1
    let expected: u64 = ((CompilationType::Virtualization as u64) << 16) 
                       | (((ImportOptions::HAS_COMPILATION_TYPE.bits() | ImportOptions::LOCK_TO_KEY.bits()) as u64) << 8) 
                       | (ApiType::Begin as u64);
    assert_eq!(encoded, expected);
    
    let (api_type, options, comp_type) = ImportInfo::decode(encoded);
    assert_eq!(api_type, ApiType::Begin);
    assert!(options.contains(ImportOptions::HAS_COMPILATION_TYPE));
    assert!(options.contains(ImportOptions::LOCK_TO_KEY));
    assert_eq!(comp_type, CompilationType::Virtualization);
}

/// Test helper functions
#[test]
fn test_helper_functions_matches_cpp() {
    // BITS_TO_BYTES
    assert_eq!(bits_to_bytes(7), 1);
    assert_eq!(bits_to_bytes(8), 1);
    assert_eq!(bits_to_bytes(9), 2);
    assert_eq!(bits_to_bytes(16), 2);
    
    // BYTES_TO_BITS
    assert_eq!(bytes_to_bits(1), 8);
    assert_eq!(bytes_to_bits(2), 16);
    assert_eq!(bytes_to_bits(4), 32);
    
    // align_value
    assert_eq!(align_value(0u64, 8u64), 0);
    assert_eq!(align_value(5u64, 8u64), 8);
    assert_eq!(align_value(8u64, 8u64), 8);
    assert_eq!(align_value(9u64, 8u64), 16);
    assert_eq!(align_value(0x1000u64, 0x1000u64), 0x1000);
    assert_eq!(align_value(0x1001u64, 0x1000u64), 0x2000);
}

/// Test sentinel constants
#[test]
fn test_sentinel_constants() {
    // NEED_FIXUP should be u64::MAX
    assert_eq!(NEED_FIXUP, u64::MAX);
    
    // LARGE_VALUE should be u64::MAX - 1
    assert_eq!(LARGE_VALUE, u64::MAX - 1);
    
    // NEED_SEH_HANDLER should be u64::MAX
    assert_eq!(NEED_SEH_HANDLER, u64::MAX);
}
