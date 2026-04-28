
#ifndef FILES_TYPES_H
#define FILES_TYPES_H

#include "../../runtime/common.h"

// ---------------------------------------------------------------------------
// Bit conversion macros
// ---------------------------------------------------------------------------

#define BITS_TO_BYTES(x) (((x)+7)>>3)
#define BYTES_TO_BITS(x) ((x)<<3)

// ---------------------------------------------------------------------------
// Memory protection flags
// ---------------------------------------------------------------------------

enum MemoryTypeFlags
{
	mtNone = 0x0,
	mtReadable = 0x1,
	mtExecutable = 0x2,
	mtWritable = 0x4,
	mtNotDiscardable = 0x8,
	mtDiscardable = 0x10,
	mtNotPaged = 0x20,
	mtShared = 0x40,
	mtSolid = 0x80
};

// ---------------------------------------------------------------------------
// SDK / API function types
// ---------------------------------------------------------------------------

enum APIType {
	atNone,
	atBegin,
	atEnd,
	atIsVirtualMachinePresent,
	atIsDebuggerPresent,
	atIsValidImageCRC,
	atDecryptStringA,
	atDecryptStringW,
	atFreeString,
	atActivateLicense,
	atDeactivateLicense,
	atGetOfflineActivationString,
	atGetOfflineDeactivationString,
	atSetSerialNumber,
	atGetSerialNumberState,
	atGetSerialNumberData,
	atGetCurrentHWID,
	atLoadResource,
	atFindResourceA,
	atFindResourceExA,
	atFindResourceW,
	atFindResourceExW,
	atLoadStringA,
	atLoadStringW,
	atEnumResourceNamesA,
	atEnumResourceNamesW,
	atEnumResourceLanguagesA,
	atEnumResourceLanguagesW,
	atEnumResourceTypesA,
	atEnumResourceTypesW,
	atDecryptBuffer,
	atRuntimeInit,
	atLoaderData,
	atIsProtected,
	atSetupImage,
	atFreeImage,
	atCalcCRC,
	atRandom,
	atBoxPointer,
	atUnboxPointer
};

// ---------------------------------------------------------------------------
// Import options (bit flags)
// ---------------------------------------------------------------------------

enum ImportOption {
	ioNone = 0x0000,
	ioNoReturn = 0x0001,
	ioHasDataReference = 0x0002,
	ioNative = 0x0004,
	ioHasCompilationType = 0x0008,
	ioLockToKey = 0x0010,
	ioFromRuntime = 0x0020,
	ioNoReferences = 0x0040,
	ioIsRelative = 0x0080,
	ioHasDirectReference = 0x0100,
	ioHasCallPrefix = 0x0200
};

// ---------------------------------------------------------------------------
// Runtime feature flags
// ---------------------------------------------------------------------------

enum RuntimeOptions {
	roNone,
	roHWID = 0x0001,
	roKey = 0x0002,
	roResources = 0x0004,
	roStrings = 0x0008,
	roBundler = 0x0010,
	roRegistry = 0x0020,
	roActivation = 0x0040,
	roMemoryProtection = 0x0080
};

// ---------------------------------------------------------------------------
// Compilation strategy for a protected function
// ---------------------------------------------------------------------------

enum CompilationType : uint8_t {
	ctVirtualization,
	ctMutation,
	ctUltra,
	ctNone = 0xFF
};

// ---------------------------------------------------------------------------
// ImportInfo: compact descriptor for SDK import entries
// (only depends on APIType, ImportOption, CompilationType)
// ---------------------------------------------------------------------------

struct ImportInfo {
	APIType type;
	const char *name;
	uint32_t options;
	CompilationType compilation_type;
	uint64_t encode() const
	{
		return (compilation_type << 16) | (options << 8) | type; //-V629
	};
	void decode(uint64_t value)
	{
		type = static_cast<APIType>(value & 0xff);
		options = (value >> 8) & 0xff;
		compilation_type = static_cast<CompilationType>((value >> 16) & 0xff);
	};
};

// ---------------------------------------------------------------------------
// Fixup / relocation types
// ---------------------------------------------------------------------------

enum FixupType
{
	ftUnknown,
	ftHigh,
	ftLow,
	ftHighLow
};

// Sentinel values used in fixup maps
// (forward-declare IFixup to avoid pulling in the full fixup header)
class IFixup;
#define NEED_FIXUP reinterpret_cast<IFixup *>(-1)
#define LARGE_VALUE reinterpret_cast<IFixup *>(-2)

// ---------------------------------------------------------------------------
// Map / symbol object classification
// ---------------------------------------------------------------------------

enum ObjectType : uint8_t
{
	otCode,
	otData,
	otExport,
	otMarker,
	otAPIMarker,
	otImport,
	otString,
	otUnknown
};

// ---------------------------------------------------------------------------
// Map-file section types
// ---------------------------------------------------------------------------

enum MapSectionType {
	msSections,
	msFunctions
};

// ---------------------------------------------------------------------------
// Compiler-generated helper function types
// ---------------------------------------------------------------------------

enum CompilerFunctionType {
	cfNone,
	cfBaseRegistr,
	cfGetBaseRegistr,
	cfDllFunctionCall,
	cfCxxSEH,
	cfCxxSEH3,
	cfCxxSEH4,
	cfSEH4Prolog,
	cfVB6SEH,
	cfInitBCBSEH,
	cfBCBSEH,
	cfRelocatorMinGW,
	cfPatchImport,
	cfJmpFunction
};

enum CompilerFunctionOption {
	coUsed = 1,
	coNoReturn = 2,
};

// ---------------------------------------------------------------------------
// SEH handler sentinel
// ---------------------------------------------------------------------------

class ISEHandler;
#define NEED_SEH_HANDLER reinterpret_cast<ISEHandler *>(-1)

// ---------------------------------------------------------------------------
// File open flags and result codes
// ---------------------------------------------------------------------------

enum OpenMode {
	foRead = 0x01,
	foWrite = 0x02,
	foHeaderOnly = 0x04,
	foCopyToTemp = 0x08
};

enum OpenStatus {
	osSuccess,
	osOpenError,
	osUnknownFormat,
	osInvalidFormat,
	osUnsupportedCPU,
	osUnsupportedSubsystem
};

// ---------------------------------------------------------------------------
// Calling conventions (used by IArchitecture)
// ---------------------------------------------------------------------------

enum CallingConvention {
	ccStdcall,
	ccCdecl,
	ccMSx64,
	ccABIx64,
	ccStdcallToMSx64
};

// ---------------------------------------------------------------------------
// Runtime resource descriptor (pure POD, no class deps)
// ---------------------------------------------------------------------------

struct ResourceInfo {
	const uint8_t *file;
	size_t size;
	const uint8_t *code;
};

#endif // FILES_TYPES_H
