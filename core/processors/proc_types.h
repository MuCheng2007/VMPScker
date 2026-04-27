/**
 * Processors types and enums.
 */

#ifndef PROC_TYPES_H
#define PROC_TYPES_H

#include "../objects.h"
#include "../osutils.h"
#include "../files.h"

// Forward declarations
class CommandLink;
class Buffer;
class CommandBlock;
class IVirtualMachine;
class SignatureList;
class ICommand;
class IFunction;
class Folder;
class MemoryManager;
class CommandInfoList;
class FunctionInfoList;
class FunctionInfo;
class IArchitecture;
class IRuntimeFunction;
class Watermark;
class IVirtualMachineList;

// Type aliases
typedef uint32_t CommandType;

// Operand type flags
enum OperandType : uint16_t {
	otNone = 0x0000,
	otValue = 0x0001,
	otRegistr = 0x0002,
	otMemory = 0x0004,
	otSegmentRegistr = 0x0008,
	otControlRegistr = 0x0010,
	otDebugRegistr = 0x0020,
	otFPURegistr = 0x0040,
	otHiPartRegistr = 0x0080,
	otBaseRegistr = 0x0100,
	otMMXRegistr = 0x0200,
	otXMMRegistr = 0x0400,
};

// Command options flags
enum CommandOption {
	roInverseFlag = 0x0001,
	roLockPrefix = 0x0002,
	roFar = 0x0004,
	roVexPrefix = 0x0008,
	roBreaked = 0x0010,
	roClearOriginalCode = 0x0020,
	roNeedCompile = 0x0040,
	roCreateNewBlock = 0x0080,
	roFillNop = 0x0100,
	roInternal = 0x0200,
	roNoNative = 0x0400,
	roNoSaveFlags = 0x0800,
	roWritable = 0x1000,
	roUseAsJmp = 0x2000,
	roNoProgress = 0x4000,
	roExternal = 0x8000,
	roNeedCRC = 0x10000,
	roInvalidOpcode = 0x20000,
	roDataSegment = 0x40000,
	roImportSegment = 0x80000,
};

// Virtual machine registers
enum VMRegistr {
	regEFX = 16,
	regETX,
	regERX,
	regEIX,
	regEmpty,
	regExtended = 0x80
};

// Link types for command linking
enum LinkType {
	ltNone,
	ltSEHBlock,
	ltFinallyBlock,
	ltDualSEHBlock,
	ltFilterSEHBlock,
	ltJmp,
	ltJmpWithFlag,
	ltJmpWithFlagNSFS,
	ltJmpWithFlagNSNA,
	ltJmpWithFlagNSNS,
	ltCall,
	ltCase,
	ltSwitch,
	ltNative,
	ltOffset,
	ltGateOffset,
	ltExtSEHBlock,
	ltMemSEHBlock,
	ltExtSEHHandler,
	ltVBMemSEHBlock,
	ltDelta
};

// Section options for command blocks
enum SectionOption {
	rtNone = 0x0000,
	rtLinkedToInt = 0x0001,
	rtLinkedToExt = 0x0002,
	rtLinkedFrom = 0x0004,
	rtLinkedNext = 0x0008,
	rtBeginSection = 0x0010,
	rtEndSection = 0x0020,
	rtCloseSection = 0x0040,
	rtNoInverseResult = 0x0080,
	rtInverseResult = 0x0100,
	rtNoSaveFlags = 0x0200,
	rtInverseWrite = 0x0400,
	rtLinkedFromOtherType = 0x0800,
	rtBackwardDirection = 0x1000
};

// VM command options
enum VMCommandOption {
	voNone = 0x0000,
	voLinkCommand = 0x0001,
	voFixup = 0x0002,
	voSectionCommand = 0x0004,
	voInverseValue = 0x0008,
	voUseBeginSectionCryptor = 0x0010,
	voUseEndSectionCryptor = 0x0020,
	voBeginOffset = 0x0040,
	voEndOffset = 0x0080,
	voInitOffset = 0x0100,
	voNoCRC = 0x0200,
	voNoCryptValue = 0x0400
};

// Comment types for commands
enum CommentType : uint8_t {
	ttUnknown,
	ttNone,
	ttJmp,
	ttFunction,
	ttImport,
	ttString,
	ttVariable,
	ttComment,
	ttExport,
	ttMarker
};

// Access type for command info
enum AccessType : uint8_t {
	atRead,
	atWrite
};

// Internal link type for VM commands
enum InternalLinkType {
	vlNone,
	vlCRCTableAddress,
	vlCRCTableCount,
	vlCRCValue
};

// Address base type for function info
enum AddressBaseType {
	btValue,
	btImageBase,
	btFunctionBegin
};

// Crypt command type for value encryption
enum CryptCommandType : uint8_t {
	ccAdd,
	ccSub,
	ccXor,
	ccInc,
	ccDec,
	ccBswap,
	ccRol,
	ccRor,
	ccNot,
	ccNeg,
	ccUnknown
};

// Entry type for function entry point
enum EntryType : uint8_t {
	etDefault,
	etRandomAddress,
	etNone
};

// Compilation options
enum CompilationOption {
	coLockToKey = 0x2000
};

// Function tags
enum FunctionTag {
	ftNone,
	ftLicensing,
	ftBundler,
	ftRegistry,
	ftResources,
	ftLoader,
	ftProcessor
};

// Command tags
enum CommandTag {
	cmdtNone,
	cmdtMutant
};

// Comment information structure
struct CommentInfo {
	std::string value;
	CommentType type;
	CommentInfo() : type(ttUnknown) {}
	CommentInfo(CommentType type_, const std::string &value_) : type(type_), value(value_) {}
	std::string display_value() const 
	{
		std::string res;
		if (value.empty())
			return std::string();
		return (value[0] < 5) ? value[0] + DisplayString(value.substr(1)) : DisplayString(value);
	}
};

#endif // PROC_TYPES_H
