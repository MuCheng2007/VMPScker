/**
 * Operations with executable files implementations.
 */

#include "files.h"
#include "osutils.h"
#include "streams.h"

// Modules
#include "files/utils.h"
#include "files/references.h"
#include "files/mapping.h"
#include "files/sections.h"
#include "files/imports.h"
#include "files/exports.h"
#include "files/fixups.h"
#include "files/relocations.h"
#include "files/seh.h"
#include "files/resources.h"
#include "files/runtime_func.h"
#include "files/compiler_func.h"
#include "files/memory.h"
#include "files/markers.h"
#include "files/architecture.h"

#include "processors/proc_interfaces.h"
#include "processors/proc_crypto.h"

#include "inifile.h"
#include "lang.h"
#include "core_internal/core.h"
#include "script.h"

#include "core_internal/watermark.h"
#include "core_internal/license.h"
#include "core_internal/file_manager.h"

// All implementations have been moved to files/*.cc