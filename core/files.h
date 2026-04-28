/**
 * Operations with executable files.
 */

#ifndef FILES_H
#define FILES_H

#include "../runtime/common.h"
#include "objects.h"

// Forward declarations for managers defined elsewhere
class LicensingManager;
class FileManager;
class Core;

#include "files/utils.h"
#include "files/sections.h"
#include "files/imports.h"
#include "files/exports.h"
#include "files/fixups.h"
#include "files/relocations.h"
#include "files/seh.h"
#include "files/references.h"
#include "files/mapping.h"
#include "files/resources.h"
#include "files/compiler_func.h"
#include "files/runtime_func.h"
#include "files/memory.h"
#include "files/markers.h"

// Core architecture definitions
#include "files/architecture.h"

#endif // FILES_H