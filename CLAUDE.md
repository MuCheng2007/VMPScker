# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VMPScker is a code virtualization and obfuscation engine — a VMProtect-like software protection system. It disassembles x86/x64 native code, lifts it to IR, transforms it into encrypted stack-machine bytecode, and packages it into a PE file with an embedded native VM that executes the bytecode at runtime.

The repo has two major codebases:
- **`cpp/`** — Original C++ implementation (Visual Studio solution). Mature and feature-complete.
- **`rust/`** — Ground-up Rust rewrite (Cargo workspace). This is the **active development target**.

The Rust rewrite is ~70% complete. The PE parsing/rebuilding and VM pipeline work end-to-end for basic functions. Remaining work: mutation engine, anti-debug, runtime library.

## Build & Test

```bash
# Rust — check/build the entire workspace
cd rust && cargo check              # fast validation (no codegen)
cd rust && cargo build              # debug build
cd rust && cargo build --release    # optimized build

# Run the CLI binary
cd rust && cargo run -- <subcommand> ...

# Run all tests
cd rust && cargo test

# Run tests for a specific crate
cd rust && cargo test -p vmp-core

# Run a specific test
cd rust && cargo test -p vmp-core -- pe_test

# C++ — build with Visual Studio
# Open cpp/vmprotect.sln in Visual Studio. Configuration: Debug|x64 or Release|x64.
# The C++ build requires the VMProtect SDK and may have configuration-specific dependencies.
```

## Architecture

### Pipeline (compilation flow)

```
PE file → disassemble (iced-x86) → x86 IR → pipeline::InstNode
  → pipeline::LoweringPass (x86 IR → VmOpcode stack-machine IR)
  → vm::BytecodeCompiler (VmOpcode → encrypted bytecode bytes)
  → vm::VmPayload (bytecode + native VM handlers + gates → shellcode blob)
  → pe::PeRebuilder (add .vmp0 section with payload, patch entry with jmp)
  → output PE
```

### Crate roles

| Crate | Purpose |
|-------|---------|
| `vmp-core` | Engine library: PE parsing, disassembly, IR, VM compiler, shells code generation |
| `vmp-cli` | CLI binary (`vmp`). Commands: `protect`, `analyze`, `marker`, `test-vm` |
| `vmp-runtime` | Runtime static/dynamic lib (sdys/sys/hwid/licensing — mostly placeholder) |

### Key modules in `vmp-core/src/`

- **`pe/`** — PE parsing and rebuilding (23 files, mature). Handles sections, imports, exports, relocations, exceptions (.pdata), TLS, resources, marker detection, and full PE reconstruction.
- **`intel/`** — x86/x64 disassembly and IR. Wraps `iced-x86` for decoding, defines `IrInstruction`/`IrOperand` IR types, and provides encoder, CFG builder, basic block splitter.
- **`pipeline/`** — Intermediate compilation nodes. `InstNode` holds native instruction, x86 IR, liveness info, and VM IR. `LoweringPass` converts x86 IR to stack-machine `VmOpcode` sequences.
- **`vm/`** — The virtualization core:
  - `opcode.rs` — `VmOpcode` enum: stack-machine instructions (VAdd, VSub, VXor, VNand, VPushReg, VPopReg, VJmp, VJcc, VCall, VExit, etc.)
  - `arch.rs` — `ArchConfig`: randomized physical register mappings, opcode shuffling, cryptographic chain. A new random config is generated per function.
  - `handlers.rs` — `HandlerGenerator`: emits x64 native assembly for each VM opcode using `iced-x86` CodeAssembler. Implements indirect threading dispatch (each handler ends with fetch → decrypt → jmp to next handler).
  - `compiler.rs` — `BytecodeCompiler`: converts `VmOpcode` sequences to encrypted bytecode using the ArchConfig's crypto chain.
  - `gates.rs` — `VmGates`: generates VM entry/exit gates (save/restore native context to register save area).
  - `assembler.rs` — `VmPayload`: assembles the full binary blob (save area + entry gate + handler table + exit gate + bytecode).
- **`protector.rs`** — Orchestrator: finds VMP markers in PE, disassembles protected code, runs the full pipeline, rebuilds PE with `.vmp0` section, patches the original code start with `jmp VM_ENTRY`.

### C++ codebase reference

The C++ code is the reference implementation. Key directories:
- `cpp/core/pe/` — PE parsing classes (PEArchitecture, PEImport, PEExport, PERuntimeFunction, etc.)
- `cpp/core/intel/ir/` — IR classes (IntelCommand: ~350KB monolithic instruction representation)
- `cpp/core/intel/vm/` — VM generation (IntelVirtualMachine: ~148KB, the core VM builder)
- `cpp/core/processors/` — Protection processors (proc_function, proc_command_block, proc_crypto, proc_vm)
- `cpp/core/files/` — Higher-level PE file abstraction (architecture, mapping, sections, imports, markers)

When porting a C++ feature to Rust, use the C++ code at the corresponding path as the reference for correct behavior.

### Design conventions

- The VM is a **pure stack machine** — all operations push/pop from a virtual stack (VSP). Native register state is saved/restored at VM boundaries.
- **Indirect threading**: No central dispatch loop. Each handler ends by fetching the next encrypted opcode, decrypting it, computing the next handler address, and jumping indirectly. This breaks static CFG analysis.
- **Rolling encryption**: Bytecode encryption is chained (CBC-like). Each opcode's decryption key depends on the previous opcode's state, so tampering with bytecode causes avalanche failure.
- `iced-x86`'s `CodeAssembler` is used throughout the VM module to emit native x64 machine code directly (not inline assembly — it's runtime codegen via the assembler API).
