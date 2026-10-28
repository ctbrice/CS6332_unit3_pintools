# Part 4: PIE- and ASLR-aware GOT protection

## Implementation approach

`part4.cpp` is a Pin tool that protects individual eight-byte GOT slots in the main executable. When the main image loads, it opens the image's file with ELFIO and validates the little-endian x86-64 ELF header. It locates `.rela.plt`, follows its linked symbol table and that table's linked string table, and validates record sizes, indices, and symbol-name bounds.

Unlike part2, this tool reads `Elf64_Rela` and `Elf64_Sym` records directly from ELFIO section buffers using `std::memcpy`. The low 32 bits of `r_info` identify the relocation type and the upper 32 bits identify the symbol index. Only `R_X86_64_JUMP_SLOT` entries are retained, together with their symbol names.

The runtime address is computed once at image load:

```text
runtime GOT address = ELF relocation r_offset + IMG_LoadOffset(image)
```

`r_offset` is a link-time virtual address. `IMG_LoadOffset` supplies the difference between the runtime and link-time address spaces; the tool does not use the `.text` address as the base. For example, `0x202018 + 0x555555554000 = 0x555555756018`. PIE executables use their runtime bias under ASLR, while a conventional fixed-address non-PIE executable normally has zero bias. The write checker uses the already translated address without adding the bias again. Debug output includes the ELF type, load bias, and each symbol's ELF/runtime GOT addresses.

Part3 already contains the same address translation. Part4 makes the PIE/non-PIE handling explicit and adds translation diagnostics; it retains the same write-monitoring and loader-approval policy.

For every instruction, including instructions in libraries, the tool instruments each written memory operand with a predicated analysis call before execution. It compares the destination and write size against each protected slot, detecting partial writes and writes beginning before a slot. Subtraction-based overlap checks avoid computing an overflowing end address.

For an overlapping write, the tool collects up to 64 backtrace frames while holding Pin's client lock. It allows the write only if a frame belongs to the interpreter image and resolves to `_dl_rtld_di_serinfo`. Otherwise, it writes the instruction address, destination, GOT slot, symbol name, and write size to the diagnostic file and exits with status 1 before the write executes.

## Assumptions and limitations

- Requires Linux Intel64 Pin and readable ELF metadata for the main executable. Accepted file types are `ET_EXEC` and `ET_DYN`.
- Protects only the main executable's `.rela.plt` `R_X86_64_JUMP_SLOT` entries. Shared-library GOT slots, other relocation types, and alternate relocation-section names are not protected.
- A missing `.rela.plt` leaves the protected-entry list empty and allows execution. Invalid metadata encountered by the parser terminates the process.
- Loader approval depends on the assignment's Pin/glibc environment, available symbol names, and a recognizable frame within a 64-frame backtrace. An unrecognized legitimate loader update will be rejected.
- The monitor covers writes exposed through the instrumented instruction memory operands. It does not separately intercept kernel writes into application buffers, such as those performed by a system call.
- Each checked operand scans the protected-entry vector linearly. Backtracing occurs only when a protected slot overlaps the write.
- `-o` selects the report file (default: `part4.out`). `-debug 1` enables standard-error checkpoints. Normal completion closes the file without producing a success summary.

## Important Pin APIs

| API | Use in this implementation |
| --- | --- |
| `PIN_InitSymbols` | Enable symbol lookup for the approved loader frame. |
| `PIN_Init`, `PIN_StartProgram` | Initialize Pin and start the target. |
| `IMG_AddInstrumentFunction`, `IMG_IsMainExecutable`, `IMG_Name` | Register image-load handling, select the main executable, and obtain its file path. |
| `IMG_LoadOffset` | Obtain the load bias added to each ELF GOT virtual address. |
| `INS_AddInstrumentFunction` | Register instruction instrumentation across the target and its libraries. |
| `INS_MemoryOperandCount`, `INS_MemoryOperandIsWritten` | Enumerate and select written memory operands. |
| `INS_InsertPredicatedCall`, `IPOINT_BEFORE` | Check writes before execution, subject to Pin's instruction predication. |
| `IARG_INST_PTR`, `IARG_MEMORYOP_EA`, `IARG_MEMORYOP_SIZE`, `IARG_CONST_CONTEXT`, `IARG_END` | Supply the instruction address, operand destination/size, and context to the checker. |
| `PIN_LockClient`, `PIN_UnlockClient` | Protect backtrace and image/routine lookup in analysis. |
| `PIN_Backtrace` | Collect the stack frames used to classify a GOT write. |
| `IMG_FindByAddress`, `IMG_Valid`, `IMG_IsInterpreter` | Verify that a candidate approval frame belongs to the dynamic interpreter. |
| `RTN_FindNameByAddress` | Match the frame's routine name against `_dl_rtld_di_serinfo`. |
| `PIN_ExitProcess` | Stop execution on metadata errors or suspicious writes. |
| `PIN_AddFiniFunction` | Register output-file cleanup. |
| `KNOB<std::string>`, `KNOB<BOOL>`, `KNOB_MODE_WRITEONCE`, `KNOB::Value`, `KNOB_BASE::StringKnobSummary` | Define/read diagnostic and debug options and display option help. |

## Important ELFIO APIs and ELF records

| API or record | Use in this implementation |
| --- | --- |
| `ELFIO::elfio`, `elfio::load` | Load the main executable's ELF metadata. |
| `get_class`, `get_machine`, `get_encoding`, `get_type` | Validate architecture, encoding, and ELF type before decoding raw records. |
| `reader.sections[name]`, `reader.sections[index]`, `reader.sections.size()` | Find the relocation section and follow checked links to symbol/string tables. |
| `section::get_type`, `get_entry_size`, `get_size`, `get_link` | Validate section types, record layout, and linked-section indices. |
| `section::get_data` | Access relocation, symbol, and string section bytes. |
| `Elf64_Rela::r_offset`, `Elf64_Rela::r_info` | Extract the ELF GOT virtual address, relocation type, and symbol index. |
| `Elf64_Sym::st_name` | Locate the symbol name in the linked string table. |
| `R_X86_64_JUMP_SLOT` | Select the protected PLT/GOT relocation type. |

This tool does not use ELFIO's relocation or symbol accessor classes; it decodes the validated section data directly.

## Build

- mkdir obj-intel64
- make -e obj-intel64/part1.so

## Run

- pin -t obj-intel64/part4.so -- ls

Optional debugging:
- pin -t obj-intel64/part4.so -debug 1 -- ls
- pin -t obj-intel64/part4.so -debug 1 -- ls 2>debug.log # To output log to own file

