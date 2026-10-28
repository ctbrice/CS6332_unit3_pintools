# Part 2: Parse GOT relocations

## Implementation approach

`part2.cpp` is a standalone ELFIO program accepting one ELF file path. It validates that the input is a little-endian x86-64 `ET_EXEC` or `ET_DYN` file, locates `.rela.plt`, and checks its relocation-record layout and linked-section index.

It enumerates relocations with `relocation_section_accessor`, keeps only `R_X86_64_JUMP_SLOT`, and follows the relocation section's `sh_link` to its symbol table. `symbol_section_accessor` resolves each relocation's symbol index to a name. Each protected entry retains its own relocation offset and symbol name. The entries are sorted by offset and printed as a table, preceded by the first and last slot start addresses.

## Assumptions and limitations

- Only `.rela.plt` `R_X86_64_JUMP_SLOT` entries are reported. Other relocation sections/types and other architectures are outside this implementation's scope.
- Relocation offsets are ELF virtual addresses, not file offsets or resolved function addresses. PIE/shared-object runtime addresses require adding a load bias; this standalone program does not determine one.
- Each x86-64 GOT slot holds an eight-byte pointer. The printed range summarizes slot start addresses and does not imply that gaps are protected or include the final slot's full extent.
- Missing `.rela.plt` or no matching relocations is a successful empty result. Invalid inputs or failed relocation/symbol reads return status 1.
- This part uses ELFIO and does not use Pin.

## Important ELFIO APIs

| API | Use in this implementation |
| --- | --- |
| `ELFIO::elfio`, `elfio::load` | Load and parse the supplied ELF file. |
| `get_class`, `get_machine`, `get_encoding`, `get_type` | Validate the ELF architecture, byte order, and file type. |
| `reader.sections[name]`, `reader.sections[index]`, `reader.sections.size()` | Locate `.rela.plt` and its linked symbol table, checking the section index. |
| `section::get_type`, `get_entry_size`, `get_size`, `get_link` | Validate relocation layout and follow `sh_link` to the symbol table. |
| `relocation_section_accessor`, `get_entries_num`, `get_entry` | Enumerate relocations and extract offset, symbol index, type, and addend. |
| `symbol_section_accessor`, `get_symbol` | Resolve a relocation's symbol index to its name and associated metadata. |
| `R_X86_64_JUMP_SLOT`, `Elf64_Rela`, `Elf64_Addr` | Select PLT/GOT relocations, validate record size, and represent slot addresses. |

## Build

- make part2

## Run

- ./part2 <elf_file>
