/*
Copyright (C) 2001-present by Serge Lamikhov-Center

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <elfio/elfio.hpp>

using namespace ELFIO;

// Keep every slot individually: gaps between slots are not protected entries.
struct GotEntry {
    Elf64_Addr offset;
    std::string name;
};

int main( int argc, char** argv )
{
    if ( argc != 2 ) {
        std::cerr << "Usage: " << argv[0] << " <elf_file>\n";
        return 1;
    }

    elfio reader;
    if ( !reader.load( argv[1] ) ) {
        std::cerr << "Cannot open or parse ELF file: " << argv[1] << '\n';
        return 1;
    }

    // Relocation type numbers depend on the architecture.
    if ( reader.get_class() != ELFCLASS64 ||
         reader.get_machine() != EM_X86_64 ||
         reader.get_encoding() != ELFDATA2LSB ||
         (reader.get_type() != ET_EXEC && reader.get_type() != ET_DYN) ) {
        std::cerr << "Expected an x86-64 ELF executable or shared object.\n";
        return 1;
    }

    section* rela_plt = reader.sections[".rela.plt"];
    if ( rela_plt == nullptr ) {
        std::cout << "No .rela.plt section; no matching GOT entries.\n";
        return 0;
    }
    if ( rela_plt->get_type() != SHT_RELA ||
         rela_plt->get_entry_size() != sizeof(Elf64_Rela) ||
         rela_plt->get_size() % sizeof(Elf64_Rela) != 0 ||
         rela_plt->get_link() >= reader.sections.size() ) {
        std::cerr << "Invalid .rela.plt section.\n";
        return 1;
    }

    // sh_link identifies the symbol table used by these relocations.
    // Usually it is .dynsym; do not assume the regular .symtab is present.
    section* symbol_table = reader.sections[rela_plt->get_link()];
    const relocation_section_accessor relocations( reader, rela_plt );
    std::vector<GotEntry> protected_entries;

    for ( Elf_Xword i = 0; i < relocations.get_entries_num(); ++i ) {
        Elf64_Addr offset;
        Elf_Word symbol_index;
        unsigned int relocation_type;
        Elf_Sxword addend;
        if ( !relocations.get_entry( i, offset, symbol_index,
                                    relocation_type, addend ) ) {
            std::cerr << "Cannot read relocation " << i << ".\n";
            return 1;
        }
        if ( relocation_type != R_X86_64_JUMP_SLOT ) {
            continue;
        }

        // A symbol table is needed only for matching entries. Static binaries
        // can have other .rela.plt relocations without a symbol table.
        if ( symbol_table->get_type() != SHT_DYNSYM &&
             symbol_table->get_type() != SHT_SYMTAB ) {
            std::cerr << "Relocations do not link to a symbol table.\n";
            return 1;
        }
        const symbol_section_accessor symbols( reader, symbol_table );

        std::string name;
        Elf64_Addr value;
        Elf_Xword size;
        unsigned char bind, type, other;
        Elf_Half section_index;
        if ( !symbols.get_symbol( symbol_index, name, value, size, bind,
                                  type, section_index, other ) ) {
            std::cerr << "Cannot resolve symbol for relocation " << i << ".\n";
            return 1;
        }

        // r_offset is the GOT slot's address, not the symbol's value.
        // Each x86-64 slot holds an 8-byte pointer. For PIE/shared objects,
        // the runtime load bias must be added to this ELF virtual address.
        protected_entries.push_back( {offset, name} );
    }

    if ( protected_entries.empty() ) {
        std::cout << "No R_X86_64_JUMP_SLOT entries in .rela.plt.\n";
        return 0;
    }

    std::sort( protected_entries.begin(), protected_entries.end(),
               []( const GotEntry& a, const GotEntry& b ) {
                   return a.offset < b.offset;
               } );

    // These are the first and last slot START addresses, not a byte range.
    std::cout << std::hex << std::setfill('0')
              << "GOT range: 0x" << std::setw(12)
              << protected_entries.front().offset
              << " ~ 0x" << std::setw(12)
              << protected_entries.back().offset << "\n\n"
              << "Offset          Symbol name\n"
              << "---------------------------------\n";
    for ( const GotEntry& entry : protected_entries ) {
        std::cout << std::setw(12) << entry.offset
                  << "    " << entry.name << '\n';
    }
    return 0;
}

