/*
 * Part 4: guard the main executable's GOT with PIE and ASLR support.
 * Build as a Linux Intel64 Pintool with ELFIO on the include path, as in Part 2.
 */
#include "pin.H"
#include <elfio/elfio.hpp>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace ELFIO;

struct GotEntry {
    ADDRINT address;             // Runtime address, including any PIE load bias.
    std::string name;
};

// Initialized when the main executable loads, before its code executes.
static std::vector<GotEntry> protectedEntries;
static std::ofstream outFile;
KNOB<std::string> outputFile(KNOB_MODE_WRITEONCE, "pintool", "o",
                             "part4.out", "part 4 diagnostic file");
KNOB<BOOL> debugLog(KNOB_MODE_WRITEONCE, "pintool", "debug", "0",
                    "log load bias, GOT address translations, and guard checkpoints");

static VOID Debug(const char* message)
{
    // Flush each checkpoint so it survives a crash.
    if (debugLog.Value()) std::cerr << "GOT guard debug: " << message << std::endl;
}

static VOID MetadataError(const std::string& message)
{
    std::cerr << "GOT guard: " << message << std::endl;
    PIN_ExitProcess(1);          // Do not run with incomplete protection.
}

static VOID ImageLoad(IMG image, VOID*)
{
    if (!IMG_IsMainExecutable(image)) return;
    Debug("loading main executable ELF metadata");

    // Use the same ELF metadata as Part 2, retaining each slot individually.
    elfio reader;
    Debug("ELFIO reader constructed; obtaining executable path");
    const std::string executablePath = IMG_Name(image);
    Debug("calling ELFIO reader.load");
    if (!reader.load(executablePath)) {
        MetadataError("cannot read " + executablePath);
        return;
    }
    Debug("ELFIO reader.load returned; validating ELF header");
    if (reader.get_class() != ELFCLASS64 ||
        reader.get_machine() != EM_X86_64 ||
        reader.get_encoding() != ELFDATA2LSB ||
        (reader.get_type() != ET_EXEC && reader.get_type() != ET_DYN)) {
        MetadataError("expected an x86-64 ELF executable");
        return;
    }

    // Pin provides the difference between this image's runtime addresses and
    // its ELF link-time virtual addresses. This is the load bias, not simply
    // the address of .text or the lowest mapped address.
    //
    // PIE (ET_DYN): ASLR usually gives a different bias on each run.
    // Non-PIE (ET_EXEC): the usual fixed mapping has a bias of zero.
    // The same addition therefore handles both executable types.
    const ADDRINT loadBias = IMG_LoadOffset(image);
    if (debugLog.Value()) {
        std::cerr << "GOT guard debug: main executable=" << executablePath
                  << " type=" << (reader.get_type() == ET_DYN ? "PIE" : "non-PIE")
                  << std::hex << std::showbase << " load bias=" << loadBias
                  << std::dec << std::endl;
    }

    section* rela = reader.sections[".rela.plt"];
    Debug("looked up .rela.plt");
    if (rela == 0) {
        Debug("no .rela.plt entries to protect");
        return;
    }
    if (rela->get_type() != SHT_RELA ||
        rela->get_entry_size() != sizeof(Elf64_Rela) ||
        rela->get_size() % sizeof(Elf64_Rela) != 0 ||
        rela->get_link() >= reader.sections.size()) {
        MetadataError("invalid .rela.plt section");
        return;
    }

    section* symbolTable = reader.sections[rela->get_link()];
    if (symbolTable == 0 ||
        (symbolTable->get_type() != SHT_DYNSYM &&
         symbolTable->get_type() != SHT_SYMTAB) ||
        symbolTable->get_entry_size() != sizeof(Elf64_Sym) ||
        symbolTable->get_size() % sizeof(Elf64_Sym) != 0 ||
        symbolTable->get_link() >= reader.sections.size()) {
        MetadataError("invalid relocation symbol table");
        return;
    }
    section* strings = reader.sections[symbolTable->get_link()];
    if (strings == 0 || strings->get_type() != SHT_STRTAB) {
        MetadataError("invalid symbol string table");
        return;
    }

    // ELFIO loads the section bytes. Read only the ELF64 records needed here,
    // without relocation/symbol accessor calls. The ELF header check above
    // ensures these records use x86-64 little-endian layout.
    Debug("obtaining relocation, symbol, and string section bytes");
    const char* relocationData = rela->get_data();
    const char* symbolData = symbolTable->get_data();
    const char* stringData = strings->get_data();
    if (relocationData == 0 || symbolData == 0 || stringData == 0) {
        MetadataError("missing relocation, symbol, or string data");
        return;
    }

    Debug("reading ELF64 relocation records directly");
    const Elf_Xword relocationCount = rela->get_size() / sizeof(Elf64_Rela);
    const Elf_Xword symbolCount = symbolTable->get_size() / sizeof(Elf64_Sym);
    for (Elf_Xword i = 0; i < relocationCount; ++i) {
        // memcpy avoids assuming the section's byte buffer is aligned.
        Elf64_Rela relocation = {};
        std::memcpy(&relocation, relocationData + i * sizeof(relocation),
                    sizeof(relocation));
        const Elf_Word relocationType = static_cast<Elf_Word>(relocation.r_info);
        if (relocationType != R_X86_64_JUMP_SLOT) continue;

        // ELF64 r_info stores the symbol index in its upper 32 bits.
        const Elf_Xword symbolIndex = relocation.r_info >> 32;
        if (symbolIndex >= symbolCount) {
            MetadataError("relocation symbol index is out of bounds");
            return;
        }
        Elf64_Sym symbol = {};
        std::memcpy(&symbol, symbolData + symbolIndex * sizeof(symbol),
                    sizeof(symbol));
        const Elf_Xword nameStart = symbol.st_name;
        if (nameStart >= strings->get_size()) {
            MetadataError("symbol name offset is out of bounds");
            return;
        }

        // Find the terminating zero within the string table, so a malformed
        // name cannot make std::string read past the section.
        Elf_Xword nameEnd = nameStart;
        while (nameEnd < strings->get_size() && stringData[nameEnd] != '\0') {
            ++nameEnd;
        }
        if (nameEnd == strings->get_size()) {
            MetadataError("unterminated symbol name");
            return;
        }
        const std::string name(stringData + nameStart,
                               static_cast<std::size_t>(nameEnd - nameStart));

        // r_offset is a link-time virtual address, not a file offset.
        // Translate it once when the main image loads, before checking writes:
        //     runtime GOT address = ELF GOT virtual address + load bias
        // Example: 0x202018 + 0x555555554000 = 0x555555756018.
        const ADDRINT elfAddress = static_cast<ADDRINT>(relocation.r_offset);
        const ADDRINT runtimeAddress = elfAddress + loadBias;
        protectedEntries.push_back({runtimeAddress, name});
        if (debugLog.Value()) {
            std::cerr << "GOT guard debug: symbol=" << name
                      << std::hex << std::showbase
                      << " ELF GOT=" << elfAddress
                      << " runtime GOT=" << runtimeAddress
                      << std::dec << std::endl;
        }
    }
    Debug("finished loading GOT metadata");
}

static bool ApprovedLoaderContext(const CONTEXT* context)
{
    void* frames[64] = {};
    // Both stack unwinding and symbol/image lookup require the client lock.
    PIN_LockClient();
    Debug("entering PIN_Backtrace");
    const int count = PIN_Backtrace(context, frames, 64);
    Debug("PIN_Backtrace returned; looking up frame symbols");
    bool approved = false;

    for (int i = 0; i < count; ++i) {
        const ADDRINT address = reinterpret_cast<ADDRINT>(frames[i]);
        const IMG image = IMG_FindByAddress(address);
        // Require a loader frame: an application function with the same
        // name must not grant permission to write the GOT.
        if (!IMG_Valid(image) || !IMG_IsInterpreter(image)) continue;
        if (RTN_FindNameByAddress(address) == "_dl_rtld_di_serinfo") {
            approved = true;
            break;
        }
    }
    PIN_UnlockClient();
    Debug(approved ? "loader update approved" : "loader context not approved");
    return approved;
}

static VOID CheckWrite(ADDRINT instruction, ADDRINT destination, UINT32 size,
                      const CONTEXT* context)
{
    if (size == 0) return;
    for (const GotEntry& entry : protectedEntries) {
        // Both addresses are now runtime addresses. Do not add the bias here
        // again: entry.address was already translated in ImageLoad.
        // Ranges overlap if either starts inside the other. Subtraction
        // avoids overflowing destination + size. Each GOT slot is 8 bytes;
        // even a one-byte overwrite must be checked.
        const bool overlaps = destination <= entry.address
            ? entry.address - destination < size
            : destination - entry.address < 8;
        if (!overlaps) continue;
        if (debugLog.Value()) {
            std::cerr << std::hex << std::showbase
                      << "GOT guard debug: overlap instruction=" << instruction
                      << " destination=" << destination
                      << " GOT=" << entry.address << std::dec
                      << " size=" << size << std::endl;
        }
        if (ApprovedLoaderContext(context)) return;

        outFile << std::hex << std::showbase
                << "Attempted GOT overwrite: instruction=" << instruction
                << " destination=" << destination
                << " GOT entry=" << entry.address
                << " symbol=" << (entry.name.empty() ? "<unknown>" : entry.name)
                << std::dec << " write size=" << size << std::endl;
        std::cerr << "GOT overwrite detected; see " << outputFile.Value()
                  << std::endl;
        // IPOINT_BEFORE stops the attack before the write executes.
        // endl above flushes the report before terminating the process.
        PIN_ExitProcess(1);
        return;
    }
}

static VOID Instruction(INS instruction, VOID*)
{
    // This callback is serialized by Pin's client lock.
    static bool firstInstruction = true;
    if (firstInstruction) {
        Debug("instrumenting application instructions");
        firstInstruction = false;
    }
    // Instrument libraries too: an application's arbitrary write can be
    // performed by a helper such as memcpy.
    for (UINT32 operand = 0; operand < INS_MemoryOperandCount(instruction); ++operand) {
        if (!INS_MemoryOperandIsWritten(instruction, operand)) continue;
        INS_InsertPredicatedCall(instruction, IPOINT_BEFORE, AFUNPTR(CheckWrite),
                                 IARG_INST_PTR,
                                 IARG_MEMORYOP_EA, operand,
                                 IARG_MEMORYOP_SIZE, operand,
                                 IARG_CONST_CONTEXT, IARG_END);
    }
    // Predication skips nonexecuting writes, including zero-count REP.
    // Pin checks each executed REP iteration.
}

static VOID Fini(INT32, VOID*)
{
    outFile.close();
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();          // Needed to recognize the approved loader frame.
    if (PIN_Init(argc, argv)) {
        std::cerr << "Guard the main executable's GOT entries.\n"
                  << KNOB_BASE::StringKnobSummary() << std::endl;
        return 1;
    }
    outFile.open(outputFile.Value().c_str());
    if (!outFile) {
        std::cerr << "Cannot open " << outputFile.Value() << std::endl;
        return 1;
    }
    Debug("tool initialized; starting application");
    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}

