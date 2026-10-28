Overview
In this assignment, you will implement runtime defenses against two classes of binary attacks:

control-flow hijacking through corruption of return addresses; and
arbitrary-write attacks that attempt to overwrite the Global Offset Table (GOT).
You will implement these defenses without source-code access using the Intel Pin dynamic binary instrumentation framework. Pin allows you to instrument a binary at runtime and insert inline monitoring logic without recompiling the target program.

You will also use the ELFIO library to extract ELF relocation metadata and connect this static information to addresses observed during execution.

Learning objectives
After completing this assignment, you should be able to:

use Pin to instrument instructions at runtime;
identify dynamically executed memory-write instructions;
implement a runtime shadow stack;
parse ELF relocation information;
identify GOT entries from relocation metadata;
connect static ELF information with dynamically observed memory accesses;
distinguish legitimate dynamic-linker updates from suspicious GOT overwrites; and
translate ELF virtual addresses to runtime addresses for PIE binaries under ASLR.
The assignment progresses as follows:

Pin instrumentation
Shadow-stack enforcement
ELF relocation parsing
GOT write monitoring
PIE/ASLR-aware
GOT protection
Part 0: Your First Binary Instrumentation — 10 points
Extend the Pin inscount example so that your Pintool counts the number of dynamically executed instructions that perform a memory write.

For this part, count a memory-writing instruction once each time it executes, even if the instruction has more than one memory operand.

For example, if a memory-writing instruction executes 100 times, it contributes 100 to the final count.

Your tool should report the final count when the target program terminates.

Part 1: Implement a Shadow Stack — 35 points
The objective of this part is to implement a shadow stack using Pin.

A shadow stack is a well-known defense against control-flow hijacking attacks that corrupt return addresses stored on the normal program stack.

Basic algorithm
Your Pintool should implement the following logic:

For each call instruction:

determine the expected return address, i.e., the address of the instruction immediately following the call;
push that address onto the shadow stack.
For each ret instruction:

determine the return target that the program is about to use;
compare it with the expected return address stored at the top of the shadow stack.
If the addresses match:

pop the expected return address from the shadow stack;
allow execution to continue.
If the addresses do not match:

report a possible control-flow hijacking attack;
terminate the target process.
Conceptually:

call foo
Normal stack
return address
Shadow stack
expected return address
record
ret
Actual return target
matches expected target?
Allow return
Pop shadow stack
Match
Report attack
Terminate process
Mismatch
Your shadow stack must maintain correct call/return nesting for the supplied challenge programs.

For the attack binaries used in this assignment, you may assume conventional call/ret behavior. You are not required to support non-local control transfers such as C++ exception unwinding or setjmp/longjmp unless otherwise specified.

If your Pintool maintains state for multiple application threads, each thread must use an independent shadow stack rather than a single shared stack.

Evaluation note: Your Pintool will be evaluated using the aslr-* and rop-* challenge binaries as well as selected benign binaries from previous units.

Part 2: Parse ELF Relocations with ELFIO — 25 points
To protect GOT entries against arbitrary writes, you must first identify where those entries are located.

In this part, you will use the ELFIO library to parse ELF relocation information and identify GOT entries and their corresponding addresses.

For the GOT-related portions of this assignment, we focus on x86-64 ELF binaries.

Relocation information
The readelf --relocs command displays relocation entries contained in an ELF binary.

For example:

$ readelf --relocs /tmp/8-fs-aw-64

Relocation section '.rela.plt' at offset 0x4e0 contains 11 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 putchar@GLIBC_2.2.5 + 0
000000601020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000601030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000601038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000601040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000601048  000800000007 R_X86_64_JUMP_SLO 0000000000000000 prctl@GLIBC_2.2.5 + 0
000000601050  000900000007 R_X86_64_JUMP_SLO 0000000000000000 getegid@GLIBC_2.2.5 + 0
000000601058  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 setregid@GLIBC_2.2.5 + 0
000000601060  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 open@GLIBC_2.2.5 + 0
000000601068  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
For this assignment, we are primarily interested in PLT/GOT entries represented by R_X86_64_JUMP_SLOT relocations in .rela.plt.

The relocation offset identifies the virtual address of the corresponding GOT slot.

Required output
Write a program using ELFIO that produces output equivalent to the following:

$ ./part2 /tmp/8-fs-aw-64

GOT range: 0x000000601018 ~ 0x000000601068

Offset          Symbol name
---------------------------------
000000601018    putchar
000000601020    puts
000000601028    __stack_chk_fail
...
000000601068    exit
At minimum, your program must:

open and parse the ELF binary;
locate the relevant relocation section;
enumerate the relevant relocation entries;
obtain each relocation offset;
resolve the corresponding symbol name; and
report the protected GOT entries.
You may additionally report the minimum and maximum GOT addresses as a convenient summary.

However, for later parts, you should preserve the individual protected GOT entries, rather than assuming that every byte between the minimum and maximum addresses necessarily corresponds to a GOT entry.

Please refer to the ELFIO tutorial, the ELFIO manual, and the GNU readelf.c source for examples of parsing relocation information.

Part 3: Guard GOT Entries Against Arbitrary Writes — 60 points
You will now combine Pin instrumentation with the ELF metadata extracted in Part 2.

Your goal is to detect attempts by application code to overwrite protected GOT entries.

Background: legitimate GOT modification
With lazy dynamic linking, GOT entries may initially be unresolved. The dynamic loader updates these entries when functions are resolved for the first time.

During regular execution, a call path may include the glibc runtime resolver:

Regular execution captured using GDB:

 ► f 0   0x7ffff7deef11 _dl_runtime_resolve_xsavec+1
   f 1         0x400986 read_func+18
   f 2         0x400b08 input_func+14
   f 3         0x400b48 main+51
   f 4   0x7ffff7a2d840 __libc_start_main+240
When the target executes under Pin, the corresponding call path differs because Pin manages the target process and its libraries within its own runtime environment.

For example, a backtrace captured using PIN_Backtrace() may look like:

0x7f3671e6eb47 : _dl_rtld_di_serinfo
0x7f3671e76f8a : _dl_find_dso_for_object
0x4009d4       : read_func
0x400b08       : input_func
0x400b48       : main
0x7f365e497840 : __libc_start_main
0x4007e9       : _start
For the environment used in this assignment, a GOT modification originating from the expected Pin/dynamic-loader path containing _dl_rtld_di_serinfo() should be treated as a legitimate loader update.

An application-originated overwrite of a protected GOT entry should instead be treated as suspicious.

Required runtime policy
Your Pintool should implement the following logic for memory writes:

Instrument instructions that perform memory writes.

At runtime, determine the effective destination address of each write.

Determine the size of the memory write.

Check whether the memory region being written overlaps a protected GOT entry identified in Part 2.

If the write does not overlap a protected GOT entry:

allow execution to continue.
If the write does overlap a protected GOT entry:

determine whether the write occurs as part of an approved dynamic-loader operation.
If the write is legitimate:

allow execution to continue.
Otherwise:

report an attempted GOT overwrite;
terminate the process.
Conceptually:

Memory write
Protected
GOT entry?
Approved loader
context?
Yes
Allow execution
No
Allow execution
Yes
Report GOT overwrite
No
Terminate process
Your diagnostic output for a detected attack should include enough information to identify the event, such as:

the instruction address;
the destination address;
the protected GOT entry being modified; and
the associated symbol name, if available.
You do not need to reproduce this exact output format, but the information should be sufficient for debugging.

Evaluation note: At minimum, your Pintool should detect the arbitrary-write attacks exercised by 0-aw0-64 and 1-aw-64, while continuing to execute benign programs without false alarms.

The grading environment will use the same Pin/glibc environment provided for the assignment so that expected legitimate loader behavior is reproducible.

Part 4: Support Position-Independent Executables (PIE) — 45 points
Parts 2 and 3 assume that the relocation addresses obtained from the ELF binary correspond directly to the runtime addresses used by the process.

That assumption no longer holds for a Position-Independent Executable (PIE) running under ASLR.

Consider the following PIE binary:

$ readelf --relocs fs-no-binary-pie-64

Relocation section '.rela.plt' at offset 0x8a8 contains 19 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000202018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 getenv@GLIBC_2.2.5 + 0
000000202020  000300000007 R_X86_64_JUMP_SLO 0000000000000000 putchar@GLIBC_2.2.5 + 0
000000202028  000500000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000202030  000600000007 R_X86_64_JUMP_SLO 0000000000000000 fread@GLIBC_2.2.5 + 0
000000202038  000700000007 R_X86_64_JUMP_SLO 0000000000000000 write@GLIBC_2.2.5 + 0
000000202040  000800000007 R_X86_64_JUMP_SLO 0000000000000000 getpid@GLIBC_2.2.5 + 0
000000202048  000900000007 R_X86_64_JUMP_SLO 0000000000000000 fclose@GLIBC_2.2.5 + 0
000000202050  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 chdir@GLIBC_2.2.5 + 0
000000202058  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000202060  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000202068  000d00000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000202070  000e00000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000202078  001000000007 R_X86_64_JUMP_SLO 0000000000000000 prctl@GLIBC_2.2.5 + 0
000000202080  001100000007 R_X86_64_JUMP_SLO 0000000000000000 setregid@GLIBC_2.2.5 + 0
000000202088  001200000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
000000202090  001300000007 R_X86_64_JUMP_SLO 0000000000000000 open@GLIBC_2.2.5 + 0
000000202098  001400000007 R_X86_64_JUMP_SLO 0000000000000000 fopen@GLIBC_2.2.5 + 0
0000002020a0  001600000007 R_X86_64_JUMP_SLO 0000000000000000 getppid@GLIBC_2.2.5 + 0
The addresses reported in the ELF file are link-time virtual addresses. Because PIE binaries can be relocated by ASLR, the executable may be loaded at a different runtime base address each time it executes.

You therefore need to determine the executable image’s runtime load bias.

Conceptually:

runtime address = ELF virtual address + load bias
More precisely, the load bias represents the difference between the runtime mapping of the executable image and its link-time ELF virtual-address space.

For example:

ELF GOT entry
      |
      |  + runtime load bias
      v
runtime GOT address
      |
      v
Pin memory-write monitor
Required implementation
Modify your Part 3 solution so that it:

identifies the main executable image when it is loaded;
determines its runtime load address/load bias;
translates each GOT relocation address obtained from the ELF file into its corresponding runtime address;
monitors writes against these translated runtime GOT addresses; and
applies the same legitimate-loader versus suspicious-write policy developed in Part 3.
Do not assume that the .text section itself defines the relocation base. Your implementation should reason about the loaded executable image and its load bias.

Your Part 4 implementation must continue to support the non-PIE cases from Part 3.

Evaluation note: We will provide PIE testing binaries and corresponding exploits to verify your implementation.