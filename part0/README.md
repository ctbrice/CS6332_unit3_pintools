# Part 0: Count memory-writing instructions

## Implementation approach

`part0.cpp` extends Pin's instruction-counting example. At instrumentation time, it walks each trace's basic blocks and counts instructions for which `INS_IsMemoryWrite` is true. It inserts one analysis call into each block containing writes. Each execution of that block adds its static number of memory-writing instructions to the running count, counting an instruction once rather than once per memory operand.

At normal application termination, the tool writes `Count <value>` to the output file. The `-o` knob selects the file; its default is `inscount.out`.

## Assumptions and limitations

- Counting occurs at basic-block granularity and assumes the block's instructions execute as counted. Faults or conditional/REP execution can make this differ from counting individually executed writes.
- The global `UINT64` counter is shared and unsynchronized; concurrent application threads can lose updates.
- A final report depends on Pin invoking the termination callback. The output stream is not checked for open failures.
- This part uses Pin and does not use ELFIO.

## Important Pin APIs

| API | Use in this implementation |
| --- | --- |
| `PIN_Init`, `PIN_StartProgram` | Initialize Pin and start the instrumented application. |
| `TRACE_AddInstrumentFunction` | Register the trace instrumentation callback. |
| `TRACE_BblHead`, `BBL_Valid`, `BBL_Next` | Traverse each trace's basic blocks. |
| `BBL_InsHead`, `INS_Valid`, `INS_Next` | Traverse instructions within a block. |
| `INS_IsMemoryWrite` | Identify instructions that write memory. |
| `BBL_InsertCall`, `IPOINT_ANYWHERE` | Insert a counting call that Pin can schedule within the block. |
| `PIN_FAST_ANALYSIS_CALL`, `IARG_FAST_ANALYSIS_CALL` | Use Pin's fast analysis calling convention for the counting callback. |
| `IARG_UINT32`, `IARG_END` | Pass the block's write-instruction count and terminate the argument list. |
| `PIN_AddFiniFunction` | Register the callback that writes and closes the report. |
| `KNOB<string>`, `KNOB_MODE_WRITEONCE`, `KNOB::Value`, `KNOB_BASE::StringKnobSummary` | Define/read the output option and display option help. |

## Build

- mkdir obj-intel64
- make -e obj-intel64/part0.so

## Run

- pin -t obj-intel64/part0.so -- ls
