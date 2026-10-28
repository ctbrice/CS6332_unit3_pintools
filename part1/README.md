# Part 1: Shadow stack

## Implementation approach

`part1.cpp` maintains an independent `vector<ADDRINT>` shadow stack for each application thread using Pin thread-local storage. Thread-start callbacks allocate the state, and thread-finish callbacks release it.

The trace callback instruments calls and returns before they execute. On a call, the tool reads `REG_RIP` and pushes `RIP + instruction length` as the expected return address. Before a return, it reads `REG_RSP` and safely copies the return target from the application stack. A matching target pops the shadow stack and allows execution to continue. Missing thread state, an unreadable target, an empty shadow stack, or a mismatch produces a diagnostic on standard error and terminates the process with status 1. Mismatch diagnostics include the expected and actual addresses.

## Assumptions and limitations

- Uses x86-64 registers and assumes conventional, nested call/return behavior.
- Does not reconcile exception unwinding, `setjmp`/`longjmp`, stack switching, or other transfers that bypass normal returns.
- Each thread starts with an empty shadow stack; a return without an observed matching call is rejected.
- The source declares an `-o` option with default `inscount.out`, but never opens or writes that file. Diagnostics go to standard error.
- This part does not use ELFIO.

## Important Pin APIs

| API | Use in this implementation |
| --- | --- |
| `PIN_Init`, `PIN_StartProgram` | Initialize Pin and start application execution. |
| `TRACE_AddInstrumentFunction` | Register call/return instrumentation. |
| `TRACE_BblHead`, `BBL_Valid`, `BBL_Next`, `BBL_InsHead`, `INS_Valid`, `INS_Next` | Traverse trace blocks and their instructions. |
| `INS_IsCall`, `INS_IsRet`, `INS_Size` | Identify calls/returns and obtain the call's instruction length. |
| `INS_InsertCall`, `IPOINT_BEFORE` | Invoke analysis before calls and returns execute. |
| `IARG_THREAD_ID`, `IARG_CONST_CONTEXT`, `IARG_UINT32`, `IARG_END` | Pass the thread ID, register context, and call length to analysis. |
| `PIN_GetContextReg`, `REG_RIP`, `REG_RSP` | Read the current instruction and stack pointers. |
| `PIN_SafeCopy` | Read the application return address and check that the complete address was copied. |
| `PIN_CreateThreadDataKey`, `INVALID_TLS_KEY` | Allocate and validate a TLS key. |
| `PIN_SetThreadData`, `PIN_GetThreadData` | Store and retrieve each thread's shadow stack. |
| `PIN_AddThreadStartFunction`, `PIN_AddThreadFiniFunction` | Allocate and destroy per-thread state. |
| `PIN_ExitProcess` | Terminate on a suspected hijack or initialization failure. |
| `KNOB<string>`, `KNOB_BASE::StringKnobSummary` | Declare the currently unused output option and print option help. |

The analysis functions are declared with `PIN_FAST_ANALYSIS_CALL`; their inserted calls do not specify `IARG_FAST_ANALYSIS_CALL`.

## Build

- mkdir obj-intel64
- make -e obj-intel64/part1.so

## Run

- pin -t obj-intel64/part1.so -- ls
