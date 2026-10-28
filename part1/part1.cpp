/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <fstream>
#include <vector>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;
using std::vector;

ofstream OutFile;

struct THREAD_DATA
{
	vector<ADDRINT> shadow_stack;
};

TLS_KEY tls_key;

static void PIN_FAST_ANALYSIS_CALL OnCall(THREADID thread_id, const CONTEXT *ctxt, UINT32 len)
{
	THREAD_DATA* thread_data = static_cast<THREAD_DATA*>(PIN_GetThreadData(tls_key, thread_id));
	if (thread_data == 0)
	{
		cerr << "Shadow stack creation error" << endl;
		PIN_ExitProcess(1);
		return;
	}

	ADDRINT rip = PIN_GetContextReg(ctxt, REG_RIP);
	thread_data->shadow_stack.push_back(rip + len);
}

static void PIN_FAST_ANALYSIS_CALL OnReturn(THREADID thread_id, const CONTEXT *ctxt)
{
	THREAD_DATA* thread_data = static_cast<THREAD_DATA*>(PIN_GetThreadData(tls_key, thread_id));
	if (thread_data == 0)
	{
		cerr << "Possible hijack. Shadow stack uninitialized." << endl;
		PIN_ExitProcess(1);
		return;
	}

	ADDRINT rsp = PIN_GetContextReg(ctxt, REG_RSP);
	ADDRINT actual_return_address = 0;
	// Before RET, target is at top of app stack
	if (PIN_SafeCopy(&actual_return_address, reinterpret_cast<const VOID*>(rsp),
							sizeof(actual_return_address)) != sizeof(actual_return_address))
	{
		cerr << "Possible hijack. Unable to read return target." << endl;
		PIN_ExitProcess(1);
		return;
	}

	if (thread_data->shadow_stack.empty())
	{
		cerr << "Possible hijack. Empty shadow stack." << endl;
		PIN_ExitProcess(1);
		return;
	}

	// Reject bad returns before changing shadow stack.
	ADDRINT expected_return_address = thread_data->shadow_stack.back();
	if (actual_return_address != expected_return_address)
	{
		cerr << "Possible hijack. Expected return target "
				<< std::hex
				<< expected_return_address << ", got " << actual_return_address
				<< std::dec << endl;
		PIN_ExitProcess(1);
		return;
	}

	thread_data->shadow_stack.pop_back();
}

// Allocate independent thread shadow stack
VOID ThreadStart(THREADID thread_id, CONTEXT* ctxt, INT32 flags, VOID* v)
{
	THREAD_DATA* thread_data = new THREAD_DATA;
	if (!PIN_SetThreadData(tls_key, thread_data, thread_id))
	{
		delete thread_data;
		cerr << "Unable to initialize shadow stack for thread" << endl;
		PIN_ExitProcess(1);
	}
}

// Release thread state
VOID ThreadFini(THREADID thread_id, const CONTEXT* ctxt, INT32 code, VOID* v)
{
	THREAD_DATA* thread_data = static_cast<THREAD_DATA*>(PIN_GetThreadData(tls_key, thread_id));
	delete thread_data;
}

VOID Trace(TRACE trace, VOID* v)
{
    // Visit every basic block  in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		for (auto ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			if(INS_IsCall(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnCall),
					IARG_THREAD_ID,
					IARG_CONST_CONTEXT,
					IARG_UINT32, INS_Size(ins),
					IARG_END);
			}
			else if (INS_IsRet(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnReturn),
					IARG_THREAD_ID,
					IARG_CONST_CONTEXT,
					IARG_END);
			}
		}
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool checks call and return addresses against a shadow stack" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    tls_key = PIN_CreateThreadDataKey(0);
    if (tls_key == INVALID_TLS_KEY)
    {
	    cerr << "Pin thread-local storage key error" << endl;
	    return 1;
    }

	// Creates and destorys seperate shadow stacks for each application thread
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

