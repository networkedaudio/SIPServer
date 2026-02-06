#include "aes67_api.h"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h> // For GetProcessHeaps if needed

/*
Optional memory cleansing - call be called programmatically from aes67 CLI
or alternately from CLI script in Freeswitch 
	"fsctl reclaim_mem"

For heap-specific cleanup, enumerate private heaps with GetProcessHeaps and call HeapCompact(hHeap, 0) on each
during idle periods; it coalesces free blocks but rarely shrinks the committed virtual address space and is mainly for
convenience as Windows auto-compacts on HeapFree

Call TrimWorkingSetIdle() periodically (e.g., every 30-60 seconds of idle) or on telephony idle detection; avoid during
active RTP/audio processing to prevent latency spikes from page faults. ​

Performance Considerations
Working set trimming works best for telephony DLLs with bursty allocations, as it reduces RSS (resident set size) by up
to 2/3 during idle without affecting virtual commit size.

Monitor with GetProcessMemoryInfo before/after to tune
frequency; excessive calls hurt perf. 
HeapCompact adds minimal overhead but offers little footprint reduction unless fragmented. ​
*/

volatile BOOL memcheck_active = TRUE;			//default is on

void CompactHeaps(void)
{
	HANDLE hHeap = GetProcessHeap();
	HeapCompact(hHeap, 0);

	// For private heaps: enumerate and compact each
	DWORD numHeaps;
	HANDLE *heaps = NULL;
	if (GetProcessHeaps(0, heaps) == 0) { // First pass for count
		numHeaps = GetProcessHeaps(0, NULL);
		heaps = HeapAlloc(GetProcessHeap(), 0, numHeaps * sizeof(HANDLE));
		GetProcessHeaps(numHeaps, heaps);
		for (DWORD i = 0; i < numHeaps; ++i) { HeapCompact(heaps[i], 0); }
		HeapFree(GetProcessHeap(), 0, heaps);
	}
}

/*
Windows treats both parameters as special when set to(SIZE_T)− 1(SIZE_T)−1
	: it attempts to remove as many pages as possible from the process working set,
	  effectively “emptying” it without changing virtual allocations
		  or destroying heap contents
				 .This is equivalent to calling EmptyWorkingSet on the process and is safe to trigger during genuine
			 idle periods to reduce resident memory pressure.
*/

void TrimCurrentProcessWorkingSet(void)
{
	HANDLE hProcess = GetCurrentProcess();

	// Optional: ensure the call succeeds; you might log or collect stats.
	if (!SetProcessWorkingSetSize(hProcess, (SIZE_T)-1, (SIZE_T)-1)) {
		// handle error if desired: GetLastError();
	}
}
#else
void CompactHeaps(void) { ; }
void TrimCurrentProcessWorkingSet(void) { ; }
#endif


long interval_min = INTERVAL_MIN;

// FreeSwitch calls this every 20 seconds by default -set in config files as an XML parameter, if not set it is 20secs
void heartbeat_callback(switch_event_t *event)
{
	static long unsigned call_count = 0;
	call_count++;
	if (call_count >=
		((3600L / 20L) * interval_min) / 60L) { // convert to number of 20 sec blips - careful about integer division
		call_count = 0;
		periodic_mem_check(TRUE); // force clear
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "AES67: Cleaning memory ---\n");
	}
}
