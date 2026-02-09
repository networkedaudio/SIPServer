#ifndef _AES67COUNTERS
#define _AES67COUNTERS
typedef struct {
    int bufs;
	int chars;
    int caps;
    int objs;
    int errs;
    int structs;
    int samples;
    int memory;
    int events;
    int messages;
    int features;
    int gobjects;
	int debugs;
	int stats;
} G_alloc_counts;

// -- need to define the following in c file --
extern volatile G_alloc_counts g_alloc_counts;	// declared volatile and accessed atomically to avoid miscounts due to threading
#endif