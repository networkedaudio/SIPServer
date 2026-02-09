// Wrappers to track allocations/deallocations (debug)
// allows display the counters from the CLI : use "aes67 allocs"
// also to wrap sensitive gstreamer calls with mutexes as recommended by gst documentation
//
// to use, prefix functions that are allocators with AL_  and deallocators with DA_. Most AL DA can use mutexes as well
// MU_ just mutexes the call with an appropriate mutex (hardcoded here)
//
// NB - the dealloc/deref  wrappers always check if the passed ptr is NULL first
//
// todo:
// - use flags to remove mutexes
// - use flags to disable counters
//
// Copyright GERRAudio 2025-2026
//
#ifndef G_WRAP
#define G_WRAP

#include "aes67_counters.h"
#include <glib.h>
#include <gst/app/gstappsink.h>
#include <gst/audio/audio-channels.h>
#include <gst/gst.h>
#include <stdarg.h>

// specialized mutexes, must be declared and initialized in c module where MU_ functions are used

// extern switch_mutex_t *general_pipl_lock;

// extern switch_mutex_t *alloc_mcp_lock;
// extern switch_mutex_t *alloc_bkup_lock;

// Atomic incr/decr for debugging only
// forces serialization of counters
// slower and not useful except for debug but validates leaks
// can be changed if performance impacted (not likely)
#define ATOMIC_COUNTS 1
#ifdef ATOMIC_COUNTS
#include <glib.h>
#define G_ATOMIC_LOCK_FREE
inline void g_atomic_int_dec(int *i) { g_atomic_int_add(i, -1); }
#define accounting_incr(c) g_atomic_int_inc(&c)
#define accounting_decr(c) g_atomic_int_dec(&c)
#else
#define accounting_incr(c) (c++)
#define accounting_decr(c) (c--)
#endif

// --- Macro for allocation wrappers ---
#define G_WRAP_ALLOC(ret_type, func, counter, tp1, p1)                                                                 \
	inline ret_type AL_##func(tp1 p1)                                                                                  \
	{                                                                                                                  \
		ret_type _ret = func(p1);                                                                                      \
		if (_ret) accounting_incr(g_alloc_counts.counter);                                                             \
		return _ret;                                                                                                   \
	}

// with mutex
#define G_WRAP_ALLOC_M(ret_type, func, counter, tp1, p1, l)                                                            \
	inline ret_type AL_##func(tp1 p1)                                                                                  \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type _ret = func(p1);                                                                                      \
		if (_ret) accounting_incr(g_alloc_counts.counter);                                                             \
		switch_mutex_unlock(l);                                                                                        \
		return _ret;                                                                                                   \
	}

// allocators
#define G_WRAP_ALLOC2(ret_type, func, counter, tp1, p1, tp2, p2)                                                       \
	inline ret_type AL_##func(tp1 p1, tp2 p2)                                                                          \
	{                                                                                                                  \
		ret_type _ret = func(p1, p2);                                                                                  \
		if (_ret) accounting_incr(g_alloc_counts.counter);                                                             \
		return _ret;                                                                                                   \
	}
// with mutex
#define G_WRAP_ALLOC2_M(ret_type, func, counter, tp1, p1, tp2, p2, l)                                                  \
	inline ret_type AL_##func(tp1 p1, tp2 p2)                                                                          \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type _ret = func(p1, p2);                                                                                  \
		if (_ret) accounting_incr(g_alloc_counts.counter);                                                             \
		switch_mutex_unlock(l);                                                                                        \
		return _ret;                                                                                                   \
	}

#define G_WRAP_ALLOC3(ret_type, func, counter, tp1, p1, tp2, p2, tp3, p3)                                              \
	inline ret_type AL_##func(tp1 p1, tp2 p2, tp3 p3)                                                                  \
	{                                                                                                                  \
		ret_type _ret = func(p1, p2, p3);                                                                              \
		if (_ret) accounting_incr(g_alloc_counts.counter);                                                             \
		return _ret;                                                                                                   \
	}
// with mutex
#define G_WRAP_ALLOC3_M(ret_type, func, counter, tp1, p1, tp2, p2, tp3, p3, l)                                         \
	inline ret_type AL_##func(tp1 p1, tp2 p2, tp3 p3)                                                                  \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type _ret = func(p1, p2, p3);                                                                              \
		if (_ret) accounting_incr(g_alloc_counts.counter);                                                             \
		switch_mutex_unlock(l);                                                                                        \
		return _ret;                                                                                                   \
	}

#define G_WRAP_ALLOC4(ret_type, func, counter, tp1, p1, tp2, p2, tp3, p3, tp4, p4)                                     \
	inline ret_type AL_##func(tp1 p1, tp2 p2, tp3 p3, tp4 p4)                                                          \
	{                                                                                                                  \
		ret_type _ret = func(p1, p2, p3, p4);                                                                          \
		if (_ret) accounting_incr(g_alloc_counts.counter);                                                             \
		return _ret;                                                                                                   \
	}

#define G_WRAP_ALLOC7(ret_type, func, counter, tp1, p1, tp2, p2, tp3, p3, tp4, p4, tp5, p5, tp6, p6, tp7, p7)          \
	inline ret_type AL_##func(tp1 p1, tp2 p2, tp3 p3, tp4 p4, tp5 p5, tp6 p6, tp7 p7)                                  \
	{                                                                                                                  \
		ret_type _ret = func(p1, p2, p3, p4, p5, p6, p7);                                                              \
		if (_ret) accounting_incr(g_alloc_counts.counter);                                                             \
		return _ret;                                                                                                   \
	}

// TODO define
// G_WRAP_ALLOC2(GstPad *, gst_element_get_request_pad, pads, GstElement *, e, const gchar *, n)
// G_WRAP_ALLOC2(GstPad *, gst_element_get_static_pad, pads, GstElement *, e, const gchar *, n)
// G_WRAP_ALLOC(GstPad *, gst_pad_get_peer, pads, GstPad *, p)

// used to wrap deallocators to set ptr to NULL
#define DEC_objs_forceNULL(a)                                                                                          \
	do {                                                                                                               \
		if (a) {                                                                                                       \
			DA_dec_objs(a);                                                                                            \
			a = NULL;                                                                                                  \
		}                                                                                                              \
	} while (0);

// --- Macro for deallocation wrappers ---
// the nulling will not work unless I do weird & stuff - worked around it
#define G_WRAP_FREE(fname, counter, arg_type)                                                                          \
	inline void DA_##fname(arg_type p)                                                                                 \
	{                                                                                                                  \
		if (p != NULL) {                                                                                               \
			fname(p);                                                                                                  \
			accounting_decr(g_alloc_counts.counter);                                                                   \
		}                                                                                                              \
	}

//
// ==== incr/decr to use when wrapping is undesired
// --- Macro for increment-only wrappers (for manual tracking) ---
#define G_WRAP_INC(counter, name, t, p)                                                                                \
	inline void AL_##name(t p) { accounting_incr(g_alloc_counts.counter); }
// --- Sample increment wrapper ---
// G_WRAP_INC(samples, cnt_samples, GstSample *, p)

// --- Macro for decrement-only wrappers (for manual tracking) ---
// the nulling will not work due to the function
#define G_WRAP_DEC(counter, name, t, p)                                                                                \
	inline void DA_##name(t p)                                                                                         \
	{                                                                                                                  \
		if (p) { accounting_decr(g_alloc_counts.counter); }                                                            \
	}

// --- Macro for decrement-only wrappers no nulling (for manual tracking and accounting) ---
// can be disabled
#define COUNT_OBJS 1
#ifdef COUNT_OBJS
#define G_WRAP_DECNN(counter, name, t, p)                                                                              \
	inline void DA_NoNulling_##name(t p) { accounting_decr(g_alloc_counts.counter); }
#else
#define G_WRAP_DECNN(counter, name, t, p)                                                                              \
	inline void DA_NoNulling_##name(t p) { ; }
#endif

//==== Mutex wrappers
//
#define MU_WRAP1(ret_type, fname, tp1, p1, l)                                                                          \
	inline ret_type MU_##fname(tp1 p1)                                                                                 \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type retval = fname(p1);                                                                                   \
		switch_mutex_unlock(l);                                                                                        \
		return retval;                                                                                                 \
	}

// void return
#define MU_WRAPV1c(fname, tp1, p1, l)                                                                                  \
	inline void MUc_##fname(tp1 p1)                                                                                    \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		fname(p1);                                                                                                     \
		switch_mutex_unlock(l);                                                                                        \
	}

#define MU_WRAPV1p(fname, tp1, p1, l)                                                                                  \
	inline void MUp_##fname(tp1 p1)                                                                                    \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		fname(p1);                                                                                                     \
		switch_mutex_unlock(l);                                                                                        \
	}

#define MU_WRAP2(ret_type, fname, tp1, p1, tp2, p2, l)                                                                 \
	inline ret_type MU_##fname(tp1 p1, tp2 p2)                                                                         \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type retval = fname(p1, p2);                                                                               \
		switch_mutex_unlock(l);                                                                                        \
		return retval;                                                                                                 \
	}

// void return
#define MU_WRAPV2(fname, tp1, p1, tp2, p2, l)                                                                          \
	inline void MU_##fname(tp1 p1, tp2 p2)                                                                             \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		fname(p1, p2);                                                                                                 \
		switch_mutex_unlock(l);                                                                                        \
	}

#define MU_WRAPV2p(fname, tp1, p1, tp2, p2, l)                                                                         \
	inline void MUp_##fname(tp1 p1, tp2 p2)                                                                            \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		fname(p1, p2);                                                                                                 \
		switch_mutex_unlock(l);                                                                                        \
	}

// MU_WRAPV2p(gst_element_release_request_pad, GstElement *, element, GstPad *, p, general_pipl_lock)

#define MU_WRAP3(ret_type, fname, tp1, p1, tp2, p2, tp3, p3, l)                                                        \
	inline ret_type MU_##fname(tp1 p1, tp2 p2, tp3 p3)                                                                 \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type retval = fname(p1, p2, p3);                                                                           \
		switch_mutex_unlock(l);                                                                                        \
	}

#define MU_WRAP3S(ret_type, fname, t1, p1, t2, p2, t3, p3, l)                                                          \
	inline ret_type MU3_##fname(t1 p1, t2 p2, t3 p3)                                                                   \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type _result = fname(p1, p2, p3);                                                                          \
		switch_mutex_unlock(l);                                                                                        \
		return _result;                                                                                                \
	}

// void return
#define MU_WRAPV3(fname, tp1, p1, tp2, p2, tp3, p3, l)                                                                 \
	inline void MU_##fname(tp1 p1, tp2 p2, tp3 p3)                                                                     \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		fname(p1, p2, p3);                                                                                             \
		switch_mutex_unlock(l);                                                                                        \
	}

#define MU_WRAP4(ret_type, fname, tp1, p1, tp2, p2, tp3, p3, tp4, p4, l)                                               \
	inline ret_type MU_##fname(tp1 p1, tp2 p2, tp3 p3, tp4 p4)                                                         \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type retval = fname(p1, p2, p3, p4);                                                                       \
		switch_mutex_unlock(l);                                                                                        \
		return retval;                                                                                                 \
	}

#define MU_WRAP7(ret_type, fname, t1, p1, t2, p2, t3, p3, t4, p4, t5, p5, t6, p6, t7, p7, l)                           \
	inline ret_type MU_##fname(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5, t6 p6, t7 p7)                                        \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type _result = fname(p1, p2, p3, p4, p5, p6, p7);                                                          \
		switch_mutex_unlock(l);                                                                                        \
		return _result;                                                                                                \
	}

#define MU_WRAP8S(ret_type, fname, t1, p1, t2, p2, t3, p3, t4, p4, t5, p5, t6, p6, t7, p7, t8, p8, l)                  \
	inline ret_type MU8_##fname(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5, t6 p6, t7 p7, t8 p8)                                \
	{                                                                                                                  \
		switch_mutex_lock(l);                                                                                          \
		ret_type _result = fname(p1, p2, p3, p4, p5, p6, p7, p8);                                                      \
		switch_mutex_unlock(l);                                                                                        \
		return _result;                                                                                                \
	}

// ===
// gst functions that may require mutexes
//
//  === memcpy lock
// void *memcpy(void *dest, const void *src, size_t n);
// MU_WRAPV3(memcpy, void *, dest, const void *, src, size_t, n, alloc_mcp_lock)

// ===element (obj) locks

// MU_WRAP2(gboolean, gst_bin_add, GstBin *, bin, GstElement *, element, general_pipl_lock)

#define MU_g_object_set(p1, ...)                                                                                       \
	do {                                                                                                               \
		switch_mutex_lock(alloc_elem_lock);                                                                            \
		g_object_set(p1, __VA_ARGS__);                                                                                 \
		switch_mutex_unlock(alloc_elem_lock);                                                                          \
	} while (0)

// void gst_bin_add_many (GstBin *bin, GstElement *element_1, ...);
#define MU_gst_bin_add_many(p1, ...)                                                                                   \
	do {                                                                                                               \
		switch_mutex_lock(alloc_elem_lock);                                                                            \
		gst_bin_add_many(p1, __VA_ARGS__);                                                                             \
		switch_mutex_unlock(alloc_elem_lock);                                                                          \
	} while (0)

// G_WRAP_INC(objs, cnt_objs, gpointer, p)
//  chars
// G_WRAP_INC(chars, cnt_chars, gchar *, p)

G_WRAP_FREE(g_free, chars, gpointer)
// G_WRAP_ALLOC(gpointer, g_malloc0, chars, gsize, c)
// G_WRAP_ALLOC(gchar *, g_strdup, chars, gchar *, str)
// G_WRAP_ALLOC(gchar *, gst_structure_to_string, chars, const GstStructure *, s)

// --- inc/dec wrappers ---
// G_WRAP_INC(bufs, cnt_bufs, GstStructure *, p)
G_WRAP_INC(samples, cnt_samples, GstSample *, p)
G_WRAP_DEC(bufs, dec_bufs, GstBuffer *, p)
G_WRAP_DECNN(bufs, dec_bufs, GstBuffer *, p)
G_WRAP_DECNN(objs, dec_objs, GstElement *, p)
G_WRAP_DECNN(caps, dec_caps, GstCaps *, p)
// G_WRAP_DECNN(chars, dec_chars, gchar *, c)

// --- Structure wrappers ---
G_WRAP_INC(structs, cnt_structs, GstStructure *, p)
G_WRAP_FREE(gst_structure_free, structs, GstStructure *)

G_WRAP_ALLOC(GstStructure *, gst_structure_copy, structs, const GstStructure *, s)
G_WRAP_ALLOC(GstStructure *, gst_structure_new_empty, structs, const gchar *, name)
//
// no macro for variadic function below
//
inline GstStructure *AL_gst_structure_new(const gchar *name, const gchar *first, ...)
{
	va_list args;
	va_start(args, first);
	GstStructure *s = gst_structure_new_valist(name, first, args);
	va_end(args);
	if (s) g_alloc_counts.structs++;
	return s;
}

// --- Error wrappers ---
G_WRAP_INC(errs, cnt_errs, GError *, p)
G_WRAP_FREE(g_error_free, errs, GError *)

// --- Object wrappers ---
G_WRAP_FREE(gst_object_unref, objs, GstObject *)

G_WRAP_DEC(objs, dec_objs, GstObject *, p)
G_WRAP_DEC(caps, dec_caps, GstCaps *, p)
G_WRAP_DEC(samples, dec_samples, GstSample *, p)

// G_WRAP_INC(objs, cnt_objs, GstObject *, p)
G_WRAP_INC(objs, cnt_caps, GstCaps *, p)

G_WRAP_ALLOC(GstBus *, gst_pipeline_get_bus, objs, GstPipeline *, b)
G_WRAP_ALLOC2(GstElement *, gst_bin_get_by_name, objs, GstBin *, bin, const gchar *, n)
G_WRAP_ALLOC(GstElement *, gst_pipeline_new, objs, const gchar *, n)
// Add to document 3
G_WRAP_ALLOC3(GstBuffer *, gst_buffer_new_allocate, bufs, GstAllocator *, allocator, gsize, size, GstAllocationParams *, params)
G_WRAP_ALLOC2(GstElement *, gst_element_factory_make, objs, const gchar *, factoryname, const gchar *, name)
// G_WRAP_ALLOC2(GstPad *, gst_element_get_static_pad, objs, GstElement *, e, const gchar *, n)
// G_WRAP_ALLOC2(GstPad *, gst_element_request_pad_simple, objs, GstElement *, e, const gchar *, n)
// G_WRAP_ALLOC(GstPad *, gst_pad_get_peer, objs, GstPad *, p)
// G_WRAP_ALLOC2(GstSample *, gst_app_sink_try_pull_sample, samples, GstAppSink *, sink, GstClockTime, timeout)

G_WRAP_ALLOC2(GstPad *, gst_element_get_request_pad, objs, GstElement *, e, const gchar *, n)
G_WRAP_ALLOC2(GstPad *, gst_element_request_pad_simple, objs, GstElement *, e, const gchar *, n)
G_WRAP_ALLOC2(GstPad *, gst_element_get_static_pad, objs, GstElement *, e, const gchar *, n)
G_WRAP_ALLOC(GstPad *, gst_pad_get_peer, objs, GstPad *, p)
// Add after other pad wrappers

// ===pipeline locks

// gboolean gst_pipeline_set_clock(GstPipeline *pipeline, GstClock *clock);
// MU_WRAP2(gboolean, gst_pipeline_set_clock, GstPipeline *, p, GstClock *, c, general_pipl_lock)
// void gst_pipeline_use_clock(GstPipeline *pipeline, GstClock *clock);
// MU_WRAPV2(gst_pipeline_use_clock, GstPipeline *, pipeline, GstClock *, clock, general_pipl_lock)
// gst_object_unref(GST_OBJECT(stream->pipeline));
// MU_WRAPV1p(gst_object_unref, gpointer, pipeline, general_pipl_lock)
// gboolean gst_bin_remove(GstBin *bin, GstElement *element);
// MU_WRAP2(gboolean, gst_bin_remove, GstBin *, bin, GstElement *, element, general_pipl_lock)
// GstStateChangeReturn gst_element_get_state(GstElement *e, GstState *s,GstState *pending, GstClockTime timeout);
// MU_WRAP4(GstStateChangeReturn, gst_element_get_state, GstElement *, e, GstState *, s, GstState *, p, GstClockTime,t, general_pipl_lock)
// gboolean gst_bus_remove_watch(GstBus *bus);
// MU_WRAP1(gboolean, gst_bus_remove_watch, GstBus *, bus, general_pipl_lock)
// GstObject* gst_element_get_parent(GstElement *element);
G_WRAP_ALLOC(GstObject *, gst_element_get_parent, objs, GstElement *, e)
// --- Sample  wrappers ---
G_WRAP_FREE(gst_sample_unref, samples, GstSample *)

// --- caps wrappers ---
G_WRAP_FREE(gst_caps_unref, caps, GstCaps *)
G_WRAP_ALLOC(GstCaps *, gst_caps_copy, caps, GstCaps *, c)

// --- buffer wrapper ---
G_WRAP_FREE(gst_buffer_unref, bufs, GstBuffer *)
// G_WRAP_ALLOC(GstBuffer *, gst_sample_get_buffer, bufs, GstBuffer *, b)

// Pad name allocation
G_WRAP_ALLOC(gchar *, gst_pad_get_name, chars, GstPad *, p)

// Clock allocations
G_WRAP_ALLOC(GstClock *, gst_element_get_clock, objs, GstElement *, e)

// Network string allocation
// G_WRAP_ALLOC(gchar *, g_inet_address_to_string, chars, GInetAddress *, addr)
// G_WRAP_ALLOC2(GstClock*, gst_ptp_clock_new, objs, const gchar*, name, guint, domain)

inline GstClock *AL_g_object_new_clock(GType object_type, const gchar *first_prop, ...)
{
	va_list args;
	va_start(args, first_prop);
	GstClock *clock = (GstClock *)g_object_new_valist(object_type, first_prop, args);
	va_end(args);
	if (clock) g_alloc_counts.objs++;
	return clock;
}
#endif
