#include "aes67_api.h"
#include <gst/app/gstappsink.h>
#include <gst/audio/audio-channels.h>
#include <gst/net/net.h>

#include "aes67_alloc.h"					// allocation tracker and mutex wrappers
volatile G_alloc_counts g_alloc_counts={0}; // debug counters for allocation

#define ELEMENT_NAME_SIZE 30 + SESSION_ID_LEN
#define STR_SIZE 15
#define NAME_ELEMENT(name, element, ch_idx) g_snprintf(name, ELEMENT_NAME_SIZE, "%s-ch%u", element, ch_idx)

#define NAME_SESSION_ELEMENT(name, element, ch_idx, sess_id)                                                           \
	do {                                                                                                               \
		if (sess_id != NULL)                                                                                           \
			g_snprintf(name, ELEMENT_NAME_SIZE, "%s-ch%u-sess%s", element, ch_idx, sess_id);                           \
		else                                                                                                           \
			g_snprintf(name, ELEMENT_NAME_SIZE, "%s-ch%u", element, ch_idx);                                           \
	} while (0)

#define RTP_DEPAY "rx-depay"

#ifdef _WIN32
#define SYNTHETIC_CLOCK_INTERVAL_MS 1000
#else
#define SYNTHETIC_CLOCK_INTERVAL_MS 100
#endif

#define ENABLE_THREADSHARE
#define DEFAULT_CONTEXT_NAME "ts"
#define DEFAULT_CONTEXT_WAIT 10		// ms

#define MAKE_TS_ELEMENT(var, factory, name, context)                                                                   \
	do {                                                                                                               \
		var = AL_gst_element_factory_make(factory, name);                                                              \
		g_object_set(var, "context-wait", DEFAULT_CONTEXT_WAIT, "context", context, NULL);                             \
	} while (0)

typedef struct channel_remap channel_remap_t;

struct channel_remap {
	int channels;
	// map[input channel index] = output channel index;
	int map[MAX_IO_CHANNELS];
};

// Based on gst_rtp_channel_orders in gstrtpchannels.c
channel_remap_t channel_remaps[] = {
	{
		.channels = 5,
		.map = {0, 1, 4, 2, 3},
	},
};

void dump_pipeline(GstPipeline *pipe, const char *name)
{
	char *tmp = g_strdup_printf("%s-%s", gst_element_get_name(pipe), name);
	GST_DEBUG_BIN_TO_DOT_FILE(GST_BIN(pipe), GST_DEBUG_GRAPH_SHOW_ALL, tmp);

	g_free(tmp);
}

static gboolean bus_callback(GstBus *bus, GstMessage *msg, gpointer data)
{
	g_stream_t *stream = (g_stream_t *)data;
	GstElement *pipeline = (GstElement *)stream->pipeline;
	switch (GST_MESSAGE_TYPE(msg)) {

	case GST_MESSAGE_EOS:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "End of stream\n");
		gst_element_set_state(pipeline, GST_STATE_NULL);
		break;

	case GST_MESSAGE_ERROR: {
		gchar *debug = NULL;
		GError *error = NULL;

		gst_message_parse_error(msg, &error, &debug);
		g_free(debug);
		debug = NULL;

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error: %s\n", error->message);
		if (stream->error_cb) 
			stream->error_cb(error->message, stream);
		g_error_free(error);

		gst_element_set_state(pipeline, GST_STATE_NULL);
		break;
	}
	case GST_MESSAGE_STATE_CHANGED: {
		GstState old, new, pending;
		GstPipeline *pipe = stream->pipeline;
		gst_message_parse_state_changed(msg, &old, &new, &pending);
		if (msg->src == (GstObject *)pipe) {
			gchar *old_state = NULL;
			gchar *new_state = NULL;
			gchar *transition = NULL;
			guint len = 0;
			old_state = g_strdup(gst_element_state_get_name(old));
			new_state = g_strdup(gst_element_state_get_name(new));
			len = (guint)(strlen(old_state) + strlen(new_state) + strlen("_to_") + 5);
			transition = g_malloc0(len);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Pipeline %s changed state from %s to %s\n",
							  GST_OBJECT_NAME(msg->src), old_state, new_state);
			g_snprintf(transition, len, "%s_to_%s", old_state, new_state);
			dump_pipeline(pipe, transition);
			g_free(old_state);		//not counted
			old_state = NULL;
			g_free(new_state);		//not counted
			new_state = NULL;
			g_free(transition);		//not counted
			transition = NULL;
		}
		break;
	}
	default:
		break;
	}

	return TRUE;
}

#ifdef ENABLE_THREADSHARE
static GstCaps *request_pt_map(GstElement *jitterbuffer, guint pt, gpointer user_data)
{
	GstCaps *caps = GST_CAPS(user_data);
	GstCaps *ret = NULL;

	ret = AL_gst_caps_copy(caps);
	gst_caps_set_simple(ret, "payload", G_TYPE_INT, pt, NULL);

	return ret;
}

static void destroy_caps(void *data, GClosure G_GNUC_UNUSED *closure)
{
	if (data != NULL) {
		DA_gst_caps_unref(GST_CAPS(data));
	}
}
#endif

static void deinterleave_pad_added(GstElement *deinterleave, GstPad *pad, gpointer userdata)
{
	g_stream_t *stream = (g_stream_t *)userdata;

	// Check if shutdown is in progress BEFORE any allocations
	if (!stream || !g_atomic_int_get(&stream->pipeline_active)) {
		goto done; // Bail immediately, no allocations
	}


	GstElement *pipeline = NULL; 

	GstElement *tee = NULL;
	GstPad *tee_sink_pad = NULL;
	gchar name[ELEMENT_NAME_SIZE];
	gchar *pad_name = NULL;
	guint ch_idx;


	// no check for shutdown in progress here

	pipeline = GST_ELEMENT(AL_gst_element_get_parent(deinterleave));		
	pad_name = AL_gst_pad_get_name(pad);
	if(sscanf(pad_name, "src_%u", &ch_idx) != 1)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Pad name format unexpected: %s", pad_name);
		goto exit;
	}

	NAME_ELEMENT(name, "tee", ch_idx);
	tee = AL_gst_bin_get_by_name(GST_BIN(pipeline), name); 
	if (!tee) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Tee element not found for %s", name);
		goto exit;
	}
	tee_sink_pad = AL_gst_element_get_static_pad(tee, "sink");
	if (gst_pad_link(pad, tee_sink_pad) != GST_PAD_LINK_OK) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to link deinterleave %s pad in the rx pipeline",
						  pad_name);
	}
	//fall thru
exit:
	dump_pipeline(GST_PIPELINE(pipeline), pad_name);
	DA_gst_object_unref(tee_sink_pad);
	DA_gst_object_unref(GST_OBJECT(tee));
	// setting pipeline state to null here kills audio so just deref the pointer
	DA_gst_object_unref(GST_OBJECT(pipeline));	
	DA_g_free(pad_name);						//counted
done:
	return;
}

gboolean update_clock(gpointer userdata)			//is this a (critical) section
{
	g_stream_t *stream = (g_stream_t *)userdata;

	if (!g_atomic_int_get(&stream->pipeline_active)) {
		goto done_no_unlock;	// Fast path exit
	}


	GstStructure *stats = NULL;
	guint32 rtp_timestamp;
	GstElement *pipeline = NULL;
	GstClockTime internal, external;
	gdouble r_sq;
	GstElement *rtpdepay = NULL;

	pipeline = (GstElement *)stream->pipeline;
	rtpdepay = AL_gst_bin_get_by_name(GST_BIN(pipeline), RTP_DEPAY);
	if (!rtpdepay) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "rtpdepay not found in pipeline");
		goto done;
	}

	g_object_get(G_OBJECT(rtpdepay), "stats", &stats, NULL);		//allocates

	if (gst_structure_get_uint(stats, "timestamp", &rtp_timestamp)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "rtp timestamp in rtpdepay %u\n", rtp_timestamp);

		internal = gst_clock_get_internal_time(stream->clock);
		external = gst_util_uint64_scale(rtp_timestamp, GST_SECOND, stream->sample_rate);

		if (gst_clock_add_observation(stream->clock, internal, external, &r_sq) &&
			!g_atomic_int_get(&stream->clock_sync)) {
			g_atomic_int_set(&stream->clock_sync, 1);

			gst_pipeline_use_clock(GST_PIPELINE(pipeline), stream->clock);
			gst_pipeline_set_clock(GST_PIPELINE(pipeline), stream->clock);
		}
	}

	DA_gst_structure_free(stats);
	DA_gst_object_unref(GST_OBJECT(rtpdepay));
done:
done_no_unlock:
	return G_SOURCE_CONTINUE;
}

/*
  Creates a new queue and appsink and links them to a new branch (sink pad)
  of the tee in the Rx pipeline. These are associated to a particular session
  calling on an endpoint.
  This allows to accept multiple listeners on single endpoint

  Note: The caller needs to lock the `stream` using `STREAM_READER_LOCK` before
  calling this function and unlock the `stream` using `STREAM_READER_UNLOCK` after
  returning from this function

*/

gboolean add_appsink(g_stream_t *stream, guint ch_idx, gchar *session)
{
	gboolean ret = FALSE;

	// Also check atomic flag
	if (!g_atomic_int_get(&stream->pipeline_active)) {
		goto done_no_unlock;
	
	}
	gchar name[ELEMENT_NAME_SIZE];
	gchar dot_name[ELEMENT_NAME_SIZE + 10];

	GstPad *tee_src_pad = NULL;
	GstPad *queue_sink_pad = NULL;
	GstElement *tee = NULL;
	GstElement *queue = NULL;
	GstElement *appsink = NULL;


	if (!stream || ch_idx >= MAX_IO_CHANNELS) goto error; //added check

	NAME_ELEMENT(name, "tee", ch_idx);

	GRecMutex *ch_mutex = &stream->appsrc_mutexes[ch_idx];
	g_rec_mutex_lock(ch_mutex); 
	tee = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), name);	
	g_rec_mutex_unlock(ch_mutex); 

	if (!tee ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to get %s element in the pipeline\n", name);
		goto error;
	}

	g_rec_mutex_lock(ch_mutex);

	NAME_SESSION_ELEMENT(name, "queue", ch_idx, session);
	queue =  AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), name);

	if (queue) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "%s already exists in the pipeline ch: %d, session %s",
						  name, ch_idx, session);
		DA_gst_object_unref(GST_OBJECT(queue));
		queue = NULL;
		g_rec_mutex_unlock(ch_mutex);
		goto error;
	}


#ifndef ENABLE_THREADSHARE
	queue = AL_gst_element_factory_make("queue", name);
#else
	MAKE_TS_ELEMENT(queue, "ts-queue", name, stream->ts_ctx);
#endif
	NAME_SESSION_ELEMENT(name, "appsink", ch_idx, session);
	appsink = AL_gst_element_factory_make("appsink", name);
	g_rec_mutex_unlock(ch_mutex);

	if (!queue || !appsink) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to create appsink or queue element for ch: %d, session %s", ch_idx, session);
		goto error;
	}
	//check if pipeline is still active
	if (!g_atomic_int_get(&stream->pipeline_active)) {
		// Clean up all allocated objects
		DA_gst_object_unref(GST_OBJECT(tee_src_pad));
		DA_gst_object_unref(queue_sink_pad);
		DA_gst_object_unref(GST_OBJECT(appsink));
		DA_gst_object_unref(GST_OBJECT(queue));
		DA_gst_object_unref(GST_OBJECT(tee));
		goto done_no_unlock;
	}

	g_rec_mutex_lock(ch_mutex);
	g_object_set(appsink, "emit-signals", FALSE, "sync", FALSE, "async", FALSE, "drop", TRUE, "max-buffers", 1,
				 "enable-last-sample", FALSE, NULL);

	gboolean retval = gst_bin_add(GST_BIN(stream->pipeline), appsink);
	g_rec_mutex_unlock(ch_mutex);

	if (!retval) {
		DA_gst_object_unref(appsink);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to add appsink to the pipeline ch: %d, session: %s", ch_idx, session);
		goto error;
	}

	g_rec_mutex_lock(ch_mutex);
	retval = gst_bin_add(GST_BIN(stream->pipeline), queue);
	g_rec_mutex_unlock(ch_mutex);

	if (!retval) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to add queue to the pipeline ch: %d, session: %s", ch_idx, session);
		goto error;
	}

	if (!gst_element_link(queue, appsink)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to link appsink and queue ch: %d, session: %s",
						  ch_idx, session);
		goto error;
	}
	// Both queue and appsink were successfully added to pipeline
	// These were allocated via AL_ wrappers, so increment counter:
	g_atomic_int_add(&stream->pipeline_elements_count, 2);

	if (!(tee_src_pad = AL_gst_element_request_pad_simple(tee, "src_%u"))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to get src pad from the tee element ch: %d, session: %s", ch_idx, session);
		goto error;
	}

	if (!(queue_sink_pad = AL_gst_element_get_static_pad(queue, "sink"))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to get sink pad from the queue element ch: %d, session: %s", ch_idx, session);
		goto error;
	}

	if (!gst_element_sync_state_with_parent(queue)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to sync queue state with pipeline. ch: %d, session: %s", ch_idx, session);
		goto error;
	}

	if (!gst_element_sync_state_with_parent(appsink)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to sync appsink state with pipeline. ch: %d, session: %s", ch_idx, session);
		goto error;
	}

	if (GST_PAD_LINK_OK != (gst_pad_link(tee_src_pad, queue_sink_pad))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to link the queue and tee. ch: %d, session: %s",
						  ch_idx, session);
		goto error;
	}

	g_snprintf(dot_name, ELEMENT_NAME_SIZE + 10, "%s-add", name);
	dump_pipeline(GST_PIPELINE(stream->pipeline), dot_name);

// fall thru
	ret = TRUE;

	DA_gst_object_unref(GST_OBJECT(tee_src_pad));
	DA_gst_object_unref(queue_sink_pad);
	//  accounting


	DA_NoNulling_dec_objs(GST_OBJECT(tee)); 
	DA_NoNulling_dec_objs(GST_OBJECT(queue));
	DA_NoNulling_dec_objs(GST_OBJECT(appsink));
	return ret;

error: 
	DA_gst_object_unref(tee_src_pad); 
	DA_gst_object_unref(queue_sink_pad);
	DA_gst_object_unref(GST_OBJECT(appsink));			//check
	DA_gst_object_unref(GST_OBJECT(queue));
	DA_gst_object_unref(GST_OBJECT(tee));
done_no_unlock:
	return ret;
}

/*
  Unlinks a session's associated queue and appsink from the tee and removes them
  from the Rx pipeline.

  Note: The caller needs to lock the `stream` using `STREAM_READER_LOCK` before
  calling this function and unlock the `stream` using `STREAM_READER_UNLOCK` after
  returning from this function

*/

gboolean remove_appsink(g_stream_t *stream, guint ch_idx, gchar *session)
{
	gboolean ret = FALSE;
	GstElement *queue = NULL;
	GstElement *appsink = NULL;
	GstElement *tee = NULL;
	GstPad *tee_src_pad = NULL;
	GstPad *queue_sink_pad = NULL;

	if (!stream || ch_idx >= MAX_IO_CHANNELS) goto exit; // added check
	if (!g_atomic_int_get(&stream->pipeline_active)) { 
		goto done_no_unlock; 
	}

	gchar name[ELEMENT_NAME_SIZE];
	gchar dot_name[ELEMENT_NAME_SIZE + 10];



	/*
	 * tee -> queue -> appsink
	 *
	 * We unlink the tee and queue first and then remove the queue and
	 * appsink.
	 */

	GRecMutex *ch_mutex = &stream->appsrc_mutexes[ch_idx];
	g_rec_mutex_lock(ch_mutex); 

	NAME_SESSION_ELEMENT(name, "queue", ch_idx, session);
	queue = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), name);
	g_rec_mutex_unlock(ch_mutex);

	if (!queue ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to find %s in the pipeline\n", name);
		goto exit;
	}

	g_rec_mutex_lock(ch_mutex);
	NAME_ELEMENT(name, "tee", ch_idx);
	tee = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), name);		//tees deallocated by pipline
	g_rec_mutex_unlock(ch_mutex);

	if (!tee ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to find %s in the pipeline\n", name);
		goto exit;
	}

	g_rec_mutex_lock(ch_mutex);
	if (!(queue_sink_pad = AL_gst_element_get_static_pad(queue, "sink"))) {
		g_rec_mutex_unlock(ch_mutex);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to get sink pad from the queue element ch: %d, session: %s", ch_idx, session);
		goto exit;
	}

	if (!(tee_src_pad = AL_gst_pad_get_peer(queue_sink_pad))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to get src pad from the tee element ch: %d, session: %s", ch_idx, session);
		g_rec_mutex_unlock(ch_mutex);
		goto exit;
	}
	g_rec_mutex_unlock(ch_mutex);


	if (!gst_pad_unlink(tee_src_pad, queue_sink_pad)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to unlink tee and queue ch: %d, session: %s",
						  ch_idx, session);
	}

	// Drain pending samples from appsink BEFORE bin_remove to avoid races
	GstSample *sample = NULL;
	GstClockTime timeout = 100 * GST_MSECOND; // 100ms total drain window

	g_rec_mutex_lock(ch_mutex);
	NAME_SESSION_ELEMENT(name, appsink, ch_idx, session);
	appsink = gst_bin_get_by_name(GST_BIN(stream->pipeline), name);


	if (appsink) {
		gst_element_send_event(appsink, gst_event_new_flush_start());
		gst_element_send_event(appsink, gst_event_new_flush_stop(TRUE));
		while (!gst_app_sink_is_eos(GST_APP_SINK(appsink))) {
			sample = gst_app_sink_try_pull_sample(GST_APP_SINK(appsink), timeout);
			if (sample) {
				DA_gst_sample_unref(sample);
				sample = NULL;
			} else {
				break; // No more samples or timeout
			}
		}
		// Force appsink to NULL state safely
		gst_element_set_state(appsink, GST_STATE_NULL);
		DA_gst_object_unref(appsink);
		appsink = NULL;
	}


	gst_element_release_request_pad(tee, tee_src_pad);

	NAME_SESSION_ELEMENT(name, "appsink", ch_idx, session);
	appsink = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), name);
	g_rec_mutex_unlock(ch_mutex);

	if (!appsink ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to find %s in the pipeline\n", name);
		goto exit;
	}

	gst_element_unlink(queue, appsink);
	g_rec_mutex_lock(ch_mutex);
	if (!gst_bin_remove(GST_BIN(stream->pipeline), queue)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to remove queue from the pipeline ch: %d, session: %s", ch_idx, session);
	}
	g_rec_mutex_unlock(ch_mutex);

	if (queue) 
		gst_element_set_state(queue, GST_STATE_NULL);
	if (appsink) 
		gst_element_set_state(appsink, GST_STATE_NULL);


	g_rec_mutex_lock(ch_mutex);
	if (!gst_bin_remove(GST_BIN(stream->pipeline), appsink)) { // non fatal //check mutex
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "Failed to remove appsink from the pipeline ch: %d, session: %s", ch_idx, session);
	}
	g_rec_mutex_unlock(ch_mutex);		

	// Both queue and appsink were removed from pipeline (even if one failed, attempt was made)
	// Decrement the counter to match the increments in add_appsink():
	g_atomic_int_add(&stream->pipeline_elements_count, -2);

	g_snprintf(dot_name, ELEMENT_NAME_SIZE + 10, "%s-del", name);
	dump_pipeline(GST_PIPELINE(stream->pipeline), dot_name);			//for info only

	ret = TRUE;

exit:
	DA_gst_object_unref(tee_src_pad);
	DA_gst_object_unref(queue_sink_pad);
	DA_gst_object_unref(GST_OBJECT(appsink));
	DA_gst_object_unref(GST_OBJECT(queue));
	DA_gst_object_unref(GST_OBJECT(tee));
done_no_unlock:
	return ret;
}

static gboolean backup_sender_timeout_cb(gpointer userdata)
{
	gboolean retval = TRUE;
	g_stream_t *stream = (g_stream_t *)userdata;

    if (!g_atomic_int_get(&stream->pipeline_active)) {
		retval = G_SOURCE_CONTINUE; // Shutdown in progress
		goto done_no_unlock;
		
	}

	GstElement *fakesink = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), "tx-monitor-fakesink");
	GstClock *clock = NULL;
	GstBuffer *buffer = NULL;
	GstSample *last_sample = NULL;
	GstNetAddressMeta *meta = NULL;

	GSocketAddress *sock_addr = NULL;
	gchar *host = NULL;

	if (fakesink) {
		clock = AL_gst_element_get_clock(fakesink);
		if (!clock) {
			//switch_log_printf(...);
			DA_gst_object_unref(GST_OBJECT(GST_OBJECT(fakesink))); // added
			retval = G_SOURCE_CONTINUE;
	   	    goto done;
		} 

		if (clock) {
			// pipeline in PLAYING state
			GstClockTime current_time = gst_clock_get_time(clock);
			GstClockTime delta;
			GstClockTime timestamp;

			GstClockTime max_delta = stream->backup_sender_idle_wait_ms * GST_MSECOND;

			g_object_get(G_OBJECT(fakesink), "last-sample", &last_sample, NULL);	//allocates!
							
			if (!last_sample) 
				goto exit;
			AL_cnt_samples(last_sample); // accounting

			buffer = gst_sample_get_buffer(last_sample);	//no alloc 
			timestamp = GST_BUFFER_DTS_OR_PTS(buffer);
			meta = gst_buffer_get_net_address_meta(buffer);
			//

			sock_addr = meta->addr;
			host = g_inet_address_to_string(g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS(sock_addr))); //allocates!
			/* If the buffer timestamp is after the previous callback or before the next callback
			  we know that new buffers are arriving and so pause our Tx */
			delta = timestamp < current_time ? current_time - timestamp : timestamp - current_time;
			

			if (delta < max_delta && FALSE == stream->pause_backup_sender) {
				stream->pause_backup_sender = TRUE;

				drop_output_buffers(TRUE, stream);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
								  "got buffer from %s. Paused the backup sender\n", host);
			} else if (delta >= max_delta && TRUE == stream->pause_backup_sender) {
				stream->pause_backup_sender = FALSE;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
								  "Time since last-sample from %s - %" GST_TIME_FORMAT ". Resuming the backup sender\n",
								  host, GST_TIME_ARGS(delta));

				// Stop dropping Tx buffers only if the if 'txdrop' is FALSE,
				// in other words if 'txflow' is set to ON by the user
				if (FALSE == stream->txdrop)
					drop_output_buffers(FALSE, stream);
				else
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
									  "txflow is off, continuing to drop the buffers\n");
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "got last-sample from %s\n", host);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
								  "delta - %" GST_TIME_FORMAT "; current time - %" GST_TIME_FORMAT
								  "; last-sample timestamp - %" GST_TIME_FORMAT "\n",
								  GST_TIME_ARGS(delta), GST_TIME_ARGS(current_time), GST_TIME_ARGS(timestamp));
			}


			DA_gst_sample_unref(last_sample);
			last_sample = NULL;

			DA_gst_object_unref(GST_OBJECT(clock));
			clock = NULL;

		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Clock not available, pipeline is not PLAYING\n");
		}
		DA_gst_object_unref(GST_OBJECT(fakesink));
		fakesink = NULL;

	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not find fakesink the stream\n");
	}

exit:
	DA_gst_sample_unref(last_sample);
	DA_gst_object_unref(GST_OBJECT(clock));
	DA_gst_object_unref(GST_OBJECT(fakesink));
	g_free(host);			//not counted
done:
done_no_unlock:
	return retval;
}



g_stream_t *create_pipeline(pipeline_data_t *data, event_callback_t *error_cb)
{
	GstBus *bus = NULL;
	GstElement *pipeline = NULL;
	GstElement *rtp_pay = NULL;
	GstElement *rtpdepay = NULL;
	GstElement *rtpjitbuf = NULL;
	char *pipeline_name = NULL;

	// init entire structure
	g_stream_t *stream = g_new0(g_stream_t, 1);			
	// Initialize the counter used for deallocation in stop pipeline
	g_atomic_int_set(&stream->pipeline_elements_count, 0);

	char fixed_name[25] = {"pipeline"};
	char *ts_ctx = DEFAULT_CONTEXT_NAME;

	stream->bus_watch_id = gst_bus_add_watch(bus, bus_callback, stream);		//added

	if (data->name)
		pipeline_name = data->name;
	else
		pipeline_name = fixed_name;

	if (0 != strlen(data->ts_context_name)) 
		ts_ctx = data->ts_context_name;

	stream->ts_ctx = ts_ctx;
	pipeline = gst_pipeline_new(pipeline_name);		// allocates memory!
	if (!pipeline) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create the pipeline\n");
		goto error;
	}
	stream->pipeline_active = 0; // Start inactive

	if (data->direction & DIRECTION_RX) {
		GstElement *udp_source = NULL;
		GstElement *deinterleave = NULL;
		GstElement *rx_audioconv = NULL;
		GstElement *capsfilter = NULL;
		GstElement *split = NULL;
		GstElement *tee = NULL;

		GstCaps *udp_caps = NULL;
		GstCaps *rx_caps = NULL;

#ifndef ENABLE_THREADSHARE
		udp_source = AL_gst_element_factory_make("udpsrc", "rx-src");
#else
		MAKE_TS_ELEMENT(udp_source, "ts-udpsrc", "rx-src", ts_ctx);
#endif
		g_object_set(udp_source, "buffer-size", 1048576, NULL);

		if (data->rx_codec == L16) {
			rtpdepay = AL_gst_element_factory_make("rtpL16depay", RTP_DEPAY);
			udp_caps = gst_caps_new_simple("application/x-rtp", 
					"clock-rate", G_TYPE_INT, data->sample_rate, 
					"channels",	G_TYPE_INT, data->channels, 
					"channel-order", G_TYPE_STRING, "unpositioned",
					"encoding-name", G_TYPE_STRING, "L16", 
					"media", G_TYPE_STRING, "audio", NULL);
			if (!udp_caps)		{ 
				goto ddirRX_error;
			}
		} else {
			rtpdepay = AL_gst_element_factory_make("rtpL24depay", RTP_DEPAY);
			udp_caps =	gst_caps_new_simple("application/x-rtp", 
			"clock-rate", G_TYPE_INT, data->sample_rate, 
			"channels",	G_TYPE_INT, data->channels, 
			"channel-order", G_TYPE_STRING, "unpositioned",
			"encoding-name", G_TYPE_STRING, "L24", 
			"media", G_TYPE_STRING, "audio", NULL);
			if (!udp_caps) { 
				goto ddirRX_error;
			}
		}

		rtpjitbuf = AL_gst_element_factory_make("rtpjitterbuffer", "rx-jitbuf");

		// TODO: remove after testing
		#ifdef PUTBACKTHISERROR
		stream->jitterbuf_signal_id = g_signal_connect_data(rtpjitbuf, "request-pt-map", G_CALLBACK(request_pt_map), 
			gst_caps_ref(udp_caps),  destroy_caps, 0);
		#endif

		g_object_set(rtpjitbuf, "latency", data->rtp_jitbuf_latency,
		 "mode", 0 /* none */, 
		 NULL);
		rx_audioconv = AL_gst_element_factory_make("audioconvert", "rx-aconv");
		g_object_set(rx_audioconv, "dithering", 0 /* none */, NULL);

		capsfilter = AL_gst_element_factory_make("capsfilter", "rx-caps");

		/*Always feed S16LE to the FS*/
		rx_caps = gst_caps_new_simple("audio/x-raw", 
			"channels", G_TYPE_INT, data->channels, 
			"format", G_TYPE_STRING, "S16LE",
			"layout", G_TYPE_STRING, "interleaved",
			 NULL);
		if (!rx_caps) { // error
			DA_gst_caps_unref(udp_caps);
			udp_caps = NULL;
			goto ddirRX_error;
		}
		g_object_set(capsfilter, "caps", rx_caps, NULL);
		DA_gst_caps_unref(rx_caps);
		rx_caps = NULL;

		split = AL_gst_element_factory_make("audiobuffersplit", "rx-split");
		g_object_set(split, "output-buffer-duration", data->codec_ms, 1000, NULL);

		deinterleave = AL_gst_element_factory_make("deinterleave", "rx-deinterleave");

		for (gint ch = 0; ch < data->channels; ch++) {
			gchar name[ELEMENT_NAME_SIZE];

			NAME_ELEMENT(name, "tee", ch);
			tee = gst_element_factory_make("tee", name);		//do not count, since pipeline deallocs

			if (!tee) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
								  "Failed to create tee element in rx pipeline\n");
				continue;
			}
			g_object_set(tee, "allow-not-linked", TRUE, NULL);
			gst_bin_add(GST_BIN(pipeline), tee);
			// The deinterleave will be linked to the tee dynamically
		}

		stream->deinterleave_signal_id =
			g_signal_connect(deinterleave, "pad-added",
			G_CALLBACK(deinterleave_pad_added), stream); 

		g_object_set(udp_source, "address", data->rx_ip_addr, "port", data->rx_port, 
			"multicast-iface", data->rtp_iface,
			"retrieve-sender-address", FALSE, 
			NULL);
		g_object_set(udp_source, "caps", udp_caps, NULL);
		stream->jitterbuf_signal_id = g_signal_connect_data(rtpjitbuf, "request-pt-map", G_CALLBACK(request_pt_map),
															udp_caps, // Don't ref here, destroy_caps will handle it
															destroy_caps, 0);


		if (!udp_source || !rtpdepay || !rtpjitbuf || !rx_audioconv || !capsfilter || !split || !deinterleave) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create rx elements\n");
			goto ddirRX_error;
		}

		gst_bin_add_many(GST_BIN(pipeline), udp_source, rtpdepay, rtpjitbuf, rx_audioconv, capsfilter, split, deinterleave, NULL);
		g_atomic_int_add(&stream->pipeline_elements_count, 7);

		if (!gst_element_link_many(udp_source, rtpjitbuf, rtpdepay, split, rx_audioconv, capsfilter, deinterleave, NULL)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to link elements in the rx pipeline");
			goto ddirRX_error;
		}


		goto ddirRX_exit;

	ddirRX_error:
		DA_gst_caps_unref(udp_caps); 
		udp_caps = NULL;
		DA_gst_caps_unref(rx_caps); 
		rx_caps = NULL;
		DA_gst_object_unref(GST_OBJECT(udp_source));
		udp_source = NULL;
		DA_gst_object_unref(GST_OBJECT(deinterleave));
		deinterleave = NULL;
		DA_gst_object_unref(GST_OBJECT(rx_audioconv));
		rx_audioconv = NULL;
		DA_gst_object_unref(GST_OBJECT(capsfilter));
		capsfilter = NULL;
		tee = NULL;
		DA_gst_object_unref(GST_OBJECT(split));
		split = NULL;
		DA_gst_object_unref(GST_OBJECT(rtpjitbuf));		//added to pipeline
		rtpjitbuf = NULL;
		DA_gst_object_unref(GST_OBJECT(rtpdepay));		// added to pipeline
		rtpdepay = NULL;
		goto error;

	ddirRX_exit:
		//  accounting
		if (udp_source) DA_NoNulling_dec_objs(udp_source); 
		if (rtpdepay) DA_NoNulling_dec_objs(rtpdepay);
		if (rtpjitbuf) DA_NoNulling_dec_objs(rtpjitbuf);
		if (rx_audioconv) DA_NoNulling_dec_objs(rx_audioconv);
		if (capsfilter) DA_NoNulling_dec_objs(capsfilter);
		if (split) DA_NoNulling_dec_objs(split);
		if (deinterleave) DA_NoNulling_dec_objs(deinterleave);

		DA_gst_caps_unref(udp_caps); 
		udp_caps = NULL;
		DA_gst_caps_unref(rx_caps); 
		rx_caps = NULL;
	}

	if (data->direction & DIRECTION_TX) {
		GstElement *udpsink = NULL;
		GstElement *tx_audioconv = NULL;
		GstElement *audiointerleave = NULL;
		GstElement *capsfilter = NULL;
		GstElement *tx_valve = NULL;
		GstElement *appsrc = NULL;
		GstCaps	*caps = NULL;

		audiointerleave = AL_gst_element_factory_make("audiointerleave", "audiointerleave"); // allocates memory!
		gst_bin_add(GST_BIN(pipeline), audiointerleave);
		g_atomic_int_inc(&stream->pipeline_elements_count); // audiointerleave
		g_object_set(audiointerleave, "start-time-selection", GST_AGGREGATOR_START_TIME_SELECTION_FIRST, NULL);
		g_object_set(audiointerleave, "output-buffer-duration", data->codec_ms * GST_MSECOND, NULL);

		if (data->tx_codec == L16) {
			rtp_pay = AL_gst_element_factory_make("rtpL16pay", "rtp-pay");

		} else {
			rtp_pay = AL_gst_element_factory_make("rtpL24pay", "rtp-pay");
		}
		g_object_set(rtp_pay, "pt", data->rtp_payload_type, NULL);

		if (data->ptime_ms != -1.0) {
			g_object_set(rtp_pay, "max-ptime", (gint64)(data->ptime_ms * 1000000), "min-ptime",
						 (gint64)(data->ptime_ms * 1000000), NULL);
		}

		
		for (gint ch = 0; ch < data->channels; ch++) {
			gchar name[ELEMENT_NAME_SIZE];
			gchar pad_name[STR_SIZE];

			NAME_ELEMENT(name, "appsrc", ch);
			g_snprintf(pad_name, STR_SIZE, "sink_%u", ch);

			appsrc = gst_element_factory_make("appsrc", name);			//do not count - deallocated automatically
			if (!appsrc) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create %s \n", name);
				continue;
			}

			/*Always accept S16LE from the FS*/
			caps = gst_caps_new_simple("audio/x-raw", 
				"rate", G_TYPE_INT, data->sample_rate, 
				"channels", G_TYPE_INT, 1,
				"format", G_TYPE_STRING, "S16LE", 
				"layout", G_TYPE_STRING, "interleaved",
			   "channel-mask", GST_TYPE_BITMASK, (guint64)0, NULL);

			g_object_set(appsrc, "format", GST_FORMAT_TIME, NULL);
			g_object_set(appsrc, "do-timestamp", TRUE, NULL);
			g_object_set(appsrc, "is-live", TRUE, NULL);
			/* Second * 3 allows a little bit of headroom */
			g_object_set(appsrc, "max-bytes", data->codec_ms * data->sample_rate * 2 * 3 / 1000, NULL);

			g_object_set(appsrc, "caps", caps, NULL);
			DA_gst_caps_unref(caps);
			caps = NULL;
			gst_bin_add(GST_BIN(pipeline), appsrc);

			if (!gst_element_link_pads(appsrc, "src", audiointerleave, pad_name)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
								  "Failed to link pads of %s with audiointerleave\n", name);
				goto ddirTX_error;				// on errors, dealloc of added elemets occurs when pipeline de-allocated
			}
			//do not remove appsrc, it goes when pipeline is torn down
		}

		tx_valve = AL_gst_element_factory_make("valve", "tx-valve");
		g_object_set(tx_valve, "drop", data->txdrop, NULL);

		capsfilter = AL_gst_element_factory_make("capsfilter", "tx-capsf");

		tx_audioconv = AL_gst_element_factory_make("audioconvert", "tx-audioconv");
		g_object_set(tx_audioconv, "dithering", 0 /* none */, NULL);

		udpsink = AL_gst_element_factory_make("udpsink", "tx-sink");

		caps = gst_caps_new_simple("audio/x-raw", 
			"rate", G_TYPE_INT, data->sample_rate, 
			"channels", G_TYPE_INT,  data->channels, 
			"format", G_TYPE_STRING, "S16LE", 
			"layout", G_TYPE_STRING, "interleaved", 
			"channel-mask", GST_TYPE_BITMASK, (guint64)0, 
			NULL);

		g_object_set(capsfilter, "caps", caps, NULL);
		DA_gst_caps_unref(caps);
		caps = NULL;

		g_object_set(udpsink, 
		"host", data->tx_ip_addr, 
		"port", data->tx_port, 
		"multicast-iface", data->rtp_iface,
					 NULL);
		g_object_set(udpsink, "sync", TRUE, "async", FALSE, NULL);
		g_object_set(udpsink, "qos", TRUE, "qos-dscp", 34, NULL);
		g_object_set(udpsink, "processing-deadline", 0 * GST_MSECOND, NULL);
		if (data->is_backup_sender) {
#ifndef _WIN32
			// Disable IP_MULTICAST_LOOP to avoid listening packets from same host
			// For Linux this needs to be set on the sender's side
			g_object_set(udpsink, "loop", FALSE, NULL);
#endif
		}

		if (!audiointerleave || !tx_valve || !tx_audioconv || !rtp_pay || !udpsink) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create tx elements\n");
			goto ddirTX_error;
		}

		gst_bin_add_many(GST_BIN(pipeline), tx_valve, capsfilter, tx_audioconv, rtp_pay, udpsink, NULL);
		g_atomic_int_add(&stream->pipeline_elements_count, 5);

		if (!gst_element_link_many(audiointerleave, tx_valve, capsfilter, tx_audioconv, rtp_pay, udpsink, NULL)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to link elements");
			goto ddirTX_error;
		}


		goto ddirTX_exit;

	ddirTX_error:
		DA_gst_caps_unref(caps);
		caps = NULL;
		DA_gst_object_unref(GST_OBJECT(udpsink));
		udpsink = NULL;
		DA_gst_object_unref(GST_OBJECT(tx_audioconv));
		tx_audioconv = NULL;
		DA_gst_object_unref(GST_OBJECT(audiointerleave));
		audiointerleave = NULL;
		DA_gst_object_unref(GST_OBJECT(capsfilter));
		capsfilter = NULL;
		DA_gst_object_unref(GST_OBJECT(tx_valve));
		tx_valve = NULL;
		gst_object_unref(GST_OBJECT(appsrc));
		appsrc = NULL; // added to pipeline in loop, not counted
		goto error;

	ddirTX_exit:
		//accounting
		DA_NoNulling_dec_objs(GST_OBJECT(udpsink));
		DA_NoNulling_dec_objs(GST_OBJECT(tx_audioconv));
		DA_NoNulling_dec_objs(GST_OBJECT(audiointerleave));
		DA_NoNulling_dec_objs(GST_OBJECT(capsfilter));
		DA_NoNulling_dec_objs(GST_OBJECT(tx_valve));
		// rtp_pay done later
		// appsrc not counted added to pipeline in loop, not counted
	}

	/* if this stream is configured to be a backup sender, we pause our Tx if we find another sender doing Tx
	  on the same multicast address and resume once the remote sender stops
	*/
	GstElement *udpsrc = NULL;
	GstElement *fakesink = NULL;
	GstCaps *caps = NULL;
	if (data->is_backup_sender) {

		/* create a dummy pipeline with `udpsrc ! fakesink` just to receive on udp and read the last-sample from
		 * fakesink */
#ifndef ENABLE_THREADSHARE
		udpsrc = AL_gst_element_factory_make("udpsrc", "tx-monitor-udpsrc");
#else
		MAKE_TS_ELEMENT(udpsrc, "ts-udpsrc", "tx-monitor-udpsrc", ts_ctx);
#endif

		fakesink = AL_gst_element_factory_make("fakesink", "tx-monitor-fakesink");

		if (data->tx_codec == L16) {
				caps =	gst_caps_new_simple("application/x-rtp", 
				"clock-rate", G_TYPE_INT, data->sample_rate, 
				"channels",	G_TYPE_INT, data->channels, 
				"channel-order", G_TYPE_STRING, "unpositioned",
				"encoding-name", G_TYPE_STRING, "L16", 
				"media", G_TYPE_STRING, "audio", NULL);
		} else {
				caps = gst_caps_new_simple("application/x-rtp", 
				"clock-rate", G_TYPE_INT, data->sample_rate, 
				"channels",	G_TYPE_INT, data->channels, 
				"channel-order", G_TYPE_STRING, "unpositioned",
				"encoding-name", G_TYPE_STRING, "L24", 
				"media", G_TYPE_STRING, "audio", NULL);
		}

		if (!udpsrc || !fakesink) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
							  "Failed to create tx-monitor elements, cannot listen for primary sender\n");
			goto bksnd_error;
		} else {
			g_object_set(udpsrc, "address", data->tx_ip_addr, "port", data->tx_port,
						 // #ifdef _WIN32
						 //  Disable IP_MULTICAST_LOOP to avoid listening packets from same host
						 //  For Windows this needs to be set on the receiver's side
						 "loop", FALSE,
						 // #endif
						 "multicast-iface", data->rtp_iface, "caps", caps, NULL);

			g_object_set(fakesink, "async", FALSE, NULL);

			gst_bin_add_many(GST_BIN(pipeline), udpsrc, fakesink, NULL);
			// Count backup sender elements that were allocated via AL_ wrappers:
			// udpsrc, fakesink = 2 elements
			g_atomic_int_add(&stream->pipeline_elements_count, 2);

			if (!gst_element_link_many(udpsrc, fakesink, NULL)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
								  "Failed to link tx-monitor elements, cannot listen for primary sender\n");
				goto bksnd_error;
			} else {
				stream->pause_backup_sender = FALSE;
				stream->backup_sender_idle_wait_ms = data->backup_sender_idle_wait_ms;

				/* add a timer to check for remote sender's buffers every `backup_sender_idle_wait_ms` to resumek
				  our Tx as soon as possible once the remote Tx stops */
				stream->backup_sender_idle_timer = g_timeout_add_full(
					G_PRIORITY_DEFAULT, data->backup_sender_idle_wait_ms, backup_sender_timeout_cb, stream, NULL);
			}
		}
		DA_gst_caps_unref(caps);
		caps = NULL;

		GstStateChangeReturn ret = gst_element_set_state(pipeline, GST_STATE_PAUSED); // added extra check
		if (ret == GST_STATE_CHANGE_FAILURE) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Pipeline state change failed\n");
			goto bksnd_error;
		}

// normal exit
		DA_gst_caps_unref(caps);
		caps = NULL;
		DA_NoNulling_dec_objs(udpsrc);
		DA_NoNulling_dec_objs(fakesink);

		goto bksnd_continue;

	bksnd_error:
		DA_gst_caps_unref(caps);
		caps = NULL;
		DA_gst_object_unref(GST_OBJECT(udpsrc));
		udpsrc = NULL;
		DA_gst_object_unref(GST_OBJECT(fakesink));
		fakesink = NULL;
		goto error;
	}

	// ---
bksnd_continue: 
	bus = AL_gst_pipeline_get_bus(GST_PIPELINE(pipeline));
	gst_bus_add_watch(bus, bus_callback, stream);
	DA_gst_object_unref(GST_OBJECT(bus));
	bus = NULL;

	stream->error_cb = error_cb;
	stream->pipeline = GST_PIPELINE(pipeline);
	stream->mainloop = g_main_loop_new(NULL, FALSE);
	stream->thread = g_thread_new(pipeline_name, start_pipeline, stream);
	stream->sample_rate = data->sample_rate;

	g_atomic_int_set(&stream->clock_sync, 0);

	gst_element_set_start_time(pipeline, GST_CLOCK_TIME_NONE);
	gst_element_set_base_time(pipeline, 0);

	if (rtp_pay) {
		/* We have data->codec_ms of latency in the audiointerleave, so add that in */
		/* FIXME: we should be cleverer and apply the pipeline latency as computed instead */
		g_object_set(rtp_pay, "timestamp-offset",
					 gst_util_uint64_scale_int((data->codec_ms + data->rtp_ts_offset) * GST_MSECOND, data->sample_rate,
											   GST_SECOND) % G_MAXUINT32, NULL);
	}

	if (rtpdepay && data->synthetic_ptp) {
		if (stream->clock) {
			DA_gst_object_unref(GST_OBJECT(stream->clock)); // check - added
			stream->clock = NULL;
		}
		stream->clock = AL_g_object_new_clock(GST_TYPE_SYSTEM_CLOCK, "name", "SyntheticPtpClock", NULL);

		stream->cb_rx_stats_id =
			g_timeout_add_full(G_PRIORITY_DEFAULT, SYNTHETIC_CLOCK_INTERVAL_MS, update_clock, stream, NULL);
		/* We'll set the pipeline clock once it's synced */
	} else {
		if (stream->clock) {
			DA_gst_object_unref(GST_OBJECT(stream->clock)); /// added check
			stream->clock = NULL;
		}
		gst_pipeline_use_clock(GST_PIPELINE(pipeline), data->clock);
		g_atomic_int_set(&stream->clock_sync, 1);
	}

	for (guint ch = 0; ch < MAX_IO_CHANNELS; ch++) 
		stream->leftover_bytes[ch] = 0;
	goto exit;

error:
	if (pipeline) gst_element_set_state(pipeline, GST_STATE_NULL); // added check
	DA_gst_object_unref(GST_OBJECT(pipeline));
	pipeline = NULL;
	DA_gst_object_unref(GST_OBJECT(rtp_pay));
	rtp_pay = NULL;

	if (stream != NULL) {
		if (stream->clock != NULL) {
			DA_gst_object_unref(GST_OBJECT(stream->clock)); // added - check
			stream->clock = NULL;
		} else {
			DA_NoNulling_dec_objs(GST_OBJECT(stream->clock)); // accounting
		}
		teardown_mainloop(stream->mainloop);							   // added - check
		if (stream->mainloop != NULL) g_main_loop_unref(stream->mainloop); // added - check
		if (stream->thread != NULL) g_thread_join(stream->thread);		   // added - check
		g_free(stream);			//not counted
		stream = NULL;
	}
	return NULL;

exit:
	// accounting
	DA_NoNulling_dec_objs(pipeline);
	DA_NoNulling_dec_objs(rtp_pay);
	DA_NoNulling_dec_objs(stream->clock);
	//DA_NoNulling_dec_chars(stream);  not counted
	DA_NoNulling_dec_objs(udpsrc);
	DA_NoNulling_dec_objs(fakesink);
	g_atomic_int_set(&stream->pipeline_active, 1); // Mark as active
	return stream;
}


void use_ptp_clock(g_stream_t *stream, GstClock *ptp_clock)		//locked by caller
{
	if (!stream) goto error; //added check
	if (!g_atomic_int_get(&stream->pipeline_active)) { 
		goto error;
	}


	g_atomic_int_set(&stream->clock_sync, 0);
	gst_element_set_state(GST_ELEMENT(stream->pipeline), GST_STATE_READY);

	/* cb_rx_stats_id will be non zero only when
	Rx is operational and pipeline clock is not ptp*/
	if (stream->cb_rx_stats_id) {
		g_source_remove(stream->cb_rx_stats_id);
		stream->cb_rx_stats_id = 0;
	}

	if (stream->clock) {
		DA_gst_object_unref(GST_OBJECT(stream->clock)); // added check
		stream->clock = NULL;
	} else {
		DA_NoNulling_dec_objs(GST_OBJECT(stream->clock)); // accounting
	}
 
	gst_pipeline_use_clock(GST_PIPELINE(stream->pipeline), ptp_clock);		
	gst_pipeline_set_clock(GST_PIPELINE(stream->pipeline), ptp_clock);		
	gst_element_set_state(GST_ELEMENT(stream->pipeline), GST_STATE_PLAYING);	
	dump_pipeline(stream->pipeline, "ptp-clock-switch");
	g_atomic_int_set(&stream->clock_sync, 1);


error:
	return;
}

void *start_pipeline(void *data)
{
	g_stream_t *stream = (g_stream_t *)data;
	gst_element_set_state(GST_ELEMENT(stream->pipeline), GST_STATE_PLAYING);

	dump_pipeline(stream->pipeline, "start-pipeline");
	start_mainloop(stream->mainloop);
	return NULL;
}


// Here be demons - be careful what you change and maintain order of operations
// if this runs while calls are in progress, some deallocations do not occur
// this is why there is the atomic flag that indicates it is in progress
// and it must be checked in critical sections push pull bufs and pad ops
//
void stop_pipeline(g_stream_t *stream)
{
	if (!stream) goto error_no_unlock;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Stopping pipeline...\n");
	// CRITICAL: Set flag to 0  this immediately stops audio I/O
	g_atomic_int_set(&stream->pipeline_active, 0);

	// Give active threads time to see flag and exit cleanly
	g_usleep(50000); // 50ms should be sufficient (pull timeout is 10ms)

	// STOP ALL TIMERS/SOURCES FIRST (atomic)
	gint timer_id = g_atomic_int_exchange_and_add(&stream->backup_sender_idle_timer, 0);
	if (timer_id > 0) {
		g_source_remove(timer_id);
		g_atomic_int_set(&stream->backup_sender_idle_timer, 0);
	}

	if (stream->bus_watch_id > 0) {
		g_source_remove(stream->bus_watch_id);
		stream->bus_watch_id = 0;
	}

	if (stream->cb_rx_stats_id > 0) {
		g_source_remove(stream->cb_rx_stats_id);
		stream->cb_rx_stats_id = 0;
	}

	// DISCONNECT SIGNALS BEFORE NULL STATE (CRITICAL - elements still exist)
	if (stream->deinterleave_signal_id > 0) {
		GstElement *deinterleave = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), "rx-deinterleave");
		if (deinterleave) {
			g_signal_handler_block(deinterleave, stream->deinterleave_signal_id); // Block first
			g_signal_handler_disconnect(deinterleave, stream->deinterleave_signal_id);
			DA_gst_object_unref(GST_OBJECT(deinterleave));
			deinterleave = NULL;
		}
		stream->deinterleave_signal_id = 0;
	}

	if (stream->jitterbuf_signal_id > 0) {
		GstElement *rtpjitbuf = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), "rx-jitbuf");
		if (rtpjitbuf) {
			g_signal_handler_disconnect(rtpjitbuf, stream->jitterbuf_signal_id);
			DA_gst_object_unref(GST_OBJECT(rtpjitbuf));
			rtpjitbuf = NULL;
		}
		stream->jitterbuf_signal_id = 0;
	}


	// Account for elements that will be freed when pipeline is destroyed:
	int remaining = g_atomic_int_get(&stream->pipeline_elements_count);
	if (remaining > 0) {
		g_alloc_counts.objs -= remaining;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
						  "Accounted for %d elements that will be destroyed with pipeline\n", remaining);
	} else if (remaining < 0) {
		// This indicates a bug: more removes than adds
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "ERROR: pipeline_elements_count is negative (%d) - accounting mismatch!\n", remaining);
	}
	// DUMP PIPELINE (still live)
	dump_pipeline(stream->pipeline, "pipeline-stop");

	// Drain all appsinks BEFORE setting pipeline to NULL
	GstIterator *iter = gst_bin_iterate_elements(GST_BIN(stream->pipeline));
	GValue item = G_VALUE_INIT;

	while (gst_iterator_next(iter, &item) == GST_ITERATOR_OK) {
		GstElement *element = g_value_get_object(&item);

		// Check if this is an appsink
		if (GST_IS_APP_SINK(element)) {
			GstSample *sample;

			// Drain all samples from this appsink
			while ((sample = gst_app_sink_try_pull_sample(GST_APP_SINK(element), 0))) { DA_gst_sample_unref(sample); }
		}

		g_value_reset(&item);
	}

	gst_iterator_free(iter);

	// NULL STATE - destroys ALL elements safely
	//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Setting pipeline to NULL...\n");
	gst_element_set_state(GST_ELEMENT(stream->pipeline), GST_STATE_NULL);

	GstState state, pending;
	GstStateChangeReturn ret = gst_element_get_state(
		GST_OBJECT(stream->pipeline), &state, &pending, 5 * GST_SECOND); /* or GST_CLOCK_TIME_NONE */

	if (ret != GST_STATE_CHANGE_SUCCESS || state != GST_STATE_NULL) { 
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to stop pipeline ..\n");
		// goto exit_unlock; 
		// drop through to cleanup anyhow
	}

	// UNREF PIPELINE (frees everything)
	DA_gst_object_unref(GST_OBJECT(stream->pipeline));
	stream->pipeline = NULL;

	// CLEANUP CLOCK
	if (stream->clock) {
		DA_gst_object_unref(GST_OBJECT(stream->clock));
		stream->clock = NULL;
	} else {
		DA_NoNulling_dec_objs(GST_OBJECT(stream->clock)); // accounting
	}

	// MAINLOOP + THREADS
	teardown_mainloop(stream->mainloop);
	if (stream->thread != NULL) {
		g_thread_join(stream->thread);
		stream->thread = NULL;
	}

	// MUTEX CLEANUP 
	for (int i = 0; i < MAX_IO_CHANNELS; i++) {
		// Try to ensure mutex is unlocked
		if (g_rec_mutex_trylock(&stream->appsrc_mutexes[i])) { g_rec_mutex_unlock(&stream->appsrc_mutexes[i]); }
		g_rec_mutex_clear(&stream->appsrc_mutexes[i]);
	}

	//  FINAL FREE
	g_free(stream);


exit_unlock:
	if (timer_id > 0) {
		g_source_remove(timer_id);
		g_atomic_int_set(&stream->backup_sender_idle_timer, 0);
	}
	//
	periodic_mem_check(FALSE); // de allocate memory here if required
	//
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Pipeline and mainloop cleaned up\n");
	return;

error_no_unlock:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Pipeline stop error, no stream found\n");
	return;
}



void teardown_mainloop(GMainLoop *mainloop)
{
	g_main_loop_quit(mainloop);
	g_main_loop_unref(mainloop);
}


void start_mainloop(GMainLoop *mainloop)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Running mainloop\n");
	g_main_loop_run(mainloop);

}


gboolean push_buffer(g_stream_t *stream, unsigned char *payload, guint len, guint ch_idx, switch_timer_t *timer)
{
	gboolean retval = FALSE;
	GstElement *appsrc = NULL;
	GstBuffer *buf = NULL;
	// Fast atomic check
	if (!stream || ch_idx >= MAX_IO_CHANNELS 
		|| !g_atomic_int_get(&stream->pipeline_active)) {
		goto error; // Pipeline stopping, bail immediately
	}

	// per channel lock
	GRecMutex *ch_mutex = &stream->appsrc_mutexes[ch_idx];
	g_rec_mutex_lock(ch_mutex);

	GstPipeline *pipeline = stream->pipeline;
	if (!pipeline || !g_atomic_int_get(&stream->pipeline_active)) { // added check
		goto exit;
	}

	GstState cur_state = GST_STATE_NULL;
	GstState pending_state = GST_STATE_NULL;

	GstMapInfo info;
	GstFlowReturn result;
	gchar name[ELEMENT_NAME_SIZE];


	NAME_ELEMENT(name, "appsrc", ch_idx);
	appsrc = AL_gst_bin_get_by_name(GST_BIN(pipeline), name);	//check 

  	g_rec_mutex_unlock(ch_mutex);
	switch_core_timer_next(timer);						//wait a bit
	g_rec_mutex_lock(ch_mutex);

	if (!appsrc ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Failed to find appsrc in the pipeline\n");
		goto exit;
	}

			
	if (!g_atomic_int_get(&stream->clock_sync)) {
		retval = TRUE;
		goto exit;
	}

	gst_element_get_state(GST_ELEMENT(pipeline), &cur_state, &pending_state, 0);
	if (cur_state != GST_STATE_PAUSED && cur_state != GST_STATE_PLAYING) {
		retval = TRUE;
		goto exit;
	}


	buf = AL_gst_buffer_new_allocate(NULL, len, NULL);			
	if (!buf ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to allocate buffer\n");
		goto exit; 
	}

	if (!gst_buffer_map(buf, &info, GST_MAP_WRITE)) {		//MU here kills audio from phone to BP
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to get buffer map\n");
		goto exit; 
	}

	memcpy(info.data, payload, len);
	gst_buffer_unmap(buf, &info);	

	g_signal_emit_by_name(appsrc, "push-buffer", buf, &result);
	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Pushed buffer\n");


	if (result == GST_FLOW_ERROR) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to do 'push-buffer' \n");
		goto exit;
	}
	// fall thru, no error

	retval = TRUE;

exit:
	DA_gst_buffer_unref(buf);
	DA_gst_object_unref(GST_OBJECT(appsrc));
	g_rec_mutex_unlock(ch_mutex);
	return retval;

error:
	return 0;
}

//
// critical to manage threads properly here
//
int pull_buffers(g_stream_t *stream, unsigned char *payload, 
				guint needed_bytes, guint ch_idx, switch_timer_t *timer,
				 gchar *session)
{
	GstBuffer *buf = NULL;
	GstSample *sample = NULL;
	GstElement *appsink = NULL;

	gsize total_bytes = 0;
	if (!stream || ch_idx >= MAX_IO_CHANNELS 
		|| !g_atomic_int_get(&stream->pipeline_active))
		goto error; 

	GstState cur_state = GST_STATE_NULL, pending_state=GST_STATE_NULL;

	GstMapInfo info;
	gchar name[ELEMENT_NAME_SIZE];

	// PER-CHANNEL lock (critical)
	GRecMutex *ch_mutex = &stream->appsrc_mutexes[ch_idx];
	g_rec_mutex_lock(ch_mutex);

	if (session == NULL)
		NAME_ELEMENT(name, "appsink", ch_idx);
	else
		NAME_SESSION_ELEMENT(name, "appsink", ch_idx, session);

	// Double-check after acquiring channel mutex
	if (!g_atomic_int_get(&stream->pipeline_active)) { 
		goto exit;
	}

	appsink = gst_bin_get_by_name(GST_BIN(stream->pipeline), name); // threadsafe
	if (!appsink) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to find %s in the pipeline\n", name);
		goto exit;
	}
	gst_element_get_state(GST_ELEMENT(stream->pipeline), 
		&cur_state, &pending_state, 0); 

	if (cur_state != GST_STATE_PAUSED && cur_state != GST_STATE_PLAYING) {
		goto exit;
	}

	if (gst_app_sink_is_eos(GST_APP_SINK(appsink))) { 
		goto exit;
	}

	// Note: assumes leftover_bytes will never be more than buflen, which is
	// likely true (packet is limited to MTU, while buflen is 8192)
	// FIXME: revisit this to check whether we need this anymore

	if (stream->leftover_bytes[ch_idx]) {
		size_t copy = stream->leftover_bytes[ch_idx] <= needed_bytes ? stream->leftover_bytes[ch_idx] : needed_bytes;
		memcpy(payload, stream->leftover[ch_idx], copy); // check
		total_bytes += copy;
		stream->leftover_bytes[ch_idx] -= copy;
	}


	while (total_bytes < needed_bytes) {
		// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "pulling buffer\n");
		if (!g_atomic_int_get(&stream->pipeline_active)) {
			goto exit;
		}
	
		g_rec_mutex_unlock(ch_mutex);
		sample = gst_app_sink_try_pull_sample(GST_APP_SINK(appsink),
			10 * GST_MSECOND);	
		g_rec_mutex_lock(ch_mutex);
	
		if (!sample) {
			// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Failed to pull sample\n");
			g_rec_mutex_unlock(ch_mutex);
			switch_cond_next();
			g_rec_mutex_lock(ch_mutex);
			break;
		}

		if (!g_atomic_int_get(&stream->pipeline_active)) {
			DA_gst_sample_unref(sample); 
			sample = NULL;
			break;
		}

		AL_cnt_samples(sample);					// count the successful allocation
		buf = gst_sample_get_buffer(sample);	 // no alloc no count
												
		if (!g_atomic_int_get(&stream->pipeline_active)) {
			DA_gst_sample_unref(sample);
			sample = NULL;
			goto exit;
		}

		if (!buf) {
			DA_gst_sample_unref(sample);
			sample = NULL;
			continue;
		}

		if (!g_atomic_int_get(&stream->pipeline_active)) {
			DA_gst_sample_unref(sample);
			sample = NULL;
			goto exit;
		}

		gboolean r = gst_buffer_map(buf, &info, GST_MAP_READ);

		if (r) {			
			if (total_bytes + info.size > needed_bytes) {
				gsize want = needed_bytes - total_bytes;
				stream->leftover_bytes[ch_idx] = info.size - want;
				memcpy(stream->leftover[ch_idx], info.data + want, stream->leftover_bytes[ch_idx]);
				info.size = want;
			}
			memcpy(payload + total_bytes, info.data, info.size); // check
			total_bytes += info.size;
		}

		gst_buffer_unmap(buf, &info); //check
		DA_gst_sample_unref(sample);
		sample = NULL;
	}

#if 0
  {
    // Dump data to file
    char name[100];
    int fd;

    NAME_ELEMENT (name, "/tmp/raw", ch_idx);
    fd = open (name, O_WRONLY | O_CREAT | O_APPEND);

    write (fd, payload, total_bytes);
    close (fd);
  }
#endif

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%u Returning needed %d, total_bytes: %d\n", ch_idx,
	// needed_bytes, total_bytes); switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Leftover %lu\n",
	// stream->leftover_bytes[ch_idx]);

// fall thru

exit:
	if (appsink) {
		gst_object_unref(appsink); 
	}
	DA_gst_sample_unref(sample);
	g_rec_mutex_unlock(ch_mutex);
error:
	return (int) total_bytes;
}

void drop_input_buffers(gboolean drop, g_stream_t *stream, guint32 ch_idx)
{
	GstElement *valve = NULL;
	if (!stream || ch_idx >= MAX_IO_CHANNELS 
		|| !g_atomic_int_get(&stream->pipeline_active)) { 
		goto error; 
	}

	gchar name[ELEMENT_NAME_SIZE];

	// PER-CHANNEL lock (critical)
	GRecMutex *ch_mutex = &stream->appsrc_mutexes[ch_idx];
	g_rec_mutex_lock(ch_mutex);
	NAME_ELEMENT(name, "valve", ch_idx);

	valve = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), name); // increases ref count check 

	if (!valve ) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to get valve element in the pipeline\n");
		goto exit;
	}

	g_object_set(valve, "drop", drop, NULL);
	g_snprintf(name, 2*STR_SIZE, "drop-ch%d-%d", ch_idx, drop);		//check increased string size

	dump_pipeline(stream->pipeline, name);
	//fall thru
exit: 
	DA_gst_object_unref(GST_OBJECT(valve));		//check 
	g_rec_mutex_unlock(ch_mutex);
error:
	return;
}

//caller must free returned string!!
gchar *get_rtp_stats(g_stream_t *stream)
{
	GstElement *rtpjitbuf = NULL;
	gchar *stats_str = NULL;		//fixed: dynamic allocation required since this is NOT on the stack
	if (!g_atomic_int_get(&stream->pipeline_active)) { 
		goto done_no_unlock; 
	}
	if (!stream) goto exit; //added check

	rtpjitbuf = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), "rx-jitbuf");

	if (rtpjitbuf) {
		GstStructure *stats = NULL;
		g_object_get(G_OBJECT(rtpjitbuf), "stats", &stats, NULL);
		stats_str = gst_structure_to_string(stats);	
		DA_gst_structure_free(stats); // added

		stats = NULL;
		DA_gst_object_unref(GST_OBJECT(rtpjitbuf));
	} else {
		stats_str = g_strdup_printf(""); // must be heap
	}
exit:
done_no_unlock:
	return stats_str;			//deallocated by caller!!
}

void drop_output_buffers(gboolean drop, g_stream_t *stream)
{
	if (!g_atomic_int_get(&stream->pipeline_active)) { 
		goto done_no_unlock; 
	}
	GstElement *tx_valve = NULL;
	gchar name[ELEMENT_NAME_SIZE];
	if (!stream) goto exit;

	tx_valve = AL_gst_bin_get_by_name(GST_BIN(stream->pipeline), "tx-valve"); 
	if (!tx_valve) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to get valve element in the pipeline\n");
		goto exit;
	}

	g_object_set(tx_valve, "drop", drop, NULL);

	g_snprintf(name, ELEMENT_NAME_SIZE, "tx-drop-%d", drop);
	dump_pipeline(stream->pipeline, name);
	//fall thru
exit:
	DA_gst_object_unref(GST_OBJECT(tx_valve));
done_no_unlock:
	return;
}
