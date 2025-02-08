#include <switch.h>

#include <gst/app/gstappsink.h>
#include <gst/audio/audio-channels.h>
#include <gst/net/net.h>
#include "aes67_api.h"

#define ELEMENT_NAME_SIZE 30 + SESSION_ID_LEN
#define STR_SIZE 15
#define NAME_ELEMENT(name, element, ch_idx) \
    g_snprintf(name, ELEMENT_NAME_SIZE, "%s-ch%u", element, ch_idx)

#define NAME_SESSION_ELEMENT(name, element, ch_idx, sess_id) \
  do { \
    if (sess_id != NULL) \
      g_snprintf(name, ELEMENT_NAME_SIZE, "%s-ch%u-sess%s", element, ch_idx, sess_id); \
    else \
      g_snprintf(name, ELEMENT_NAME_SIZE, "%s-ch%u", element, ch_idx); \
  } while (0)

#define RTP_DEPAY "rx-depay"

#ifdef _WIN32
#define SYNTHETIC_CLOCK_INTERVAL_MS 1000
#else
#define SYNTHETIC_CLOCK_INTERVAL_MS 100
#endif

#define ENABLE_THREADSHARE
#define DEFAULT_CONTEXT_NAME "ts"
#define DEFAULT_CONTEXT_WAIT 10 // ms

#define MAKE_TS_ELEMENT(var, factory, name, context) \
  do { \
    var = gst_element_factory_make (factory, name); \
    g_object_set(var, "context-wait", DEFAULT_CONTEXT_WAIT, \
        "context", context, NULL); \
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
    .map = { 0, 1, 4, 2, 3 },
  },
};

void
dump_pipeline (GstPipeline *pipe, const char *name)
{
  char *tmp = g_strdup_printf("%s-%s", gst_element_get_name(pipe), name);

  GST_DEBUG_BIN_TO_DOT_FILE (GST_BIN (pipe),
      GST_DEBUG_GRAPH_SHOW_ALL, tmp);

  g_free(tmp);
}

static gboolean
bus_callback (GstBus * bus, GstMessage * msg, gpointer data)
{

  g_stream_t *stream = (g_stream_t *) data;
  GstElement *pipeline = (GstElement *) stream->pipeline;
  switch (GST_MESSAGE_TYPE (msg)) {

    case GST_MESSAGE_EOS:
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
          "End of stream\n");
      gst_element_set_state (pipeline, GST_STATE_NULL);
      break;

    case GST_MESSAGE_ERROR:{
      gchar *debug;
      GError *error;

      gst_message_parse_error (msg, &error, &debug);
      g_free (debug);

      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error: %s\n",
          error->message);
      if (stream->error_cb)
        stream->error_cb (error->message, stream);
      g_error_free (error);

      gst_element_set_state (pipeline, GST_STATE_NULL);
      break;
    }
    case GST_MESSAGE_STATE_CHANGED:{
      GstState old, new, pending;
      GstPipeline *pipe = stream->pipeline;
      gst_message_parse_state_changed (msg, &old, &new, &pending);
      if (msg->src == (GstObject *) pipe) {
        gchar *old_state, *new_state, *transition;
        guint len = 0;
        old_state = g_strdup (gst_element_state_get_name (old));
        new_state = g_strdup (gst_element_state_get_name (new));
        len = strlen (old_state) + strlen (new_state) + strlen ("_to_") + 5;
        transition = g_malloc0 (len);
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
            "Pipeline %s changed state from %s to %s\n",
            GST_OBJECT_NAME (msg->src), old_state, new_state);
        g_snprintf (transition, len, "%s_to_%s", old_state, new_state);
        dump_pipeline(pipe, transition);
        g_free (old_state);
        g_free (new_state);
        g_free (transition);
      }
      break;
    }
    default:
      break;
  }

  return TRUE;

}

#ifdef ENABLE_THREADSHARE
static GstCaps *
request_pt_map(GstElement *jitterbuffer, guint pt, gpointer user_data)
{
  GstCaps *caps = GST_CAPS(user_data), *ret;

  ret = gst_caps_copy(caps);
  gst_caps_set_simple(ret, "payload", G_TYPE_INT, pt, NULL);

  return ret;
}

static void
destroy_caps(void *data, GClosure G_GNUC_UNUSED *closure)
{
  gst_caps_unref(data);
}
#endif

static void
deinterleave_pad_added (GstElement * deinterleave, GstPad * pad,
    gpointer userdata)
{
  GstElement *pipeline =
      GST_ELEMENT (gst_element_get_parent (deinterleave)), *tee;
  GstPad *tee_sink_pad;
  gchar name[ELEMENT_NAME_SIZE];
  gchar *pad_name;
  guint ch_idx;

  pad_name = gst_pad_get_name (pad);
  sscanf (pad_name, "src_%u", &ch_idx);

  NAME_ELEMENT (name, "tee", ch_idx);
  tee = gst_bin_get_by_name (GST_BIN (pipeline), name);
  g_assert_nonnull (tee);

  tee_sink_pad = gst_element_get_static_pad (tee, "sink");

  if (gst_pad_link (pad, tee_sink_pad) != GST_PAD_LINK_OK) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to link deinterleave %s pad in the rx pipeline", pad_name);
  }

  dump_pipeline(GST_PIPELINE(pipeline), pad_name);

  gst_object_unref (tee_sink_pad);
  gst_object_unref(tee);
  gst_object_unref(pipeline);
  g_free (pad_name);
}

gboolean update_clock (gpointer userdata) {
  g_stream_t *stream = (g_stream_t *) userdata;
  GstStructure *stats = NULL;
  guint32 rtp_timestamp;
  GstElement *pipeline;
  GstClockTime internal, external;
  gdouble r_sq;
  GstElement *rtpdepay;

  pipeline = (GstElement *) stream->pipeline;
  rtpdepay = gst_bin_get_by_name (GST_BIN (pipeline), RTP_DEPAY);

  g_object_get (G_OBJECT(rtpdepay), "stats", &stats, NULL);

  if (gst_structure_get_uint(stats, "timestamp", &rtp_timestamp) ) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "rtp timestamp in rtpdepay %u\n", rtp_timestamp);

    internal = gst_clock_get_internal_time(stream->clock);
    external = gst_util_uint64_scale (rtp_timestamp, GST_SECOND, stream->sample_rate);

    if (gst_clock_add_observation(stream->clock, internal, external, &r_sq) &&
        !g_atomic_int_get (&stream->clock_sync)) {
      g_atomic_int_set(&stream->clock_sync, 1);

      gst_pipeline_use_clock (GST_PIPELINE (pipeline), stream->clock);
      gst_pipeline_set_clock (GST_PIPELINE (pipeline), stream->clock);
    }
  }

  gst_structure_free(stats);
  gst_object_unref (rtpdepay);

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

gboolean
add_appsink (g_stream_t *stream, guint ch_idx, gchar *session)
{
  gchar name[ELEMENT_NAME_SIZE];
  gchar dot_name[ELEMENT_NAME_SIZE+10];
  GstPad *tee_src_pad = NULL, *queue_sink_pad = NULL;
  GstElement *tee = NULL, *queue = NULL, *appsink = NULL;
  gboolean ret = FALSE;

  NAME_ELEMENT(name, "tee", ch_idx);
  tee = gst_bin_get_by_name (GST_BIN(stream->pipeline), name);
  if (tee == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to get %s element in the pipeline\n", name);
    goto error;
  }

  NAME_SESSION_ELEMENT(name, "queue", ch_idx, session);
  if (NULL != (queue = gst_bin_get_by_name(GST_BIN (stream->pipeline), name))) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
        "%s already exists in the pipeline ch: %d, session %s", name, ch_idx, session);
    goto error;
  }
#ifndef ENABLE_THREADSHARE
      queue = gst_element_factory_make ("queue", name);
#else
      MAKE_TS_ELEMENT(queue, "ts-queue", name, stream->ts_ctx);
#endif

  NAME_SESSION_ELEMENT(name, "appsink", ch_idx, session);
  appsink = gst_element_factory_make ("appsink", name);

  if (!queue || !appsink ) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to create appsink or queue element for ch: %d, session %s", ch_idx, session);
    goto error;
  }

  g_object_set (appsink, "emit-signals", FALSE, "sync", FALSE, "async", FALSE,
      "drop", TRUE, "max-buffers", 1, "enable-last-sample", FALSE, NULL);

  if (!gst_bin_add(GST_BIN(stream->pipeline), appsink)) {
	  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
			"Failed to add appsink to the pipeline ch: %d, session: %s", ch_idx, session);
    goto error;
  }

  if(!gst_bin_add(GST_BIN(stream->pipeline), queue)) {
	  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
			"Failed to add queue to the pipeline ch: %d, session: %s", ch_idx, session);
    goto error;
  }

  if (!gst_element_link(queue, appsink)) {
	  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						"Failed to link appsink and queue ch: %d, session: %s", ch_idx, session);
    goto error;
  }

  if (NULL == (tee_src_pad = gst_element_request_pad_simple (tee, "src_%u"))) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to get src pad from the tee element ch: %d, session: %s", ch_idx, session);
    goto error;
  }

  if (NULL == (queue_sink_pad = gst_element_get_static_pad (queue, "sink"))) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to get sink pad from the queue element ch: %d, session: %s", ch_idx, session);
    goto error;
  }

  if (!gst_element_sync_state_with_parent (queue)) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to sync queue state with pipeline. ch: %d, session: %s", ch_idx, session);
    goto error;
  }

  if (!gst_element_sync_state_with_parent(appsink)) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to sync appsink state with pipeline. ch: %d, session: %s", ch_idx, session);
    goto error;
  }

  if (GST_PAD_LINK_OK != (gst_pad_link(tee_src_pad, queue_sink_pad))) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to link the queue and tee. ch: %d, session: %s", ch_idx, session);
    goto error;
  }

  g_snprintf(dot_name, ELEMENT_NAME_SIZE+10, "%s-add", name);
  dump_pipeline(GST_PIPELINE(stream->pipeline), dot_name);

  ret = TRUE;
  goto exit;

  error:
    if (NULL != appsink)
      gst_object_unref(appsink);
    if (NULL != queue)
      gst_object_unref(queue);
    if (NULL != tee)
      gst_object_unref(tee);

  exit:
    if (NULL != tee_src_pad)
      gst_object_unref(tee_src_pad);
    if (NULL != queue_sink_pad)
      gst_object_unref(queue_sink_pad);

  return ret;
}

/*
  Unlinks a session's associated queue and appsink from the tee and removes them
  from the Rx pipeline.

  Note: The caller needs to lock the `stream` using `STREAM_READER_LOCK` before
  calling this function and unlock the `stream` using `STREAM_READER_UNLOCK` after
  returning from this function

*/

gboolean
remove_appsink(g_stream_t *stream, guint ch_idx, gchar *session) {
  gchar name[ELEMENT_NAME_SIZE];
  gchar dot_name[ELEMENT_NAME_SIZE + 10];

  GstElement *queue = NULL, *appsink = NULL, *tee = NULL;
  GstPad *tee_src_pad = NULL, *queue_sink_pad = NULL;
  gboolean ret = FALSE;

  /*
   * tee -> queue -> appsink
   *
   * We unlink the tee and queue first and then remove the queue and
   * appsink.
   */
  NAME_SESSION_ELEMENT(name, "queue", ch_idx, session);
  queue = gst_bin_get_by_name (GST_BIN (stream->pipeline), name);
  if (queue == NULL ) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to find %s in the pipeline\n", name);
    goto exit;
  }

  NAME_ELEMENT(name, "tee", ch_idx);
	tee = gst_bin_get_by_name (GST_BIN (stream->pipeline), name);
  if (tee == NULL ) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to find %s in the pipeline\n", name);
    goto exit;
  }

  if (NULL == (queue_sink_pad = gst_element_get_static_pad (queue, "sink"))) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to get sink pad from the queue element ch: %d, session: %s", ch_idx, session);
    goto exit;
  }

  if (NULL == (tee_src_pad = gst_pad_get_peer (queue_sink_pad))) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to get src pad from the tee element ch: %d, session: %s", ch_idx, session);
    goto exit;
  }

  if (!gst_pad_unlink(tee_src_pad, queue_sink_pad)) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to unlink tee and queue ch: %d, session: %s", ch_idx, session);
  }
  gst_element_release_request_pad (tee, tee_src_pad);

  gst_object_unref(tee_src_pad);
  tee_src_pad = NULL;

  gst_object_unref(queue_sink_pad);
  queue_sink_pad = NULL;

  NAME_SESSION_ELEMENT(name, "appsink", ch_idx, session);
  appsink = gst_bin_get_by_name (GST_BIN (stream->pipeline), name);
  if (appsink == NULL ) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to find %s in the pipeline\n", name);
    goto exit;
  }

  gst_element_unlink(queue, appsink);

  if (!gst_bin_remove(GST_BIN(stream->pipeline), queue)) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to remove queue from the pipeline ch: %d, session: %s", ch_idx, session);
  }

  if (!gst_bin_remove(GST_BIN(stream->pipeline), appsink)) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to remove appsink from the pipeline ch: %d, session: %s", ch_idx, session);
  }

  gst_element_set_state(queue, GST_STATE_NULL);
  gst_element_set_state(appsink, GST_STATE_NULL);

  g_snprintf(dot_name, ELEMENT_NAME_SIZE+10, "%s-del", name);
  dump_pipeline(GST_PIPELINE(stream->pipeline), dot_name);

  ret = TRUE;

exit:
  if (NULL != tee_src_pad)
    gst_object_unref(tee_src_pad);
  if (NULL != queue_sink_pad)
    gst_object_unref(queue_sink_pad);
  if (NULL != appsink)
    gst_object_unref(appsink);
  if (NULL != queue)
    gst_object_unref(queue);
  if (NULL != tee)
    gst_object_unref(tee);

  return ret;
}

static gboolean
backup_sender_timeout_cb(gpointer userdata)
{
  g_stream_t *stream = (g_stream_t *)userdata;
  GstElement *fakesink =  gst_bin_get_by_name (GST_BIN (stream->pipeline), "tx-monitor-fakesink");
  if (fakesink) {
    GstClock *clock = gst_element_get_clock (fakesink);

    if (clock) {
      //pipeline in PLAYING state
      GstClockTime current_time = gst_clock_get_time(clock);
	    GstClockTime delta;
      GstBuffer *buffer = NULL;
      GstClockTime timestamp;
      GstSample *last_sample = NULL;
      GstNetAddressMeta *meta;
      GSocketAddress * sock_addr;
      gchar *host;
      GstClockTime max_delta = stream->backup_sender_idle_wait_ms * GST_MSECOND;

      g_object_get(G_OBJECT(fakesink), "last-sample", &last_sample, NULL);

      if (!last_sample)
        return TRUE;

      buffer = gst_sample_get_buffer(last_sample);
      timestamp = GST_BUFFER_DTS_OR_PTS (buffer);
      meta = gst_buffer_get_net_address_meta(buffer);

      sock_addr = meta->addr;
      host = g_inet_address_to_string (g_inet_socket_address_get_address
            (G_INET_SOCKET_ADDRESS (sock_addr)));

      /* If the buffer timestamp is after the previous callback or before the next callback
        we know that new buffers are arriving and so pause our Tx */
      delta = timestamp < current_time ? current_time - timestamp : timestamp - current_time;

      if (delta < max_delta && FALSE == stream->pause_backup_sender) {
        stream->pause_backup_sender = TRUE;

        drop_output_buffers(TRUE, stream);
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
          "got buffer from %s. Paused the backup sender\n", host);
      } else if (delta >= max_delta && TRUE == stream->pause_backup_sender) {
        stream->pause_backup_sender = FALSE;

        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
          "Time since last-sample from %s - %"GST_TIME_FORMAT". Resuming the backup sender\n", host, GST_TIME_ARGS(delta));

        // Stop dropping Tx buffers only if the if 'txdrop' is FALSE,
        // in other words if 'txflow' is set to ON by the user
        if (FALSE == stream->txdrop)
          drop_output_buffers(FALSE, stream);
        else
          switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "txflow is off, continuing to drop the buffers\n");
	    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "got last-sample from %s\n", host);

		    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "delta - %"GST_TIME_FORMAT"; current time - %"GST_TIME_FORMAT"; last-sample timestamp - %"GST_TIME_FORMAT"\n", GST_TIME_ARGS(delta), GST_TIME_ARGS(current_time), GST_TIME_ARGS(timestamp));
      }

      gst_sample_unref(last_sample);
      gst_object_unref(clock);
    } else {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Clock not available, pipeline is not PLAYING\n");
    }

    gst_object_unref (GST_OBJECT (fakesink));
  } else {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Could not find fakesink the stream\n");
  }

  return TRUE;
}

g_stream_t *
create_pipeline (pipeline_data_t *data, event_callback_t * error_cb)
{
  GstBus *bus;
  GstElement *pipeline, *rtp_pay = NULL, *rtpdepay = NULL, *rtpjitbuf = NULL;
  g_stream_t *stream = g_new (g_stream_t, 1);
  char fixed_name[25] = { "pipeline" };
  char *ts_ctx = DEFAULT_CONTEXT_NAME;
  char *pipeline_name;
  if (data->name)
    pipeline_name = data->name;
  else
    pipeline_name = fixed_name;

  if (0 != strlen(data->ts_context_name))
    ts_ctx = data->ts_context_name;

  stream->ts_ctx = ts_ctx;
  pipeline = gst_pipeline_new (pipeline_name);
  if (!pipeline) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to create the pipeline\n");
    return NULL;
  }

  if (data->direction & DIRECTION_RX) {
    GstElement *udp_source, *deinterleave, *rx_audioconv,
        *capsfilter, *split, *tee;
    GstCaps *udp_caps = NULL, *rx_caps = NULL;

#ifndef ENABLE_THREADSHARE
    udp_source = gst_element_factory_make ("udpsrc", "rx-src");
#else
    MAKE_TS_ELEMENT(udp_source, "ts-udpsrc", "rx-src", ts_ctx);
#endif
    g_object_set(udp_source, "buffer-size", 1048576, NULL);

    if (data->rx_codec == L16) {
      rtpdepay = gst_element_factory_make ("rtpL16depay", RTP_DEPAY);
      udp_caps = gst_caps_new_simple ("application/x-rtp",
          "clock-rate", G_TYPE_INT, data->sample_rate,
          "channels", G_TYPE_INT, data->channels,
          "channel-order", G_TYPE_STRING, "unpositioned",
          "encoding-name", G_TYPE_STRING, "L16",
          "media", G_TYPE_STRING, "audio", NULL);
    } else {
      rtpdepay = gst_element_factory_make ("rtpL24depay", RTP_DEPAY);
      udp_caps = gst_caps_new_simple ("application/x-rtp",
          "clock-rate", G_TYPE_INT, data->sample_rate,
          "channels", G_TYPE_INT, data->channels,
          "channel-order", G_TYPE_STRING, "unpositioned",
          "encoding-name", G_TYPE_STRING, "L24",
          "media", G_TYPE_STRING, "audio", NULL);
    }

    rtpjitbuf = gst_element_factory_make("rtpjitterbuffer", "rx-jitbuf");
    g_signal_connect_data(rtpjitbuf, "request-pt-map", G_CALLBACK(request_pt_map),
        gst_caps_ref(udp_caps), destroy_caps, 0);

    g_object_set(rtpjitbuf, "latency", data->rtp_jitbuf_latency,
        "mode", 0 /* none */,
        NULL);
    rx_audioconv = gst_element_factory_make ("audioconvert", "rx-aconv");
    g_object_set(rx_audioconv, "dithering", 0 /* none */, NULL);

    capsfilter = gst_element_factory_make ("capsfilter", "rx-caps");

    /*Always feed S16LE to the FS*/
    rx_caps = gst_caps_new_simple ("audio/x-raw",
        "channels", G_TYPE_INT, data->channels,
        "format", G_TYPE_STRING, "S16LE",
        "layout", G_TYPE_STRING, "interleaved", NULL);

    g_object_set (capsfilter, "caps", rx_caps, NULL);
    gst_caps_unref (rx_caps);

    split = gst_element_factory_make ("audiobuffersplit", "rx-split");
    g_object_set (split, "output-buffer-duration", data->codec_ms, 1000, NULL);

    deinterleave = gst_element_factory_make ("deinterleave", "rx-deinterleave");

    for (guint ch = 0; ch < data->channels; ch++) {
      gchar name[ELEMENT_NAME_SIZE];

      NAME_ELEMENT(name, "tee", ch);
      tee = gst_element_factory_make ("tee", name);

      if (!tee) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to create tee element in rx pipeline\n");
        continue;
      }
      g_object_set(tee, "allow-not-linked", TRUE, NULL);

      gst_bin_add (GST_BIN(pipeline), tee);
      // The deinterleave will be linked to the tee dynamically
    }

    g_signal_connect (deinterleave, "pad-added",
        G_CALLBACK (deinterleave_pad_added), NULL);

    g_object_set (udp_source, "address", data->rx_ip_addr, "port", data->rx_port,
        "multicast-iface", data->rtp_iface,
        "retrieve-sender-address", FALSE,
        NULL);
    g_object_set (udp_source, "caps", udp_caps, NULL);
    gst_caps_unref (udp_caps);

    if (!udp_source || !rtpdepay || !rtpjitbuf || !rx_audioconv || !capsfilter
        || !split || !deinterleave) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Failed to create rx elements\n");
      goto error;
    }

    gst_bin_add_many (GST_BIN (pipeline), udp_source, rtpdepay, rtpjitbuf, rx_audioconv,
        capsfilter, split, deinterleave, NULL);

    if (!gst_element_link_many (udp_source, rtpjitbuf, rtpdepay, split, rx_audioconv, capsfilter,
            deinterleave, NULL)) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Failed to link elements in the rx pipeline");
      goto error;
    }
  }

  if (data->direction & DIRECTION_TX) {
    GstElement *udpsink, *tx_audioconv, *audiointerleave, *capsfilter, *tx_valve;
    GstElement *appsrc;
    GstCaps *caps = NULL;

    audiointerleave =
        gst_element_factory_make ("audiointerleave", "audiointerleave");
    gst_bin_add (GST_BIN (pipeline), audiointerleave);
    g_object_set(audiointerleave, "start-time-selection", GST_AGGREGATOR_START_TIME_SELECTION_FIRST, NULL);
    g_object_set(audiointerleave, "output-buffer-duration", data->codec_ms * GST_MSECOND, NULL);

    if (data->tx_codec == L16) {
      rtp_pay = gst_element_factory_make ("rtpL16pay", "rtp-pay");

    } else {
      rtp_pay = gst_element_factory_make ("rtpL24pay", "rtp-pay");
    }
    g_object_set(rtp_pay, "pt", data->rtp_payload_type, NULL);

    if (data->ptime_ms != -1.0) {
      g_object_set(rtp_pay, "max-ptime", (gint64) (data->ptime_ms * 1000000),
          "min-ptime", (gint64) (data->ptime_ms * 1000000), NULL);
    }

    for (guint ch = 0; ch < data->channels; ch++) {
      gchar name[ELEMENT_NAME_SIZE];
      gchar pad_name[STR_SIZE];

      NAME_ELEMENT (name, "appsrc", ch);
      g_snprintf (pad_name, STR_SIZE, "sink_%u", ch);

      appsrc = gst_element_factory_make ("appsrc", name);
      if (!appsrc) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to create %s \n", name);
        continue;
      }

      /*Always accept S16LE from the FS*/
      caps = gst_caps_new_simple ("audio/x-raw",
          "rate", G_TYPE_INT, data->sample_rate,
          "channels", G_TYPE_INT, 1,
          "format", G_TYPE_STRING, "S16LE",
          "layout", G_TYPE_STRING, "interleaved",
          "channel-mask", GST_TYPE_BITMASK, (guint64) 0, NULL);
      g_object_set (appsrc, "format", GST_FORMAT_TIME, NULL);
      g_object_set (appsrc, "do-timestamp", TRUE, NULL);
      g_object_set (appsrc, "is-live", TRUE, NULL);
      /* Second * 3 allows a little bit of headroom */
      g_object_set (appsrc, "max-bytes", data->codec_ms * data->sample_rate * 2 * 3 / 1000,  NULL);

      g_object_set (appsrc, "caps", caps, NULL);
      gst_caps_unref (caps);
      gst_bin_add (GST_BIN (pipeline), appsrc);

      if (!gst_element_link_pads (appsrc, "src", audiointerleave, pad_name)) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to link pads of %s with audiointerleave\n", name);
        goto error;

      }
    }

    tx_valve = gst_element_factory_make ("valve", "tx-valve");
    g_object_set (tx_valve, "drop", data->txdrop, NULL);

    capsfilter = gst_element_factory_make ("capsfilter", "tx-capsf");

    tx_audioconv = gst_element_factory_make ("audioconvert", "tx-audioconv");
    g_object_set(tx_audioconv, "dithering", 0 /* none */, NULL);

    udpsink = gst_element_factory_make ("udpsink", "tx-sink");

    caps = gst_caps_new_simple ("audio/x-raw",
        "rate", G_TYPE_INT, data->sample_rate,
        "channels", G_TYPE_INT, data->channels,
        "format", G_TYPE_STRING, "S16LE",
        "layout", G_TYPE_STRING, "interleaved",
        "channel-mask", GST_TYPE_BITMASK, (guint64) 0,
        NULL);
    g_object_set (capsfilter, "caps", caps, NULL);
    gst_caps_unref (caps);

    g_object_set (udpsink, "host", data->tx_ip_addr, "port", data->tx_port, "multicast-iface", data->rtp_iface, NULL);
    g_object_set (udpsink, "sync", TRUE, "async", FALSE, NULL);
    g_object_set (udpsink, "qos", TRUE, "qos-dscp", 34, NULL);
    g_object_set (udpsink, "processing-deadline", 0 * GST_MSECOND, NULL);
    if (data->is_backup_sender) {
#ifndef _WIN32
      // Disable IP_MULTICAST_LOOP to avoid listening packets from same host
      // For Linux this needs to be set on the sender's side
      g_object_set(udpsink, "loop", FALSE, NULL);
#endif
    }

    if (!audiointerleave || !tx_valve || !tx_audioconv || !rtp_pay || !udpsink) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Failed to create tx elements\n");
      goto error;
    }

    gst_bin_add_many (GST_BIN (pipeline), tx_valve, capsfilter, tx_audioconv, rtp_pay,
        udpsink, NULL);

    if (!gst_element_link_many (audiointerleave, tx_valve, capsfilter, tx_audioconv,
            rtp_pay, udpsink, NULL)) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Failed to link elements");
      goto error;
    }
  }

  /* if this stream is configured to be a backup sender, we pause our Tx if we find another sender doing Tx
    on the same multicast address and resume once the remote sender stops
  */
  if (data->is_backup_sender) {
    GstElement *udpsrc, *fakesink;
    GstCaps *caps;

  /* create a dummy pipeline with `udpsrc ! fakesink` just to receive on udp and read the last-sampe from fakesink */
#ifndef ENABLE_THREADSHARE
    udpsrc = gst_element_factory_make ("udpsrc", "tx-monitor-udpsrc");
#else
    MAKE_TS_ELEMENT(udpsrc, "ts-udpsrc", "tx-monitor-udpsrc", ts_ctx);
#endif

    fakesink = gst_element_factory_make ("fakesink", "tx-monitor-fakesink");

    if (data->tx_codec == L16) {
      caps = gst_caps_new_simple ("application/x-rtp",
          "clock-rate", G_TYPE_INT, data->sample_rate,
          "channels", G_TYPE_INT, data->channels,
          "channel-order", G_TYPE_STRING, "unpositioned",
          "encoding-name", G_TYPE_STRING, "L16",
          "media", G_TYPE_STRING, "audio", NULL);
    } else {
      caps = gst_caps_new_simple ("application/x-rtp",
          "clock-rate", G_TYPE_INT, data->sample_rate,
          "channels", G_TYPE_INT, data->channels,
          "channel-order", G_TYPE_STRING, "unpositioned",
          "encoding-name", G_TYPE_STRING, "L24",
          "media", G_TYPE_STRING, "audio", NULL);
    }

    if (!udpsrc || !fakesink) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to create tx-monitor elements, cannot listen for primary sender\n");
    } else {
      g_object_set (udpsrc,
        "address", data->tx_ip_addr, "port", data->tx_port,
#ifdef _WIN32
        // Disable IP_MULTICAST_LOOP to avoid listening packets from same host
        // For Windows this needs to be set on the receiver's side
         "loop", FALSE,
#endif
        "multicast-iface", data->rtp_iface, "caps", caps, NULL);

      g_object_set(fakesink, "async", FALSE, NULL);

      gst_bin_add_many (GST_BIN (pipeline), udpsrc, fakesink, NULL);
      if (!gst_element_link_many (udpsrc, fakesink, NULL)) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to link tx-monitor elements, cannot listen for primary sender\n");
      } else {
        stream->pause_backup_sender = FALSE;
        stream->backup_sender_idle_wait_ms = data->backup_sender_idle_wait_ms;

        /* add a timer to check for remote sender's buffers every `backup_sender_idle_wait_ms` to resumek
          our Tx as soon as possible once the remote Tx stops */
        stream->backup_sender_idle_timer = g_timeout_add_full(G_PRIORITY_DEFAULT,
          data->backup_sender_idle_wait_ms, backup_sender_timeout_cb, stream, NULL);
      }
    }
    gst_caps_unref(caps);
  }

  bus = gst_pipeline_get_bus (GST_PIPELINE (pipeline));
  gst_bus_add_watch (bus, bus_callback, stream);
  gst_object_unref (bus);

  stream->error_cb = error_cb;
  stream->pipeline = GST_PIPELINE (pipeline);
  stream->mainloop = g_main_loop_new (NULL, FALSE);
  stream->thread = g_thread_new (pipeline_name, start_pipeline, stream);
  stream->sample_rate = data->sample_rate;

  g_atomic_int_set (&stream->clock_sync, 0);

  gst_element_set_start_time(pipeline, GST_CLOCK_TIME_NONE);
  gst_element_set_base_time(pipeline, 0);

  if (rtp_pay) {
    /* We have data->codec_ms of latency in the audiointerleave, so add that in */
    /* FIXME: we should be cleverer and apply the pipeline latency as computed instead */
    g_object_set (rtp_pay, "timestamp-offset",
        gst_util_uint64_scale_int ((data->codec_ms + data->rtp_ts_offset) * GST_MSECOND, data->sample_rate, GST_SECOND)
          % G_MAXUINT32,
        NULL);
  }

  if (rtpdepay && data->synthetic_ptp) {
    stream->clock = g_object_new (GST_TYPE_SYSTEM_CLOCK, "name", "SyntheticPtpClock", NULL);
    stream->cb_rx_stats_id =
      g_timeout_add_full(G_PRIORITY_DEFAULT, SYNTHETIC_CLOCK_INTERVAL_MS, update_clock, stream, NULL);
    /* We'll set the pipeline clock once it's synced */
  } else {
    stream->clock = NULL;
    gst_pipeline_use_clock (GST_PIPELINE(pipeline), data->clock);
    g_atomic_int_set (&stream->clock_sync, 1);
  }

  for (guint ch = 0; ch < MAX_IO_CHANNELS; ch++)
    stream->leftover_bytes[ch] = 0;

  return stream;

error:
  gst_object_unref (pipeline);
  g_free (stream);
  return NULL;

}

void
use_ptp_clock(g_stream_t *stream, GstClock *ptp_clock)
{
  g_atomic_int_set(&stream->clock_sync, 0);
  gst_element_set_state(GST_ELEMENT (stream->pipeline), GST_STATE_READY);

  /* cb_rx_stats_id will be non zero only when
  Rx is operational and pipeline clock is not ptp*/
  if (stream->cb_rx_stats_id) {
    g_source_remove(stream->cb_rx_stats_id);
    stream->cb_rx_stats_id = 0;
  }

  if (stream->clock) {
    gst_object_unref (stream->clock);
    stream->clock = NULL;
  }

  gst_pipeline_use_clock(GST_PIPELINE(stream->pipeline), ptp_clock);
  gst_pipeline_set_clock(GST_PIPELINE(stream->pipeline), ptp_clock);
  gst_element_set_state(GST_ELEMENT (stream->pipeline), GST_STATE_PLAYING);
  dump_pipeline(stream->pipeline, "ptp-clock-switch");

  g_atomic_int_set (&stream->clock_sync, 1);
}

void *
start_pipeline (void *data)
{
  g_stream_t *stream = (g_stream_t *) data;
  gst_element_set_state (GST_ELEMENT (stream->pipeline), GST_STATE_PLAYING);

  dump_pipeline(stream->pipeline, "start-pipeline");
  start_mainloop (stream->mainloop);
  return NULL;
}

void
stop_pipeline (g_stream_t * stream)
{
  GstBus *bus;

  dump_pipeline(stream->pipeline, "pipeline-stop");

  gst_element_set_state (GST_ELEMENT (stream->pipeline), GST_STATE_NULL);

  /* cb_rx_stats_id will be non zero only when
  Rx is operational and pipeline clock is not ptp*/
  if (stream->cb_rx_stats_id)
    g_source_remove(stream->cb_rx_stats_id);

  if (stream->backup_sender_idle_timer)
    g_source_remove(stream->backup_sender_idle_timer);

  bus = gst_pipeline_get_bus (GST_PIPELINE (stream->pipeline));
  gst_bus_remove_watch (bus);
  gst_object_unref (bus);

  gst_object_unref (stream->pipeline);
  if (stream->clock)
    gst_object_unref (stream->clock);
  teardown_mainloop (stream->mainloop);
  g_thread_join (stream->thread);
  g_free (stream);
  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
      "Pipeline and mainloop cleaned up\n");

}

void
teardown_mainloop (GMainLoop * mainloop)
{

  g_main_loop_quit (mainloop);
  g_main_loop_unref (mainloop);
}


void
start_mainloop (GMainLoop * mainloop)
{

  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Running mainloop\n");
  g_main_loop_run (mainloop);
}


gboolean
push_buffer (g_stream_t *stream, unsigned char *payload, guint len,
    guint ch_idx, switch_timer_t * timer)
{
  GstState cur_state = GST_STATE_NULL, pending_state;
  GstBuffer *buf;
  GstMapInfo info;
  GstFlowReturn ret;
  gchar name[ELEMENT_NAME_SIZE];
  GstElement *appsrc = NULL;
  GstPipeline *pipeline = stream->pipeline;
  gboolean res = FALSE;

  NAME_ELEMENT (name, "appsrc", ch_idx);
  appsrc = gst_bin_get_by_name (GST_BIN (pipeline), name);

  switch_core_timer_next (timer);

  if (appsrc == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
        "Failed to find appsrc in the pipeline\n");
    return FALSE;
  }

  if (!g_atomic_int_get(&stream->clock_sync)) {
    ret = TRUE;
    goto done;
  }

  gst_element_get_state (GST_ELEMENT (pipeline), &cur_state, &pending_state, 0);
  if (cur_state != GST_STATE_PAUSED && cur_state != GST_STATE_PLAYING) {
    ret = TRUE;
    goto done;
  }

  buf = gst_buffer_new_allocate (NULL, len, NULL);
  if (buf == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to allocate buffer\n");
    goto done;
  }

  if (!gst_buffer_map (buf, &info, GST_MAP_WRITE)) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to get buffer map\n");
    goto done;
  }
  memcpy (info.data, payload, len);
  gst_buffer_unmap (buf, &info);

  g_signal_emit_by_name (appsrc, "push-buffer", buf, &ret);
  // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Pushed buffer\n");

  gst_buffer_unref (buf);
  if (ret == GST_FLOW_ERROR) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to do 'push-buffer' \n");
    goto done;
  }

  res = TRUE;

done:
  gst_object_unref (GST_OBJECT (appsrc));
  return res;
}


int
pull_buffers (g_stream_t * stream, unsigned char *payload, guint needed_bytes,
    guint ch_idx, switch_timer_t * timer, gchar *session)
{
  GstState cur_state = GST_STATE_NULL, pending_state;
  GstBuffer *buf;
  GstSample *sample;
  GstMapInfo info;
  int total_bytes = 0;
  gchar name[ELEMENT_NAME_SIZE];
  GstElement *appsink;

  if (session == NULL)
    NAME_ELEMENT (name, "appsink", ch_idx);
  else
    NAME_SESSION_ELEMENT(name, "appsink", ch_idx, session);

  appsink = gst_bin_get_by_name (GST_BIN (stream->pipeline), name);

  if (appsink == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to find %s in the pipeline\n", name);
    return 0;
  }

  gst_element_get_state (GST_ELEMENT (stream->pipeline), &cur_state,
      &pending_state, 0);
  if (cur_state != GST_STATE_PAUSED && cur_state != GST_STATE_PLAYING)
    goto out;

  if (gst_app_sink_is_eos (GST_APP_SINK (appsink)))
    goto out;

  // Note: assumes leftover_bytes will never be more than buflen, which is
  // likely true (packet is limited to MTU, while buflen is 8192)
  // FIXME: revisit this to check whether we need this anymore
  if (stream->leftover_bytes[ch_idx]) {
    int copy =
        stream->leftover_bytes[ch_idx] <=
        needed_bytes ? stream->leftover_bytes[ch_idx] : needed_bytes;
    memcpy (payload, stream->leftover[ch_idx], copy);
    total_bytes += copy;
    stream->leftover_bytes[ch_idx] -= copy;
  }

  while (total_bytes < needed_bytes) {
    // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "pulling buffer\n");
    sample =
        gst_app_sink_try_pull_sample (GST_APP_SINK (appsink),
        10 * GST_MSECOND);
    if (!sample) {
      // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Failed to pull sample\n");
      switch_cond_next ();
      break;
    }
    buf = gst_sample_get_buffer (sample);

    if (!buf)
      continue;

    if (gst_buffer_map (buf, &info, GST_MAP_READ)) {
      if (total_bytes + info.size > needed_bytes) {
        int want = needed_bytes - total_bytes;

        stream->leftover_bytes[ch_idx] = info.size - want;
        memcpy (stream->leftover[ch_idx], info.data + want,
            stream->leftover_bytes[ch_idx]);

        info.size = want;
      }

      memcpy (payload + total_bytes, info.data, info.size);
      total_bytes += info.size;
    }
    gst_buffer_unmap (buf, &info);
    gst_sample_unref (sample);

    // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Got %d\n", total_bytes);
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

  // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%u Returning needed %d, total_bytes: %d\n", ch_idx, needed_bytes, total_bytes);
  // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Leftover %lu\n", stream->leftover_bytes[ch_idx]);

out:
  gst_object_unref(appsink);
  return total_bytes;
}


void
drop_input_buffers (gboolean drop, g_stream_t * stream, guint32 ch_idx)
{
  gchar name[ELEMENT_NAME_SIZE];
  GstElement *valve;
  NAME_ELEMENT (name, "valve", ch_idx);
  valve = gst_bin_get_by_name (GST_BIN (stream->pipeline), name);
  if (valve == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to get valve element in the pipeline\n");
    return;
  }
  g_object_set (valve, "drop", drop, NULL);
  g_snprintf (name, STR_SIZE, "drop-ch%d-%d", ch_idx, drop);
  dump_pipeline(stream->pipeline, name);
  gst_object_unref(valve);
}

gchar *
get_rtp_stats (g_stream_t *stream) {

  GstElement *rtpjitbuf;
  gchar *stats_str = NULL;
  rtpjitbuf = gst_bin_get_by_name(GST_BIN(stream->pipeline), "rx-jitbuf");

  if (rtpjitbuf) {
    GstStructure * stats;
    g_object_get(G_OBJECT(rtpjitbuf), "stats", &stats, NULL);
    stats_str = gst_structure_to_string (stats);
  }

  return stats_str;
}

void drop_output_buffers (gboolean drop, g_stream_t *stream)
{
  GstElement *tx_valve;
  gchar name[ELEMENT_NAME_SIZE];

  tx_valve = gst_bin_get_by_name(GST_BIN(stream->pipeline), "tx-valve");
  if (tx_valve == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to get valve element in the pipeline\n");
    return;
  }

  g_object_set (tx_valve, "drop", drop, NULL);

  g_snprintf (name, ELEMENT_NAME_SIZE, "tx-drop-%d", drop);
  dump_pipeline(stream->pipeline, name);

  gst_object_unref(tx_valve);
}
