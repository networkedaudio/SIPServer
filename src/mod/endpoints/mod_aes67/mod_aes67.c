/*
 * Based on mod_portaudio (whose license and header extract follows)
 *
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License `
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Anthony Minessale II <anthm@freeswitch.org>
 * Moises Silva <moises.silva@gmail.com> (Multiple endpoints work sponsored by Comrex Corporation)
 * Raymond Chandler <intralanman@freeswitch.org>
 *
 */

/*
 * mod_aes67.c -- AES67 Endpoint Module
 *
 */

#include "switch.h"

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include "aes67_api.h"
#include <gst/net/net.h>

#define MY_EVENT_RINGING "aes67::ringing"
#define MY_EVENT_MAKE_CALL "aes67::makecall"
#define MY_EVENT_CALL_HELD "aes67::callheld"
#define MY_EVENT_CALL_RESUMED "aes67::callresumed"
#define MY_EVENT_CALL_AUDIO_LEVEL "aes67::call_audio_level"
#define MY_EVENT_ERROR_AUDIO_DEV "aes67::audio_dev_error"
#define MY_EVENT_PTP_STATS "aes67::ptp_stats"
#define MY_EVENT_PTP_GM_CHANGE "aes67::ptp_grandmaster_change"
#define SWITCH_PA_CALL_ID_VARIABLE "gst_call_id"

#define MIN_STREAM_SAMPLE_RATE 8000
#define STREAM_SAMPLES_PER_PACKET(stream) ((stream->codec_ms * stream->sample_rate) / 1000)
#define NW_IFACE_LEN 1024

#define STREAM_READER_TRYLOCK(s) (!g_atomic_int_get(&(s)->reloading) && \
                                  g_rw_lock_reader_trylock(&(s)->rwlock))
#define STREAM_READER_LOCK(s) (g_rw_lock_reader_lock(&(s)->rwlock))
#define STREAM_READER_UNLOCK(s) g_rw_lock_reader_unlock(&(s)->rwlock)
#define STREAM_WRITER_LOCK(s) (g_rw_lock_writer_lock(&(s)->rwlock))
#define STREAM_WRITER_UNLOCK(s) g_rw_lock_writer_unlock(&(s)->rwlock)

SWITCH_MODULE_LOAD_FUNCTION (mod_aes67_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION (mod_aes67_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION (mod_aes67_runtime);
SWITCH_MODULE_DEFINITION (mod_aes67, mod_aes67_load,
    mod_aes67_shutdown, mod_aes67_runtime);

static switch_memory_pool_t *module_pool = NULL;
switch_endpoint_interface_t *aes67_endpoint_interface;

#define SAMPLE_TYPE  gint16
typedef int16_t SAMPLE;


typedef enum
{
  GFLAG_NONE = 0,
  GFLAG_EAR = (1 << 0),
  GFLAG_MOUTH = (1 << 1),
  GFLAG_RING = (1 << 2)
} GFLAGS;

typedef enum
{
  TFLAG_IO = (1 << 0),
  TFLAG_INBOUND = (1 << 1),
  TFLAG_OUTBOUND = (1 << 2),
  TFLAG_DTMF = (1 << 3),
  TFLAG_VOICE = (1 << 4),
  TFLAG_HANGUP = (1 << 5),
  TFLAG_LINEAR = (1 << 6),
  TFLAG_ANSWER = (1 << 7),
  TFLAG_HUP = (1 << 8),
  TFLAG_MASTER = (1 << 9),
  TFLAG_AUTO_ANSWER = (1 << 10)
} TFLAGS;

typedef struct
{
  char ip_addr[IP_ADDR_MAX_LEN];
  int port;
} udp_sock_t;

struct audio_stream
{
  udp_sock_t *outdev;
  udp_sock_t *indev;
  g_stream_t *stream;
  switch_timer_t write_timer;
  struct audio_stream *next;
};
typedef struct audio_stream audio_stream_t;

/* Audio stream that can be shared across endpoints
 *
 * Note: Every time we add a new member to this struct and it is used in conf
 * we need to make sure the `stream_compare` function is updated to compare
 * the newly added variable.
 */
typedef struct _shared_audio_stream_t
{
  /*! Friendly name for this stream */
  char name[255];
  /*! Sampling rate */
  int sample_rate;
  /*! Buffer packetization (and therefore timing) */
  int codec_ms;
  /*! The Rx IP addr and port */
  udp_sock_t *indev;
  /*! Input channels being used */
  uint8_t inchan_used[MAX_IO_CHANNELS];
  /*! The Tx IP addr and port */
  udp_sock_t *outdev;
  /*! Output channels being used */
  uint8_t outchan_used[MAX_IO_CHANNELS];
  /*! How many channels to create (for both rx and tx) */
  int channels;
  /*! The io stream helper to buffer audio */
  g_stream_t *stream;
  /* It can be shared after all :-)  */
  switch_mutex_t *mutex;
  /* Tx Codec type L16 or L24*/
  aes67_codec_t tx_codec;
  /* Rx Codec type L16 or L24*/
  aes67_codec_t rx_codec;
  /*ptime value for rtp payloader in msec*/
  double ptime_ms;
  /*pointer to the pipeline clock*/
  void *clock;
  /* if we don't have PTP, synthesize from receiver */
  int synthetic_ptp;
  /*offset (in msec) to be added to rtptime*/
  double rtp_ts_offset;
  /* network interface for udp multicast */
  char rtp_iface[NW_IFACE_LEN];
  /* RTP payload type */
  int rtp_payload_type;
  /* latency for the RTP jitterbuffer*/
  int rtp_jitbuf_latency;
  /* current state of txflow of the stream*/
  switch_bool_t txflow;
  /* to sync the read/write during stream reload*/
  volatile gint reloading;
  GRWLock rwlock;
  /* context name for threadshare elements*/
  char ts_context_name[TS_CONTEXT_NAME_LEN];
  /* accept multiple listen only streams*/
  switch_bool_t multiple_listen;
  /* Pause the Tx if an alternative sender found with same multicast address*/
  switch_bool_t is_backup_sender;
  /* Timeout in ms to wait for other sender packets arrival*/
  int backup_sender_idle_wait_ms;
} shared_audio_stream_t;

typedef struct private_object private_t;
/* Endpoint that can be called via aes67/endpoint/<endpoint-name> */
typedef struct _audio_endpoint
{
  /*! Friendly name for this endpoint */
  char name[255];

  /*! Input stream for this endpoint */
  shared_audio_stream_t *in_stream;

  /*! Output stream for this endpoint */
  shared_audio_stream_t *out_stream;

  /*! Channel index within the input stream where we get the audio for this endpoint */
  int inchan;

  /*! Channel index within the output stream where we get the audio for this endpoint */
  int outchan;

  /*! Number of Listen only sessions that are connected to same endpoint*/
  switch_size_t active_listen_sessions;

  /*! Let's be safe */
  switch_mutex_t *mutex;
} audio_endpoint_t;

struct private_object
{
  unsigned int flags;
  switch_core_session_t *session;
  switch_caller_profile_t *caller_profile;
  char call_id[50];
  int sample_rate;
  int codec_ms;
  switch_mutex_t *flag_mutex;
  char *hold_file;
  switch_file_handle_t fh;
  switch_file_handle_t *hfh;
  switch_frame_t hold_frame;
  unsigned char holdbuf[SWITCH_RECOMMENDED_BUFFER_SIZE];
  audio_endpoint_t *audio_endpoint;
  struct private_object *next;
  float average_level_rx;
  float average_level_tx;
  float new_value_weight;
  float old_value_weight;
  uint32_t scount_rx;
  uint32_t scount_tx;
  /*! For timed read and writes */
  switch_timer_t read_timer;
  switch_timer_t write_timer;

  /* We need our own read frame */
  switch_frame_t read_frame;
  unsigned char read_buf[SWITCH_RECOMMENDED_BUFFER_SIZE];

  /* Needed codecs for the core to read/write in the proper format */
  switch_codec_t read_codec;
  switch_codec_t write_codec;
};


static struct
{
  int debug;
  int port;
  char *cid_name;
  char *cid_num;
  char *dialplan;
  char *context;
  char *hold_file;
  char *timer_name;
  udp_sock_t *indev;
  udp_sock_t *outdev;
  int call_id;
  int unload_device_fail;
  switch_hash_t *call_hash;
  switch_mutex_t *device_lock;
  switch_mutex_t *pvt_lock;
  switch_mutex_t *streams_lock;
  switch_mutex_t *flag_mutex;
  switch_mutex_t *gst_mutex;
  switch_mutex_t *sh_shtreams_lock;
  int sample_rate;
  int codec_ms;
  char bit_depth[AUDIO_FMT_STR_LEN];
  int channels;
  aes67_codec_t tx_codec;
  aes67_codec_t rx_codec;
  audio_stream_t *main_stream;
  switch_codec_t read_codec;
  switch_codec_t write_codec;
  switch_frame_t read_frame;
  switch_frame_t cng_frame;
  unsigned char databuf[SWITCH_RECOMMENDED_BUFFER_SIZE];
  unsigned char cngbuf[SWITCH_RECOMMENDED_BUFFER_SIZE];
  private_t *call_list;
  audio_stream_t *stream_list;
  /*! Streams that can be used by multiple endpoints at the same time */
  switch_hash_t *sh_streams;
  /*! Endpoints configured */
  switch_hash_t *endpoints;
  int ring_interval;
  GFLAGS flags;
  switch_timer_t read_timer;
  switch_timer_t readfile_timer;
  switch_timer_t hold_timer;
  int dual_streams;
  int no_auto_resume_call;
  int codecs_inited;
  int destroying_streams;
  double ptime_ms;
  void *clock;
  int synthetic_ptp;
  double rtp_ts_offset;
  char rtp_iface[NW_IFACE_LEN];
  int rtp_payload_type;
  int rtp_jitbuf_latency;
  switch_bool_t enable_ptp_stats;
  long long int ptp_stats_cb_id;
  int level_report;
  uint64_t ptp_gm_id;
  uint64_t ptp_gm_mac_addr;
  gboolean ptp_synced;
  /* PTP domain using signed int to have -1 as default value */
  int8_t ptp_domain;
  /* Network interface to be used for PTP */
  char ptp_iface[NW_IFACE_LEN];
} globals;


#define PA_MASTER 1
#define PA_SLAVE 0


SWITCH_DECLARE_GLOBAL_STRING_FUNC (set_global_dialplan, globals.dialplan);
SWITCH_DECLARE_GLOBAL_STRING_FUNC (set_global_context, globals.context);
SWITCH_DECLARE_GLOBAL_STRING_FUNC (set_global_cid_name, globals.cid_name);
SWITCH_DECLARE_GLOBAL_STRING_FUNC (set_global_cid_num, globals.cid_num);
SWITCH_DECLARE_GLOBAL_STRING_FUNC (set_global_hold_file, globals.hold_file);
SWITCH_DECLARE_GLOBAL_STRING_FUNC (set_global_timer_name, globals.timer_name);
#define is_master(t) switch_test_flag(t, TFLAG_MASTER)

static void add_pvt (private_t * tech_pvt, int master);
static void remove_pvt (private_t * tech_pvt);
static switch_status_t channel_on_init (switch_core_session_t * session);
static switch_status_t channel_on_hangup (switch_core_session_t * session);
static switch_status_t channel_on_destroy (switch_core_session_t * session);
static switch_status_t channel_on_routing (switch_core_session_t * session);
static switch_status_t channel_on_exchange_media (switch_core_session_t *
    session);
static switch_status_t channel_on_soft_execute (switch_core_session_t *
    session);
static switch_call_cause_t channel_outgoing_channel (switch_core_session_t *
    session, switch_event_t * var_event,
    switch_caller_profile_t * outbound_profile,
    switch_core_session_t ** new_session, switch_memory_pool_t ** pool,
    switch_originate_flag_t flags, switch_call_cause_t * cancel_cause);
static switch_status_t channel_read_frame (switch_core_session_t * session,
    switch_frame_t ** frame, switch_io_flag_t flags, int stream_id);
static switch_status_t channel_write_frame (switch_core_session_t * session,
    switch_frame_t * frame, switch_io_flag_t flags, int stream_id);
static switch_status_t channel_kill_channel (switch_core_session_t * session,
    int sig);

static switch_status_t create_codecs (int restart);
static void create_hold_event (private_t * tech_pvt, int unhold);
static audio_stream_t *find_audio_stream (udp_sock_t * indev,
    udp_sock_t * outdev, int already_locked);
static audio_stream_t *get_audio_stream (udp_sock_t * indev,
    udp_sock_t * outdev);
static audio_stream_t *create_audio_stream (udp_sock_t * indev,
    udp_sock_t * outdev);
int open_audio_stream (g_stream_t ** stream, udp_sock_t * indev,
    udp_sock_t * outdev);
static void add_stream (audio_stream_t * stream, int already_locked);
static void remove_stream (audio_stream_t * stream, int already_locked);
static switch_status_t destroy_audio_stream (udp_sock_t * indev,
    udp_sock_t * outdev);
static switch_status_t destroy_actual_stream (audio_stream_t * stream);
static void destroy_audio_streams ();
static void destroy_shared_audio_streams ();
static switch_status_t validate_main_audio_stream ();

static switch_status_t load_config (void);
static int is_sock_equal (udp_sock_t * a, udp_sock_t * b);
void error_callback (char *ms, g_stream_t * stream);

SWITCH_STANDARD_API(aes_cmd);

/*
   State methods they get called when the state changes to the specific state
   returning SWITCH_STATUS_SUCCESS tells the core to execute the standard state method next
   so if you fully implement the state you can return SWITCH_STATUS_FALSE to skip it.
*/
static switch_status_t
channel_on_init (switch_core_session_t * session)
{
  switch_channel_t *channel;

  if (session) {
    if ((channel = switch_core_session_get_channel (session))) {
      switch_channel_set_flag (channel, CF_AUDIO);
    }
  }

  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
channel_on_routing (switch_core_session_t * session)
{

  switch_channel_t *channel = switch_core_session_get_channel (session);
  private_t *tech_pvt = switch_core_session_get_private (session);
  switch_time_t last;
  int waitsec = globals.ring_interval * 1000000;
  switch_file_handle_t fh = { 0 };
  const char *val, *ring_file = NULL, *hold_file = NULL;
  int16_t abuf[2048];

  switch_assert (tech_pvt != NULL);

  last = switch_micro_time_now () - waitsec;

  if ((val = switch_channel_get_variable (channel, "gst_hold_file"))) {
    hold_file = val;
  } else {
    hold_file = globals.hold_file;
  }

  if (hold_file) {
    tech_pvt->hold_file = switch_core_session_strdup (session, hold_file);
  }
  if (switch_test_flag (tech_pvt, TFLAG_OUTBOUND)) {
    if (!tech_pvt->audio_endpoint
        && validate_main_audio_stream () != SWITCH_STATUS_SUCCESS) {
      switch_channel_hangup (channel, SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER);
      return SWITCH_STATUS_FALSE;
    }

    if (!tech_pvt->audio_endpoint &&
        switch_test_flag (tech_pvt, TFLAG_OUTBOUND) &&
        !switch_test_flag (tech_pvt, TFLAG_AUTO_ANSWER)) {

      add_pvt (tech_pvt, PA_SLAVE);
    }

    if (tech_pvt->audio_endpoint
        || switch_test_flag (tech_pvt, TFLAG_AUTO_ANSWER)) {
      switch_mutex_lock (globals.pvt_lock);
      add_pvt (tech_pvt, PA_MASTER);
      if (switch_test_flag (tech_pvt, TFLAG_AUTO_ANSWER)) {
        switch_channel_mark_answered (channel);
        switch_set_flag (tech_pvt, TFLAG_ANSWER);
      }
      switch_mutex_unlock (globals.pvt_lock);

	  if (tech_pvt->audio_endpoint && tech_pvt->audio_endpoint->in_stream) {
		  char session_id[SESSION_ID_LEN];
		  switch_snprintf(session_id, SESSION_ID_LEN, "%llu", switch_core_session_get_id(session));

		  switch_mutex_lock (tech_pvt->audio_endpoint->mutex);
		  STREAM_READER_LOCK(tech_pvt->audio_endpoint->in_stream);

		  if (add_appsink(tech_pvt->audio_endpoint->in_stream->stream,
			   tech_pvt->audio_endpoint->inchan, session_id)) {
			   tech_pvt->audio_endpoint->active_listen_sessions++;
		  }

		  STREAM_READER_UNLOCK(tech_pvt->audio_endpoint->in_stream);
		  switch_mutex_unlock (tech_pvt->audio_endpoint->mutex);
	  }

      switch_yield (1000000);
    } else {
      // switch_channel_mark_ring_ready(channel);
    }

    while (switch_channel_get_state (channel) == CS_ROUTING &&
        !switch_channel_test_flag (channel, CF_ANSWERED) &&
        !switch_test_flag (tech_pvt, TFLAG_ANSWER)) {
      switch_size_t olen = globals.readfile_timer.samples;

      if (switch_micro_time_now () - last >= waitsec) {
        char buf[512];
        switch_event_t *event;

        switch_snprintf (buf, sizeof (buf), "BRRRRING! BRRRRING! call %s\n",
            tech_pvt->call_id);

        if (switch_event_create_subclass (&event, SWITCH_EVENT_CUSTOM,
                MY_EVENT_RINGING) == SWITCH_STATUS_SUCCESS) {
          switch_event_add_header_string (event, SWITCH_STACK_BOTTOM,
              "event_info", buf);
          switch_event_add_header_string (event, SWITCH_STACK_BOTTOM, "call_id", tech_pvt->call_id);    /* left behind for backwards compatability */
          switch_channel_set_variable (channel, SWITCH_PA_CALL_ID_VARIABLE,
              tech_pvt->call_id);
          switch_channel_event_set_data (channel, event);
          switch_event_fire (&event);
        }
        switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (session),
            SWITCH_LOG_DEBUG, "%s\n", buf);
        last = switch_micro_time_now ();
      }

      if (ring_file) {
        if (switch_core_timer_next (&globals.readfile_timer) !=
            SWITCH_STATUS_SUCCESS) {
          switch_core_file_close (&fh);
          break;
        }
        switch_core_file_read (&fh, abuf, &olen);
        if (olen == 0) {
          unsigned int pos = 0;
          switch_core_file_seek (&fh, &pos, 0, SEEK_SET);
        }

      } else {
        switch_yield (10000);
      }
    }
    switch_clear_flag_locked ((&globals), GFLAG_RING);
  }

  if (ring_file) {
    switch_core_file_close (&fh);
  }

  if (switch_test_flag (tech_pvt, TFLAG_OUTBOUND)) {
    if (!switch_test_flag (tech_pvt, TFLAG_ANSWER) &&
        !switch_channel_test_flag (channel, CF_ANSWERED)) {
      switch_channel_hangup (channel, SWITCH_CAUSE_NO_ANSWER);
      return SWITCH_STATUS_SUCCESS;
    }
    switch_set_flag (tech_pvt, TFLAG_ANSWER);
  }

  switch_set_flag_locked (tech_pvt, TFLAG_IO);


  switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (session), SWITCH_LOG_DEBUG,
      "%s CHANNEL ROUTING\n",
      switch_channel_get_name (switch_core_session_get_channel (session)));
  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
channel_on_execute (switch_core_session_t * session)
{
  switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (session), SWITCH_LOG_DEBUG,
      "%s CHANNEL EXECUTE\n",
      switch_channel_get_name (switch_core_session_get_channel (session)));
  return SWITCH_STATUS_SUCCESS;
}

static audio_stream_t *
find_audio_stream (udp_sock_t * indev, udp_sock_t * outdev, int already_locked)
{
  audio_stream_t *cur_stream;

  if (!globals.stream_list) {
    return NULL;
  }

  if (!already_locked) {
    switch_mutex_lock (globals.streams_lock);
  }
  cur_stream = globals.stream_list;

  while (cur_stream != NULL) {
    if (is_sock_equal (cur_stream->outdev, outdev)) {
      if (indev == NULL || is_sock_equal (cur_stream->indev, indev)) {
        if (!already_locked) {
          switch_mutex_unlock (globals.streams_lock);
        }
        return cur_stream;
      }
    }
    cur_stream = cur_stream->next;
  }
  if (!already_locked) {
    switch_mutex_unlock (globals.streams_lock);
  }
  return NULL;
}

static void
destroy_audio_streams ()
{
  globals.destroying_streams = 1;

  while (globals.stream_list != NULL) {
    destroy_audio_stream (globals.stream_list->indev,
        globals.stream_list->outdev);
  }
  globals.destroying_streams = 0;
}

static int clear_shared_audio_stream (shared_audio_stream_t * stream);

static void
free_shared_audio_stream (shared_audio_stream_t *stream)
{
    if (!stream)
        return;

    clear_shared_audio_stream(stream);
    /* Deinit here since clear_shared_audio_stream() allows the stream to be reused when reloading */
    g_rw_lock_clear(&stream->rwlock);
    switch_safe_free(stream->indev);
    switch_safe_free(stream->outdev);
    switch_safe_free(stream);
}

static void
destroy_shared_audio_streams ()
{
  switch_hash_index_t *hi;
  shared_audio_stream_t *stream;

  globals.destroying_streams = 1;

  switch_mutex_lock(globals.sh_shtreams_lock);
  for (hi = switch_core_hash_first(globals.sh_streams); hi; hi = switch_core_hash_next(&hi)) {
    switch_core_hash_this(hi, NULL, NULL, (void **)&stream);
    free_shared_audio_stream(stream);
  }
  switch_mutex_unlock(globals.sh_shtreams_lock);
  globals.destroying_streams = 0;
}

static switch_status_t
validate_main_audio_stream ()
{
  if (globals.read_timer.timer_interface) {
    switch_core_timer_sync (&globals.read_timer);
  }

  if (globals.main_stream) {
    if (globals.main_stream->write_timer.timer_interface) {
      switch_core_timer_sync (&(globals.main_stream->write_timer));
    }

    return SWITCH_STATUS_SUCCESS;
  }

  globals.main_stream = get_audio_stream (globals.indev, globals.outdev);

  if (globals.main_stream) {
    return SWITCH_STATUS_SUCCESS;
  }

  return SWITCH_STATUS_FALSE;
}


static switch_status_t
destroy_actual_stream (audio_stream_t * stream)
{
  if (stream == NULL) {
    return SWITCH_STATUS_FALSE;
  }

  if (globals.main_stream == stream) {
    globals.main_stream = NULL;
  }

  stop_pipeline (stream->stream);
  stream->stream = NULL;

  if (stream->write_timer.timer_interface) {
    switch_core_timer_destroy (&stream->write_timer);
  }

  switch_safe_free(stream->indev);
  switch_safe_free(stream->outdev);

  switch_safe_free (stream);
  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
destroy_audio_stream (udp_sock_t * indev, udp_sock_t * outdev)
{
  audio_stream_t *stream;

  switch_mutex_lock (globals.streams_lock);
  stream = find_audio_stream (indev, outdev, 1);
  if (stream == NULL) {
    switch_mutex_unlock (globals.streams_lock);
    return SWITCH_STATUS_FALSE;
  }

  remove_stream (stream, 1);
  switch_mutex_unlock (globals.streams_lock);

  destroy_actual_stream (stream);
  return SWITCH_STATUS_SUCCESS;
}


static void
destroy_codecs (void)
{

  if (switch_core_codec_ready (&globals.read_codec)) {
    switch_core_codec_destroy (&globals.read_codec);
  }

  if (switch_core_codec_ready (&globals.write_codec)) {
    switch_core_codec_destroy (&globals.write_codec);
  }

  if (globals.read_timer.timer_interface) {
    switch_core_timer_destroy (&globals.read_timer);
  }

  if (globals.readfile_timer.timer_interface) {
    switch_core_timer_destroy (&globals.readfile_timer);
  }

  if (globals.hold_timer.timer_interface) {
    switch_core_timer_destroy (&globals.hold_timer);
  }

  globals.codecs_inited = 0;
}

static void
create_hold_event (private_t * tech_pvt, int unhold)
{
  switch_event_t *event;
  char *event_id;

  if (unhold) {
    event_id = MY_EVENT_CALL_RESUMED;
  } else {
    event_id = MY_EVENT_CALL_HELD;
  }

  if (switch_event_create_subclass (&event, SWITCH_EVENT_CUSTOM,
          event_id) == SWITCH_STATUS_SUCCESS) {
    switch_channel_event_set_data (switch_core_session_get_channel
        (tech_pvt->session), event);
    switch_event_fire (&event);
  }
}

static void
add_stream (audio_stream_t * stream, int already_locked)
{
  audio_stream_t *last;

  if (!already_locked) {
    switch_mutex_lock (globals.streams_lock);
  }
  for (last = globals.stream_list; last && last->next; last = last->next);
  if (last == NULL) {
    globals.stream_list = stream;
  } else {
    last->next = stream;
  }
  if (!already_locked) {
    switch_mutex_unlock (globals.streams_lock);
  }
}

static void
remove_stream (audio_stream_t * stream, int already_locked)
{
  audio_stream_t *previous;
  if (!already_locked) {
    switch_mutex_lock (globals.streams_lock);
  }
  if (globals.stream_list == stream) {
    globals.stream_list = stream->next;
  } else {
    for (previous = globals.stream_list;
        previous && previous->next && previous->next != stream;
        previous = previous->next) {
      ;
    }
    if (previous) {
      previous->next = stream->next;
    }
  }
  if (!already_locked) {
    switch_mutex_unlock (globals.streams_lock);
  }
}

static void
add_pvt (private_t * tech_pvt, int master)
{
  private_t *tp;
  uint8_t in_list = 0;

  switch_mutex_lock (globals.pvt_lock);

  if (*tech_pvt->call_id == '\0') {
    switch_mutex_lock (globals.gst_mutex);
    switch_snprintf (tech_pvt->call_id, sizeof (tech_pvt->call_id), "%d",
        ++globals.call_id);
    switch_channel_set_variable (switch_core_session_get_channel
        (tech_pvt->session), SWITCH_PA_CALL_ID_VARIABLE, tech_pvt->call_id);
    switch_core_hash_insert (globals.call_hash, tech_pvt->call_id, tech_pvt);
    if (!tech_pvt->audio_endpoint) {
      switch_core_session_set_read_codec (tech_pvt->session,
          &globals.read_codec);
      switch_core_session_set_write_codec (tech_pvt->session,
          &globals.write_codec);
    }
    switch_mutex_unlock (globals.gst_mutex);
    switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (tech_pvt->session),
        SWITCH_LOG_DEBUG, "Added call %s\n", tech_pvt->call_id);
  }

  for (tp = globals.call_list; tp; tp = tp->next) {
    if (tp == tech_pvt) {
      in_list = 1;
    }
    if (master && switch_test_flag (tp, TFLAG_MASTER)) {
      switch_clear_flag_locked (tp, TFLAG_MASTER);
      create_hold_event (tp, 0);
    }
  }


  if (master) {
    if (!in_list) {
      tech_pvt->next = globals.call_list;
      globals.call_list = tech_pvt;
    }
    switch_set_flag_locked (tech_pvt, TFLAG_MASTER);

  } else if (!in_list) {
    for (tp = globals.call_list; tp && tp->next; tp = tp->next);
    if (tp) {
      tp->next = tech_pvt;
    } else {
      globals.call_list = tech_pvt;
    }
  }

  switch_mutex_unlock (globals.pvt_lock);
}

static void
remove_pvt (private_t * tech_pvt)
{
  private_t *tp, *last = NULL;
  int was_master = 0;

  switch_mutex_lock (globals.pvt_lock);
  for (tp = globals.call_list; tp; tp = tp->next) {

    if (tp == tech_pvt) {
      if (switch_test_flag (tp, TFLAG_MASTER)) {
        switch_clear_flag_locked (tp, TFLAG_MASTER);
        was_master = 1;
      }
      if (last) {
        last->next = tp->next;
      } else {
        globals.call_list = tp->next;
      }
    }
    last = tp;
  }

  if (globals.call_list) {
    if (was_master && !globals.no_auto_resume_call) {
      switch_set_flag_locked (globals.call_list, TFLAG_MASTER);
      create_hold_event (globals.call_list, 1);
    }
  }

  switch_mutex_unlock (globals.pvt_lock);
}

static void
tech_close_file (private_t * tech_pvt)
{
  if (tech_pvt->hfh) {
    tech_pvt->hfh = NULL;
    switch_core_file_close (&tech_pvt->fh);
  }
}

static switch_status_t
channel_on_destroy (switch_core_session_t * session)
{
  //private_t *tech_pvt = switch_core_session_get_private(session);
  //switch_assert(tech_pvt != NULL);
  return SWITCH_STATUS_SUCCESS;
}

static int release_stream_channel (shared_audio_stream_t * stream, int index,
    int input);
static switch_status_t
channel_on_hangup (switch_core_session_t * session)
{
  private_t *tech_pvt = switch_core_session_get_private (session);
  switch_assert (tech_pvt != NULL);

  if (tech_pvt->audio_endpoint) {
    audio_endpoint_t *endpoint = tech_pvt->audio_endpoint;
    char session_id[SESSION_ID_LEN];

    switch_mutex_lock (endpoint->mutex);

    switch_snprintf(session_id, SESSION_ID_LEN, "%llu", switch_core_session_get_id(tech_pvt->session));

    if (endpoint->in_stream) {
      STREAM_READER_LOCK(endpoint->in_stream);

      if (remove_appsink(endpoint->in_stream->stream,
        endpoint->inchan, session_id)) {
        endpoint->active_listen_sessions--;
      }

      STREAM_READER_UNLOCK(endpoint->in_stream);
    }

    if (endpoint->active_listen_sessions == 0 && endpoint->in_stream) {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "releasing inchan \n");
      release_stream_channel(endpoint->in_stream, endpoint->inchan, 1);
    }

    release_stream_channel(endpoint->out_stream, endpoint->outchan, 0);
    switch_core_timer_destroy(&tech_pvt->read_timer);
    switch_core_timer_destroy(&tech_pvt->write_timer);
    switch_core_codec_destroy(&tech_pvt->read_codec);
    switch_core_codec_destroy(&tech_pvt->write_codec);

    switch_mutex_unlock (endpoint->mutex);
    tech_pvt->audio_endpoint = NULL;
  }

  switch_mutex_lock (globals.gst_mutex);
  switch_core_hash_delete (globals.call_hash, tech_pvt->call_id);
  switch_mutex_unlock (globals.gst_mutex);

  switch_clear_flag_locked (tech_pvt, TFLAG_IO);
  switch_set_flag_locked (tech_pvt, TFLAG_HUP);

  remove_pvt (tech_pvt);

  tech_close_file (tech_pvt);

  switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (session), SWITCH_LOG_DEBUG,
      "%s CHANNEL HANGUP\n",
      switch_channel_get_name (switch_core_session_get_channel (session)));

  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
channel_kill_channel (switch_core_session_t * session, int sig)
{
  switch_channel_t *channel = switch_core_session_get_channel (session);
  private_t *tech_pvt = switch_core_session_get_private (session);
  switch_assert (tech_pvt != NULL);

  switch (sig) {
    case SWITCH_SIG_KILL:
      switch_set_flag_locked (tech_pvt, TFLAG_HUP);
      switch_channel_hangup (channel, SWITCH_CAUSE_NORMAL_CLEARING);
      break;
    default:
      break;
  }
  switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (session), SWITCH_LOG_DEBUG,
      "%s CHANNEL KILL, sig %d\n", switch_channel_get_name (channel), sig);

  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
channel_on_soft_execute (switch_core_session_t * session)
{
  switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (session), SWITCH_LOG_DEBUG,
      "CHANNEL TRANSMIT\n");
  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
channel_on_exchange_media (switch_core_session_t * session)
{
  private_t *tech_pvt = switch_core_session_get_private (session);
  switch_assert (tech_pvt != NULL);

  if (tech_pvt->audio_endpoint && tech_pvt->audio_endpoint->in_stream) {
    char session_id[SESSION_ID_LEN];
    switch_snprintf(session_id, SESSION_ID_LEN, "%llu", switch_core_session_get_id(session));

    switch_mutex_lock (tech_pvt->audio_endpoint->mutex);
    STREAM_READER_LOCK(tech_pvt->audio_endpoint->in_stream);

    if (add_appsink(tech_pvt->audio_endpoint->in_stream->stream,
        tech_pvt->audio_endpoint->inchan, session_id)) {
        tech_pvt->audio_endpoint->active_listen_sessions++;
    }

    STREAM_READER_UNLOCK(tech_pvt->audio_endpoint->in_stream);
    switch_mutex_unlock (tech_pvt->audio_endpoint->mutex);
  }

  switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (session), SWITCH_LOG_DEBUG,
      "CHANNEL EXCHANGE MEDIA\n");

  return SWITCH_STATUS_SUCCESS;
}


static switch_status_t
channel_send_dtmf (switch_core_session_t * session, const switch_dtmf_t * dtmf)
{
  private_t *tech_pvt = switch_core_session_get_private (session);
  switch_assert (tech_pvt != NULL);

  switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (session), SWITCH_LOG_DEBUG,
      "DTMF ON CALL %s [%c]\n", tech_pvt->call_id, dtmf->digit);

  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
channel_endpoint_read (private_t * tech_pvt, switch_frame_t ** frame, char *session_id)
{
  int bytes = 0;
  int samples = 0;
  audio_endpoint_t *endpoint = tech_pvt->audio_endpoint;

  if (!endpoint->in_stream) {
    switch_core_timer_next (&tech_pvt->read_timer);
    *frame = &globals.cng_frame;
    return SWITCH_STATUS_SUCCESS;
  }

  tech_pvt->read_frame.data = tech_pvt->read_buf;
  tech_pvt->read_frame.buflen = sizeof (tech_pvt->read_buf);
  tech_pvt->read_frame.source = __FILE__;

  if (STREAM_READER_TRYLOCK(endpoint->in_stream)) {
    if (!endpoint->in_stream->stream) {
      return SWITCH_STATUS_FALSE;
    }
    bytes =
      pull_buffers (endpoint->in_stream->stream,
          (unsigned char *) tech_pvt->read_frame.data,
          STREAM_SAMPLES_PER_PACKET (endpoint->in_stream) *
          2 /* FIXME: non-S16LE */ ,
          endpoint->inchan, &tech_pvt->read_timer, session_id);
    STREAM_READER_UNLOCK(endpoint->in_stream);
  } else {
    // Pipeline is being reset, feed some silence
    bytes = STREAM_SAMPLES_PER_PACKET (endpoint->in_stream) * 2;
    memset(tech_pvt->read_frame.data, 0, bytes);
  }

  // FIXME: Only works for S16LE
  samples = bytes / sizeof (int16_t);
  if (!bytes) {
    switch_core_timer_next (&tech_pvt->read_timer);
    *frame = &globals.cng_frame;
    return SWITCH_STATUS_SUCCESS;
  }

  tech_pvt->read_frame.datalen = bytes;
  tech_pvt->read_frame.samples = samples;
  tech_pvt->read_frame.codec = &tech_pvt->read_codec;
  *frame = &tech_pvt->read_frame;
  return SWITCH_STATUS_SUCCESS;
}

static void update_level (private_t *tech_pvt, switch_frame_t *frame, uint8_t rx)
{
  uint32_t i, samples;
  int16_t *pcm = frame->data;
  float level = rx ? tech_pvt->average_level_rx : tech_pvt->average_level_tx;
  uint32_t scount = rx ? tech_pvt->scount_rx : tech_pvt->scount_tx;

  if (globals.level_report == SWITCH_FALSE) {
    return;
  }

  // calculate signal level
  for (i = 0; i < frame->samples; i++, scount++) {
    level = (abs(pcm[i]) * tech_pvt->new_value_weight) + (level * tech_pvt->old_value_weight);
  }

  if (rx) {
    tech_pvt->average_level_rx = level;
  } else {
    tech_pvt->average_level_tx = level;
  }

  // Fire an event when hitting the per-second rate
  // we only fire a single event for both rx/tx and do it on the rx cycle for simplicity
  samples = tech_pvt ?
    tech_pvt->read_codec.implementation->actual_samples_per_second :
    globals.read_codec.implementation->actual_samples_per_second;

  if (scount >= samples) {
    if (rx) {
      switch_event_t *event;
      if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, MY_EVENT_CALL_AUDIO_LEVEL) == SWITCH_STATUS_SUCCESS) {
        double rxdb;
        double txdb;
        float avg_rx;
        float avg_tx;

        switch_mutex_t *mutex = tech_pvt->audio_endpoint ? tech_pvt->audio_endpoint->mutex : globals.pvt_lock;

        switch_mutex_lock(mutex);
        avg_rx = tech_pvt->average_level_rx;
        avg_tx = tech_pvt->average_level_tx;
        switch_mutex_unlock(mutex);

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(tech_pvt->session),
            SWITCH_LOG_DEBUG, "firing level event at scount=%u with rate %u rx=%f tx=%f\n", scount, samples,
            avg_rx,
            avg_tx);

        rxdb = avg_rx > 0.0 ? 20 * log10(tech_pvt->average_level_rx / (float)SWITCH_SMAX) : -90;
        txdb = avg_tx > 0.0 ? 20 * log10(tech_pvt->average_level_tx / (float)SWITCH_SMAX) : -90;
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "rx-level", "%.2f", rxdb);
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "tx-level", "%.2f", txdb);
        switch_channel_event_set_data(switch_core_session_get_channel(tech_pvt->session), event);
        switch_event_fire(&event);
      }
    }
    scount = 0;
  }

  if (rx) {
    tech_pvt->scount_rx = scount;
  } else {
    tech_pvt->scount_tx = scount;
  }
}

static switch_status_t
channel_read_frame (switch_core_session_t * session, switch_frame_t ** frame,
    switch_io_flag_t flags, int stream_id)
{
  private_t *tech_pvt = switch_core_session_get_private (session);
  int samples = 0;
  int bytes = 0;
  switch_status_t status = SWITCH_STATUS_FALSE;
  switch_assert (tech_pvt != NULL);
  char session_id[SESSION_ID_LEN];
  switch_snprintf(session_id, SESSION_ID_LEN, "%llu", switch_core_session_get_id(session));


  if (tech_pvt->audio_endpoint) {
    status = channel_endpoint_read (tech_pvt, frame, session_id);
    goto normal_return;
  }

  if (!globals.main_stream) {
    goto normal_return;
  }

  if (!globals.main_stream->stream) {
    goto normal_return;
  }

  if (switch_test_flag (tech_pvt, TFLAG_HUP)) {
    goto normal_return;
  }

  if (!switch_test_flag (tech_pvt, TFLAG_IO)) {
    goto cng_wait;
  }

  if (!is_master (tech_pvt)) {
    if (tech_pvt->hold_file) {
      switch_size_t olen =
          globals.read_codec.implementation->samples_per_packet;

      if (!tech_pvt->hfh) {
        int sample_rate = globals.sample_rate;
        if (switch_core_file_open (&tech_pvt->fh,
                tech_pvt->hold_file,
                globals.read_codec.implementation->number_of_channels,
                globals.read_codec.implementation->actual_samples_per_second,
                SWITCH_FILE_FLAG_READ | SWITCH_FILE_DATA_SHORT,
                NULL) != SWITCH_STATUS_SUCCESS) {
          tech_pvt->hold_file = NULL;
          goto cng_wait;
        }

        tech_pvt->hfh = &tech_pvt->fh;
        tech_pvt->hold_frame.data = tech_pvt->holdbuf;
        tech_pvt->hold_frame.buflen = sizeof (tech_pvt->holdbuf);
        tech_pvt->hold_frame.rate = sample_rate;
        tech_pvt->hold_frame.codec = &globals.write_codec;
      }

      if (switch_core_timer_next (&globals.hold_timer) != SWITCH_STATUS_SUCCESS) {
        switch_core_file_close (&tech_pvt->fh);
        goto cng_nowait;
      }
      switch_core_file_read (tech_pvt->hfh, tech_pvt->hold_frame.data, &olen);

      if (olen == 0) {
        unsigned int pos = 0;
        switch_core_file_seek (tech_pvt->hfh, &pos, 0, SEEK_SET);
        goto cng_nowait;
      }

      tech_pvt->hold_frame.datalen = (uint32_t) (olen * sizeof (int16_t));
      tech_pvt->hold_frame.samples = (uint32_t) olen;
      *frame = &tech_pvt->hold_frame;

      status = SWITCH_STATUS_SUCCESS;
      goto normal_return;
    }

    goto cng_wait;
  }

  if (tech_pvt->hfh) {
    tech_close_file (tech_pvt);
  }

  switch_mutex_lock (globals.device_lock);
  bytes =
      pull_buffers (globals.main_stream->stream,
      (unsigned char *) globals.read_frame.data,
      globals.read_codec.implementation->samples_per_packet *
      2 /* FIXME: S16LE-only */ ,
      0, &globals.read_timer, session_id);
  // FIXME: won't work for L24/L32
  samples = bytes / sizeof (int16_t);
  switch_mutex_unlock (globals.device_lock);

  if (samples) {
    globals.read_frame.datalen = bytes;
    globals.read_frame.samples = samples;

    *frame = &globals.read_frame;

    if (!switch_test_flag ((&globals), GFLAG_MOUTH)) {
      memset (globals.read_frame.data, 255, globals.read_frame.datalen);
    }
    status = SWITCH_STATUS_SUCCESS;
  } else {
    goto cng_nowait;
  }

normal_return:
  if (*frame) {
    update_level (tech_pvt, *frame, 1);
  }
  return status;

cng_nowait:
  *frame = &globals.cng_frame;
  return SWITCH_STATUS_SUCCESS;

cng_wait:
  switch_core_timer_next (&globals.hold_timer);
  *frame = &globals.cng_frame;
  return SWITCH_STATUS_SUCCESS;

}

static switch_status_t
channel_endpoint_write (private_t * tech_pvt, switch_frame_t * frame)
{
  audio_endpoint_t *endpoint = tech_pvt->audio_endpoint;
  if (!endpoint->out_stream) {
    switch_core_timer_next (&tech_pvt->write_timer);
    return SWITCH_STATUS_SUCCESS;
  }

  if (switch_test_flag (tech_pvt, TFLAG_HUP)) {
    return SWITCH_STATUS_FALSE;
  }
  if (!switch_test_flag (tech_pvt, TFLAG_IO)) {
    return SWITCH_STATUS_SUCCESS;
  }

  if (STREAM_READER_TRYLOCK(endpoint->out_stream)) {
    if (!endpoint->out_stream->stream) {
      return SWITCH_STATUS_FALSE;
    }

    // Pipeline is not being reset, we can push data
    push_buffer (endpoint->out_stream->stream,
            (unsigned char *) frame->data, frame->datalen, endpoint->outchan,
            &(tech_pvt->write_timer));
    STREAM_READER_UNLOCK(endpoint->out_stream);
  }

  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
channel_write_frame (switch_core_session_t * session, switch_frame_t * frame,
    switch_io_flag_t flags, int stream_id)
{
  switch_status_t status = SWITCH_STATUS_FALSE;
  private_t *tech_pvt = switch_core_session_get_private (session);
  switch_assert (tech_pvt != NULL);

  update_level (tech_pvt, frame, 0);

  if (tech_pvt->audio_endpoint) {
    return channel_endpoint_write (tech_pvt, frame);
  }

  if (!globals.main_stream) {
    return SWITCH_STATUS_FALSE;
  }

  if (!globals.main_stream->stream) {
    return SWITCH_STATUS_FALSE;
  }


  if (switch_test_flag (tech_pvt, TFLAG_HUP)) {
    return SWITCH_STATUS_FALSE;
  }

  if (!is_master (tech_pvt) || !switch_test_flag (tech_pvt, TFLAG_IO)) {
    return SWITCH_STATUS_SUCCESS;
  }

  if (globals.main_stream) {
    if (switch_test_flag ((&globals), GFLAG_EAR)) {
      // Note: 0 is passed as the channel index because main stream can have only one out channel
      push_buffer (globals.main_stream->stream,
          (unsigned char *) frame->data, frame->datalen, 0,
          &(globals.main_stream->write_timer));
    }
    status = SWITCH_STATUS_SUCCESS;
  }

  return status;
}

static switch_status_t
channel_answer_channel (switch_core_session_t * session)
{
  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
channel_receive_message (switch_core_session_t * session,
    switch_core_session_message_t * msg)
{
  private_t *tech_pvt = switch_core_session_get_private (session);
  switch_assert (tech_pvt != NULL);

  switch (msg->message_id) {
    case SWITCH_MESSAGE_INDICATE_ANSWER:
      channel_answer_channel (session);
      break;
    case SWITCH_MESSAGE_INDICATE_PROGRESS:
    {
      switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (session), SWITCH_LOG_DEBUG,
          "Engage Early Media\n");
      switch_set_flag_locked (tech_pvt, TFLAG_IO);
    }
    default:
      break;
  }
  return SWITCH_STATUS_SUCCESS;
}

switch_state_handler_table_t aes67_event_handlers = {
  /*.on_init */ channel_on_init,
  /*.on_routing */ channel_on_routing,
  /*.on_execute */ channel_on_execute,
  /*.on_hangup */ channel_on_hangup,
  /*.on_exchange_media */ channel_on_exchange_media,
  /*.on_soft_execute */ channel_on_soft_execute,
  /*.on_consume_media */ NULL,
  /*.on_hibernate */ NULL,
  /*.on_reset */ NULL,
  /*.on_park */ NULL,
  /*.on_reporting */ NULL,
  /*.on_destroy */ channel_on_destroy
};

switch_io_routines_t aes67_io_routines = {
  /*.outgoing_channel */ channel_outgoing_channel,
  /*.read_frame */ channel_read_frame,
  /*.write_frame */ channel_write_frame,
  /*.kill_channel */ channel_kill_channel,
  /*.send_dtmf */ channel_send_dtmf,
  /*.receive_message */ channel_receive_message
};

static int create_shared_audio_stream (shared_audio_stream_t * stream);
static int
take_stream_channel (shared_audio_stream_t * stream, int index, int input, const char* session_id)
{
  int rc = 0;
  if (!stream) {
    return rc;
  }

  switch_mutex_lock (stream->mutex);

  if (!stream->stream && create_shared_audio_stream (stream)) {
    rc = -1;
    goto done;
  }

  if (input) {
	  if (stream->inchan_used[index] &&
        !stream->multiple_listen) {
      rc = -1;
      goto done;
    }
    stream->inchan_used[index] = 1;
  } else {
    if (!input && stream->outchan_used[index]) {
      rc = -1;
      goto done;
    }
    stream->outchan_used[index] = 1;
  }

done:
  switch_mutex_unlock (stream->mutex);
  return rc;
}

static int
release_stream_channel (shared_audio_stream_t * stream, int index, int input)
{
  int rc = 0;

  if (!stream) {
    return rc;
  }

  switch_mutex_lock (stream->mutex);

  if (input) {
    stream->inchan_used[index] = 0;
  } else {
    stream->outchan_used[index] = 0;
  }

  switch_mutex_unlock (stream->mutex);
  return rc;
}

static void init_pvt_level (private_t *tech_pvt)
{
  // Init audio level weight factors
  // FIXME: Have to adjust this if we decide on a different avg window
  float window = 1000.0f; // window in ms
  uint32_t samples = tech_pvt?
    tech_pvt->read_codec.implementation->actual_samples_per_second :
    globals.read_codec.implementation->actual_samples_per_second;

  tech_pvt->new_value_weight = 1.0f / ((float)samples * (window / 1000.0f));
  tech_pvt->old_value_weight = 1.0f - tech_pvt->new_value_weight;
}

/* Make sure when you have 2 sessions in the same scope that you pass the appropriate one to the routines
   that allocate memory or you will have 1 channel with memory allocated from another channel's pool!
*/
static switch_call_cause_t
channel_outgoing_channel (switch_core_session_t * session,
    switch_event_t * var_event, switch_caller_profile_t * outbound_profile,
    switch_core_session_t ** new_session, switch_memory_pool_t ** pool,
    switch_originate_flag_t flags, switch_call_cause_t * cancel_cause)
{
  char name[128];
  const char *id = NULL;
  private_t *tech_pvt = NULL;
  switch_channel_t *channel = NULL;
  switch_caller_profile_t *caller_profile = NULL;
  switch_call_cause_t retcause = SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
  int codec_ms = -1;
  int samples_per_packet = -1;
  int sample_rate = 0;
  audio_endpoint_t *endpoint = NULL;
  char *endpoint_name = NULL;
  const char *endpoint_answer = NULL;
  char new_sess_id[SESSION_ID_LEN];

  if (!outbound_profile) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Missing caller profile\n");
    return retcause;
  }

  if (!(*new_session =
          switch_core_session_request_uuid (aes67_endpoint_interface,
              SWITCH_CALL_DIRECTION_OUTBOUND, flags, pool,
              switch_event_get_header (var_event, "origination_uuid")))) {
    return retcause;
  }

  switch_core_session_add_stream (*new_session, NULL);
  if ((tech_pvt =
          (private_t *) switch_core_session_alloc (*new_session,
              sizeof (private_t))) != 0) {
    memset (tech_pvt, 0, sizeof (*tech_pvt));
    switch_mutex_init (&tech_pvt->flag_mutex, SWITCH_MUTEX_NESTED,
        switch_core_session_get_pool (*new_session));
    channel = switch_core_session_get_channel (*new_session);
    switch_core_session_set_private (*new_session, tech_pvt);
    tech_pvt->session = *new_session;
  } else {
    switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (*new_session),
        SWITCH_LOG_CRIT, "Hey where is my memory pool?\n");
    switch_core_session_destroy (new_session);
    return retcause;
  }

  if (outbound_profile->destination_number
      && !strncasecmp (outbound_profile->destination_number, "endpoint",
          sizeof ("endpoint") - 1)) {
    endpoint = NULL;
    endpoint_name =
        switch_core_strdup (outbound_profile->pool,
        outbound_profile->destination_number);
    endpoint_name = strchr (endpoint_name, '/');
    if (!endpoint_name) {
      switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (*new_session),
          SWITCH_LOG_CRIT, "No aes67 endpoint specified\n");
      goto error;
    }
    endpoint_name++;
    endpoint = switch_core_hash_find (globals.endpoints, endpoint_name);
    if (!endpoint) {
      switch_log_printf (SWITCH_CHANNEL_SESSION_LOG (*new_session),
          SWITCH_LOG_CRIT, "Invalid aes67 endpoint %s\n", endpoint_name);
      goto error;
    }

    switch_snprintf(new_sess_id, SESSION_ID_LEN, "%llu", switch_core_session_get_id(*new_session));
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(*new_session), SWITCH_LOG_DEBUG, "New session id: %s\n", new_sess_id);

    switch_mutex_lock (endpoint->mutex);

    if (endpoint->active_listen_sessions) {
	    // someone already has this endpoint
      // do not allow to the session
      //  if endpoint is not rx only or
      //  if the instream (rx) is not enabled to allow mulitple listeners
      if (endpoint->out_stream ||
       (!endpoint->in_stream && !endpoint->in_stream->multiple_listen)) {
        retcause = SWITCH_CAUSE_USER_BUSY;
        goto error;
      }
    }

    codec_ms =
        endpoint->in_stream ? endpoint->in_stream->
        codec_ms : endpoint->out_stream->codec_ms;
    samples_per_packet =
        endpoint->
        in_stream ? STREAM_SAMPLES_PER_PACKET (endpoint->in_stream) :
        STREAM_SAMPLES_PER_PACKET (endpoint->out_stream);
    sample_rate =
        endpoint->in_stream ? endpoint->in_stream->
        sample_rate : endpoint->out_stream->sample_rate;

    if (switch_core_timer_init (&tech_pvt->read_timer,
            globals.timer_name, codec_ms,
            samples_per_packet, module_pool) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "failed to setup read timer for endpoint '%s'!\n", endpoint->name);
      goto error;
    }

    /* The write timer must be setup regardless */
    if (switch_core_timer_init (&tech_pvt->write_timer,
            globals.timer_name, codec_ms,
            samples_per_packet, module_pool) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "failed to setup read timer for endpoint '%s'!\n", endpoint->name);
      goto error;
    }
    //hardcode to Raw 16bit
    if (switch_core_codec_init (&tech_pvt->read_codec,
            "L16", NULL, NULL, sample_rate, codec_ms, 1,
            SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL,
            NULL) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Can't load codec?\n");
      goto error;
    }
    //hardcode to Raw 16bit
    if (switch_core_codec_init (&tech_pvt->write_codec,
            "L16", NULL, NULL, sample_rate, codec_ms, 1,
            SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL,
            NULL) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Can't load codec?\n");
      goto error;
    }
    switch_core_session_set_read_codec (tech_pvt->session,
        &tech_pvt->read_codec);
    switch_core_session_set_write_codec (tech_pvt->session,
        &tech_pvt->write_codec);

    /* try to acquire the stream */
    if (take_stream_channel (endpoint->in_stream, endpoint->inchan, 1, new_sess_id)) {
      retcause = SWITCH_CAUSE_USER_BUSY;
      goto error;
    }
    if (take_stream_channel (endpoint->out_stream, endpoint->outchan, 0, NULL)) {
      release_stream_channel (endpoint->in_stream, endpoint->inchan, 1);
      retcause = SWITCH_CAUSE_USER_BUSY;
      goto error;
    }
    switch_snprintf (name, sizeof (name), "aes67/endpoint-%s",
        endpoint_name);
    if (var_event
        && (endpoint_answer =
            (switch_event_get_header (var_event, "endpoint_answer")))) {
      if (switch_true (endpoint_answer)) {
        switch_set_flag (tech_pvt, TFLAG_AUTO_ANSWER);
      }
    } else {
      switch_set_flag (tech_pvt, TFLAG_AUTO_ANSWER);
    }

    tech_pvt->audio_endpoint = endpoint;
    switch_mutex_unlock (endpoint->mutex);
  } else {
    id = !zstr (outbound_profile->
        caller_id_number) ? outbound_profile->caller_id_number : "na";
    switch_snprintf (name, sizeof (name), "aes67/%s", id);
    // switch_set_flag(tech_pvt, TFLAG_AUTO_ANSWER);
    if (outbound_profile->destination_number
        && !strcasecmp (outbound_profile->destination_number, "auto_answer")) {
      switch_set_flag (tech_pvt, TFLAG_AUTO_ANSWER);
    }
  }
  switch_channel_set_name (channel, name);
  caller_profile = switch_caller_profile_clone (*new_session, outbound_profile);
  switch_channel_set_caller_profile (channel, caller_profile);
  tech_pvt->caller_profile = caller_profile;

  switch_set_flag_locked (tech_pvt, TFLAG_OUTBOUND);
  switch_channel_set_state (channel, CS_INIT);
  switch_channel_set_flag (channel, CF_AUDIO);

  init_pvt_level (tech_pvt);

  return SWITCH_CAUSE_SUCCESS;

error:
  if (tech_pvt) {
    if (tech_pvt->read_timer.interval) {
          switch_core_timer_destroy(&tech_pvt->read_timer);
    }
	  if (tech_pvt->write_timer.interval) {
          switch_core_timer_destroy(&tech_pvt->write_timer);
    }
	  if (tech_pvt->read_codec.codec_interface) {
          switch_core_codec_destroy(&tech_pvt->read_codec);
    }
	  if (tech_pvt->write_codec.codec_interface) {
          switch_core_codec_destroy(&tech_pvt->write_codec);
    }
  }

  if (endpoint)
    switch_mutex_unlock (endpoint->mutex);

  if (new_session && *new_session) {
    switch_core_session_destroy (new_session);
  }
  return retcause;
}

static void
gst_logger (GstDebugCategory * category, GstDebugLevel level,
    const gchar * file, const gchar * function, gint line,
    GObject * object, GstDebugMessage * message, gpointer unused)
{
	gint fs_log_level;
	gchar *tag;

	if (level > gst_debug_category_get_threshold (category))
		return;

	switch (level) {
		case GST_LEVEL_ERROR:
		  fs_log_level = SWITCH_LOG_ERROR;
		  break;
		case GST_LEVEL_WARNING:
		  fs_log_level = SWITCH_LOG_WARNING;
		  break;
		case GST_LEVEL_FIXME:
		case GST_LEVEL_INFO:
		  fs_log_level = SWITCH_LOG_INFO;
		  break;
		case GST_LEVEL_DEBUG:
		  fs_log_level = SWITCH_LOG_DEBUG;
		default:
		  fs_log_level = SWITCH_LOG_INFO;
		  break;
	}

	tag = g_strdup_printf ("GStreamer+%s",
			gst_debug_category_get_name (category));

	if (object) {
		gchar *obj;

		if (GST_IS_PAD (object) && GST_OBJECT_NAME (object)) {
		  obj = g_strdup_printf ("<%s:%s>", GST_DEBUG_PAD_NAME (object));
		} else if (GST_IS_OBJECT (object) && GST_OBJECT_NAME (object)) {
		  obj = g_strdup_printf ("<%s>", GST_OBJECT_NAME (object));
		} else if (G_IS_OBJECT (object)) {
		  obj = g_strdup_printf ("<%s@%p>", G_OBJECT_TYPE_NAME (object), (void *) object);
		} else {
		  obj = g_strdup_printf ("<%p>", (void *) object);
		}

		switch_log_printf (SWITCH_CHANNEL_LOG, fs_log_level,
			"%s %p %s:%d:%s:%s %s\n",
			tag, (void *) g_thread_self (),
			file, line, function, obj, gst_debug_message_get (message));

		g_free (obj);
	} else {
		switch_log_printf (SWITCH_CHANNEL_LOG, fs_log_level,
			"%s %p %s:%d:%s %s\n",
			tag, (void *) g_thread_self (),
			file, line, function, gst_debug_message_get (message));
	}

	g_free (tag);
}

SWITCH_MODULE_LOAD_FUNCTION (mod_aes67_load)
{
  switch_status_t status;
  switch_api_interface_t *api_interface;
#define MAX_PATH_LEN 10000
  char *mod_dir = NULL;
  char media_dir[MAX_PATH_LEN];
  module_pool = pool;

  memset (&globals, 0, sizeof (globals));

  mod_dir = SWITCH_GLOBAL_dirs.mod_dir;

  //using forward slash to support in both Linux and Windows
  switch_snprintf (media_dir, sizeof (media_dir), "%s/../../Media", mod_dir);
	switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Resolving the absolute path to Media (GStreamer) path: %s\n", media_dir);

#ifdef _WIN32
	if (_fullpath(media_dir, media_dir, MAX_PATH_LEN) != NULL) {
#else
	if (realpath(media_dir, media_dir) !=  NULL) {
#endif
		switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Resolved the abolute path to Media (GStreamer) path as %s\n", media_dir);
    struct stat st_buf;
    int ret = -1;
    if (((ret = stat(media_dir, &st_buf)) == 0) && (st_buf.st_mode & S_IFDIR) ) {
      switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Setting it as environment variable: GST_PLUGIN_PATH\n");
      switch_setenv("GST_PLUGIN_PATH", media_dir, TRUE);
    } else {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Can't access %s, error: %s. Not overriding GST_PLUGIN_PATH\n", media_dir, strerror(errno));
    }
	} else {
		switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to resolve the Media (GStreamer) path"
#ifdef _WIN32
		" \n");
#else
		"%s\n", strerror(errno));
#endif
  }

  gst_init (NULL, NULL);
  // gst_debug_remove_log_function (NULL);
  // gst_debug_set_default_threshold (GST_LEVEL_WARNING);
  gst_debug_add_log_function ((GstLogFunction) gst_logger, NULL, NULL);
  switch_core_hash_init (&globals.call_hash);
  switch_core_hash_init (&globals.sh_streams);
  switch_core_hash_init (&globals.endpoints);
  switch_mutex_init (&globals.device_lock, SWITCH_MUTEX_NESTED, module_pool);
  switch_mutex_init (&globals.pvt_lock, SWITCH_MUTEX_NESTED, module_pool);
  switch_mutex_init (&globals.streams_lock, SWITCH_MUTEX_NESTED, module_pool);
  switch_mutex_init (&globals.flag_mutex, SWITCH_MUTEX_NESTED, module_pool);
  switch_mutex_init (&globals.gst_mutex, SWITCH_MUTEX_NESTED, module_pool);
  switch_mutex_init (&globals.sh_shtreams_lock, SWITCH_MUTEX_NESTED, module_pool);
  globals.codecs_inited = 0;
  globals.read_frame.data = globals.databuf;
  globals.read_frame.buflen = sizeof (globals.databuf);
  globals.cng_frame.data = globals.cngbuf;
  globals.cng_frame.buflen = sizeof (globals.cngbuf);
  switch_set_flag ((&globals.cng_frame), SFF_CNG);
  switch_malloc (globals.cng_frame.codec, sizeof (switch_codec_t));
  //hardcode to Raw 16bit
  if (switch_core_codec_init (globals.cng_frame.codec,
          "L16",
          NULL,
          NULL, globals.sample_rate, globals.codec_ms, 1,
          SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL,
          NULL) != SWITCH_STATUS_SUCCESS) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Can't load codec for cng frame\n");
  }
  globals.flags = GFLAG_EAR | GFLAG_MOUTH;


  if ((status = load_config ()) != SWITCH_STATUS_SUCCESS) {
    return status;
  }

  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
      "Input : %s:%d, Output : %s:%d, Sample Rate: %d MS: %d\n",
      globals.indev->ip_addr, globals.indev->port, globals.outdev->ip_addr,
      globals.outdev->port, globals.sample_rate, globals.codec_ms);


  if (switch_event_reserve_subclass (MY_EVENT_RINGING) != SWITCH_STATUS_SUCCESS) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Couldn't register subclass!\n");
    return SWITCH_STATUS_GENERR;
  }

  if (switch_event_reserve_subclass (MY_EVENT_MAKE_CALL) !=
      SWITCH_STATUS_SUCCESS) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Couldn't register subclass!\n");
    return SWITCH_STATUS_GENERR;
  }
  if (switch_event_reserve_subclass (MY_EVENT_CALL_HELD) !=
      SWITCH_STATUS_SUCCESS) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Couldn't register subclass!\n");
    return SWITCH_STATUS_GENERR;
  }
  if (switch_event_reserve_subclass (MY_EVENT_CALL_RESUMED) !=
      SWITCH_STATUS_SUCCESS) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Couldn't register subclass!\n");
    return SWITCH_STATUS_GENERR;
  }

  if (switch_event_reserve_subclass (MY_EVENT_ERROR_AUDIO_DEV) !=
      SWITCH_STATUS_SUCCESS) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Couldn't register subclass!\n");
    return SWITCH_STATUS_GENERR;
  }


  /* connect my internal structure to the blank pointer passed to me */
  *module_interface =
      switch_loadable_module_create_module_interface (pool, modname);
  aes67_endpoint_interface =
      switch_loadable_module_create_interface (*module_interface,
      SWITCH_ENDPOINT_INTERFACE);
  aes67_endpoint_interface->interface_name = "aes67";
  aes67_endpoint_interface->io_routines = &aes67_io_routines;
  aes67_endpoint_interface->state_handler = &aes67_event_handlers;

  SWITCH_ADD_API(api_interface, "aes67", "aes67 cli", aes_cmd, "<command> [<args>]");
  switch_console_set_complete("add aes67 help");
  switch_console_set_complete("add aes67 streams");
  switch_console_set_complete("add aes67 endpoints");
  switch_console_set_complete("add aes67 ptpstats");
  switch_console_set_complete("add aes67 rtpstats");
  switch_console_set_complete("add aes67 txflow");
  switch_console_set_complete("add aes67 reloadconf");

  /* indicate that the module should continue to be loaded */
  return SWITCH_STATUS_SUCCESS;
}

static void
emit_ptp_gm_change (gboolean synced)
{
  switch_event_t *event;

  // Clock ID formed from the MAC address
  // if the MAC address is A1-B2-C3-D4-E5-F6, the clock id would be A1-B2-C3-FF-FE-D4-E5-F6
  // strip byte 4 and 5 to retrieve MAC address from the Clock ID
  globals.ptp_gm_mac_addr = ((0xFFFFFF0000000000 & globals.ptp_gm_id) >> 16) | (0xFFFFFF & globals.ptp_gm_id);

  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
        MY_EVENT_PTP_GM_CHANGE
        " "
        "sync-status=%s, "
        "grandmaster-clock-id=0x%016" G_GINT64_MODIFIER "x, "
        "grandmaster-mac-addr=0x%012" G_GINT64_MODIFIER "x \n",
         synced? "TRUE": "FALSE", globals.ptp_gm_id, globals.ptp_gm_mac_addr);

  if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, MY_EVENT_PTP_GM_CHANGE) == SWITCH_STATUS_SUCCESS) {
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "PTP-SYNC-STATUS", "%s",
			synced ? "TRUE": "FALSE");
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "PTP-GRANDMASTER-ID", "%016" G_GINT64_MODIFIER "X",
			globals.ptp_gm_id);
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "PTP-GRANDMASTER-MAC", "%012" G_GINT64_MODIFIER "X",
			globals.ptp_gm_mac_addr);

    switch_event_fire(&event);
  }
}

static gboolean
ptp_stats_cb (guint8 d, const GstStructure * stats, gpointer user_data)
{
  gchar master_clock_stats[] = "GstPtpStatisticsBestMasterClockSelected";
  const gchar *st_name = gst_structure_get_name(stats);

  if (0 == strncasecmp(st_name, master_clock_stats, strlen(master_clock_stats))) {
    if (gst_structure_get_uint64(stats, "grandmaster-clock-id", &globals.ptp_gm_id) ) {
      emit_ptp_gm_change(globals.ptp_synced);
    }
  } else if (globals.enable_ptp_stats) {
    switch_event_t *event;
    gchar *stats_str = gst_structure_to_string (stats);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
        "PTP Stats: %s "
        "grandmaster-clock-id=0x%016" G_GINT64_MODIFIER "x, "
        "grandmaster-mac-addr=0x%012" G_GINT64_MODIFIER "x \n",
        stats_str, globals.ptp_gm_id, globals.ptp_gm_mac_addr);

    if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, MY_EVENT_PTP_STATS) == SWITCH_STATUS_SUCCESS) {
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "PTP-STATS", stats_str);
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "PTP-GRANDMASTER-ID", "%016" G_GINT64_MODIFIER "X", globals.ptp_gm_id);
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "PTP-GRANDMASTER-MAC", "%012" G_GINT64_MODIFIER "X", globals.ptp_gm_mac_addr);

        switch_event_fire(&event);
    }

    g_free (stats_str);
  }
  return TRUE;
}

static void
link_rx_stream (shared_audio_stream_t *stream)
{
  switch_hash_index_t *hi;
  for (hi = switch_core_hash_first(globals.call_hash); hi; hi = switch_core_hash_next(&hi)) {
    const void *var;
    void *val;
    private_t *tech_pvt;

    switch_core_hash_this(hi, &var, NULL, &val);
    tech_pvt = val;

    if (tech_pvt->audio_endpoint && (tech_pvt->audio_endpoint->in_stream == stream)) {
      switch_channel_t *ch = switch_core_session_get_channel(tech_pvt->session);
      switch_channel_callstate_t state = switch_channel_get_callstate(ch);
      char session_id[SESSION_ID_LEN];
      switch_snprintf(session_id, SESSION_ID_LEN, "%llu", switch_core_session_get_id(tech_pvt->session));

      switch_mutex_lock (tech_pvt->audio_endpoint->mutex);
      // stream lock aleady done before calling link_rx_stream

      if (state == CCS_ACTIVE) {
        if (add_appsink(tech_pvt->audio_endpoint->in_stream->stream,
            tech_pvt->audio_endpoint->inchan, session_id)) {
			    tech_pvt->audio_endpoint->active_listen_sessions++;
        }
      }

      switch_mutex_unlock (tech_pvt->audio_endpoint->mutex);
    }
  }
}

static switch_bool_t
stream_compare (shared_audio_stream_t *current, shared_audio_stream_t *new)
{
  switch_bool_t stream_changed = FALSE;

  if (current->sample_rate != new->sample_rate) {
    current->sample_rate = new->sample_rate;
    stream_changed = TRUE;
  }

  if (current->codec_ms != new->codec_ms) {
    current->codec_ms = new->codec_ms;
    stream_changed = TRUE;
  }

  if (current->indev && new->indev) {
      if (strcasecmp(current->indev->ip_addr, new->indev->ip_addr)) {
          strcpy(current->indev->ip_addr, new->indev->ip_addr);
          stream_changed = TRUE;
      }

      if (current->indev->port != new->indev->port) {
          current->indev->port = new->indev->port;
          stream_changed = TRUE;
      }
  } else if (current->indev || new->indev) {
      // Either old or new stream does not have an indev
      switch_safe_free(current->indev);

      current->indev = new->indev;
      new->indev = NULL;

      stream_changed = TRUE;
  }

  if (current->outdev && new->outdev) {
      if (strcasecmp(current->outdev->ip_addr, new->outdev->ip_addr)) {
          strcpy(current->outdev->ip_addr, new->outdev->ip_addr);
          stream_changed = TRUE;
      }

      if (current->outdev->port != new->outdev->port) {
          current->outdev->port = new->outdev->port;
          stream_changed = TRUE;
      }
  } else if (current->outdev || new->outdev) {
      // Either old or new stream does not have an outdev
      switch_safe_free(current->outdev);

      current->outdev = new->outdev;
      new->outdev = NULL;

      stream_changed = TRUE;
  }

  if (current->channels != new->channels) {
    current->channels = new->channels;
    stream_changed = TRUE;
  }

  if (current->tx_codec != new->tx_codec) {
    current->tx_codec = new->tx_codec;
    stream_changed = TRUE;
  }

  if (current->rx_codec != new->rx_codec) {
    current->rx_codec = new->rx_codec;
    stream_changed = TRUE;
  }

  if (current->ptime_ms != new->ptime_ms) {
    current->ptime_ms = new->ptime_ms;
    stream_changed = TRUE;
  }

  if (current->synthetic_ptp != new->synthetic_ptp) {
    current->synthetic_ptp = new->synthetic_ptp;
    stream_changed = TRUE;
  }

  if (current->rtp_ts_offset != new->rtp_ts_offset) {
    current->rtp_ts_offset = new->rtp_ts_offset;
    stream_changed = TRUE;
  }

  if (current->rtp_payload_type != new->rtp_payload_type) {
    current->rtp_payload_type = new->rtp_payload_type;
    stream_changed = TRUE;
  }

  if (current->rtp_jitbuf_latency != new->rtp_jitbuf_latency) {
    current->rtp_jitbuf_latency = new->rtp_jitbuf_latency;
    stream_changed = TRUE;
  }

  if (strcasecmp(current->rtp_iface, new->rtp_iface)) {
    strcpy(current->rtp_iface, new->rtp_iface);
    stream_changed = TRUE;
  }

  return stream_changed;
}

void clock_synced_cb(GstClock *ptp_clock, gboolean synced, void* data)
{
  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "PTP clock sync status: %d\n", synced);

  globals.ptp_synced = synced;
  // Update the global for event emission
  g_object_get(ptp_clock, "grandmaster-clock-id", &globals.ptp_gm_id, NULL);
  emit_ptp_gm_change(synced);

  if (!synced)
    return;

  if (globals.clock) {
    gst_object_unref(globals.clock);
    globals.clock = gst_object_ref(ptp_clock);
  }
  globals.synthetic_ptp = 0;

  switch_hash_index_t *hi;
  switch_mutex_lock(globals.sh_shtreams_lock);
  for (hi = switch_core_hash_first(globals.sh_streams); hi; hi = switch_core_hash_next(&hi)) {
    const void *var;
    void *val;
    shared_audio_stream_t *s = NULL;

    switch_core_hash_this(hi, &var, NULL, &val);
    s = val;
    STREAM_WRITER_LOCK(s);
    use_ptp_clock(s->stream, ptp_clock);
    STREAM_WRITER_UNLOCK(s);
  }
  switch_mutex_unlock(globals.sh_shtreams_lock);
}

static void *
init_ptp (int domain, char *iface)
{
  GstClockTime timeout = 10000000000;
  void *clock = NULL;
  if (!zstr(iface)) {
    gchar *interfaces[2] = {iface, NULL};
    if (!gst_ptp_init (GST_PTP_CLOCK_ID_NONE, interfaces))
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"failed to init ptp with iface %s", interfaces[0]);
  }

  /* if id is -1, no callback hooked yet */
  if (globals.ptp_stats_cb_id == -1) {
    globals.ptp_stats_cb_id = gst_ptp_statistics_callback_add (ptp_stats_cb, NULL, NULL);
  }

  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Creating ptp clock client\n");
  clock = gst_ptp_clock_new ("ptp-clock", domain);
  if (!gst_clock_wait_for_sync (GST_CLOCK (clock), timeout)) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Timed out waiting for the clock to sync\n");
    g_signal_connect(G_OBJECT(clock), "synced", G_CALLBACK(clock_synced_cb), NULL);
    return NULL;
  }

  globals.ptp_synced = TRUE;
  g_object_get(clock, "grandmaster-clock-id", &globals.ptp_gm_id, NULL);
  emit_ptp_gm_change(TRUE);

  return clock;
}

static switch_status_t
load_streams (switch_xml_t streams, switch_bool_t reload)
{
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_xml_t param, mystream;
  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
      "%soading streams ...\n", reload ? "Rel" : "L");

  if (reload) {
      // Destroy streams that are not in config

      switch_hash_index_t *hi;
      shared_audio_stream_t *stream;

      globals.destroying_streams = 1;

again:
      switch_mutex_lock(globals.sh_shtreams_lock);
      for (hi = switch_core_hash_first(globals.sh_streams); hi; hi = switch_core_hash_next(&hi)) {

          switch_core_hash_this(hi, NULL, NULL, (void **)&stream);

          if (NULL == switch_xml_find_child(streams, "stream", "name", stream->name)) {
              //FIXME: Prevent crash due to removal of stream currently used in active call/session
              switch_core_hash_delete(globals.sh_streams, stream->name);
              free_shared_audio_stream(stream);
              // FIXME: this is a bit ugly, but if we delete, the iterator is invalidated, so we restart
              goto again;
          }
      }
      switch_mutex_unlock(globals.sh_shtreams_lock);

      globals.destroying_streams = 0;
  }

  for (mystream = switch_xml_child (streams, "stream"); mystream;
      mystream = mystream->next) {
    shared_audio_stream_t *stream = NULL;
    shared_audio_stream_t *curr_stream = NULL;

    char *stream_name = (char *) switch_xml_attr_soft (mystream, "name");

    if (!stream_name) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Missing stream name attribute, skipping ...\n");
      continue;
    }

    /* check if that stream name is not already used */
    stream = switch_core_hash_find_locked (globals.sh_streams, stream_name, globals.sh_shtreams_lock);
    if (stream) {
      if (!reload) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "A stream with name '%s' already exists\n", stream_name);
        continue;
      }
      curr_stream = stream;
    }
    switch_zmalloc (stream, sizeof (*stream));
    if (!stream) {
      continue;
    }

    switch_mutex_init (&stream->mutex, SWITCH_MUTEX_NESTED, module_pool);
    g_rw_lock_init (&stream->rwlock);
    stream->reloading = 0;

    stream->indev = NULL;
    stream->outdev = NULL;
    stream->sample_rate = globals.sample_rate;
    stream->codec_ms = globals.codec_ms;
    stream->channels = globals.channels;
    stream->tx_codec = globals.tx_codec;
    stream->rx_codec = globals.rx_codec;
    stream->ptime_ms = globals.ptime_ms;
    stream->clock = globals.clock;
    stream->synthetic_ptp = globals.synthetic_ptp;
    stream->rtp_ts_offset = globals.rtp_ts_offset;
    strncpy(stream->rtp_iface, globals.rtp_iface, NW_IFACE_LEN);
    stream->rtp_payload_type = globals.rtp_payload_type;
    stream->rtp_jitbuf_latency = globals.rtp_jitbuf_latency;
    stream->txflow = TRUE;
	stream->multiple_listen = FALSE;
    stream->is_backup_sender = FALSE;
    stream->backup_sender_idle_wait_ms = 1000;

    memset(stream->ts_context_name, 0, TS_CONTEXT_NAME_LEN);
    switch_snprintf (stream->name, sizeof (stream->name), "%s", stream_name);
    for (param = switch_xml_child (mystream, "param"); param;
        param = param->next) {
      char *var = (char *) switch_xml_attr_soft (param, "name");
      char *val = (char *) switch_xml_attr_soft (param, "value");
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
          "Parsing stream '%s' parameter %s = %s\n", stream_name, var, val);
      if (!strcmp (var, "tx-address")) {
        if (stream->outdev == NULL) {
          switch_malloc (stream->outdev, sizeof (udp_sock_t));
          stream->outdev->port = globals.outdev ? globals.outdev->port : 0;
        }
        strncpy (stream->outdev->ip_addr, val, IP_ADDR_MAX_LEN - 1);
      } else if (!strcmp (var, "tx-port")) {
        if (stream->outdev == NULL)
          switch_malloc (stream->outdev, sizeof (udp_sock_t));
        stream->outdev->port = atoi (val);
      } else if (!strcmp (var, "rx-address")) {
        if (stream->indev == NULL) {
          switch_malloc (stream->indev, sizeof (udp_sock_t));
          stream->indev->port = globals.indev->port ? globals.indev->port : 0;
        }
        strncpy (stream->indev->ip_addr, val, IP_ADDR_MAX_LEN - 1);
      } else if (!strcmp (var, "rx-port")) {
        if (stream->indev == NULL)
          switch_malloc (stream->indev, sizeof (udp_sock_t));
        stream->indev->port = atoi (val);
      } else if (!strcmp (var, "sample-rate")) {
        stream->sample_rate = atoi (val);
        if (stream->sample_rate < MIN_STREAM_SAMPLE_RATE) {
          switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
              "Invalid sample rate specified for stream '%s', forcing to 8000\n",
              stream_name);
          stream->sample_rate = MIN_STREAM_SAMPLE_RATE;
        }
      } else if (!strcmp (var, "codec-ms")) {
        int tmp = atoi (val);
        if (switch_check_interval (stream->sample_rate, tmp)) {
          stream->codec_ms = tmp;
        } else {
          switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
              "codec-ms must be multiple of 10 and less than %d, Using default of 20\n",
              SWITCH_MAX_INTERVAL);
        }
      } else if (!strcmp (var, "channels")) {
        stream->channels = atoi (val);
        if (stream->channels < 1 || stream->channels > MAX_IO_CHANNELS) {
          switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
              "Invalid number of channels specified for stream '%s', forcing to 1\n",
              stream_name);
          stream->channels = 1;
        }
      } else if (!strcmp (var, "tx-codec")) {
        if(!strncmp(val, "L24", 3)) {
          stream->tx_codec = L24;
        } else {
          /*default value*/
          stream->tx_codec = L16;
        }
      } else if (!strcmp (var, "rx-codec")) {
        if(!strncmp(val, "L24", 3)) {
          stream->rx_codec = L24;
        } else {
          /*default value*/
          stream->rx_codec = L16;
        }
      } else if (!strcasecmp (var, "ptime-ms")) {
        stream->ptime_ms = strtod(val, NULL);
      } else if (!strcasecmp (var, "synthetic-ptp")) {
        stream->synthetic_ptp = atoi(val);
      } else if (!strcasecmp (var, "rtp-ts-offset")) {
        stream->rtp_ts_offset = strtod(val, NULL);
      } else if (!strcasecmp (var, "rtp-iface")) {
        strncpy (stream->rtp_iface, val, NW_IFACE_LEN - 1);
	  } else if (!strcasecmp(var, "rtp-interface")) {
		strncpy(stream->rtp_iface, val, NW_IFACE_LEN - 1);
	  } else if (!strcasecmp(var, "rtp-payload-type")) {
        stream->rtp_payload_type = atoi(val);
      } else if (!strcasecmp (var, "rtp-jitbuf-latency")) {
        stream->rtp_jitbuf_latency = atoi(val);
      } else if (!strcasecmp (var, "txflow-on-start")) {
        stream->txflow = atoi(val);
      } else if (!strcasecmp (var, "ts-context-name")) {
        strncpy(stream->ts_context_name, val, TS_CONTEXT_NAME_LEN-1);
	    } else if (!strcasecmp(var, "allow-multiple-listen")) {
        stream->multiple_listen = atoi(val);
      } else if (!strcasecmp(var, "is-backup-sender")) {
        stream->is_backup_sender = atoi(val);
      } else if (!strcasecmp(var, "backup-sender-idle-wait-ms")) {
        stream->backup_sender_idle_wait_ms = atoi (val);
      }
    }
    if (stream->indev == NULL && stream->outdev == NULL) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "You need at least one device for stream '%s'\n", stream_name);
      continue;
    }

    if (reload && curr_stream) {
      /* update current stream with the changes */
      if (stream_compare (curr_stream, stream)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "stream %s changed\n", curr_stream->name);

        // Signal intent-to-reload to prevent writer starvation
        g_atomic_int_set (&curr_stream->reloading, 1);
        STREAM_WRITER_LOCK(curr_stream);

        clear_shared_audio_stream(curr_stream);
        create_shared_audio_stream(curr_stream);
        link_rx_stream(curr_stream);

        g_atomic_int_set (&curr_stream->reloading, 0);
        STREAM_WRITER_UNLOCK(curr_stream);
      }
      /* dont insert the allocated stream to the sh_streams list*/
      switch_safe_free(stream->indev);
      switch_safe_free(stream->outdev);
      switch_safe_free(stream);
    } else {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
          "Created stream '%s', sample-rate = %d, codec-ms = %d\n", stream->name,
          stream->sample_rate, stream->codec_ms);
      switch_core_hash_insert_locked(globals.sh_streams, stream->name, stream, globals.sh_shtreams_lock);

      /* Create ahead-of-time to start clock sync, etc. */
      create_shared_audio_stream(stream);
    }
  }
  return status;
}

static int
check_stream_compat (shared_audio_stream_t * in_stream,
    shared_audio_stream_t * out_stream)
{
  if (!in_stream || !out_stream) {
    /* nothing to be compatible with */
    return 0;
  }
  if (in_stream->sample_rate != out_stream->sample_rate) {
    return -1;
  }
  if (in_stream->codec_ms != out_stream->codec_ms) {
    return -1;
  }
  return 0;
}

static shared_audio_stream_t *
check_stream (char *streamstr, int check_input, int *chanindex)
{
  shared_audio_stream_t *stream = NULL;
  int cnum = 0;
  char stream_name[255];
  char *chan = NULL;

  *chanindex = -1;

  switch_snprintf (stream_name, sizeof (stream_name), "%s", streamstr);

  chan = strchr (stream_name, ':');
  if (!chan) {
    return NULL;
  }
  *chan = 0;
  chan++;
  cnum = atoi (chan);

  stream = switch_core_hash_find_locked (globals.sh_streams, stream_name, globals.sh_shtreams_lock);
  if (!stream) {
    return NULL;
  }

  if (cnum < 0 || cnum > stream->channels) {
    return NULL;
  }

  if (check_input && stream->indev == NULL) {
    return NULL;
  }

  if (!check_input && stream->outdev == NULL) {
    return NULL;
  }

  *chanindex = cnum;

  return stream;
}

static switch_bool_t
endpoint_in_use (audio_endpoint_t *endp)
{
  switch_hash_index_t *hi;
  for (hi = switch_core_hash_first(globals.call_hash); hi; hi = switch_core_hash_next(&hi)) {
    const void *var;
    void *val;
    private_t *tech_pvt;

    switch_core_hash_this(hi, &var, NULL, &val);
    tech_pvt = val;

    if (tech_pvt->audio_endpoint == endp) {

      switch_channel_t *ch = switch_core_session_get_channel(tech_pvt->session);
      switch_channel_callstate_t state = switch_channel_get_callstate(ch);

      if (state == CCS_ACTIVE) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE," %s's session is ACTIVE", tech_pvt->audio_endpoint->name);
        return TRUE; 
      }
    }
  }
  return FALSE;
}

static switch_bool_t
endpoint_compare (audio_endpoint_t *curr, audio_endpoint_t *new)
{
  switch_bool_t endpoint_changed = FALSE;

  if (curr->in_stream != new->in_stream) {
    curr->in_stream = new->in_stream;
    endpoint_changed = TRUE;
  }

  if (curr->out_stream != new->out_stream) {
    curr->out_stream = new->out_stream;
    endpoint_changed = TRUE;
  }

  if (curr->inchan != new->inchan) {
    curr->inchan = new->inchan;
    endpoint_changed = TRUE;
  }

  if (curr->outchan != new->outchan) {
    curr->outchan = new->outchan;
    endpoint_changed = TRUE;
  }

  return endpoint_changed;
}

static switch_status_t
load_endpoints (switch_xml_t endpoints, switch_bool_t reload)
{
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_xml_t param, myendpoint;
  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
      "%soading endpoints ...\n", reload ? "Rel" : "L");

  if (reload) {
      switch_hash_index_t *hi;
      audio_endpoint_t *endpoint;

  again:
      for (hi = switch_core_hash_first(globals.endpoints); hi; hi = switch_core_hash_next(&hi)) {

        switch_core_hash_this(hi, NULL, NULL, (void **)&endpoint);

        if ((NULL == switch_xml_find_child(endpoints, "endpoint", "name", endpoint->name)) &&
              (FALSE == endpoint_in_use(endpoint))) {
          switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "removing endpoint %s\n", endpoint->name);
          switch_core_hash_delete(globals.endpoints, endpoint->name);
          switch_safe_free(endpoint);
          // FIXME: this is a bit ugly, but if we delete, the iterator is invalidated, so we restart
          goto again;
        }
      }
  }

  for (myendpoint = switch_xml_child (endpoints, "endpoint"); myendpoint;
      myendpoint = myendpoint->next) {
    audio_endpoint_t *endpoint = NULL;
    audio_endpoint_t *curr_endp = NULL;
    shared_audio_stream_t *stream = NULL;
    char *endpoint_name = (char *) switch_xml_attr_soft (myendpoint, "name");

    if (!endpoint_name) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Missing endpoint name attribute, skipping ...\n");
      continue;
    }

    /* check if that endpoint name is not already used */
    endpoint = switch_core_hash_find (globals.endpoints, endpoint_name);
    if (endpoint) {
      if (!reload) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "An endpoint with name '%s' already exists\n", endpoint_name);
        continue;
      } else if (endpoint_in_use(endpoint)) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "The endpoint '%s' is in use, can't change\n", endpoint_name);
        continue;
      }

      /* an endpoint with same name exists */
      curr_endp = endpoint;
    }
    switch_zmalloc (endpoint, sizeof (*endpoint));
    if (!endpoint) {
      continue;
    }

    switch_mutex_init (&endpoint->mutex, SWITCH_MUTEX_NESTED, module_pool);
    endpoint->inchan = -1;
    endpoint->outchan = -1;
    switch_snprintf (endpoint->name, sizeof (endpoint->name), "%s",
        endpoint_name);
    for (param = switch_xml_child (myendpoint, "param"); param;
        param = param->next) {
      char *var = (char *) switch_xml_attr_soft (param, "name");
      char *val = (char *) switch_xml_attr_soft (param, "value");
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
          "Parsing endpoint '%s' parameter %s = %s\n", endpoint_name, var, val);
      if (!strcmp (var, "instream")) {
        stream = check_stream (val, 1, &endpoint->inchan);
        if (!stream) {
          endpoint->in_stream = NULL;
          switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
              "Invalid instream specified for endpoint '%s'\n", endpoint_name);
          continue;
        }
        endpoint->in_stream = stream;
      } else if (!strcmp (var, "outstream")) {
        stream = check_stream (val, 0, &endpoint->outchan);
        if (!stream) {
          switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
              "Invalid outstream specified for endpoint '%s'\n", endpoint_name);
          endpoint->out_stream = NULL;
          continue;
        }
        endpoint->out_stream = stream;
      }
    }

    if (!endpoint->in_stream && !endpoint->out_stream) {
      if (reload && curr_endp) {
        switch_core_hash_delete(globals.endpoints, curr_endp->name);
        switch_safe_free(curr_endp);
      }

      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "You need at least one stream for endpoint '%s'\n", endpoint_name);
      continue;
    }

    if (check_stream_compat (endpoint->in_stream, endpoint->out_stream)) {
      if (reload && curr_endp) {
        switch_core_hash_delete(globals.endpoints, curr_endp->name);
        switch_safe_free(curr_endp);
      }
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Incompatible input and output streams for endpoint '%s'\n",
          endpoint_name);
      continue;
    }

    if (reload && curr_endp) {
      /* check anything changed in the existing endpoint */
      if (endpoint_compare(curr_endp, endpoint)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "endpoint %s changed\n", curr_endp->name);
      }
      /* free the allocated endpoint */
      switch_safe_free(endpoint);
    } else {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
          "Created endpoint '%s', instream = %s, outstream = %s\n",
          endpoint->name,
          endpoint->in_stream ? endpoint->in_stream->name : "(none)",
          endpoint->out_stream ? endpoint->out_stream->name : "(none)");
      switch_core_hash_insert (globals.endpoints, endpoint->name, endpoint);
    }
  }
  return status;
}

static switch_status_t
load_globals (switch_xml_t cfg)
{

  switch_xml_t settings, param;
  if ((settings = switch_xml_child (cfg, "settings"))) {
    for (param = switch_xml_child (settings, "param"); param;
        param = param->next) {
      char *var = (char *) switch_xml_attr_soft (param, "name");
      char *val = (char *) switch_xml_attr_soft (param, "value");

      if (!strcmp (var, "hold-file")) {
        set_global_hold_file (val);
      } else if (!strcmp (var, "dual-streams")) {
        if (switch_true (val)) {
          globals.dual_streams = 1;
        } else {
          globals.dual_streams = 0;
        }
      } else if (!strcmp (var, "timer-name")) {
        set_global_timer_name (val);
      } else if (!strcmp (var, "sample-rate")) {
        globals.sample_rate = atoi (val);
      } else if (!strcmp (var, "channels")) {
        globals.channels = atoi (val);
      } else if (!strcmp (var, "codec-ms")) {
        int tmp = atoi (val);
        if (switch_check_interval (globals.sample_rate, tmp)) {
          globals.codec_ms = tmp;
        } else {
          switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
              "codec-ms must be multiple of 10 and less than %d, Using default of 20\n",
              SWITCH_MAX_INTERVAL);
        }
      } else if (!strcmp (var, "dialplan")) {
        set_global_dialplan (val);
      } else if (!strcmp (var, "context")) {
        set_global_context (val);
      } else if (!strcmp (var, "cid-name")) {
        set_global_cid_name (val);
      } else if (!strcmp (var, "cid-num")) {
        set_global_cid_num (val);
      } else if (!strcmp (var, "tx-address")) {
        if (globals.outdev == NULL) {
          switch_malloc (globals.outdev, sizeof (udp_sock_t));
          globals.outdev->port = 0;
        }
        strncpy (globals.outdev->ip_addr, val, IP_ADDR_MAX_LEN - 1);
      } else if (!strcmp (var, "tx-port")) {
        if (globals.outdev == NULL)
          switch_malloc (globals.outdev, sizeof (udp_sock_t));
        globals.outdev->port = atoi (val);
      } else if (!strcmp (var, "rx-address")) {
        if (globals.indev == NULL) {
          switch_malloc (globals.indev, sizeof (udp_sock_t));
          globals.indev->port = 0;
        }
        strncpy (globals.indev->ip_addr, val, IP_ADDR_MAX_LEN - 1);
      } else if (!strcmp (var, "rx-port")) {
        if (globals.indev == NULL)
          switch_malloc (globals.indev, sizeof (udp_sock_t));
        globals.indev->port = atoi (val);
      } else if (!strcasecmp (var, "unload-on-device-fail")) {
        globals.unload_device_fail = switch_true (val);
      } else if (!strcasecmp (var, "tx-codec")) {
        if(!strcasecmp(val, "L24")) {
          globals.tx_codec = L24;
        }
      }else if (!strcasecmp (var, "rx-codec")) {
        if(!strcasecmp(val, "L24")) {
          globals.rx_codec = L24;
        }
      } else if (!strcasecmp (var, "ptime-ms")) {
        globals.ptime_ms = strtod(val, NULL);
      } else if (!strcasecmp (var, "ptp-domain")) {
        char *iface;
        globals.ptp_domain = atoi (val);
        iface = (char *) switch_xml_attr_soft (param, "iface");
        if (!zstr(iface)) {
          strncpy(globals.ptp_iface, iface, NW_IFACE_LEN - 1);
        }
      } else if (!strcasecmp(var, "ptp-interface")) {
        globals.ptp_domain = 0;
        // hacky fix to prevent failing to get ptp from crashing FreeSWITCH

        strncpy(globals.ptp_iface, val, NW_IFACE_LEN - 1);
      } else if (!strcasecmp(var, "synthetic-ptp")) {
        globals.synthetic_ptp = atoi(val);
      } else if (!strcasecmp (var, "rtp-ts-offset")) {
        globals.rtp_ts_offset = strtod(val, NULL);
      } else if (!strcasecmp (var, "rtp-iface")) {
        strncpy (globals.rtp_iface, val, NW_IFACE_LEN - 1);
      } else if (!strcasecmp (var, "rtp-payload-type")) {
        globals.rtp_payload_type = atoi(val);
      } else if (!strcasecmp (var, "rtp-jitbuf-latency")) {
        globals.rtp_jitbuf_latency = atoi(val);
      } else if (!strcmp(var, "level-report")) {
        globals.level_report = switch_true(val);
      }
    }
  }
  // do a check here to see that none of the required parms are null
  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
load_config (void)
{
  char *cf = "aes67.conf";
  switch_xml_t cfg, xml, streams, endpoints;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!(xml = switch_xml_open_cfg (cf, &cfg, NULL))) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Open of %s failed\n", cf);
    return SWITCH_STATUS_TERM;
  }
  destroy_audio_streams ();
  destroy_shared_audio_streams ();
  destroy_codecs ();
  globals.dual_streams = 0;
  globals.no_auto_resume_call = 0;
  globals.indev = globals.outdev = NULL;
  globals.sample_rate = 8000;
  globals.unload_device_fail = 0;
  //default codec to Raw 16bit.
  globals.tx_codec = L16;
  globals.rx_codec = L16;
  globals.ptime_ms = -1.0;
  globals.ptp_domain = -1;

  /* Setting the clock to REALTIME as default */
  /* Note: Although using MONOTONIC clock is better usually, we use
  REALTIME clock in this case so that if the system clock is in sync
  with PTP, we could use same clock on the pipeline, hence using the PTP
  indirectly */

  globals.clock = g_object_new (GST_TYPE_SYSTEM_CLOCK, "clock-type", GST_CLOCK_TYPE_REALTIME, NULL);
  globals.synthetic_ptp = 0;
  globals.rtp_ts_offset = 0.0;
  memset(globals.rtp_iface, 0, NW_IFACE_LEN);
  globals.rtp_payload_type = 96; /* gstreamer default value*/
  globals.ptp_stats_cb_id = -1; /* default to -1 */
  globals.rtp_jitbuf_latency = 10;
  memset(globals.ptp_iface, 0, NW_IFACE_LEN);

  if(SWITCH_STATUS_SUCCESS != (status = load_globals(cfg))) {
    return status;
  }

  if (globals.ptp_domain >= 0) {
    void *ptp_clock = init_ptp (globals.ptp_domain, globals.ptp_iface);
    if (NULL == ptp_clock) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,"Switching to Synthetic PTP \n");
      globals.synthetic_ptp = 1;
    } else {
      /* using PTP clock, clean up the default GST_CLOCK_TYPE_REALTIME clock */
      gst_object_unref (globals.clock);
      globals.clock = ptp_clock;
    }
  }

  globals.enable_ptp_stats = FALSE;

  if (!globals.dialplan) {
    set_global_dialplan ("XML");
  }

  if (!globals.context) {
    set_global_context ("default");
  }

  if (!globals.sample_rate) {
    globals.sample_rate = 8000;
  }

  if (!globals.codec_ms) {
    globals.codec_ms = 20;
  }

  globals.cng_frame.datalen =
      switch_samples_per_packet (globals.sample_rate, globals.codec_ms) * 2;

  if (!globals.ring_interval) {
    globals.ring_interval = 5;
  }

  if (!globals.timer_name) {
    set_global_timer_name ("soft");
  }
  //FIXME can we have default values of indev and outdev?

  /* streams and endpoints must be last, some initialization depend on globals defaults */
  if ((streams = switch_xml_child (cfg, "streams"))) {
    load_streams (streams, FALSE);
  }

  if ((endpoints = switch_xml_child (cfg, "endpoints"))) {
    load_endpoints (endpoints, FALSE);
  }


  switch_xml_free (xml);

  return status;
}

/*
  If it exists, this is called in it's own thread when the module-load completes
  If it returns anything but SWITCH_STATUS_TERM it will be called again automatically
  Macro expands to: switch_status_t mod_aes67_runtime() */
SWITCH_MODULE_RUNTIME_FUNCTION (mod_aes67_runtime)
{
  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
      "Returning from runtime\n");
  return SWITCH_STATUS_TERM;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION (mod_aes67_shutdown)
{

  if (globals.ptp_stats_cb_id != -1)
    gst_ptp_statistics_callback_remove(globals.ptp_stats_cb_id);

  destroy_audio_streams ();
  destroy_shared_audio_streams ();
  destroy_codecs ();
  gst_ptp_deinit ();

  if (globals.clock)
    gst_object_unref (globals.clock);

  switch_core_hash_destroy (&globals.call_hash);
  switch_core_hash_destroy (&globals.sh_streams);
  switch_core_hash_destroy (&globals.endpoints);

  switch_event_free_subclass (MY_EVENT_RINGING);
  switch_event_free_subclass (MY_EVENT_MAKE_CALL);
  switch_event_free_subclass (MY_EVENT_ERROR_AUDIO_DEV);
  switch_event_free_subclass (MY_EVENT_CALL_HELD);
  switch_event_free_subclass (MY_EVENT_CALL_RESUMED);


  switch_safe_free (globals.dialplan);
  switch_safe_free (globals.context);
  switch_safe_free (globals.cid_name);
  switch_safe_free (globals.cid_num);
  switch_safe_free (globals.hold_file);
  switch_safe_free (globals.timer_name);

  //todo clean cng_frame.codec
  switch_core_codec_destroy (globals.cng_frame.codec);
  free (globals.cng_frame.codec);

  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
create_codecs (int restart)
{
  int sample_rate = globals.sample_rate;
  int codec_ms = globals.codec_ms;

  if (restart) {
    destroy_codecs ();
  }
  if (globals.codecs_inited) {
    return SWITCH_STATUS_SUCCESS;
  }
  //hardcode to Raw 16bit
  if (!switch_core_codec_ready (&globals.read_codec)) {
    if (switch_core_codec_init (&globals.read_codec,
            "L16",
            NULL,
            NULL, sample_rate, codec_ms, 1,
            SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL,
            NULL) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Can't load codec?\n");
      return SWITCH_STATUS_FALSE;
    }
  }

  switch_assert (globals.read_codec.implementation);

  //hardcode to Raw 16bit
  if (!switch_core_codec_ready (&globals.write_codec)) {
    if (switch_core_codec_init (&globals.write_codec,
            "L16",
            NULL,
            NULL,
            sample_rate, codec_ms, 1,
            SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL,
            NULL) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Can't load codec?\n");
      switch_core_codec_destroy (&globals.read_codec);
      return SWITCH_STATUS_FALSE;
    }
  }

  if (!globals.read_timer.timer_interface) {
    if (switch_core_timer_init (&globals.read_timer,
            globals.timer_name, codec_ms,
            globals.read_codec.implementation->samples_per_packet,
            module_pool) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "setup timer failed!\n");
      switch_core_codec_destroy (&globals.read_codec);
      switch_core_codec_destroy (&globals.write_codec);
      return SWITCH_STATUS_FALSE;
    }
  }
  if (!globals.readfile_timer.timer_interface) {
    if (switch_core_timer_init (&globals.readfile_timer,
            globals.timer_name, codec_ms,
            globals.read_codec.implementation->samples_per_packet,
            module_pool) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "setup timer failed!\n");
      switch_core_codec_destroy (&globals.read_codec);
      switch_core_codec_destroy (&globals.write_codec);
      return SWITCH_STATUS_FALSE;
    }
  }


  if (!globals.hold_timer.timer_interface) {
    if (switch_core_timer_init (&globals.hold_timer,
            globals.timer_name, codec_ms,
            globals.read_codec.implementation->samples_per_packet,
            module_pool) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "setup hold timer failed!\n");
      switch_core_codec_destroy (&globals.read_codec);
      switch_core_codec_destroy (&globals.write_codec);
      switch_core_timer_destroy (&globals.read_timer);
      switch_core_timer_destroy (&globals.readfile_timer);

      return SWITCH_STATUS_FALSE;
    }
  }

  globals.cng_frame.rate = globals.read_frame.rate = sample_rate;
  globals.cng_frame.codec = globals.read_frame.codec = &globals.read_codec;

  globals.codecs_inited = 1;
  return SWITCH_STATUS_SUCCESS;
}


int
open_audio_stream (g_stream_t ** stream, udp_sock_t * indev,
    udp_sock_t * outdev)
{
  pipeline_data_t data;
  if (!indev && !outdev) {
    *stream = NULL;
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "indev or outdev not defined\n");
    return -1;
  }
  data.direction = 0;

  if (indev) {
    data.direction |= DIRECTION_RX;
    strncpy (data.rx_ip_addr, indev->ip_addr, IP_ADDR_MAX_LEN);
    data.rx_port = indev->port;
  }
  if (outdev) {
    data.direction |= DIRECTION_TX;
    strncpy (data.tx_ip_addr, outdev->ip_addr, IP_ADDR_MAX_LEN);
    data.tx_port = outdev->port;
  }
  data.sample_rate = globals.sample_rate;
  strncpy (data.bit_depth, globals.bit_depth, AUDIO_FMT_STR_LEN);
  data.tx_codec = globals.tx_codec;
  data.rx_codec = globals.rx_codec;
  data.codec_ms = globals.codec_ms;
  data.channels = globals.channels;
  data.name = NULL;
  data.ptime_ms = globals.ptime_ms;
  data.clock = globals.clock;
  data.synthetic_ptp = globals.synthetic_ptp;
  data.rtp_iface = globals.rtp_iface;
  data.rtp_payload_type = globals.rtp_payload_type;
  data.rtp_jitbuf_latency = globals.rtp_jitbuf_latency;

  *stream = create_pipeline (&data, error_callback);

  return 0;
}

int open_shared_audio_stream (shared_audio_stream_t * shstream)
{
  pipeline_data_t data;
  udp_sock_t *indev = shstream->indev;
  udp_sock_t *outdev = shstream->outdev;

  if (!indev && !outdev) {
    shstream->stream = NULL;
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "indev or outdev not defined\n");
    return -1;
  }
  data.direction = 0;
  if (indev) {
    data.direction |= DIRECTION_RX;
    strncpy (data.rx_ip_addr, indev->ip_addr, IP_ADDR_MAX_LEN);
    data.rx_port = indev->port;
  }
  if (outdev) {
    data.direction |= DIRECTION_TX;
    strncpy (data.tx_ip_addr, outdev->ip_addr, IP_ADDR_MAX_LEN);
    data.tx_port = outdev->port;
  }
  data.sample_rate = shstream->sample_rate;
  data.tx_codec = shstream->tx_codec;
  data.rx_codec = shstream->rx_codec;
  data.codec_ms = shstream->codec_ms;
  data.channels = shstream->channels;
  data.name = shstream->name;
  data.ptime_ms = shstream->ptime_ms;
  data.clock = globals.clock; // no clock setting per stream, only globals
  data.synthetic_ptp = shstream->synthetic_ptp;
  data.rtp_ts_offset = shstream->rtp_ts_offset;
  data.rtp_iface = shstream->rtp_iface;
  data.rtp_payload_type = shstream->rtp_payload_type;
  data.rtp_jitbuf_latency = shstream->rtp_jitbuf_latency;
  data.txdrop = !shstream->txflow;
  data.ts_context_name = shstream->ts_context_name;
  data.is_backup_sender = shstream->is_backup_sender;
  data.backup_sender_idle_wait_ms = shstream->backup_sender_idle_wait_ms;

  shstream->stream = create_pipeline (&data, error_callback);
  return 0;
}

static int
create_shared_audio_stream (shared_audio_stream_t * shstream)
{

  switch_event_t *event;

  if (-1 == open_shared_audio_stream (shstream)) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Can't open audio device (indev = %s:%d, outdev = %s:%d)\n",
        shstream->indev->ip_addr, shstream->indev->port,
        shstream->outdev->ip_addr, shstream->outdev->port);
    if (switch_event_create_subclass (&event, SWITCH_EVENT_CUSTOM,
            MY_EVENT_ERROR_AUDIO_DEV) == SWITCH_STATUS_SUCCESS) {
      switch_event_add_header_string (event, SWITCH_STACK_BOTTOM, "Reason",
          "Failed to create gstreamer pipeline");
      switch_event_fire (&event);
    }
    return -1;
  }
  // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Created shared audio stream %s: %d channels %d\n",
  //              shstream->name, shstream->sample_rate, shstream->channels);
  return 0;
}

static int
clear_shared_audio_stream (shared_audio_stream_t * shstream)
{
  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
      "Destroying shared audio stream %s\n", shstream->name);
  if (shstream->stream)
    stop_pipeline (shstream->stream);

  shstream->stream = NULL;

  return 0;
}

static audio_stream_t *
create_audio_stream (udp_sock_t * indev, udp_sock_t * outdev)
{
  switch_event_t *event;
  audio_stream_t *stream;
  int ret;

  stream = malloc (sizeof (*stream));
  if (stream == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT,
        "Unable to alloc memory\n");
    return NULL;
  }
  memset (stream, 0, sizeof (*stream));
  stream->next = NULL;
  stream->stream = NULL;
  stream->indev = indev;
  stream->outdev = outdev;
  if (!stream->write_timer.timer_interface) {
    if (switch_core_timer_init (&(stream->write_timer),
            globals.timer_name, globals.codec_ms,
            globals.read_codec.implementation->samples_per_packet,
            module_pool) != SWITCH_STATUS_SUCCESS) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "setup timer failed!\n");
      switch_safe_free (stream);
      return NULL;
    }
  }

  ret = open_audio_stream (&(stream->stream), indev, outdev);


  if (ret != 0) {
    switch_safe_free (stream);
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Can't open audio device\n");
    if (switch_event_create_subclass (&event, SWITCH_EVENT_CUSTOM,
            MY_EVENT_ERROR_AUDIO_DEV) == SWITCH_STATUS_SUCCESS) {
      switch_event_add_header_string (event, SWITCH_STACK_BOTTOM, "Reason",
          "Failed to create gstreamer pipeline");
      switch_event_fire (&event);
    }
    return NULL;
  }
  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
      "Created audio stream: %d channels %d\n", globals.sample_rate,
      globals.channels);
  return stream;
}

audio_stream_t *
get_audio_stream (udp_sock_t * indev, udp_sock_t * outdev)
{
  audio_stream_t *stream = NULL;
  if (outdev == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Error invalid output audio device\n");
    return NULL;
  }
  if (create_codecs (0) != SWITCH_STATUS_SUCCESS) {
    return NULL;
  }

  stream = find_audio_stream (indev, outdev, 0);
  if (stream != NULL) {
    return stream;
  }
  stream = create_audio_stream (indev, outdev);
  if (stream) {
    add_stream (stream, 0);
  }
  return stream;
}

static int
is_sock_equal (udp_sock_t * a, udp_sock_t * b)
{
  /* FIXME: strcasecmp can fail if one of the `ip_addr` strings has preceeding 0s */
  return ((a->port == b->port) && (!strcasecmp (a->ip_addr, b->ip_addr)));
}

void
error_callback (char *msg, g_stream_t * stream)
{
  // switch_event_t *event;
  switch_channel_t *channel;
  private_t *tp;
  for (tp = globals.call_list; tp; tp = tp->next) {
    if ((tp->audio_endpoint->in_stream
            && (tp->audio_endpoint->in_stream->stream == stream))
        || (tp->audio_endpoint->out_stream
            && (tp->audio_endpoint->out_stream->stream == stream))) {
      channel = switch_core_session_get_channel (tp->session);
      goto hangup;
    }
  }
  return;

hangup:
  //Note: this could be sync blocking call, would prefer a more asyn event kind which will call channel_kill
  switch_channel_hangup (channel, SWITCH_CAUSE_PROTOCOL_ERROR);
}

static switch_status_t list_shared_streams(switch_stream_handle_t *stream)
{
  switch_hash_index_t *hi;
  int cnt = 0;
  switch_mutex_lock(globals.sh_shtreams_lock);
  for (hi = switch_core_hash_first(globals.sh_streams); hi; hi = switch_core_hash_next(&hi)) {
    const void *var;
    void *val;
    shared_audio_stream_t *s = NULL;
    switch_core_hash_this(hi, &var, NULL, &val);
    s = val;
	stream->write_function(stream, "stream name: %s \t indev.ip_addr: %s, indev.port: %d, "
                    "outdev.ip_addr: %s, outdev.port: %d, sample-rate: %d, "
                    "codec-ms: %d, channels: %d, sythentic_ptp: %d, txflow: %s\n",
                    s->name,
                    s->indev ? s->indev->ip_addr: "None", s->indev? s->indev->port : 0,
                    s->outdev ? s->outdev->ip_addr: "None", s->outdev? s->outdev->port : 0,
                    s->sample_rate, s->codec_ms, s->channels,
                    s->synthetic_ptp, s->txflow?"on":"off");
    cnt++;
  }
  switch_mutex_unlock(globals.sh_shtreams_lock);
  stream->write_function(stream, "Total streams: %d\n", cnt);
  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t list_endpoints(switch_stream_handle_t *stream)
{
  switch_hash_index_t *hi;
  int cnt = 0;
  for (hi = switch_core_hash_first(globals.endpoints); hi; hi = switch_core_hash_next(&hi)) {
    const void *var;
    void *val;
    audio_endpoint_t *e = NULL;
    switch_core_hash_this(hi, &var, NULL, &val);
    e = val;
    stream->write_function(stream, "endpoint name: %s \t instream: %s, outstream: %s\n",
        e->name, e->in_stream ? e->in_stream->name : "(none)",
        e->out_stream ? e->out_stream->name : "(none)");
    cnt++;
  }
  stream->write_function(stream, "Total endpoints: %d\n", cnt);
  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
reload_config()
{
  char *cf = "aes67.conf";
  switch_xml_t cfg, xml, streams, endpoints;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  const char *reload_err;

  /* dont have to allocate or free 'reload_err'
   * it is a fixed size array defined in switch_xml_root
   * https://docs.freeswitch.org/structswitch__xml__root.html
   */

  if (SWITCH_STATUS_SUCCESS != (status = switch_xml_reload(&reload_err))) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "reload conf failed: %s\n", reload_err);
    return SWITCH_STATUS_GENERR;
  }

  if (!(xml = switch_xml_open_cfg (cf, &cfg, NULL))) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Open of %s failed\n", cf);
    return SWITCH_STATUS_GENERR;
  }

  // Not setting default values here they will be set already in load_config
  if (SWITCH_STATUS_SUCCESS != (status = load_globals(cfg))) {
    return status;
  }

  if ((streams = switch_xml_child (cfg, "streams"))) {
    load_streams (streams, TRUE);
  }

  if ((endpoints = switch_xml_child (cfg, "endpoints"))) {
    load_endpoints (endpoints, TRUE);
  }

  switch_xml_free (xml);
  return status;
}

SWITCH_STANDARD_API(aes_cmd)
{

  char *argv[10] = { 0 };
  int argc = 0;
  char *mycmd = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  const char *usage_string = "USAGE:\n"
  "--------------------------------------------------------------------------------\n"
  "aes67 help\n"
  "aes67 streams\n"
  "aes67 endpoints\n"
  "aes67 ptpstats <on|off> \n"
  "aes67 rtpstats <stream>\n"
  "aes67 txflow <stream> <on|off>\n"
  "aes67 reloadconf\n"
  "--------------------------------------------------------------------------------\n";
  if (zstr(cmd)) {
    stream->write_function(stream, "%s", usage_string);
    goto done;
  }

  if(!(mycmd = strdup(cmd))) {
    status = SWITCH_STATUS_MEMERR;
    goto done;
  }

  if (!(argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0]))))) {
    stream->write_function(stream, "%s", usage_string);
    goto done;
  }

  if (!argv[0]) {
    stream->write_function(stream, "Unknown Command\n");
    goto done;
  }

  if (!strcasecmp(argv[0], "streams")) {
    list_shared_streams(stream);
  } else if (!strcasecmp(argv[0], "endpoints")) {
    list_endpoints(stream);
  } else if (!strcasecmp(argv[0], "ptpstats")) {
    if (!argv[1]) {
      stream->write_function(stream, "Please mention 'on' or 'off'\n");
      stream->write_function(stream, "%s", usage_string);
      goto done;
    }

    if (!strcasecmp(argv[1], "on")){
      globals.enable_ptp_stats = TRUE;
      stream->write_function(stream, "PTP stats printing Enabled!\n");
    } else if (!strcasecmp(argv[1], "off")) {
      globals.enable_ptp_stats = FALSE;
      stream->write_function(stream, "PTP stats printing Disabled!\n");
    } else {
      stream->write_function(stream, "Please mention 'on' or 'off'\n");
      stream->write_function(stream, "%s", usage_string);
      goto done;
    }
  } else if (!strcasecmp(argv[0], "rtpstats")) {
    shared_audio_stream_t *astream;
    char *rtp_stats;
    if (!argv[1]) {
      stream->write_function(stream, "Please provide the name of the stream\n");
      stream->write_function(stream, "%s", usage_string);
      goto done;
    }

    astream = switch_core_hash_find_locked (globals.sh_streams, argv[1], globals.sh_shtreams_lock);
    if (!astream) {
      stream->write_function(stream, "Stream with name %s not found\n", argv[1]);
      stream->write_function(stream, "%s", usage_string);
      goto done;
    }

    if (STREAM_READER_TRYLOCK(astream)) {
      rtp_stats = get_rtp_stats(astream->stream);
      if (rtp_stats) {
        stream->write_function(stream, "%s\n",rtp_stats);
        g_free(rtp_stats);
      }

      STREAM_READER_UNLOCK(astream);
    } else {
      stream->write_function(stream, "reloadconf in progress, please retry\n");
    }
  } else if (!strcasecmp(argv[0], "txflow")) {
    shared_audio_stream_t *astream;

    if (!argv[1]) {
      stream->write_function(stream, "Please provide the name of the stream\n");
      stream->write_function(stream, "%s", usage_string);
      goto done;
    }

    astream = switch_core_hash_find_locked (globals.sh_streams, argv[1], globals.sh_shtreams_lock);
    if (!astream) {
      stream->write_function(stream, "Stream with name %s not found\n", argv[1]);
      stream->write_function(stream, "%s", usage_string);
      goto done;
    }

    if (!strcasecmp(argv[2], "on")){
      if (STREAM_READER_TRYLOCK(astream)) {
          drop_output_buffers(FALSE, astream->stream);
          astream->txflow = TRUE;
          // We still need txflow during the pipeline init to set valve's drop property
          // the stream is initialized after the pipeline is created, so we need to preserve
          // txflow somewhere until then
          astream->stream->txdrop = FALSE;
          stream->write_function(stream, "Tx buffers flowing!\n");

          STREAM_READER_UNLOCK(astream);
        } else {
          stream->write_function(stream, "failed to start txflow: reloadconf in progress\n");
        }
    } else if (!strcasecmp(argv[2], "off")) {
      if (STREAM_READER_TRYLOCK(astream )) {
          drop_output_buffers(TRUE, astream->stream);
          astream->txflow = FALSE;
          astream->stream->txdrop = TRUE;
          stream->write_function(stream, "Tx buffers dropping!\n");

          STREAM_READER_UNLOCK(astream);
        } else {
          stream->write_function(stream, "failed to stop txflow: reloadconf in progress\n");
        }
    } else {
      stream->write_function(stream, "Please mention 'on' or 'off'\n");
      stream->write_function(stream, "%s", usage_string);
      goto done;
    }
  } else if (!strcasecmp(argv[0], "reloadconf")) {
    reload_config();
  }

  done:
  switch_safe_free(mycmd);
  return status;
  }

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
