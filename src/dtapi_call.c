/*
 * tel-plugin-dbus-tapi
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Ja-young Gu <jygu@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <glib.h>

#include <tcore.h>
#include <plugin.h>
#include <server.h>
#include <co_call.h>

#include "generated-code.h"
#include "dtapi_common.h"

static gboolean on_call_dial(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_type, gint call_ecc, gchar *call_number,
	gpointer user_data)
{
	struct treq_call_dial req;
	struct custom_data *ctx = user_data;

	memset(&req, 0x0, sizeof(req));

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.type = call_type;
	req.ecc = call_ecc;

	if (call_number)
		g_strlcpy(req.number, call_number, MAX_CALL_DIAL_NUM_LEN);

	dbg("[%s] Dial number len: [%d] Dial number: [%s]",
		GET_CP_NAME(invocation), strlen(req.number), req.number);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_DIAL,
		&req, sizeof(struct treq_call_dial));

	return TRUE;
}

static gboolean on_call_answer(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gint answer_type, gpointer user_data)
{
	struct treq_call_answer req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;
	req.type = answer_type;

	dbg("[%s] Call handle: [%d] Answer type: [%s]",
		GET_CP_NAME(invocation), req.handle,
		(req.type == CALL_ANSWER_TYPE_ACCEPT ? "ACCEPT" :
		(req.type == CALL_ANSWER_TYPE_REJECT ? "REJECT" :
		(req.type == CALL_ANSWER_TYPE_REPLACE ? "REPLACE" :
		(req.type == CALL_ANSWER_TYPE_HOLD_ACCEPT ? "HOLD & ACCEPT" :
		"UNKNOWN OPERATION")))));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_ANSWER,
		&req, sizeof(struct treq_call_answer));

	return TRUE;
}

static gboolean on_call_end(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gint end_type, gpointer user_data)
{
	struct treq_call_end req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;
	req.type = end_type;

	dbg("[%s] Call handle: [%d] End type: [%s]",
		GET_CP_NAME(invocation), req.handle,
		(req.type == CALL_END_TYPE_ALL ? "END ALL" :
		(req.type == CALL_END_TYPE_ACTIVE_ALL ? "END ALL ACTIVE" :
		(req.type == CALL_END_TYPE_HOLD_ALL ? "END ALL HELD" :
		(req.type == CALL_END_TYPE_DEFAULT ? "END SPECIFIC" :
		"UNKNOWN OPERATION")))));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_END, &req, sizeof(struct treq_call_end));

	return TRUE;
}

static gboolean on_call_start_cont_dtmf(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	guchar dtmf_digit, gpointer user_data)
{
	struct treq_call_start_cont_dtmf  req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(req));

	req.dtmf_digit = dtmf_digit;

	dbg("[%s] DTMF Digit: [%c]", GET_CP_NAME(invocation), req.dtmf_digit);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_START_CONT_DTMF,
		&req, sizeof(struct treq_call_start_cont_dtmf));

	return TRUE;
}

static gboolean on_call_stop_cont_dtmf(TelephonyCall *call,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	dbg("[%s] Stop DTMF", GET_CP_NAME(invocation));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_STOP_CONT_DTMF,
		NULL, 0);

	return TRUE;
}

static gboolean on_call_send_burst_dtmf(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gchar *dtmf_string, gint pulse_width, gint inter_digit_interval, gpointer user_data)
{
	struct treq_call_send_burst_dtmf req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(req));

	if (dtmf_string) {
		g_strlcpy(req.dtmf_string, dtmf_string, MAX_CALL_BURST_DTMF_STRING_LEN + 1);
	} else {
		err("Invalid DTMF string");

		FAIL_RESPONSE(invocation, "Invalid Input");

		return TRUE;
	}

	req.pulse_width = pulse_width;
	req.inter_digit_interval = inter_digit_interval;

	dbg("[%s] Pulse width: [%d] Inter-digit interval: [%d]",
		GET_CP_NAME(invocation),
		req.pulse_width, req.inter_digit_interval);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SEND_BURST_DTMF,
		&req, sizeof(struct treq_call_send_burst_dtmf));

	return TRUE;
}

static gboolean on_call_active(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gpointer user_data)
{
	struct treq_call_active req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;

	dbg("[%s] Call handle: [%d]", GET_CP_NAME(invocation), req.handle);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_ACTIVE,
		&req, sizeof(struct treq_call_active));

	return TRUE;
}

static gboolean on_call_hold(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gpointer user_data)
{
	struct treq_call_hold req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;

	dbg("[%s] Call handle: [%d]", GET_CP_NAME(invocation), req.handle);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_HOLD,
		&req, sizeof(struct treq_call_hold));

	return TRUE;
}

static gboolean on_call_swap(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gpointer user_data)
{
	struct treq_call_swap req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;

	dbg("[%s] Call handle: [%d]", GET_CP_NAME(invocation), req.handle);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SWAP,
		&req, sizeof(struct treq_call_swap));

	return TRUE;
}

static gboolean on_call_join(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gpointer user_data)
{
	struct treq_call_join req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;

	dbg("[%s] Call handle: [%d]", GET_CP_NAME(invocation), req.handle);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_JOIN,
		&req, sizeof(struct treq_call_join));

	return TRUE;
}

static gboolean on_call_split(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gpointer user_data)
{
	struct treq_call_split req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;

	dbg("[%s] Call handle: [%d]", GET_CP_NAME(invocation), req.handle);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SPLIT,
		&req, sizeof(struct treq_call_split));

	return TRUE;
}

static gboolean on_call_transfer(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gpointer user_data)
{
	struct treq_call_transfer req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;

	dbg("[%s] Call handle: [%d]", GET_CP_NAME(invocation), req.handle);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_TRANSFER,
		&req, sizeof(struct treq_call_transfer));

	return TRUE;
}

static gboolean on_call_deflect(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gchar *call_number, gpointer user_data)
{
	struct treq_call_deflect req = {0};
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	if (call_number)
		g_strlcpy(req.number, call_number, MAX_CALL_DIAL_NUM_LEN);

	dbg("[%s] Call handle: [%d] Number: [%s]", GET_CP_NAME(invocation),
		req.handle, req.number);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_DEFLECT,
		&req, sizeof(struct treq_call_deflect));

	return TRUE;
}

static gboolean on_call_get_privacy_mode(TelephonyCall *call,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_GET_PRIVACY_MODE,
		NULL, 0);

	return TRUE;
}

static gboolean on_call_set_privacy_mode(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint privacy_mode, gpointer user_data)
{
	struct treq_call_set_voice_privacy_mode req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "w"))
		return TRUE;

	req.privacy_mode = privacy_mode;

	dbg("[%s] Privacy mode: [%d]", GET_CP_NAME(invocation), req.privacy_mode);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SET_PRIVACY_MODE,
		&req, sizeof(struct treq_call_set_voice_privacy_mode));

	return TRUE;
}

static gboolean on_call_get_status(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	TcorePlugin *plugin = 0;
	CoreObject *call_co = NULL;
	CallObject *call_obj = NULL;

	gchar call_number[MAX_CALL_NUMBER_LEN];
	gint call_type;
	gboolean call_direction;
	gint call_status;
	gboolean call_multiparty_state;
	gboolean is_volte_call;

	if (!check_access_control(invocation, AC_CALL, "r"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	call_co = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_CALL);
	call_obj = tcore_call_object_find_by_handle(call_co, call_handle);
	if (!call_obj) {
		err("Call object: NULL");

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	}

	dbg("[%s] Call handle: [%d]", GET_CP_NAME(invocation), call_handle);

	memset(call_number, 0x0, MAX_CALL_NUMBER_LEN);
	tcore_call_object_get_number(call_obj, call_number);
	call_type = tcore_call_object_get_type(call_obj);
	call_direction = tcore_call_object_get_direction(call_obj);

	if (call_direction == TCORE_CALL_DIRECTION_OUTGOING)
		call_direction = TRUE;
	else
		call_direction = FALSE;

	call_status = tcore_call_object_get_status(call_obj);
	call_multiparty_state = tcore_call_object_get_multiparty_state(call_obj);
	is_volte_call = tcore_call_object_get_is_volte_call(call_obj);

	telephony_call_complete_get_status(call, invocation,
		call_handle, call_number, call_type,
		call_direction, call_status, call_multiparty_state, is_volte_call);

	return TRUE;
}

static gboolean on_call_get_status_all(TelephonyCall *call,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	TcorePlugin *plugin = 0;
	CoreObject *call_co = NULL;
	CallObject *call_obj = NULL;
	GSList *list, *tmp;

	GVariant *gv = NULL;
	GVariantBuilder b;

	gint call_id;
	gint handle;
	gchar call_number[MAX_CALL_NUMBER_LEN];
	gint call_type;
	gboolean call_direction;
	gint call_status;
	gboolean call_multiparty_state;

	int len, i;

	if (!check_access_control(invocation, AC_CALL, "r"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	call_co = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_CALL);

	g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
	for (i = 0; i < TCORE_CALL_STATUS_MAX; i++) {
		tmp = list = tcore_call_object_find_by_status(call_co, i);
		if (list == NULL)
			continue;

		while (tmp) {
			call_obj = (CallObject *)tmp->data;
			if (!call_obj) {
				err("call object: NULL");

				/* Next Call object */
				tmp = g_slist_next(tmp);
				continue;
			}

			handle = tcore_call_object_get_handle(call_obj);
			call_id = tcore_call_object_get_id(call_obj);

			memset(call_number, 0, MAX_CALL_NUMBER_LEN);
			len = tcore_call_object_get_number(call_obj, call_number);
			if (!len)
				warn("[ CHECK ] NO number: Call handle: [%d]", handle);

			call_type = tcore_call_object_get_type(call_obj);
			call_direction = tcore_call_object_get_direction(call_obj);

			if (call_direction == TCORE_CALL_DIRECTION_OUTGOING)
				call_direction = TRUE;
			else
				call_direction = FALSE;

			call_status = tcore_call_object_get_status(call_obj);
			if ((TCORE_CALL_STATUS_SETUP == call_status)
					|| (TCORE_CALL_STATUS_SETUP_PENDING == call_status)) {
				dbg("SETUP/SETUP_PENDING found. This is already notified as " \
					"dialing status to applicaiton, so change it to 'Dialing' ");
				call_status = TCORE_CALL_STATUS_DIALING;
			}

			call_multiparty_state = tcore_call_object_get_multiparty_state(call_obj);

			dbg("Call handle: [%d] Call ID: [%d] Call number: [%s] Call number len: [%d]",
				handle, call_id, call_number, len);
			dbg("Call Type: [%s] Call Direction: [%s] Call Status: [%s] Multi-Party Call: [%s]",
				call_type == TCORE_CALL_TYPE_VOICE ? "VOICE" :
				(call_type == TCORE_CALL_TYPE_VIDEO ? "VIDEO" :
				(call_type == TCORE_CALL_TYPE_E911 ? "E911" :
				(call_type == TCORE_CALL_TYPE_STDOTASP ? "STDOTASP" :
				(call_type == TCORE_CALL_TYPE_NONSTDOTASP ? "NONSTDOTASP" : "UNKNOWN")))),
				(call_direction == TRUE ? "MO" : "MT"),
				(call_status == TCORE_CALL_STATUS_IDLE ? "IDLE" :
				(call_status == TCORE_CALL_STATUS_ACTIVE ? "ACTIVE" :
				(call_status == TCORE_CALL_STATUS_HELD ? "HELD" :
				(call_status == TCORE_CALL_STATUS_DIALING ? "DIALING" :
				(call_status == TCORE_CALL_STATUS_ALERT ? "ALERT" :
				(call_status == TCORE_CALL_STATUS_INCOMING ? "INCOMING" :
				(call_status == TCORE_CALL_STATUS_WAITING ? "WAITING" :
				(call_status == TCORE_CALL_STATUS_SETUP ? "SETUP" :
				(call_status == TCORE_CALL_STATUS_SETUP_PENDING ? "SETUP_PENDING" : "UNKNOWN"))))))))),
				(call_multiparty_state == 1 ? "YES" : "NO"));

			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "call_id",
				g_variant_new_int32(handle));
			g_variant_builder_add(&b, "{sv}", "call_number",
				g_variant_new_string(call_number));
			g_variant_builder_add(&b, "{sv}", "call_type",
				g_variant_new_int32(call_type));
			g_variant_builder_add(&b, "{sv}", "call_direction",
				g_variant_new_boolean(call_direction));
			g_variant_builder_add(&b, "{sv}", "call_state",
				g_variant_new_int32(call_status));
			g_variant_builder_add(&b, "{sv}", "call_multiparty_state",
				g_variant_new_boolean(call_multiparty_state));
			g_variant_builder_close(&b);

			/* Next Call object */
			tmp = g_slist_next(tmp);
		}

		/* Free list */
		g_slist_free(list);
	}
	gv = g_variant_builder_end(&b);

	telephony_call_complete_get_status_all(call, invocation, gv);

	return TRUE;
}

static gboolean on_call_set_sound_path(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint sound_path, gboolean extra_volume_on, gpointer user_data)
{
	struct treq_call_set_sound_path req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "w"))
		return TRUE;

	req.path = sound_path;
	req.extra_volume_on = extra_volume_on;

	dbg("[%s] Sound path: [%d] Extra Volume: [%s]", GET_CP_NAME(invocation),
		req.path, (extra_volume_on ? "ON" : "OFF"));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SET_SOUND_PATH,
		&req, sizeof(struct treq_call_set_sound_path));

	return TRUE;
}

static gboolean on_call_get_sound_volume_level(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint sound_device, gint sound_type, gpointer user_data)
{
	struct treq_call_get_sound_volume_level req;
	struct custom_data *ctx = user_data;
	TReturn ret;

	if (!check_access_control(invocation, AC_CALL, "r"))
		return TRUE;

	req.device = sound_device;
	req.sound = sound_type;

	dbg("[%s] Sound device: [%d] Sound type: [%d]", GET_CP_NAME(invocation),
		req.device, req.sound);

	/* Dispatch request */
	ret = dtapi_dispatch_request_ex(ctx, call, invocation,
		TREQ_CALL_GET_SOUND_VOLUME_LEVEL,
		&req, sizeof(struct treq_call_get_sound_volume_level));
	if (ret != TCORE_RETURN_SUCCESS) {
		GVariantBuilder b;
		GVariant *result = 0;

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
		g_variant_builder_add(&b, "{sv}", "err", g_variant_new_int32(ret));
		g_variant_builder_close(&b);
		result = g_variant_builder_end(&b);

		telephony_call_complete_get_sound_volume_level(call,
			invocation, result, ret);
	}

	return TRUE;
}

static gboolean on_call_set_sound_volume_level(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint sound_device, gint sound_type, gint sound_volume,
	gpointer user_data)
{
	struct treq_call_set_sound_volume_level req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "w"))
		return TRUE;

	req.device = sound_device;
	req.sound = sound_type;
	req.volume = sound_volume;

	dbg("[%s] Sound device: [%d] Sound type: [%d] Volume level: [%d]",
		GET_CP_NAME(invocation),
		req.device, req.sound, req.volume);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SET_SOUND_VOLUME_LEVEL,
		&req, sizeof(struct treq_call_set_sound_volume_level));

	return TRUE;
}

static gboolean on_call_get_sound_mute_status(TelephonyCall *call,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_GET_SOUND_MUTE_STATUS,
		NULL, 0);

	return TRUE;
}

static gboolean on_call_set_sound_mute_status(TelephonyCall *call,
	GDBusMethodInvocation *invocation, gint status, gint path,
	gpointer user_data)
{
	struct treq_call_set_sound_mute_status req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "w"))
		return TRUE;

	req.path = path;
	req.status = status;

	dbg("[%s] Path: [%s] Mute Status: [%s]", GET_CP_NAME(invocation),
		(req.path == CALL_SOUND_MUTE_PATH_TX ? "OUTGOING" :
		(req.path == CALL_SOUND_MUTE_PATH_RX ? "INCOMING" :
		"BOTH In- & Out-coming")),
		(req.status == CALL_SOUND_MUTE_STATUS_OFF ? "OFF" : "ON"));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SET_SOUND_MUTE_STATUS,
		&req, sizeof(struct treq_call_set_sound_mute_status));

	return TRUE;
}

static gboolean on_call_set_sound_recording(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint recording_state, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_sound_recording req;

	if (!check_access_control(invocation, AC_CALL, "w"))
		return TRUE;

	req.state = (gboolean)recording_state;

	dbg("[%s] Recording state: [%s]", GET_CP_NAME(invocation),
		(req.state ? "ON" : "OFF"));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SET_SOUND_RECORDING,
		&req, sizeof(struct treq_call_set_sound_recording));

	return TRUE;
}

static gboolean on_call_set_sound_equalization(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint eq_mode, gint eq_direction, gchar *eq_parameter,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_sound_equalization req;

	if (!check_access_control(invocation, AC_CALL, "w"))
		return TRUE;

	req.mode = eq_mode;
	req.direction = (enum telephony_call_sound_direction)eq_direction;
	memcpy((char *)req.parameter, (const char *)eq_parameter, (MAX_CALL_EQ_PARAMETER_SIZE * 2));

	dbg("[%s] Equalization mode: [%d] Direction: [%s]",
		GET_CP_NAME(invocation), req.mode,
		(req.direction == CALL_SOUND_DIRECTION_LEFT ? "LEFT" : "RIGHT"));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SET_SOUND_EQUALIZATION,
		&req, sizeof(struct treq_call_set_sound_equalization));

	return TRUE;
}

static gboolean on_call_set_sound_noise_reduction(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint nr_state, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_sound_noise_reduction req;

	if (!check_access_control(invocation, AC_CALL, "w"))
		return TRUE;

	req.status = (gboolean)nr_state;

	dbg("[%s] NR Status: [%d]", GET_CP_NAME(invocation), req.status);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SET_SOUND_NOISE_REDUCTION,
		&req, sizeof(struct treq_call_set_sound_noise_reduction));

	return TRUE;
}

static gboolean on_call_set_sound_clock_status(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gboolean clock_status, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_sound_clock_status req;

	if (!check_access_control(invocation, AC_CALL, "w"))
		return TRUE;

	req.status = clock_status;

	dbg("[%s] Clock Status: [%s]", GET_CP_NAME(invocation),
		(req.status ? "ON" : "OFF"));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SET_SOUND_CLOCK_STATUS,
		&req, sizeof(struct treq_call_set_sound_clock_status));

	return TRUE;
}

static gboolean on_call_set_preferred_voice_subscription(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint preferred_subscription, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_preferred_voice_subscription req;

	if (!check_access_control(invocation, AC_CALL, "w"))
		return TRUE;

	req.preferred_subs = preferred_subscription;

	dbg("[%s] Preferred Voice subscription: [%s]", GET_CP_NAME(invocation),
		(req.preferred_subs == CALL_PREFERRED_VOICE_SUBS_CURRENT_NETWORK ? "CURRENT NW" :
		(req.preferred_subs == CALL_PREFERRED_VOICE_SUBS_ASK_ALWAYS ? "ASK ALWAYS" :
		(req.preferred_subs == CALL_PREFERRED_VOICE_SUBS_SIM1 ? "SIM 1" :
		(req.preferred_subs == CALL_PREFERRED_VOICE_SUBS_SIM2 ? "SIM 2" :
		"UNKNOWN")))));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_SET_PREFERRED_VOICE_SUBSCRIPTION,
		&req, sizeof(struct treq_call_set_preferred_voice_subscription));

	return TRUE;
}

static gboolean on_call_get_preferred_voice_subscription(TelephonyCall *call,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_CALL, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_GET_PREFERRED_VOICE_SUBSCRIPTION,
		NULL, 0);

	return TRUE;
}

static gboolean on_call_modify(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gint call_type, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_modify req = {0};

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;
	req.call_type = call_type;

	dbg("[%s] Call handle: [%d] Call type: [%s]",
		GET_CP_NAME(invocation), req.handle,
		(req.call_type == CALL_TYPE_VOICE ? "VOICE" :
		(req.call_type == CALL_TYPE_VIDEO ? "VIDEO" :
		"EMERGENCY")));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_MODIFY,
		&req, sizeof(struct treq_call_modify));

	return TRUE;
}

static gboolean on_call_confirm_modify(TelephonyCall *call,
	GDBusMethodInvocation *invocation,
	gint call_handle, gint confirm_type, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_confirm_modify req = {0};

	if (!check_access_control(invocation, AC_CALL, "x"))
		return TRUE;

	req.handle = call_handle;
	req.confirm_type = confirm_type;

	dbg("[%s] Call handle: [%d] Confirm type: [%s]",
		GET_CP_NAME(invocation), req.handle,
		(req.confirm_type == CALL_CONFIRM_TYPE_ACCEPT ? "ACCEPT" :
		"REJECT"));

	/* Dispatch request */
	dtapi_dispatch_request(ctx, call, invocation,
		TREQ_CALL_CONFIRM_MODIFY,
		&req, sizeof(struct treq_call_confirm_modify));

	return TRUE;
}

gboolean dbus_plugin_setup_call_interface(TelephonyObjectSkeleton *object,
	struct custom_data *ctx)
{
	TelephonyCall *call;

	call = telephony_call_skeleton_new();
	telephony_object_skeleton_set_call(object, call);
	g_object_unref(call);

	dbg("call = %p", call);

	/*
	 * Register signal handlers for CALL interface
	 */
	g_signal_connect(call,
		"handle-dial",
		G_CALLBACK(on_call_dial), ctx);

	g_signal_connect(call,
		"handle-answer",
		G_CALLBACK(on_call_answer), ctx);

	g_signal_connect(call,
		"handle-end",
		G_CALLBACK(on_call_end), ctx);

	g_signal_connect(call,
		"handle-start-cont-dtmf",
		G_CALLBACK(on_call_start_cont_dtmf), ctx);

	g_signal_connect(call,
		"handle-stop-cont-dtmf",
		G_CALLBACK(on_call_stop_cont_dtmf), ctx);

	g_signal_connect(call,
		"handle-send-burst-dtmf",
		G_CALLBACK(on_call_send_burst_dtmf), ctx);

	g_signal_connect(call,
		"handle-active",
		G_CALLBACK(on_call_active), ctx);

	g_signal_connect(call,
		"handle-hold",
		G_CALLBACK(on_call_hold), ctx);

	g_signal_connect(call,
		"handle-swap",
		G_CALLBACK(on_call_swap), ctx);

	g_signal_connect(call,
		"handle-join",
		G_CALLBACK(on_call_join), ctx);

	g_signal_connect(call,
		"handle-split",
		G_CALLBACK(on_call_split), ctx);

	g_signal_connect(call,
		"handle-transfer",
		G_CALLBACK(on_call_transfer), ctx);

	g_signal_connect(call,
		"handle-deflect",
		G_CALLBACK(on_call_deflect), ctx);

	g_signal_connect(call,
		"handle-get-privacy-mode",
		G_CALLBACK(on_call_get_privacy_mode), ctx);

	g_signal_connect(call,
		"handle-set-privacy-mode",
		G_CALLBACK(on_call_set_privacy_mode), ctx);

	g_signal_connect(call,
		"handle-get-status",
		G_CALLBACK(on_call_get_status), ctx);

	g_signal_connect(call,
		"handle-get-status-all",
		G_CALLBACK(on_call_get_status_all), ctx);

	g_signal_connect(call,
		"handle-set-sound-path",
		G_CALLBACK(on_call_set_sound_path), ctx);

	g_signal_connect(call,
		"handle-get-sound-volume-level",
		G_CALLBACK(on_call_get_sound_volume_level), ctx);

	g_signal_connect(call,
		"handle-set-sound-volume-level",
		G_CALLBACK(on_call_set_sound_volume_level), ctx);

	g_signal_connect(call,
		"handle-get-sound-mute-status",
		G_CALLBACK(on_call_get_sound_mute_status), ctx);

	g_signal_connect(call,
		"handle-set-sound-mute-status",
		G_CALLBACK(on_call_set_sound_mute_status), ctx);

	g_signal_connect(call,
		"handle-set-sound-recording",
		G_CALLBACK(on_call_set_sound_recording), ctx);

	g_signal_connect(call,
		"handle-set-sound-equalization",
		G_CALLBACK(on_call_set_sound_equalization), ctx);

	g_signal_connect(call,
		"handle-set-sound-noise-reduction",
		G_CALLBACK(on_call_set_sound_noise_reduction), ctx);

	g_signal_connect(call,
		"handle-set-sound-clock-status",
		G_CALLBACK(on_call_set_sound_clock_status), ctx);

	g_signal_connect(call,
		"handle-set-preferred-voice-subscription",
		G_CALLBACK(on_call_set_preferred_voice_subscription), ctx);

	g_signal_connect(call,
		"handle-get-preferred-voice-subscription",
		G_CALLBACK(on_call_get_preferred_voice_subscription), ctx);

	g_signal_connect(call,
		"handle-modify",
		G_CALLBACK(on_call_modify), ctx);

	g_signal_connect(call,
		"handle-confirm-modify",
		G_CALLBACK(on_call_confirm_modify), ctx);

	return TRUE;
}

gboolean dbus_plugin_call_response(struct custom_data *ctx,
	UserRequest *ur, struct dbus_request_info *dbus_info,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	char *cpname = dbus_info ? GET_CP_NAME(dbus_info->invocation) : "";

	switch (command) {
	case TRESP_CALL_DIAL: {
		struct tresp_call_dial *resp = (struct tresp_call_dial *)data;

		dbg("[%s] CALL_DIAL - Result: [%d]",
			cpname, resp->err);

		telephony_call_complete_dial(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_ANSWER: {
		struct tresp_call_answer *resp = (struct tresp_call_answer *)data;

		dbg("[%s] CALL_ANSWER - Result: [%d] Call handle: [%d]",
			cpname, resp->err, resp->handle);

		telephony_call_complete_answer(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->handle);
	}
	break;

	case TRESP_CALL_END: {
		struct tresp_call_end *resp = (struct tresp_call_end *)data;

		dbg("[%s] CALL_END - Result: [%d] Call handle: [%d] End type: [%d]",
			cpname, resp->err, resp->handle, resp->type);

		telephony_call_complete_end(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->handle, resp->type);
	}
	break;

	case TRESP_CALL_HOLD: {
		struct tresp_call_hold *resp = (struct tresp_call_hold *)data;

		dbg("[%s] CALL_HOLD - Result: [%d] Call handle: [%d]",
			cpname, resp->err, resp->handle);

		telephony_call_complete_hold(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->handle);
	}
	break;

	case TRESP_CALL_ACTIVE: {
		struct tresp_call_active *resp = (struct tresp_call_active *)data;

		dbg("[%s] CALL_ACTIVE - Result: [%d] Call handle: [%d]",
			cpname, resp->err, resp->handle);

		telephony_call_complete_active(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->handle);
	}
	break;

	case TRESP_CALL_SWAP: {
		struct tresp_call_swap *resp = (struct tresp_call_swap *)data;

		dbg("[%s] CALL_SWAP - Result: [%d] Call handle: [%d]",
			cpname, resp->err, resp->handle);

		telephony_call_complete_swap(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->handle);
	}
	break;

	case TRESP_CALL_JOIN: {
		struct tresp_call_join *resp = (struct tresp_call_join *)data;

		dbg("[%s] CALL_JOIN - Result: [%d] Call handle: [%d]",
			cpname, resp->err, resp->handle);

		telephony_call_complete_join(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->handle);
	}
	break;

	case TRESP_CALL_SPLIT: {
		struct tresp_call_split *resp = (struct tresp_call_split *)data;

		dbg("[%s] CALL_SPLIT - Result: [%d] Call handle: [%d]",
			cpname, resp->err, resp->handle);

		telephony_call_complete_split(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->handle);
	}
	break;

	case TRESP_CALL_DEFLECT: {
		struct tresp_call_deflect *resp = (struct tresp_call_deflect *)data;

		dbg("[%s] CALL_DEFLECT - Result: [%d] Call handle: [%d]",
			cpname, resp->err, resp->handle);

		telephony_call_complete_deflect(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_TRANSFER: {
		struct tresp_call_transfer *resp = (struct tresp_call_transfer *)data;

		dbg("[%s] CALL_TRANSFER - Result: [%d] Call handle: [%d]",
			cpname, resp->err, resp->handle);

		telephony_call_complete_transfer(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->handle);
	}
	break;

	case TRESP_CALL_START_CONT_DTMF: {
		struct tresp_call_dtmf *resp = (struct tresp_call_dtmf *)data;

		dbg("[%s] CALL_START_CONT_DTMF - Result: [%d]", cpname, resp->err);

		telephony_call_complete_start_cont_dtmf(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_STOP_CONT_DTMF: {
		struct tresp_call_dtmf *resp = (struct tresp_call_dtmf *)data;

		dbg("[%s] CALL_STOP_CONT_DTMF - Result: [%d]", cpname, resp->err);

		telephony_call_complete_stop_cont_dtmf(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_SEND_BURST_DTMF: {
		struct tresp_call_dtmf *resp = (struct tresp_call_dtmf *)data;

		dbg("[%s] CALL_SEND_BURST_DTMF - Result: [%d]", cpname, resp->err);

		telephony_call_complete_send_burst_dtmf(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_GET_PRIVACY_MODE: {
		struct tresp_call_get_voice_privacy_mode *resp = (struct tresp_call_get_voice_privacy_mode *)data;

		dbg("[%s] CALL_GET_PRIVACY_MODE - Result: [%d] Privacy mode: [%d]",
			cpname, resp->err, resp->privacy_mode);

		telephony_call_complete_get_privacy_mode(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->privacy_mode);
	}
	break;

	case TRESP_CALL_SET_PRIVACY_MODE: {
		struct tresp_call_set_voice_privacy_mode *resp = (struct tresp_call_set_voice_privacy_mode *)data;

		dbg("[%s] CALL_SET_PRIVACY_MODE - Result: [%d]", cpname, resp->err);

		telephony_call_complete_set_privacy_mode(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_SET_SOUND_PATH: {
		struct tresp_call_set_sound_path *resp = (struct tresp_call_set_sound_path *)data;

		dbg("[%s] CALL_SET_SOUND_PATH - Result: [%d]", cpname, resp->err);

		telephony_call_complete_set_sound_path(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_SET_SOUND_VOLUME_LEVEL: {
		struct tresp_call_set_sound_volume_level *resp = (struct tresp_call_set_sound_volume_level *)data;

		dbg("[%s] CALL_SET_SOUND_VOLUME_LEVEL  - Result: [%d]", cpname, resp->err);

		telephony_call_complete_set_sound_volume_level(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_GET_SOUND_VOLUME_LEVEL: {
		struct tresp_call_get_sound_volume_level *resp = (struct tresp_call_get_sound_volume_level *)data;
		GVariant *result = 0;
		GVariantBuilder b;
		int i = 0;

		dbg("[%s] CALL_GET_SOUND_VOLUME_LEVEL  - Result: [%d]", cpname, resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

		g_variant_builder_add(&b, "{sv}", "err",
			g_variant_new_int32(resp->err));
		if (!resp->err) {
			dbg("resp->record_num : [%d]", resp->record_num);

			for (i = 0; i < resp->record_num; i++) {
				dbg("sound_type : [%d], level:[%d]",
					resp->record[i].sound, resp->record[i].volume);
				g_variant_builder_add(&b, "{sv}", "type",
					g_variant_new_int32(resp->record[i].sound));
				g_variant_builder_add(&b, "{sv}", "level",
					g_variant_new_int32(resp->record[i].volume));
			}
		}
		g_variant_builder_close(&b);
		result = g_variant_builder_end(&b);

		telephony_call_complete_get_sound_volume_level(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_CALL_SET_SOUND_MUTE_STATUS: {
		struct tresp_call_set_sound_mute_status *resp = (struct tresp_call_set_sound_mute_status *)data;

		dbg("[%s] CALL_SET_SOUND_MUTE_STATUS  - Result: [%d]", cpname, resp->err);

		telephony_call_complete_set_sound_mute_status(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_GET_SOUND_MUTE_STATUS: {
		struct tresp_call_get_sound_mute_status *resp = (struct tresp_call_get_sound_mute_status *)data;

		dbg("[%s] CALL_GET_SOUND_MUTE_STATUS  - Result: [%d] Path: [%d] Status: [%d]",
			cpname, resp->err, resp->path, resp->status);

		telephony_call_complete_get_sound_mute_status(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->path, resp->status);

	}
	break;

	case TRESP_CALL_SET_SOUND_RECORDING: {
		struct tresp_call_set_sound_recording *resp = (struct tresp_call_set_sound_recording *)data;

		dbg("[%s] CALL_SET_SOUND_RECORDING - Result: [%d]", cpname, resp->err);

		telephony_call_complete_set_sound_recording(dbus_info->interface_object,
			dbus_info->invocation, resp->err);

	}
	break;

	case TRESP_CALL_SET_SOUND_EQUALIZATION: {
		struct tresp_call_set_sound_equalization *resp = (struct tresp_call_set_sound_equalization *)data;

		dbg("[%s] CALL_SET_SOUND_EQUALIZATION - Result: [%d]", cpname, resp->err);

		telephony_call_complete_set_sound_equalization(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_SET_SOUND_NOISE_REDUCTION: {
		struct tresp_call_set_sound_noise_reduction *resp = (struct tresp_call_set_sound_noise_reduction *)data;

		dbg("[%s] CALL_SET_SOUND_NOISE_REDUCTION - Result: [%d]", cpname, resp->err);

		telephony_call_complete_set_sound_noise_reduction(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_SET_SOUND_CLOCK_STATUS: {
		struct tresp_call_set_sound_clock_status *resp = (struct tresp_call_set_sound_clock_status *)data;

		dbg("[%s] CALL_SET_SOUND_CLOCK_STATUS - Result: [%d]", cpname, resp->err);

		telephony_call_complete_set_sound_clock_status(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_SET_PREFERRED_VOICE_SUBSCRIPTION: {
		struct tresp_call_set_preferred_voice_subscription *resp = (struct tresp_call_set_preferred_voice_subscription *)data;

		dbg("[%s] CALL_SET_PREFERRED_VOICE_SUBSCRIPTION - Result: [%d]",
			cpname, resp->err);

		telephony_call_complete_set_preferred_voice_subscription(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_GET_PREFERRED_VOICE_SUBSCRIPTION: {
		struct tresp_call_get_preferred_voice_subscription *resp = (struct tresp_call_get_preferred_voice_subscription *)data;

		dbg("[%s] CALL_GET_PREFERRED_VOICE_SUBSCRIPTION - Result: [%d] Preferred Subscription: [%d]",
			cpname, resp->err, resp->preferred_subs);

		telephony_call_complete_get_preferred_voice_subscription(dbus_info->interface_object,
			dbus_info->invocation, resp->preferred_subs, resp->err);
	}
	break;

	case TRESP_CALL_MODIFY: {
		const struct tresp_call_modify *resp = data;

		dbg("[%s] CALL_MODIFY - Result: [%d]", cpname, resp->err);

		telephony_call_complete_modify(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_CALL_CONFIRM_MODIFY: {
		const struct tresp_call_confirm_modify *resp = data;

		dbg("[%s] CALL_CONFIRM_MODIFY - Result: [%d]", cpname, resp->err);

		telephony_call_complete_confirm_modify(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	default:
		err("Unhandled/Unknown Response: [0x%x]", command);
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_call_notification(struct custom_data *ctx,
	CoreObject *source, TelephonyObjectSkeleton *object,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyCall *call;
	char *cp_name;

	if (!object) {
		dbg("object is NULL");
		return FALSE;
	}

	if (!data) {
		err("data is NULL");
		return FALSE;
	}

	cp_name = (char *)tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	call = telephony_object_peek_call(TELEPHONY_OBJECT(object));
	if (call == NULL) {
		err("call object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_CALL_STATUS_IDLE: {
		struct tnoti_call_status_idle *idle = (struct tnoti_call_status_idle *)data;

		dbg("[%s] CALL_STATUS_IDLE: [%s]", cp_name,
			(idle->type != CALL_TYPE_VIDEO ? "Voice" : "Video"));

		if (idle->type != CALL_TYPE_VIDEO)
			telephony_call_emit_voice_call_status_idle(call,
				idle->handle, idle->cause, 0, 0);
		else
			telephony_call_emit_video_call_status_idle(call,
				idle->handle, idle->cause, 0, 0);
	}
	break;

	case TNOTI_CALL_STATUS_DIALING: {
		struct tnoti_call_status_dialing *dialing = (struct tnoti_call_status_dialing *)data;

		dbg("[%s] CALL_STATUS_DIALING: [%s] Call handle: [%d]", cp_name,
			(dialing->type != CALL_TYPE_VIDEO ? "Voice" : "Video"),
			dialing->handle);

		if (dialing->type != CALL_TYPE_VIDEO)
			telephony_call_emit_voice_call_status_dialing(call, dialing->handle);
		else
			telephony_call_emit_video_call_status_dialing(call, dialing->handle);
	}
	break;

	case TNOTI_CALL_STATUS_ALERT: {
		struct tnoti_call_status_alert *alert = (struct tnoti_call_status_alert *)data;

		dbg("[%s] CALL_STATUS_ALERT: [%s] Call handle: [%d]", cp_name,
			(alert->type != CALL_TYPE_VIDEO ? "Voice" : "Video"),
			alert->handle);

		if (alert->type != CALL_TYPE_VIDEO)
			telephony_call_emit_voice_call_status_alert(call, alert->handle);
		else
			telephony_call_emit_video_call_status_alert(call, alert->handle);
	}
	break;

	case TNOTI_CALL_STATUS_ACTIVE: {
		struct tnoti_call_status_active *active = (struct tnoti_call_status_active *)data;

		dbg("[%s] CALL_STATUS_ACTIVE: [%s] Call handle: [%d]", cp_name,
			(active->type != CALL_TYPE_VIDEO ? "Voice" : "Video"),
			active->handle);

		if (active->type != CALL_TYPE_VIDEO)
			telephony_call_emit_voice_call_status_active(call, active->handle);
		else
			telephony_call_emit_video_call_status_active(call, active->handle);
	}
	break;

	case TNOTI_CALL_STATUS_HELD: {
		struct tnoti_call_status_held *held = (struct tnoti_call_status_held *)data;

		dbg("[%s] CALL_STATUS_HELD: Call handle: [%d]", cp_name,
			held->handle);

		telephony_call_emit_voice_call_status_held(call, held->handle);
	}
	break;

	case TNOTI_CALL_STATUS_INCOMING: {
		struct tnoti_call_status_incoming *incoming = (struct tnoti_call_status_incoming *)data;

		dbg("[%s] CALL_STATUS_INCOMING: [%s] Call handle: [%d]", cp_name,
			(incoming->type != CALL_TYPE_VIDEO ? "Voice" : "Video"),
			incoming->handle);

		if (incoming->type != CALL_TYPE_VIDEO)
			telephony_call_emit_voice_call_status_incoming(call,
				incoming->handle,
				incoming->cli.mode,
				incoming->cli.no_cli_cause,
				incoming->cli.number,
				incoming->forward,
				incoming->active_line,
				incoming->cna.name);
		else
			telephony_call_emit_video_call_status_incoming(call,
				incoming->handle,
				incoming->cli.mode,
				incoming->cli.no_cli_cause,
				incoming->cli.number,
				incoming->forward,
				incoming->active_line,
				incoming->cna.name);
	}
	break;

	case TNOTI_CALL_INFO_WAITING: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_WAITING: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_waiting(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_FORWARDED: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_FORWARDED: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_forwarded(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_FORWARDED_CALL: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_FORWARDED_CALL: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_forwarded_call(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_BARRED_INCOMING: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_BARRED_INCOMING: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_barred_incoming(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_BARRED_OUTGOING: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_BARRED_OUTGOING: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_barred_outgoing(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_FORWARD_CONDITIONAL: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_FORWARD_CONDITIONAL: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_forward_conditional(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_FORWARD_UNCONDITIONAL: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_FORWARD_UNCONDITIONAL: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_forward_unconditional(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_HELD: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_HELD: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_call_held(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_ACTIVE: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_ACTIVE: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_call_active(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_JOINED: {
		int *id = (int *)data;

		dbg("[%s] CALL_INFO_JOINED: Call handle: [%d]",
			cp_name, (gint)*id);

		telephony_call_emit_call_joined(call, (gint)*id);
	}
	break;

	case TNOTI_CALL_INFO_PRIVACY_MODE: {
		struct tnoti_call_info_voice_privacy_mode *privacy_info = (struct tnoti_call_info_voice_privacy_mode *)data;

		dbg("[%s] CALL_INFO_PRIVACY_MODE: Privacy mode: [%d]",
			cp_name, privacy_info->privacy_mode);

		telephony_call_emit_call_privacy_mode(call, privacy_info->privacy_mode);
	}
	break;

	case TNOTI_CALL_OTASP_STATUS: {
		struct tnoti_call_otasp_status  *otasp = (struct tnoti_call_otasp_status *)data;

		dbg("[%s] CALL_OTASP_STATUS : status(%d)",
			cp_name, otasp->otasp_status);

		telephony_call_emit_call_otasp_status(call, otasp->otasp_status);
	}
	break;

	case TNOTI_CALL_OTAPA_STATUS: {
		struct tnoti_call_otapa_status  *otapa = (struct tnoti_call_otapa_status *)data;

		dbg("[%s] CALL_OTAPA_STATUS: Status: [%d]",
			cp_name, otapa->otapa_status);

		telephony_call_emit_call_otapa_status(call, otapa->otapa_status);
	}
	break;

	case TNOTI_CALL_SIGNAL_INFO: {
		struct tnoti_call_signal_info *sig_info = (struct tnoti_call_signal_info *)data;
		unsigned int signal;

		if (sig_info->signal_type == CALL_SIGNAL_TYPE_TONE) {
			signal = sig_info->signal.sig_tone_type;
		} else if (sig_info->signal_type == CALL_SIGNAL_TYPE_ISDN_ALERTING) {
			signal = sig_info->signal.sig_isdn_alert_type;
		} else if (sig_info->signal_type == CALL_SIGNAL_TYPE_IS54B_ALERTING) {
			signal = sig_info->signal.sig_is54b_alert_type;
		} else {
			err("Unknown Signal type");
			return FALSE;
		}

		dbg("[%s] CALL_SIGNAL_INFO: Signal type: [%d] Pitch type: [%d] Signal: [%d]",
			cp_name, sig_info->signal_type, sig_info->pitch_type, signal);

		telephony_call_emit_call_signal_info(call,
			sig_info->signal_type, sig_info->pitch_type, signal);
	}
	break;

	case TNOTI_CALL_INFO_REC: {
		struct tnoti_call_info_rec *noti = (struct tnoti_call_info_rec *)data;
		gchar *param = NULL;

		if (noti->rec_info.type == CALL_REC_NAME_INFO) {
			param = g_strdup(noti->rec_info.data.name);
		} else if (noti->rec_info.type == CALL_REC_NUMBER_INFO) {
			param = g_strdup(noti->rec_info.data.number);
		} else {
			err("Unknown rec info type (%d)", noti->rec_info.type);
			return FALSE;
		}

		dbg("[%s] CALL_INFO_REC: id: [%d] type: [%d] param: [%s]",
			cp_name, noti->rec_info.handle, noti->rec_info.type, param);

		telephony_call_emit_call_info_rec(call, noti->rec_info.handle, noti->rec_info.type, param);
		g_free(param);
	}
	break;

	case TNOTI_CALL_SOUND_PATH: {
		struct tnoti_call_sound_path *noti = (struct tnoti_call_sound_path *)data;

		dbg("[%s] CALL_SOUND_PATH: Path: [%d]", cp_name, noti->path);

		telephony_call_emit_call_sound_path(call, noti->path);
	}
	break;

	case TNOTI_CALL_SOUND_RINGBACK_TONE: {
		struct tnoti_call_sound_ringback_tone *noti = (struct tnoti_call_sound_ringback_tone *)data;

		dbg("[%s] CALL_SOUND_RINGBACK_TONE: Status: [%d]",
			cp_name, (gint)noti->status);

		telephony_call_emit_call_sound_ringback_tone(call, (gint)noti->status);
	}
	break;

	case TNOTI_CALL_SOUND_WBAMR: {
		struct tnoti_call_sound_wbamr *noti = (struct tnoti_call_sound_wbamr *)data;

		dbg("[%s] CALL_SOUND_WBAMR: Status: [%d]",
			cp_name, (gint)noti->status);

		telephony_call_emit_call_sound_wbamr(call, (gint)noti->status);
	}
	break;

	case TNOTI_CALL_SOUND_EQUALIZATION: {
		struct tnoti_call_sound_equalization *noti = (struct tnoti_call_sound_equalization *)data;

		dbg("[%s] CALL_SOUND_EQUALIZATION: Direction: [%d]",
			cp_name, (gint)noti->direction);

		telephony_call_emit_call_sound_equalization(call, (gint)noti->mode, (gint)noti->direction);
	}
	break;

	case TNOTI_CALL_SOUND_NOISE_REDUCTION: {
		struct tnoti_call_sound_noise_reduction *noti = (struct tnoti_call_sound_noise_reduction *)data;

		dbg("[%s] CALL_SOUND_NOISE_REDUCTION: Status: [%d]",
			cp_name, (gint)noti->status);

		telephony_call_emit_call_sound_noise_reduction(call, (gint)noti->status);
	}
	break;

	case TNOTI_CALL_SOUND_CLOCK_STATUS: {
		struct tnoti_call_sound_clock_status *noti = (struct tnoti_call_sound_clock_status *)data;

		dbg("[%s] CALL_SOUND_CLOCK_STATUS: Status: [%d]",
			cp_name, (gint)noti->status);

		telephony_call_emit_call_sound_clock_status(call, noti->status);
	}
	break;

	case TNOTI_CALL_PREFERRED_VOICE_SUBSCRIPTION: {
		struct tnoti_call_preferred_voice_subscription *noti = (struct tnoti_call_preferred_voice_subscription *)data;

		dbg("[%s] CALL_PREFERRED_VOICE_SUBSCRIPTION: Subscription: [%d]",
			cp_name, noti->preferred_subs);

		telephony_call_emit_call_preferred_voice_subscription(call, noti->preferred_subs);
	}
	break;

	case TNOTI_CALL_MODIFY_REQUEST: {
		const struct tnoti_call_modify_request *noti = data;

		dbg("[%s] CALL_MODIFY_REQUEST: Call handle: [%d] Call type: [%d]",
			cp_name, noti->handle, noti->call_type);

		telephony_call_emit_call_modify_request(call, noti->handle, noti->call_type);
	}
	break;

	case TNOTI_CALL_INFO_FALLBACK:{
		struct tnoti_call_fallback* noti = (struct tnoti_call_fallback *)data;

		dbg("[%s] CALL_INFO_FALLBACK: Call handle: [%d] Fallback to: [%d]",
			cp_name, noti->handle, noti->fallback_to);

		telephony_call_emit_call_fallback(call, noti->handle, noti->fallback_to);
	}
	break;

	default:
		err("Unhandled/Unknown Notification: [0x%x]", command);
	break;
	}

	return TRUE;
}
