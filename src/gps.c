/*
 * tel-plugin-dbus_tapi
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <hal.h>
#include <communicator.h>
#include <storage.h>
#include <queue.h>
#include <user_request.h>
#include <co_gps.h>
#include <co_sim.h>
#include <co_ps.h>

#include "generated-code.h"
#include "common.h"

static gboolean
on_gps_set_frequency_aiding (TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		guchar data,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_GPS, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, gps, invocation);
	dbg("data=%d",data);

	tcore_user_request_set_data(ur, sizeof(data), (const char*)&data);
	tcore_user_request_set_command(ur, TREQ_GPS_SET_FREQUENCY_AIDING);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_gps_complete_set_frequency_aiding(gps, invocation, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_gps_confirm_measure_pos (TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		const gchar *data,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	gboolean result = TRUE;
	guchar *decoded_data = NULL;
	gsize length;

	if (check_access_control(invocation, AC_GPS, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, gps, invocation);

	decoded_data = g_base64_decode(data, &length);
	dbg("decoded length=%d", length);
	tcore_user_request_set_data(ur, length, decoded_data);
	tcore_user_request_set_command(ur, TREQ_GPS_CONFIRM_MEASURE_POS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		tcore_user_request_unref(ur);
		result = FALSE;
	}

	telephony_gps_complete_confirm_measure_pos(gps, invocation, result);
	g_free(decoded_data);

	return TRUE;
}


gboolean dbus_plugin_setup_gps_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonyGps *gps;

	gps = telephony_gps_skeleton_new();
	telephony_object_skeleton_set_gps(object, gps);

	g_object_unref(gps);

	dbg("gps = %p", gps);

	g_signal_connect (gps,
			"handle-set-frequency-aiding",
			G_CALLBACK (on_gps_set_frequency_aiding),
			ctx);

	g_signal_connect (gps,
			"handle-confirm-measure-pos",
			G_CALLBACK (on_gps_confirm_measure_pos),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_gps_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	const struct tresp_gps_set_frequency_aiding*resp_gps_frequency_aiding = data;

	CoreObject *co_gps;
	char *modem_name = NULL;
	TcorePlugin *p = NULL;

	modem_name = tcore_user_request_get_modem_name(ur);
	if (!modem_name)
		return FALSE;

	p = tcore_server_find_plugin(ctx->server, modem_name);
	free(modem_name);
	if (!p)
		return FALSE;

	co_gps = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_GPS);
	if (!co_gps)
		return FALSE;

	switch (command) {
		case TRESP_GPS_SET_FREQUENCY_AIDING:
			dbg("receive TRESP_GPS_SET_FREQUENCY_AIDING");
			dbg("resp->result = %d", resp_gps_frequency_aiding->result);
			telephony_gps_complete_set_frequency_aiding(dbus_info->interface_object, dbus_info->invocation, resp_gps_frequency_aiding->result);
			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}

gboolean dbus_plugin_gps_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyGps *gps;

	if (!object) {
		dbg("object is NULL");
		return FALSE;
	}

	gps = telephony_object_peek_gps(TELEPHONY_OBJECT(object));
	dbg("gps = %p", gps);

	switch (command) {
		case TNOTI_GPS_ASSIST_DATA:
		{
			gchar *encoded_data = NULL;
			dbg("TNOTI_GPS_ASSIST_DATA. data=%p, data_len=%d", data, data_len);
			encoded_data = g_base64_encode((const guchar*)data, data_len);
			telephony_gps_emit_assist_data(gps, encoded_data);
			g_free(encoded_data);
		}
			break;

		case TNOTI_GPS_MEASURE_POSITION:
		{
			gchar *encoded_data = NULL;
			dbg("TNOTI_GPS_MEASURE_POSITION. data=%p, data_len=%d", data, data_len);
			encoded_data = g_base64_encode((const guchar*)data, data_len);
			telephony_gps_emit_measure_position(gps, encoded_data);
			g_free(encoded_data);
		}
			break;

		case TNOTI_GPS_RESET_ASSIST_DATA:
			dbg("TNOTI_GPS_RESET_ASSIST_DATA");
			telephony_gps_emit_reset_assist_data(gps);
			break;

		case TNOTI_GPS_FREQUENCY_AIDING_DATA:
		{
			gchar *encoded_data = NULL;
			dbg("TNOTI_GPS_FREQUENCY_AIDING_DATA. data=%p, data_len=%d", data, data_len);
			encoded_data = g_base64_encode((const guchar*)data, data_len);
			telephony_gps_emit_frequency_aiding(gps, encoded_data);
			g_free(encoded_data);
		}
			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}

