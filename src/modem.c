/*
 * tel-plugin-dbus_tapi
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
#include <co_modem.h>

#include "generated-code.h"
#include "common.h"

static gboolean
on_modem_set_power (TelephonyModem *modem,
		GDBusMethodInvocation *invocation,
		gint mode,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret = TCORE_RETURN_SUCCESS;

	if (check_access_control(invocation, AC_MODEM, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, modem, invocation);
	tcore_user_request_set_data(ur, 0, NULL);

	switch (mode) {
		case 0:
			tcore_user_request_set_command(ur, TREQ_MODEM_POWER_OFF);
			break;
		case 1:
			tcore_user_request_set_command(ur, TREQ_MODEM_POWER_ON);
			break;
		case 2:
			tcore_user_request_set_command(ur, TREQ_MODEM_POWER_RESET);
			break;
		default:
			ret = TCORE_RETURN_EINVAL;
			goto ERR;
			break;
	}

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS)
		goto ERR;

	return TRUE;

ERR:
	telephony_modem_complete_set_power(modem, invocation, ret);
	g_free(ur);

	return TRUE;
}

static gboolean
on_modem_set_flight_mode (TelephonyModem *modem,
		GDBusMethodInvocation *invocation,
		gboolean enable,
		gpointer user_data)
{
	struct treq_modem_set_flightmode data;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_MODEM, "w") == FALSE)
		return FALSE;

	data.enable = enable;

	ur = MAKE_UR(ctx, modem, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_modem_set_flightmode), &data);
	tcore_user_request_set_command(ur, TREQ_MODEM_SET_FLIGHTMODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_modem_complete_set_flight_mode(modem, invocation, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_modem_get_flight_mode (TelephonyModem *modem,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct treq_modem_get_flightmode data;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_MODEM, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, modem, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_modem_get_flightmode), &data);
	tcore_user_request_set_command(ur, TREQ_MODEM_GET_FLIGHTMODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_modem_complete_get_flight_mode(modem, invocation, FALSE, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_modem_get_version (TelephonyModem *modem,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_MODEM, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, modem, invocation);
	tcore_user_request_set_command(ur, TREQ_MODEM_GET_VERSION);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_modem_complete_get_version(modem, invocation,
				ret,
				NULL, NULL, NULL, NULL);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_modem_get_serial_number (TelephonyModem *modem,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_MODEM, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, modem, invocation);
	tcore_user_request_set_command(ur, TREQ_MODEM_GET_SN);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_modem_complete_get_serial_number(modem, invocation, ret, NULL);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_modem_get_imei (TelephonyModem *modem,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_MODEM, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, modem, invocation);
	tcore_user_request_set_command(ur, TREQ_MODEM_GET_IMEI);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_modem_complete_get_imei(modem, invocation, ret, NULL);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_modem_set_dun_pin_ctrl (TelephonyModem *modem, GDBusMethodInvocation *invocation,
		gint arg_signal, gboolean arg_status, gpointer user_data)
{
	struct treq_modem_set_dun_pin_control data;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_MODEM, "x") == FALSE)
		return FALSE;

	data.signal = arg_signal;
	data.status = arg_status;

	ur = MAKE_UR(ctx, modem, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_modem_set_dun_pin_control), &data);
	tcore_user_request_set_command(ur, TREQ_MODEM_SET_DUN_PIN_CONTROL);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_modem_complete_set_dun_pin_ctrl(modem, invocation, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_modem_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonyModem *modem;

	modem = telephony_modem_skeleton_new();
	telephony_object_skeleton_set_modem(object, modem);
	g_object_unref(modem);

	dbg("modem = %p", modem);

	g_signal_connect (modem,
			"handle-set-power",
			G_CALLBACK (on_modem_set_power),
			ctx);

	g_signal_connect (modem,
			"handle-set-flight-mode",
			G_CALLBACK (on_modem_set_flight_mode),
			ctx);

	g_signal_connect (modem,
			"handle-get-flight-mode",
			G_CALLBACK (on_modem_get_flight_mode),
			ctx);

	g_signal_connect (modem,
			"handle-get-version",
			G_CALLBACK (on_modem_get_version),
			ctx);

	g_signal_connect (modem,
			"handle-get-serial-number",
			G_CALLBACK (on_modem_get_serial_number),
			ctx);

	g_signal_connect (modem,
			"handle-get-imei",
			G_CALLBACK (on_modem_get_imei),
			ctx);

	g_signal_connect (modem,
			"handle-set-dun-pin-ctrl",
			G_CALLBACK (on_modem_set_dun_pin_ctrl),
			ctx);


	return TRUE;
}

gboolean dbus_plugin_modem_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	const struct tresp_modem_set_flightmode *resp_set_flight_mode = data;
	const struct tresp_modem_get_flightmode *resp_get_flight_mode = data;
	const struct tresp_modem_set_dun_pin_control *resp_dun_pin_ctrl = data;
	const struct tresp_modem_get_imei *resp_get_imei = data;
	const struct tresp_modem_get_sn *resp_get_sn = data;
	const struct tresp_modem_get_version *resp_get_version = data;

	switch (command) {
		case TRESP_MODEM_SET_FLIGHTMODE:
			dbg("receive TRESP_MODEM_SET_FLIGHTMODE");
			dbg("resp->result = %d", resp_set_flight_mode->result);
			telephony_modem_complete_set_flight_mode(dbus_info->interface_object, dbus_info->invocation, resp_set_flight_mode->result);
			break;

		case TRESP_MODEM_GET_FLIGHTMODE:
			dbg("receive TRESP_MODEM_GET_FLIGHTMODE");
			dbg("resp->result = %d", resp_get_flight_mode->result);
			telephony_modem_complete_get_flight_mode(dbus_info->interface_object, dbus_info->invocation, resp_get_flight_mode->enable, resp_get_flight_mode->result);
			break;

		case TRESP_MODEM_POWER_ON:
			dbg("receive TRESP_MODEM_POWER_ON");
			telephony_modem_complete_set_power(dbus_info->interface_object, dbus_info->invocation, 0);
			break;

		case TRESP_MODEM_POWER_OFF:
			dbg("receive TRESP_MODEM_POWER_OFF");
			telephony_modem_complete_set_power(dbus_info->interface_object, dbus_info->invocation, 0);
			break;

		case TRESP_MODEM_POWER_RESET:
			dbg("receive TRESP_MODEM_POWER_RESET");
			telephony_modem_complete_set_power(dbus_info->interface_object, dbus_info->invocation, 0);
			break;

		case TRESP_MODEM_GET_IMEI:
			dbg("receive TRESP_MODEM_GET_IMEI");
			telephony_modem_complete_get_imei(dbus_info->interface_object, dbus_info->invocation, resp_get_imei->result, resp_get_imei->imei);
			break;

		case TRESP_MODEM_GET_SN:
			dbg("receive TRESP_MODEM_GET_SN");
			telephony_modem_complete_get_serial_number(dbus_info->interface_object, dbus_info->invocation, resp_get_sn->result, resp_get_sn->sn);
			break;

		case TRESP_MODEM_GET_VERSION:
			dbg("receive TRESP_MODEM_GET_VERSION");
			telephony_modem_complete_get_version(dbus_info->interface_object, dbus_info->invocation,
					resp_get_version->result,
					resp_get_version->software,
					resp_get_version->hardware,
					resp_get_version->calibration,
					resp_get_version->product_code);
			break;

		case TRESP_MODEM_SET_DUN_PIN_CONTROL:
			dbg("receive TRESP_MODEM_SET_DUN_PIN_CONTROL");
			dbg("resp->result = %d", resp_dun_pin_ctrl->result);
			telephony_modem_complete_set_dun_pin_ctrl(dbus_info->interface_object, dbus_info->invocation, resp_dun_pin_ctrl->result);
			break;

		default:
			dbg("not handled command[%d]", command);
		break;
	}

	return TRUE;
}

gboolean dbus_plugin_modem_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyModem *modem;
	const struct tnoti_modem_power *info = data;
	const struct tnoti_modem_dun_pin_control *pin = data;

	if (!object) {
		dbg("object is NULL");
		return FALSE;
	}

	modem = telephony_object_peek_modem(TELEPHONY_OBJECT(object));
	dbg("modem = %p", modem);

	switch (command) {
		case TNOTI_MODEM_POWER:
			dbg("modem->state = %d", info->state);
			telephony_modem_emit_power(modem, info->state);
			telephony_modem_set_power(modem, info->state);
			break;

		case TNOTI_MODEM_DUN_PIN_CONTROL:
			dbg("modem dun pin ctrl noti signal(%d), status(%d)", pin->signal, pin->status);
			telephony_modem_emit_dun_pin_ctrl(modem, pin->signal, pin->status);
			break;

		case TNOTI_MODEM_DUN_EXTERNAL_CALL:
			dbg("modem dun external call noti");
			telephony_modem_emit_dun_external_call(modem, TRUE);
			break;

		case TNOTI_MODEM_ADDED:
			break;

		default:
			dbg("not handled command[0x%x]", command);
		break;
	}

	return TRUE;
}

