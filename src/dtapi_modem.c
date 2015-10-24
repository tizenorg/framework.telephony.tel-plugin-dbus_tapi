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
#include <stdlib.h>

#include <glib.h>

#include <tcore.h>
#include <server.h>
#include <user_request.h>
#include <co_modem.h>

#include "generated-code.h"
#include "dtapi_common.h"

static gboolean on_modem_set_power(TelephonyModem *modem,
	GDBusMethodInvocation *invocation, gint mode, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	enum tcore_request_command command;

	if (!check_access_control(invocation, AC_MODEM, "x"))
		return TRUE;

	switch (mode) {
	case MODEM_STATE_ONLINE:
		command = TREQ_MODEM_POWER_ON;
	break;

	case MODEM_STATE_OFFLINE:
		command = TREQ_MODEM_POWER_OFF;
	break;

	case MODEM_STATE_RESET:
		command = TREQ_MODEM_POWER_RESET;
	break;

	case MODEM_STATE_LOW:
		command = TREQ_MODEM_POWER_LOW;
	break;

	default:
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}

	/* Dispatch request */
	dtapi_dispatch_request(ctx, modem, invocation,
		command,
		NULL, 0);

	return TRUE;
}

static gboolean on_modem_set_flight_mode(TelephonyModem *modem,
	GDBusMethodInvocation *invocation, gboolean enable, gpointer user_data)
{
	struct treq_modem_set_flightmode req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_MODEM, "w"))
		return TRUE;

	req.enable = enable;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, modem, invocation,
		TREQ_MODEM_SET_FLIGHTMODE,
		&req, sizeof(struct treq_modem_set_flightmode));

	return TRUE;
}

static gboolean on_modem_get_flight_mode(TelephonyModem *modem,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_MODEM, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, modem, invocation,
		TREQ_MODEM_GET_FLIGHTMODE,
		NULL, 0);

	return TRUE;
}

static gboolean on_modem_get_version(TelephonyModem *modem,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_MODEM, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, modem, invocation,
		TREQ_MODEM_GET_VERSION,
		NULL, 0);

	return TRUE;
}

static gboolean on_modem_get_serial_number(TelephonyModem *modem,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_MODEM, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, modem, invocation,
		TREQ_MODEM_GET_SN,
		NULL, 0);

	return TRUE;
}

static gboolean on_modem_get_imei(TelephonyModem *modem,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_MODEM, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, modem, invocation,
		TREQ_MODEM_GET_IMEI,
		NULL, 0);

	return TRUE;
}

static gboolean on_modem_set_dun_pin_ctrl(TelephonyModem *modem,
	GDBusMethodInvocation *invocation,
	gint signal, gboolean status, gpointer user_data)
{
	struct treq_modem_set_dun_pin_control req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_MODEM, "x"))
		return TRUE;

	req.signal = signal;
	req.status = status;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, modem, invocation,
		TREQ_MODEM_GET_VERSION,
		&req, sizeof(struct treq_modem_set_dun_pin_control));

	return TRUE;
}

static gboolean on_modem_get_device_info(TelephonyModem *modem,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_MODEM, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, modem, invocation,
		TREQ_MODEM_GET_DEVICE_INFO,
		NULL, 0);

	return TRUE;
}

gboolean dbus_plugin_setup_modem_interface(TelephonyObjectSkeleton *object,
	struct custom_data *ctx)
{
	TelephonyModem *modem;

	modem = telephony_modem_skeleton_new();
	telephony_object_skeleton_set_modem(object, modem);
	g_object_unref(modem);

	dbg("modem: [%p]", modem);

	/*
	 * Register signal handlers for Modem interface
	 */
	g_signal_connect(modem,
		"handle-set-power",
		G_CALLBACK(on_modem_set_power), ctx);

	g_signal_connect(modem,
		"handle-set-flight-mode",
		G_CALLBACK(on_modem_set_flight_mode), ctx);

	g_signal_connect(modem,
		"handle-get-flight-mode",
		G_CALLBACK(on_modem_get_flight_mode), ctx);

	g_signal_connect(modem,
		"handle-get-version",
		G_CALLBACK(on_modem_get_version), ctx);

	g_signal_connect(modem,
		"handle-get-serial-number",
		G_CALLBACK(on_modem_get_serial_number), ctx);

	g_signal_connect(modem,
		"handle-get-imei",
		G_CALLBACK(on_modem_get_imei), ctx);

	g_signal_connect(modem,
		"handle-set-dun-pin-ctrl",
		G_CALLBACK(on_modem_set_dun_pin_ctrl), ctx);

	g_signal_connect(modem,
		"handle-get-device-info",
		G_CALLBACK(on_modem_get_device_info), ctx);

	/*
	 * Initialize 'properties'
	 */
	telephony_modem_set_power(modem, MODEM_STATE_UNKNOWN);

	return TRUE;
}

gboolean dbus_plugin_modem_response(struct custom_data *ctx,
	UserRequest *ur, struct dbus_request_info *dbus_info,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	char *cpname = dbus_info ? GET_CP_NAME(dbus_info->invocation) : "";

	switch (command) {
	case TRESP_MODEM_SET_FLIGHTMODE: {
		const struct tresp_modem_set_flightmode *resp_set_flight_mode = data;
		int set_flight_mode = 3;	/* TAPI_POWER_FLIGHT_MODE_RESP_FAIL */

		if (resp_set_flight_mode->result == TCORE_RETURN_SUCCESS) {
			const struct treq_modem_set_flightmode *treq_data;
			treq_data = tcore_user_request_ref_data(ur, NULL);
			if (treq_data == NULL) {
				warn("No Request data!!!");
				set_flight_mode = 3;	/* TAPI_POWER_FLIGHT_MODE_RESP_FAIL */
			} else if (treq_data->enable == TRUE) {
				set_flight_mode = 1;	/* TAPI_POWER_FLIGHT_MODE_RESP_ON */
			} else {
				set_flight_mode = 2;	/* TAPI_POWER_FLIGHT_MODE_RESP_OFF */
			}
		}

		dbg("[%s] SET_FLIGHTMODE - [%s] [%s]", cpname,
			(resp_set_flight_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			(set_flight_mode == 1 ? "ON" :
			(set_flight_mode == 2 ? "OFF" : "Request FAIL")));

		telephony_modem_complete_set_flight_mode(dbus_info->interface_object,
			dbus_info->invocation, set_flight_mode);
	}
	break;

	case TRESP_MODEM_GET_FLIGHTMODE: {
		const struct tresp_modem_get_flightmode *resp_get_flight_mode = data;

		dbg("[%s] GET_FLIGHTMODE - [%s]", cpname,
			(resp_get_flight_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_modem_complete_get_flight_mode(dbus_info->interface_object,
			dbus_info->invocation,
			resp_get_flight_mode->enable, resp_get_flight_mode->result);
	}
	break;

	case TRESP_MODEM_POWER_ON: {
		const struct tresp_modem_power_on *resp_modem_power_on = data;
		int result = 0;

		dbg("[%s] POWER_ON - [%s]", cpname,
			(resp_modem_power_on->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		/* TBD: value should be defined in TAPI */
		if (resp_modem_power_on->result == TCORE_RETURN_EALREADY)
			result = 1;
		else if (resp_modem_power_on->result == TCORE_RETURN_OPERATION_ABORTED)
			result = 2;

		telephony_modem_complete_set_power(dbus_info->interface_object,
			dbus_info->invocation, result);
	}
	break;

	case TRESP_MODEM_POWER_OFF: {
		dbg("[%s] POWER_OFF", cpname);

		telephony_modem_complete_set_power(dbus_info->interface_object,
			dbus_info->invocation, 0);
	}
	break;

	case TRESP_MODEM_POWER_RESET: {
		dbg("[%s] POWER_RESET", cpname);

		telephony_modem_complete_set_power(dbus_info->interface_object,
			dbus_info->invocation, 0);
	}
	break;

	case TRESP_MODEM_POWER_LOW: {
		dbg("[%s] POWER_LOW", cpname);

		telephony_modem_complete_set_power(dbus_info->interface_object,
			dbus_info->invocation, 0);
	}
	break;

	case TRESP_MODEM_GET_IMEI: {
		const struct tresp_modem_get_imei *resp_get_imei = data;

		dbg("[%s] GET_IMEI - [%s]", cpname,
			(resp_get_imei->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_modem_complete_get_imei(dbus_info->interface_object,
			dbus_info->invocation,
			resp_get_imei->result, resp_get_imei->imei);
	}
	break;

	case TRESP_MODEM_GET_SN: {
		const struct tresp_modem_get_sn *resp_get_sn = data;

		dbg("[%s] GET_SN - [%s]", cpname,
			(resp_get_sn->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_modem_complete_get_serial_number(dbus_info->interface_object,
			dbus_info->invocation, resp_get_sn->result,
			resp_get_sn->sn, resp_get_sn->meid,
			resp_get_sn->imei, resp_get_sn->imeisv);
	}
	break;

	case TRESP_MODEM_GET_VERSION: {
		const struct tresp_modem_get_version *resp_get_version = data;

		dbg("[%s] GET_VERSION - [%s]", cpname,
			(resp_get_version->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_modem_complete_get_version(dbus_info->interface_object,
			dbus_info->invocation, resp_get_version->result,
			resp_get_version->software, resp_get_version->hardware,
			resp_get_version->calibration, resp_get_version->product_code,
			resp_get_version->prl_version, resp_get_version->eri_version);
	}
	break;

	case TRESP_MODEM_SET_DUN_PIN_CONTROL: {
		const struct tresp_modem_set_dun_pin_control *resp_dun_pin_ctrl = data;

		dbg("[%s] SET_DUN_PIN_CONTROL - [%s]", cpname,
			(resp_dun_pin_ctrl->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_modem_complete_set_dun_pin_ctrl(dbus_info->interface_object,
			dbus_info->invocation, resp_dun_pin_ctrl->result);
	}
	break;

	case TRESP_MODEM_GET_DEVICE_INFO: {
		const struct tresp_modem_get_device_info *resp_get_device_info = data;

		dbg("[%s] TGET_DEVICE_INFO - Vendor[%s] Device[%s]", cpname,
			resp_get_device_info->vendor_name,
			resp_get_device_info->device_name);

		telephony_modem_complete_get_device_info(dbus_info->interface_object,
			dbus_info->invocation, resp_get_device_info->result,
			resp_get_device_info->vendor_name, resp_get_device_info->device_name);
	}
	break;

	default:
		err("Unhandled/Unknown Response: [0x%x]", command);
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_modem_notification(struct custom_data *ctx,
	CoreObject *source, TelephonyObjectSkeleton *object,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyModem *modem;
	const char *cp_name;
	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	if (!object) {
		dbg("object is NULL");
		return FALSE;
	}
	modem = telephony_object_peek_modem(TELEPHONY_OBJECT(object));
	if (modem == NULL) {
		err("modem object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_MODEM_POWER: {
		const struct tnoti_modem_power *info = data;
		enum modem_state state = info->state;

		dbg("[%s] MODEM_POWER: [%s]", cp_name,
			(state == MODEM_STATE_UNKNOWN ? "UNKNOWN" :
			(state == MODEM_STATE_ONLINE ? "ONLINE" :
			(state == MODEM_STATE_OFFLINE ? "OFFLINE" :
			(state == MODEM_STATE_RESET ? "RESET" :
			(state == MODEM_STATE_LOW ? "LOW" :
			"INTERNAL STATE"))))));
		if (state > MODEM_STATE_MAX)
			break;

		telephony_modem_emit_power(modem, state);
		telephony_modem_set_power(modem, state);
	}
	break;

	case TNOTI_MODEM_DUN_PIN_CONTROL: {
		const struct tnoti_modem_dun_pin_control *pin = data;

		dbg("[%s] MODEM_DUN_PIN_CONTROL (Signal: [0x%2x] Status: [0x%2x])",
			cp_name, pin->signal, pin->status);

		telephony_modem_emit_dun_pin_ctrl(modem, pin->signal, pin->status);
	}
	break;

	case TNOTI_MODEM_DUN_EXTERNAL_CALL: {
		dbg("[%s] MODEM_DUN_EXTERNAL_CALL", cp_name);

		telephony_modem_emit_dun_external_call(modem, TRUE);
	}
	break;

	case TNOTI_MODEM_DONGLE_STATUS:
		dbg("[%s] MODEM_DONGLE_STATUS (state:[%d])", cp_name, *(int *)data);
		telephony_modem_set_dongle_status(modem,  *(int *)data);
	break;

	case TNOTI_MODEM_DONGLE_LOGIN:
		dbg("[%s] MODEM_DONGLE_LOGIN (login state:[%d])", cp_name, *(int *)data);
		telephony_modem_set_dongle_login(modem,  *(int *)data);
	break;

	default:
		err("Unhandled/Unknown Notification: [0x%x]", command);
	break;
	}

	return TRUE;
}

