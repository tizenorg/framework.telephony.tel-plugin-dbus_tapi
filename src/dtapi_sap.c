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

#include <tcore.h>
#include <plugin.h>

#include "generated-code.h"
#include "dtapi_common.h"

static gboolean on_sap_connect(TelephonySap *sap,
	GDBusMethodInvocation *invocation, gint req_max_size, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_sap_req_connect req;

	if (!check_access_control(invocation, AC_SAP, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_sap_req_connect));

	req.max_msg_size = (unsigned short)req_max_size;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sap, invocation,
		TREQ_SAP_REQ_CONNECT,
		&req, sizeof(struct treq_sap_req_connect));

	return TRUE;
}

static gboolean on_sap_disconnect(TelephonySap *sap,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SAP, "x"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sap, invocation,
		TREQ_SAP_REQ_DISCONNECT,
		NULL, 0);

	return TRUE;
}

static gboolean on_sap_get_status(TelephonySap *sap,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SAP, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sap, invocation,
		TREQ_SAP_REQ_STATUS,
		NULL, 0);

	return TRUE;
}

static gboolean on_sap_get_atr(TelephonySap *sap,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SAP, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sap, invocation,
		TREQ_SAP_REQ_ATR,
		NULL, 0);

	return TRUE;
}

static gboolean on_sap_transfer_apdu(TelephonySap *sap,
	GDBusMethodInvocation *invocation, GVariant *req_apdu, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_sap_transfer_apdu req;
	GVariantIter *iter = NULL;
	GVariant *inner_gv = NULL;
	guchar rt_i;
	int i = 0;

	dbg("Func Entrance");

	if (!check_access_control(invocation, AC_SAP, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_sap_transfer_apdu));

	inner_gv = g_variant_get_variant(req_apdu);

	g_variant_get(inner_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &rt_i)) {
		req.apdu_data[i] = rt_i;
		i++;
	}

	req.apdu_length = (unsigned int)i;
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);
	g_variant_unref(req_apdu);

	for (i = 0; i < (int)req.apdu_length; i++)
		dbg("apdu[%d][0x%02x]", i, req.apdu_data[i]);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sap, invocation,
		TREQ_SAP_TRANSFER_APDU,
		&req, sizeof(struct treq_sap_transfer_apdu));

	return TRUE;
}

static gboolean on_sap_set_protocol(TelephonySap *sap,
	GDBusMethodInvocation *invocation, gint protocol, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_sap_set_protocol req;

	if (!check_access_control(invocation, AC_SAP, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_sap_set_protocol));

	req.protocol = protocol;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sap, invocation,
		TREQ_SAP_SET_PROTOCOL,
		&req, sizeof(struct treq_sap_set_protocol));

	return TRUE;
}

static gboolean on_sap_set_power(TelephonySap *sap,
	GDBusMethodInvocation *invocation, gint mode, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_sap_set_power req;

	if (!check_access_control(invocation, AC_SAP, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_sap_set_power));

	req.mode = mode;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sap, invocation,
		TREQ_SAP_SET_POWER,
		&req, sizeof(struct treq_sap_set_power));

	return TRUE;
}

static gboolean on_sap_get_card_reader_status(TelephonySap *sap,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SAP, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sap, invocation,
		TREQ_SAP_REQ_CARDREADERSTATUS,
		NULL, 0);

	return TRUE;
}

gboolean dbus_plugin_setup_sap_interface(TelephonyObjectSkeleton *object,
	struct custom_data *ctx)
{
	TelephonySap *sap;

	sap = telephony_sap_skeleton_new();
	telephony_object_skeleton_set_sap(object, sap);
	g_object_unref(sap);

	dbg("sap = %p", sap);

	/*
	 * Register signal handlers for SAP interface
	 */
	g_signal_connect(sap,
		"handle-connect",
		G_CALLBACK(on_sap_connect), ctx);

	g_signal_connect(sap,
		"handle-disconnect",
		G_CALLBACK(on_sap_disconnect), ctx);

	g_signal_connect(sap,
		"handle-get-status",
		G_CALLBACK(on_sap_get_status), ctx);

	g_signal_connect(sap,
		"handle-get-atr",
		G_CALLBACK(on_sap_get_atr), ctx);

	g_signal_connect(sap,
		"handle-transfer-apdu",
		G_CALLBACK(on_sap_transfer_apdu), ctx);

	g_signal_connect(sap,
		"handle-set-protocol",
		G_CALLBACK(on_sap_set_protocol), ctx);

	g_signal_connect(sap,
		"handle-set-power",
		G_CALLBACK(on_sap_set_power), ctx);

	g_signal_connect(sap,
		"handle-get-card-reader-status",
		G_CALLBACK(on_sap_get_card_reader_status), ctx);

	return TRUE;
}

gboolean dbus_plugin_sap_response(struct custom_data *ctx,
	UserRequest *ur, struct dbus_request_info *dbus_info,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	switch (command) {
	case TRESP_SAP_REQ_CONNECT: {
		const struct tresp_sap_req_connect *sap_conn = data;

		dbg("dbus comm - TRESP_SAP_REQ_CONNECT");

		telephony_sap_complete_connect(dbus_info->interface_object,
			dbus_info->invocation, sap_conn->status,
			sap_conn->max_msg_size);
	}
	break;

	case TRESP_SAP_REQ_DISCONNECT: {
		const struct tresp_sap_req_disconnect *sap_disconn = data;

		dbg("dbus comm - TRESP_SAP_REQ_DISCONNECT");

		telephony_sap_complete_disconnect(dbus_info->interface_object,
			dbus_info->invocation, sap_disconn->result);
	}
	break;

	case TRESP_SAP_REQ_STATUS: {
		const struct tresp_sap_req_status *sap_status = data;

		dbg("dbus comm - TRESP_SAP_REQ_STATUS");

		telephony_sap_complete_get_status(dbus_info->interface_object,
			dbus_info->invocation, sap_status->status);
	}
	break;

	case TRESP_SAP_REQ_ATR: {
		const struct tresp_sap_req_atr *sap_atr = data;
		GVariantBuilder builder;
		GVariant * atr_gv = NULL;
		GVariant *inner_gv = NULL;
		int i = 0;

		dbg("dbus comm - TRESP_SAP_REQ_ATR");

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < (int)sap_atr->atr_length; i++) {
			dbg("sap_atr->atr[%d][0x%02x]", i, sap_atr->atr[i]);
			g_variant_builder_add(&builder, "y", sap_atr->atr[i]);
		}
		inner_gv = g_variant_builder_end(&builder);
		atr_gv = g_variant_new("v", inner_gv);

		telephony_sap_complete_get_atr(dbus_info->interface_object,
			dbus_info->invocation, sap_atr->result,
			atr_gv);
	}
	break;

	case TRESP_SAP_TRANSFER_APDU: {
		const struct tresp_sap_transfer_apdu *sap_apdu = data;
		GVariantBuilder builder;
		GVariant * apdu_gv = NULL;
		GVariant *inner_gv = NULL;
		int i = 0;

		dbg("dbus comm - TRESP_SAP_TRANSFER_APDU");

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < (int)sap_apdu->resp_apdu_length; i++) {
			dbg("sap_apdu->resp_adpdu[%d][0x%02x]", i, sap_apdu->resp_adpdu[i]);
			g_variant_builder_add(&builder, "y", sap_apdu->resp_adpdu[i]);
		}
		inner_gv = g_variant_builder_end(&builder);
		apdu_gv = g_variant_new("v", inner_gv);

		telephony_sap_complete_transfer_apdu(dbus_info->interface_object,
			dbus_info->invocation, sap_apdu->result,
			apdu_gv);
	}
	break;

	case TRESP_SAP_SET_PROTOCOL: {
		const struct tresp_sap_set_protocol *sap_protocol = data;

		dbg("dbus comm - TRESP_SAP_SET_PROTOCOL");

		telephony_sap_complete_set_protocol(dbus_info->interface_object,
			dbus_info->invocation, sap_protocol->result);
	}
	break;

	case TRESP_SAP_SET_POWER: {
		const struct tresp_sap_set_power *sap_power = data;

		dbg("dbus comm - TRESP_SAP_SET_POWER");

		telephony_sap_complete_set_power(dbus_info->interface_object,
			dbus_info->invocation, sap_power->result);
	}
	break;

	case TRESP_SAP_REQ_CARDREADERSTATUS: {
		const struct tresp_sap_req_cardreaderstatus *sap_reader = data;

		dbg("dbus comm - TRESP_SAP_REQ_CARDREADERSTATUS");

		telephony_sap_complete_get_card_reader_status(dbus_info->interface_object,
			dbus_info->invocation, sap_reader->result,
			sap_reader->reader_status);
	}
	break;

	default:
		err("Unhandled/Unknown Response: [0x%x]", command);
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_sap_notification(struct custom_data *ctx,
	CoreObject *source, TelephonyObjectSkeleton *object,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonySap *sap;

	if (!object) {
		err("object is NULL");
		return FALSE;
	}

	sap = telephony_object_peek_sap(TELEPHONY_OBJECT(object));
	if (sap == NULL) {
		err("sap object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_SAP_STATUS: {
		const struct tnoti_sap_status_changed *sap_status = data;

		dbg("notified sap_status[%d]", sap_status->status);

		telephony_sap_emit_status(sap, sap_status->status);
	}
	break;

	case TNOTI_SAP_DISCONNECT: {
		const struct tnoti_sap_disconnect *sap_disconn = data;

		dbg("notified sap_disconnect type[%d]", sap_disconn->type);

		telephony_sap_emit_disconnect(sap, sap_disconn->type);
	}
	break;

	default:
		err("Unhandled/Unknown Notification: [0x%x]", command);
	break;
	}

	return TRUE;
}
