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
#include <stdlib.h>
#include <errno.h>
#include <glib-object.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <hal.h>
#include <communicator.h>
#include <core_object.h>
#include <queue.h>
#include <user_request.h>
#include <util.h>
#include <co_sap.h>
#include <co_sim.h>

#include "generated-code.h"
#include "common.h"

static gboolean on_sap_connect(TelephonySap *sap, GDBusMethodInvocation *invocation,
		gint arg_req_max_size, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_sap_req_connect req_conn;

	if (check_access_control(invocation, AC_SAP, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sap, invocation);
	memset(&req_conn, 0, sizeof(struct treq_sap_req_connect));

	req_conn.max_msg_size = (unsigned short)arg_req_max_size;

	tcore_user_request_set_data(ur, sizeof(struct treq_sap_req_connect), &req_conn);
	tcore_user_request_set_command(ur, TREQ_SAP_REQ_CONNECT);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_sap_complete_connect(sap, invocation, SAP_CONNECTION_STATUS_UNABLE_TO_ESTABLISH, 0);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sap_disconnect(TelephonySap *sap, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_SAP, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sap, invocation);

	tcore_user_request_set_command(ur, TREQ_SAP_REQ_DISCONNECT);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_sap_complete_disconnect(sap, invocation, SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sap_get_status(TelephonySap *sap, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_SAP, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sap, invocation);

	tcore_user_request_set_command(ur, TREQ_SAP_REQ_STATUS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_sap_complete_get_status(sap, invocation, SAP_STATUS_UNKNOWN);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sap_get_atr(TelephonySap *sap, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_SAP, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sap, invocation);

	tcore_user_request_set_command(ur, TREQ_SAP_REQ_ATR);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		GVariantBuilder *builder = NULL;
		GVariant * atr_gv = NULL;
		GVariant *inner_gv = NULL;
		builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
		inner_gv = g_variant_builder_end(builder);
		atr_gv = g_variant_new("v", inner_gv);

		telephony_sap_complete_get_atr(sap, invocation,	SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE, atr_gv);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sap_transfer_apdu(TelephonySap *sap, GDBusMethodInvocation *invocation,
		GVariant *arg_req_apdu, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	struct treq_sap_transfer_apdu t_apdu;
	TReturn ret;
	GVariantIter *iter = NULL;
	GVariant *inner_gv = NULL;
	guchar rt_i;
	int i =0;

	if (check_access_control(invocation, AC_SAP, "x") == FALSE)
		return FALSE;

	dbg("Func Entrance");
	memset(&t_apdu, 0, sizeof(struct treq_sap_transfer_apdu));

	inner_gv = g_variant_get_variant(arg_req_apdu);

	g_variant_get(inner_gv, "ay", &iter);
	while ( g_variant_iter_loop (iter, "y", &rt_i)) {
		t_apdu.apdu_data[i] = rt_i;
		i++;
	}
	t_apdu.apdu_length = (unsigned int)i;
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);
	g_variant_unref(arg_req_apdu);

	for(i=0; i < (int)t_apdu.apdu_length; i++)
		dbg("apdu[%d][0x%02x]",i, t_apdu.apdu_data[i]);

	ur = MAKE_UR(ctx, sap, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sap_transfer_apdu), &t_apdu);
	tcore_user_request_set_command(ur, TREQ_SAP_TRANSFER_APDU);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		GVariantBuilder *builder = NULL;
		GVariant * apdu_gv = NULL;
		GVariant *in_gv = NULL;
		builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
		in_gv = g_variant_builder_end(builder);
		apdu_gv = g_variant_new("v", in_gv);

		telephony_sap_complete_transfer_apdu(sap, invocation, SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE, apdu_gv);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sap_set_protocol(TelephonySap *sap, GDBusMethodInvocation *invocation,
		gint arg_protocol, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_sap_set_protocol set_protocol;

	if (check_access_control(invocation, AC_SAP, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sap, invocation);
	memset(&set_protocol, 0, sizeof(struct treq_sap_set_protocol));

	set_protocol.protocol = arg_protocol;

	tcore_user_request_set_data(ur, sizeof(struct treq_sap_set_protocol), &set_protocol);
	tcore_user_request_set_command(ur, TREQ_SAP_SET_PROTOCOL);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_sap_complete_set_protocol(sap, invocation, SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sap_set_power(TelephonySap *sap, GDBusMethodInvocation *invocation,
		gint arg_mode, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_sap_set_power set_power;

	if (check_access_control(invocation, AC_SAP, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sap, invocation);
	memset(&set_power, 0, sizeof(struct treq_sap_set_power));

	set_power.mode = arg_mode;

	tcore_user_request_set_data(ur, sizeof(struct treq_sap_set_power), &set_power);
	tcore_user_request_set_command(ur, TREQ_SAP_SET_POWER);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_sap_complete_set_power(sap, invocation, SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sap_get_card_reader_status(TelephonySap *sap, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_SAP, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sap, invocation);

	tcore_user_request_set_command(ur, TREQ_SAP_REQ_CARDREADERSTATUS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_sap_complete_get_card_reader_status(sap, invocation, SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE, 0);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_sap_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonySap *sap;

	sap = telephony_sap_skeleton_new();
	telephony_object_skeleton_set_sap(object, sap);
	g_object_unref(sap);

	dbg("sap = %p", sap);

	g_signal_connect (sap,
			"handle-connect",
			G_CALLBACK (on_sap_connect),
			ctx);

	g_signal_connect (sap,
			"handle-disconnect",
			G_CALLBACK (on_sap_disconnect),
			ctx);

	g_signal_connect (sap,
			"handle-get-status",
			G_CALLBACK (on_sap_get_status),
			ctx);

	g_signal_connect (sap,
			"handle-get-atr",
			G_CALLBACK (on_sap_get_atr),
			ctx);

	g_signal_connect (sap,
			"handle-transfer-apdu",
			G_CALLBACK (on_sap_transfer_apdu),
			ctx);

	g_signal_connect (sap,
			"handle-set-protocol",
			G_CALLBACK (on_sap_set_protocol),
			ctx);

	g_signal_connect (sap,
			"handle-set-power",
			G_CALLBACK (on_sap_set_power),
			ctx);

	g_signal_connect (sap,
			"handle-get-card-reader-status",
			G_CALLBACK (on_sap_get_card_reader_status),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_sap_response(struct custom_data *ctx, UserRequest *ur,
		struct dbus_request_info *dbus_info, enum tcore_response_command command,
		unsigned int data_len, const void *data)
{
	const struct tresp_sap_req_connect *sap_conn = data;
	const struct tresp_sap_req_disconnect *sap_disconn = data;
	const struct tresp_sap_req_status *sap_status = data;
	const struct tresp_sap_req_atr *sap_atr = data;
	const struct tresp_sap_transfer_apdu *sap_apdu = data;
	const struct tresp_sap_set_protocol *sap_protocol = data;
	const struct tresp_sap_set_power *sap_power = data;
	const struct tresp_sap_req_cardreaderstatus *sap_reader = data;

	dbg("application Command = [0x%x], data_len = %d",command, data_len);

	switch (command) {
		case TRESP_SAP_REQ_CONNECT:
			dbg("dbus comm - TRESP_SAP_REQ_CONNECT");
			telephony_sap_complete_connect(dbus_info->interface_object, dbus_info->invocation,
					sap_conn->status, sap_conn->max_msg_size);
			break;

		case TRESP_SAP_REQ_DISCONNECT:
			dbg("dbus comm - TRESP_SAP_REQ_DISCONNECT");
			telephony_sap_complete_disconnect(dbus_info->interface_object, dbus_info->invocation,
					sap_disconn->result);
			break;

		case TRESP_SAP_REQ_STATUS:
			dbg("dbus comm - TRESP_SAP_REQ_STATUS");
			telephony_sap_complete_get_status(dbus_info->interface_object, dbus_info->invocation,
					sap_status->status);
			break;

		case TRESP_SAP_REQ_ATR: {
			GVariantBuilder *builder = NULL;
			GVariant * atr_gv = NULL;
			GVariant *inner_gv = NULL;
			int i =0;

			dbg("dbus comm - TRESP_SAP_REQ_ATR");
			builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
			for(i = 0; i < (int)sap_atr->atr_length; i++) {
				dbg("sap_atr->atr[%d][0x%02x]", i,sap_atr->atr[i]);
				g_variant_builder_add (builder, "y", sap_atr->atr[i]);
			}
			inner_gv = g_variant_builder_end(builder);
/*			g_variant_builder_unref (builder);*/
			atr_gv = g_variant_new("v", inner_gv);

			telephony_sap_complete_get_atr(dbus_info->interface_object, dbus_info->invocation,
					sap_atr->result, atr_gv);
		}
			break;

		case TRESP_SAP_TRANSFER_APDU: {
			GVariantBuilder *builder = NULL;
			GVariant * apdu_gv = NULL;
			GVariant *inner_gv = NULL;
			int i =0;

			dbg("dbus comm - TRESP_SAP_TRANSFER_APDU");
			builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
			for(i = 0; i < (int)sap_apdu->resp_apdu_length; i++) {
				dbg("sap_apdu->resp_adpdu[%d][0x%02x]", i,sap_apdu->resp_adpdu[i]);
				g_variant_builder_add (builder, "y", sap_apdu->resp_adpdu[i]);
			}
			inner_gv = g_variant_builder_end(builder);
/*			g_variant_builder_unref (builder);*/
			apdu_gv = g_variant_new("v", inner_gv);

			telephony_sap_complete_transfer_apdu(dbus_info->interface_object, dbus_info->invocation,
					sap_apdu->result, apdu_gv);
		}
			break;

		case TRESP_SAP_SET_PROTOCOL:
			dbg("dbus comm - TRESP_SAP_SET_PROTOCOL");
			telephony_sap_complete_set_protocol(dbus_info->interface_object, dbus_info->invocation,
					sap_protocol->result);
			break;

		case TRESP_SAP_SET_POWER:
			dbg("dbus comm - TRESP_SAP_SET_POWER");
			telephony_sap_complete_set_power(dbus_info->interface_object, dbus_info->invocation,
					sap_power->result);
			break;

		case TRESP_SAP_REQ_CARDREADERSTATUS:
			dbg("dbus comm - TRESP_SAP_REQ_CARDREADERSTATUS");
			telephony_sap_complete_get_card_reader_status(dbus_info->interface_object, dbus_info->invocation,
					sap_reader->result, sap_reader->reader_status);
			break;

		default:
			dbg("not handled command[%d]", command);
		break;
	}

	return TRUE;
}

gboolean dbus_plugin_sap_notification(struct custom_data *ctx, const char *plugin_name,
		TelephonyObjectSkeleton *object, enum tcore_notification_command command,
		unsigned int data_len, const void *data)
{
	TelephonySap *sap;
	const struct tnoti_sap_status_changed *n_sap_status = data;
	const struct tnoti_sap_disconnect *n_sap_disconn = data;

	if (!object) {
		dbg("object is NULL");
		return FALSE;
	}

	sap = telephony_object_peek_sap(TELEPHONY_OBJECT(object));
	dbg("sap = %p", sap);

	dbg("notification !!! (command = 0x%x, data_len = %d)", command, data_len);

	switch (command) {
		case TNOTI_SAP_STATUS:
			dbg("notified sap_status[%d]", n_sap_status->status);
			telephony_sap_emit_status(sap, n_sap_status->status);
			break;
		case TNOTI_SAP_DISCONNECT:
			dbg("notified sap_disconnect type[%d]", n_sap_disconn->type);
			telephony_sap_emit_disconnect(sap, n_sap_disconn->type);
			break;
		default:
			dbg("not handled command[%d]", command);
		break;
	}

	return TRUE;
}
