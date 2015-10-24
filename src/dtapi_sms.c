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
#include <server.h>
#include <plugin.h>
#include <co_sms.h>

#include "generated-code.h"
#include "dtapi_common.h"

static gboolean on_sms_send_msg(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint format, GVariant *sca,
	gint tpdu_length, GVariant *tpdu_data,
	gint more_msg, gpointer user_data)
{
	struct treq_sms_send_msg req;
	struct custom_data *ctx = user_data;
	enum tcore_request_command command;

	int i = 0;
	GVariantIter *iter = NULL;
	GVariant *inner_gv = NULL;

	if (!check_access_control(invocation, AC_SMS, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_sms_send_msg));

	if (SMS_NETTYPE_3GPP == format) {
		command =  TREQ_SMS_SEND_UMTS_MSG;
	} else if (SMS_NETTYPE_3GPP2 == format) {
		command = TREQ_SMS_SEND_CDMA_MSG;
	} else {
		err("Invalid Format Received:[%d]", format);

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	}

	inner_gv = g_variant_get_variant(sca);
	g_variant_get(inner_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &req.msgDataPackage.sca[i])) {
		i++;
		if (i >= SMS_SMSP_ADDRESS_LEN)
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	req.msgDataPackage.msgLength = tpdu_length;

	i = 0;
	inner_gv = g_variant_get_variant(tpdu_data);
	g_variant_get(inner_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &req.msgDataPackage.tpduData[i])) {
		i++;
		if (i >= SMS_SMDATA_SIZE_MAX + 1)
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	req.msgDataPackage.format = format;
	req.more = more_msg;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		command,
		&req, sizeof(struct treq_sms_send_msg));

	return  TRUE;
}

static gboolean on_sms_read_msg(TelephonySms *sms,
	GDBusMethodInvocation *invocation, gint msg_index, gpointer user_data)
{
	struct treq_sms_read_msg req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "r"))
		return TRUE;

	req.index = msg_index;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_READ_MSG,
		&req, sizeof(struct treq_sms_read_msg));

	return TRUE;
}

static gboolean on_sms_save_msg(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint format, gint msg_status, GVariant *sca,
	gint tpdu_length, GVariant *tpdu_data, gpointer user_data)
{
	struct treq_sms_save_msg req;
	struct custom_data *ctx = user_data;

	int i = 0;
	GVariantIter *iter = NULL;
	GVariant *inner_gv = NULL;

	if (!check_access_control(invocation, AC_SMS, "w"))
		return TRUE;

	if (SMS_NETTYPE_3GPP == format) {
		req.msgDataPackage.format = SMS_NETTYPE_3GPP;
	} else if (SMS_NETTYPE_3GPP2 == format) {
		req.msgDataPackage.format = SMS_NETTYPE_3GPP2;
	} else {
		err("Invalid Format Received:[%d]", format);

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	}

	req.simIndex = 0xffff;
	req.msgStatus = msg_status;

	inner_gv = g_variant_get_variant(sca);
	g_variant_get(inner_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &req.msgDataPackage.sca[i])) {
		i++;
		if (i >= SMS_SMSP_ADDRESS_LEN)
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	i = 0;
	inner_gv = g_variant_get_variant(tpdu_data);
	g_variant_get(inner_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &req.msgDataPackage.tpduData[i])) {
		i++;
		if (i >= SMS_SMDATA_SIZE_MAX + 1)
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	req.msgDataPackage.msgLength = tpdu_length;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_SAVE_MSG,
		&req, sizeof(struct treq_sms_save_msg));

	return TRUE;
}

static gboolean on_sms_delete_msg(TelephonySms *sms,
	GDBusMethodInvocation *invocation, gint msg_index, gpointer user_data)
{
	struct treq_sms_delete_msg req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "x"))
		return TRUE;

	req.index = msg_index;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_DELETE_MSG,
		&req, sizeof(struct treq_sms_delete_msg));

	return TRUE;
}

static gboolean on_sms_get_msg_count(TelephonySms *sms,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_GET_COUNT,
		NULL, 0);

	return TRUE;
}

static gboolean on_sms_get_sca(TelephonySms *sms,
	GDBusMethodInvocation *invocation, gint msg_index, gpointer user_data)
{
	struct treq_sms_get_sca req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "r"))
		return TRUE;

	req.index = msg_index;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_GET_SCA,
		&req, sizeof(struct treq_sms_get_sca));

	return TRUE;
}

static gboolean on_sms_set_sca(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint msg_index,
	gint sca_ton, gint sca_npi, gint sca_length, GVariant *sca,
	gpointer user_data)
{
	if (!check_access_control(invocation, AC_SMS, "w"))
		return TRUE;

	if ((sca_length <= 0)
			|| (sca_length > (SMS_MAX_SMS_SERVICE_CENTER_ADDR + 1))) {
		err("[tcore_SMS] TAPI_API_INVALID_INPUT !!!");

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
	} else if (msg_index != 0) {
		err("[tcore_SMS] Index except 0 is supported");

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
	} else {
		struct treq_sms_set_sca req;
		struct custom_data *ctx = user_data;

		int i = 0;
		GVariantIter *iter = NULL;
		GVariant *inner_gv = NULL;

		memset(&req, 0, sizeof(struct treq_sms_set_sca));

		req.index = msg_index;
		req.scaInfo.dialNumLen = sca_length;
		req.scaInfo.typeOfNum = sca_ton;
		req.scaInfo.numPlanId = sca_npi;

		inner_gv = g_variant_get_variant(sca);
		g_variant_get(inner_gv, "ay", &iter);
		while (g_variant_iter_loop(iter, "y", &req.scaInfo.diallingNum[i])) {
			i++;
			if (i >= SMS_SMSP_ADDRESS_LEN + 1)
				break;
		}

		g_variant_iter_free(iter);
		g_variant_unref(inner_gv);

		/* Dispatch request */
		dtapi_dispatch_request(ctx, sms, invocation,
			TREQ_SMS_SET_SCA,
			&req, sizeof(struct treq_sms_set_sca));
	}

	return TRUE;
}

static gboolean on_sms_get_cb_config(TelephonySms *sms,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_GET_CB_CONFIG,
		NULL, 0);

	return TRUE;
}

static gboolean on_sms_set_cb_config(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint network_type, gboolean enable_cb,
	gint msg_id_max_cnt, gint msg_id_range_cnt,
	GVariant *arg_mdgId, gpointer user_data)
{
	struct treq_sms_set_cb_config req;
	struct custom_data *ctx = user_data;

	GVariant *value = NULL;
	GVariant *inner_gv = NULL;
	GVariantIter *iter = NULL;
	GVariantIter *iter_row = NULL;
	const gchar *key = NULL;
	int i = 0;

	if (!check_access_control(invocation, AC_SMS, "w"))
		return TRUE;

	req.net3gppType = network_type;
	req.cbEnabled = enable_cb;
	req.msgIdMaxCount = msg_id_max_cnt;
	req.msgIdRangeCount = msg_id_range_cnt;

	inner_gv = g_variant_get_variant(arg_mdgId);
	g_variant_get(inner_gv, "aa{sv}", &iter);
	while (g_variant_iter_next(iter, "a{sv}", &iter_row)) {
		while (g_variant_iter_loop(iter_row, "{sv}", &key, &value)) {
			if (!g_strcmp0(key, "FromMsgId"))
				req.msgIDs[i].net3gpp.fromMsgId = g_variant_get_uint16(value);
			else if (!g_strcmp0(key, "ToMsgId"))
				req.msgIDs[i].net3gpp.toMsgId = g_variant_get_uint16(value);
			else if (!g_strcmp0(key, "CBCategory"))
				req.msgIDs[i].net3gpp2.cbCategory = g_variant_get_uint16(value);
			else if (!g_strcmp0(key, "CBLanguage"))
				req.msgIDs[i].net3gpp2.cbLanguage = g_variant_get_uint16(value);
			else if (!g_strcmp0(key, "Selected"))
				req.msgIDs[i].net3gpp2.selected = g_variant_get_byte(value);
		}
		g_variant_iter_free(iter_row);

		i++;
		if (i >= SMS_GSM_SMS_CBMI_LIST_SIZE_MAX)
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_SET_CB_CONFIG,
		&req, sizeof(struct treq_sms_set_cb_config));

	return TRUE;
}

static gboolean on_sms_set_mem_status(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint memory_status, gpointer user_data)
{
	struct treq_sms_set_mem_status req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "w"))
		return TRUE;

	req.memory_status = memory_status;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_SET_MEM_STATUS,
		&req, sizeof(struct treq_sms_set_mem_status));

	return TRUE;
}

static gboolean on_sms_get_pref_bearer(TelephonySms *sms,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_GET_PREF_BEARER,
		NULL, 0);

	return TRUE;
}

static gboolean on_sms_set_pref_bearer(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint bearer_type, gpointer user_data)
{
	struct treq_sms_set_pref_bearer req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "w"))
		return TRUE;

	req.svc = bearer_type;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_SET_PREF_BEARER,
		&req, sizeof(struct treq_sms_set_pref_bearer));

	return TRUE;
}

static gboolean on_sms_set_delivery_report(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint format, const gchar *sca,
	gint tpdu_length, const gchar *tpdu_data,
	gint rp_cause, gpointer user_data)
{
	struct treq_sms_set_delivery_report req;
	struct custom_data *ctx = user_data;

	guchar *decoded_sca = NULL;
	guchar *decoded_tpdu = NULL;

	gsize decoded_sca_len = 0;
	gsize decoded_tpdu_len = 0;

	if (!check_access_control(invocation, AC_SMS, "w"))
		return TRUE;

	memset(&req, 0, sizeof(struct treq_sms_set_delivery_report));

	if (SMS_NETTYPE_3GPP == format) {
		req.dataInfo.format = SMS_NETTYPE_3GPP;
	} else if (SMS_NETTYPE_3GPP2 == format) {
		req.dataInfo.format = SMS_NETTYPE_3GPP2;
	} else {
		err("Invalid Format Received:[%d]", format);

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	}

	decoded_sca = g_base64_decode(sca, &decoded_sca_len);
	if (NULL == decoded_sca) {
		warn("g_base64_decode: Failed to decode sca");

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	} else if (decoded_sca_len > SMS_SMSP_ADDRESS_LEN) {
		err("Invalid Sca length");

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		goto EXIT;
	}
	memcpy(req.dataInfo.sca, decoded_sca, decoded_sca_len);

	decoded_tpdu = g_base64_decode(tpdu_data, &decoded_tpdu_len);
	if (NULL == decoded_tpdu) {
		warn("g_base64_decode: Failed to decode tpdu");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		goto EXIT;
	} else if (decoded_tpdu_len > SMS_SMDATA_SIZE_MAX+1) {
		err("Invalid tpdu length");

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		goto EXIT;
	}
	memcpy(req.dataInfo.tpduData, decoded_tpdu, decoded_tpdu_len);

	info("[%s] Decoded SCA len: [%d] TPDU len: [%d]", GET_CP_NAME(invocation),
		decoded_sca_len, decoded_tpdu_len);

	req.dataInfo.msgLength = tpdu_length;
	req.rspType = rp_cause;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_SET_DELIVERY_REPORT,
		&req, sizeof(struct treq_sms_set_delivery_report));

EXIT:
	g_free(decoded_sca);
	g_free(decoded_tpdu);

	return TRUE;
}

static gboolean on_sms_set_msg_status(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint msg_index, gint msg_status, gpointer user_data)
{
	struct treq_sms_set_msg_status req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "w"))
		return TRUE;

	req.index = msg_index;
	req.msgStatus = msg_status;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_SET_MSG_STATUS,
		&req, sizeof(struct treq_sms_set_msg_status));

	return TRUE;
}

static gboolean on_sms_get_sms_params(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint msg_index, gpointer user_data)
{
	struct treq_sms_get_params req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "r"))
		return TRUE;

	req.index = msg_index;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_GET_PARAMS,
		&req, sizeof(struct treq_sms_get_params));

	return TRUE;
}

static gboolean on_sms_set_sms_params(TelephonySms *sms,
	GDBusMethodInvocation *invocation,
	gint record_index, gint record_len,
	gint alpha_id_len, GVariant *alpha_id,
	gint param_indicator,
	gint dial_num_len, gint dial_num_ton, gint dial_num_npi, GVariant *dial_num,
	gint sca_len, gint sca_ton, gint sca_npi, GVariant *sca,
	gint protocol_id, gint dcs, gint validity_period,
	gpointer user_data)
{
	struct treq_sms_set_params req;
	struct custom_data *ctx = user_data;

	int i = 0;
	GVariantIter *iter = NULL;
	GVariant *inner_gv = NULL;

	if (!check_access_control(invocation, AC_SMS, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_sms_set_params));

	req.params.recordIndex = record_index;
	req.params.recordLen = record_len;
	req.params.alphaIdLen = alpha_id_len;

	inner_gv = g_variant_get_variant(alpha_id);
	g_variant_get(inner_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &req.params.szAlphaId[i])) {
		i++;
		if (i >= SMS_SMSP_ALPHA_ID_LEN_MAX + 1)
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	req.params.paramIndicator = param_indicator;
	req.params.tpDestAddr.dialNumLen = dial_num_len;
	req.params.tpDestAddr.typeOfNum = dial_num_ton;
	req.params.tpDestAddr.numPlanId = dial_num_npi;

	i = 0;
	inner_gv = g_variant_get_variant(dial_num);
	g_variant_get(inner_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &req.params.tpDestAddr.diallingNum[i])) {
		i++;
		if (i >= SMS_SMSP_ADDRESS_LEN + 1)
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	req.params.tpSvcCntrAddr.dialNumLen = sca_len;
	req.params.tpSvcCntrAddr.typeOfNum = sca_ton;
	req.params.tpSvcCntrAddr.numPlanId = sca_npi;

	i = 0;
	inner_gv = g_variant_get_variant(sca);
	g_variant_get(inner_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &req.params.tpSvcCntrAddr.diallingNum[i])) {
		i++;
		if (i >= SMS_SMSP_ADDRESS_LEN + 1)
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	req.params.tpProtocolId = protocol_id;
	req.params.tpDataCodingScheme = dcs;
	req.params.tpValidityPeriod = validity_period;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_SET_PARAMS,
		&req, sizeof(struct treq_sms_set_params));

	return TRUE;
}

static gboolean on_sms_get_sms_param_cnt(TelephonySms *sms,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SMS, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sms, invocation,
		TREQ_SMS_GET_PARAMCNT,
		NULL, 0);

	return TRUE;
}

static gboolean on_sms_get_sms_ready_status(TelephonySms *sms,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sms = NULL;
	TcorePlugin *plugin = NULL;
	gboolean ready_status = FALSE;

	if (!check_access_control(invocation, AC_SMS, "r"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	co_sms = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SMS);
	if (!co_sms) {
		err("co_sms is NULL");

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	}

	ready_status = tcore_sms_get_ready_status(co_sms);
	dbg("[%s] ready_status = %d", GET_CP_NAME(invocation), ready_status);

	telephony_sms_complete_get_sms_ready_status(sms, invocation, ready_status);

	return TRUE;
}

gboolean dbus_plugin_setup_sms_interface(TelephonyObjectSkeleton *object,
	struct custom_data *ctx)
{
	TelephonySms *sms;

	sms = telephony_sms_skeleton_new();
	telephony_object_skeleton_set_sms(object, sms);
	g_object_unref(sms);

	dbg("sms = %p", sms);

	/*
	 * Register signal handlers for SMS interface
	 */
	g_signal_connect(sms,
		"handle-send-msg",
		G_CALLBACK(on_sms_send_msg), ctx);

	g_signal_connect(sms,
		"handle-read-msg",
		G_CALLBACK(on_sms_read_msg), ctx);

	g_signal_connect(sms,
		"handle-save-msg",
		G_CALLBACK(on_sms_save_msg), ctx);

	g_signal_connect(sms,
		"handle-delete-msg",
		G_CALLBACK(on_sms_delete_msg), ctx);

	g_signal_connect(sms,
		"handle-get-msg-count",
		G_CALLBACK(on_sms_get_msg_count), ctx);

	g_signal_connect(sms,
		"handle-get-sca",
		G_CALLBACK(on_sms_get_sca), ctx);

	g_signal_connect(sms,
		"handle-set-sca",
		G_CALLBACK(on_sms_set_sca), ctx);

	g_signal_connect(sms,
		"handle-get-cb-config",
		G_CALLBACK(on_sms_get_cb_config), ctx);

	g_signal_connect(sms,
		"handle-set-cb-config",
		G_CALLBACK(on_sms_set_cb_config), ctx);

	g_signal_connect(sms,
		"handle-set-mem-status",
		G_CALLBACK(on_sms_set_mem_status), ctx);

	g_signal_connect(sms,
		"handle-get-pref-bearer",
		G_CALLBACK(on_sms_get_pref_bearer), ctx);

	g_signal_connect(sms,
		"handle-set-pref-bearer",
		G_CALLBACK(on_sms_set_pref_bearer), ctx);

	g_signal_connect(sms,
		"handle-set-delivery-report",
		G_CALLBACK(on_sms_set_delivery_report), ctx);

	g_signal_connect(sms,
		"handle-set-msg-status",
		G_CALLBACK(on_sms_set_msg_status), ctx);

	g_signal_connect(sms,
		"handle-get-sms-params",
		G_CALLBACK(on_sms_get_sms_params), ctx);

	g_signal_connect(sms,
		"handle-set-sms-params",
		G_CALLBACK(on_sms_set_sms_params), ctx);

	g_signal_connect(sms,
		"handle-get-sms-param-cnt",
		G_CALLBACK(on_sms_get_sms_param_cnt), ctx);

	g_signal_connect(sms,
		"handle-get-sms-ready-status",
		G_CALLBACK(on_sms_get_sms_ready_status), ctx);

	return TRUE;
}

gboolean dbus_plugin_sms_response(struct custom_data *ctx,
	UserRequest *ur, struct dbus_request_info *dbus_info,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	char *cpname = dbus_info ? GET_CP_NAME(dbus_info->invocation) : "";

	switch (command) {
	case TRESP_SMS_SEND_UMTS_MSG: {
		const struct tresp_sms_send_msg *resp = data;

		dbg("[%s] SEND_UMTS_MSG (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_send_msg(dbus_info->interface_object,
			dbus_info->invocation, resp->result);
	}
	break;

	case TRESP_SMS_SEND_CDMA_MSG: {
		const struct tresp_sms_send_msg *resp = data;

		dbg("[%s] SEND_CDMA_MSG (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_send_msg(dbus_info->interface_object,
			dbus_info->invocation, resp->result);
	}
	break;

	case TRESP_SMS_READ_MSG: {
		const struct tresp_sms_read_msg *resp = data;
		GVariant *sca = NULL, *packet_sca = NULL;
		GVariant *tpdu = NULL, *packet_tpdu = NULL;
		GVariantBuilder b;
		unsigned int i;

		dbg("[%s] READ_MSG (result:[0x%x])", cpname, resp->result);

		g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));
		for (i = 0; i < SMS_SMSP_ADDRESS_LEN; i++)
			g_variant_builder_add(&b, "y", resp->dataInfo.smsData.sca[i]);
		sca = g_variant_builder_end(&b);

		g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));
		for (i = 0; i < SMS_SMDATA_SIZE_MAX + 1; i++)
			g_variant_builder_add(&b, "y", resp->dataInfo.smsData.tpduData[i]);
		tpdu = g_variant_builder_end(&b);

		packet_sca = g_variant_new("v", sca);
		packet_tpdu = g_variant_new("v", tpdu);

		telephony_sms_complete_read_msg(dbus_info->interface_object,
			dbus_info->invocation, resp->result,
			resp->dataInfo.simIndex, resp->dataInfo.msgStatus,
			resp->dataInfo.smsData.format,
			packet_sca,
			resp->dataInfo.smsData.msgLength,
			packet_tpdu);
	}
	break;

	case TRESP_SMS_SAVE_MSG: {
		const struct tresp_sms_save_msg *resp = data;

		dbg("[%s] SAVE_MSG (index:[%d] result:[0x%x])", cpname, resp->index, resp->result);

		telephony_sms_complete_save_msg(dbus_info->interface_object,
			dbus_info->invocation, resp->result, resp->index);
	}
	break;

	case TRESP_SMS_DELETE_MSG: {
		const struct tresp_sms_delete_msg *resp = data;

		dbg("[%s] DELETE_MSG (index:[%d] result:[0x%x])", cpname, resp->index, resp->result);

		telephony_sms_complete_delete_msg(dbus_info->interface_object,
			dbus_info->invocation, resp->result, resp->index);
	}
	break;

	case TRESP_SMS_GET_STORED_MSG_COUNT: {
		const struct tresp_sms_get_storedMsgCnt *resp = data;
		GVariant *list;
		GVariantBuilder b;
		unsigned int i;

		dbg("[%s] GET_STORED_MSG_COUNT (result:[0x%x])", cpname, resp->result);

		g_variant_builder_init(&b, G_VARIANT_TYPE("ai"));
		for (i = 0; i < resp->storedMsgCnt.totalCount; i++)
			g_variant_builder_add(&b, "i", resp->storedMsgCnt.indexList[i]);
		list = g_variant_builder_end(&b);

		telephony_sms_complete_get_msg_count(dbus_info->interface_object,
			dbus_info->invocation, resp->result,
			resp->storedMsgCnt.totalCount,
			resp->storedMsgCnt.usedCount,
			list);
	}
	break;

	case TRESP_SMS_GET_SCA: {
		const struct tresp_sms_get_sca *resp = data;
		GVariant *sca = NULL, *packet_sca = NULL;
		GVariantBuilder b;
		unsigned int i;

		dbg("[%s] GET_SCA (result:[0x%x])", cpname, resp->result);

		g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));
		for (i = 0; i < SMS_SMSP_ADDRESS_LEN + 1; i++)
			g_variant_builder_add(&b, "y", resp->scaAddress.diallingNum[i]);
		sca = g_variant_builder_end(&b);

		packet_sca = g_variant_new("v", sca);

		telephony_sms_complete_get_sca(dbus_info->interface_object,
			dbus_info->invocation, resp->result,
			resp->scaAddress.typeOfNum,
			resp->scaAddress.numPlanId,
			resp->scaAddress.dialNumLen,
			packet_sca);
	}
	break;

	case TRESP_SMS_SET_SCA: {
		const struct tresp_sms_set_sca *resp = data;

		dbg("[%s] SET_SCA (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_set_sca(dbus_info->interface_object, dbus_info->invocation,
			resp->result);
	}
	break;

	case TRESP_SMS_GET_CB_CONFIG: {
		const struct tresp_sms_get_cb_config *resp = data;
		GVariant *result = NULL;
		GVariantBuilder b;
		int i;

		dbg("[%s] GET_CB_CONFIG (result:[0x%x])", cpname, resp->result);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->cbConfig.msgIdRangeCount; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

			if (resp->cbConfig.net3gppType == SMS_NETTYPE_3GPP) {
				g_variant_builder_add(&b, "{sv}", "FromMsgId",
					g_variant_new_uint16(resp->cbConfig.msgIDs[i].net3gpp.fromMsgId));
				g_variant_builder_add(&b, "{sv}", "ToMsgId",
					g_variant_new_uint16(resp->cbConfig.msgIDs[i].net3gpp.toMsgId));
			} else if (resp->cbConfig.net3gppType == SMS_NETTYPE_3GPP2) {
				g_variant_builder_add(&b, "{sv}", "CBCategory",
					g_variant_new_uint16(resp->cbConfig.msgIDs[i].net3gpp2.cbCategory));
				g_variant_builder_add(&b, "{sv}", "CBLanguage",
					g_variant_new_uint16(resp->cbConfig.msgIDs[i].net3gpp2.cbLanguage));
			} else {
				dbg("Unknown 3gpp type");
				return FALSE;
			}

			g_variant_builder_add(&b, "{sv}", "Selected",
				g_variant_new_byte(resp->cbConfig.msgIDs[i].net3gpp.selected));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_sms_complete_get_cb_config(dbus_info->interface_object,
			dbus_info->invocation, resp->result,
			resp->cbConfig.net3gppType,
			resp->cbConfig.cbEnabled,
			resp->cbConfig.msgIdMaxCount,
			resp->cbConfig.msgIdRangeCount,
			result);
	}
	break;

	case TRESP_SMS_SET_CB_CONFIG: {
		const struct tresp_sms_set_cb_config *resp = data;

		dbg("[%s] SET_CB_CONFIG (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_set_cb_config(dbus_info->interface_object,
			dbus_info->invocation, resp->result);
	}
	break;

	case TRESP_SMS_SET_MEM_STATUS: {
		const struct tresp_sms_set_mem_status *resp = data;

		dbg("[%s] SET_MEM_STATUS (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_set_mem_status(dbus_info->interface_object,
			dbus_info->invocation, resp->result);
	}
	break;

	case TRESP_SMS_GET_PREF_BEARER: {
		const struct tresp_sms_get_pref_bearer *resp = data;

		dbg("[%s] GET_PREF_BEARER (result:[0x%x] svc:[0x%2x])", cpname, resp->result, resp->svc);

		telephony_sms_complete_get_pref_bearer(dbus_info->interface_object,
			dbus_info->invocation, resp->result, resp->svc);
	}
	break;

	case TRESP_SMS_SET_PREF_BEARER: {
		const struct tresp_sms_set_pref_bearer *resp = data;

		dbg("[%s] SET_PREF_BEARER (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_set_pref_bearer(dbus_info->interface_object,
			dbus_info->invocation, resp->result);
	}
	break;

	case TRESP_SMS_SET_DELIVERY_REPORT: {
		const struct tresp_sms_set_delivery_report *resp = data;

		dbg("[%s] SET_DELIVERY_REPORT (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_set_delivery_report(dbus_info->interface_object,
			dbus_info->invocation, resp->result);
	}
	break;

	case TRESP_SMS_SET_MSG_STATUS: {
		const struct tresp_sms_set_mem_status *resp = data;

		dbg("[%s] SET_MSG_STATUS (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_set_msg_status(dbus_info->interface_object,
			dbus_info->invocation, resp->result);
	}
	break;

	case TRESP_SMS_GET_PARAMS: {
		const struct tresp_sms_get_params *resp = data;
		GVariant *alphaId = NULL, *packet_alphaId = NULL;
		GVariant *destDialNum = NULL, *packet_destDialNum = NULL;
		GVariant *scaDialNum = NULL, *packet_scaDialNum = NULL;
		GVariantBuilder b;
		unsigned int i;

		dbg("[%s] GET_PARAMS (result:[0x%x])", cpname, resp->result);

		g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));
		for (i = 0; i < SMS_SMSP_ALPHA_ID_LEN_MAX + 1; i++)
			g_variant_builder_add(&b, "y", resp->paramsInfo.szAlphaId[i]);
		alphaId = g_variant_builder_end(&b);

		g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));
		for (i = 0; i < SMS_SMSP_ADDRESS_LEN + 1; i++)
			g_variant_builder_add(&b, "y", resp->paramsInfo.tpDestAddr.diallingNum[i]);
		destDialNum = g_variant_builder_end(&b);

		g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));
		for (i = 0; i < SMS_SMSP_ADDRESS_LEN + 1; i++)
			g_variant_builder_add(&b, "y", resp->paramsInfo.tpSvcCntrAddr.diallingNum[i]);
		scaDialNum = g_variant_builder_end(&b);

		packet_alphaId = g_variant_new("v", alphaId);
		packet_destDialNum = g_variant_new("v", destDialNum);
		packet_scaDialNum = g_variant_new("v", scaDialNum);

		telephony_sms_complete_get_sms_params(dbus_info->interface_object,
			dbus_info->invocation, resp->result,
			resp->paramsInfo.recordIndex,
			resp->paramsInfo.recordLen,
			resp->paramsInfo.alphaIdLen,
			packet_alphaId,
			resp->paramsInfo.paramIndicator,
			resp->paramsInfo.tpDestAddr.dialNumLen,
			resp->paramsInfo.tpDestAddr.typeOfNum,
			resp->paramsInfo.tpDestAddr.numPlanId,
			packet_destDialNum,
			resp->paramsInfo.tpSvcCntrAddr.dialNumLen,
			resp->paramsInfo.tpSvcCntrAddr.typeOfNum,
			resp->paramsInfo.tpSvcCntrAddr.numPlanId,
			packet_scaDialNum,
			resp->paramsInfo.tpProtocolId,
			resp->paramsInfo.tpDataCodingScheme,
			resp->paramsInfo.tpValidityPeriod);
	}
	break;

	case TRESP_SMS_SET_PARAMS:{
		const struct tresp_sms_set_params *resp = data;

		dbg("[%s] SET_PARAMS (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_set_sms_params(dbus_info->interface_object,
			dbus_info->invocation, resp->result);
	}
	break;

	case TRESP_SMS_GET_PARAMCNT: {
		const struct tresp_sms_get_paramcnt *resp = data;

		dbg("[%s] GET_PARAMCNT (result:[0x%x])", cpname, resp->result);

		telephony_sms_complete_get_sms_param_cnt(dbus_info->interface_object,
			dbus_info->invocation, resp->result, resp->recordCount);
	}
	break;

	default:
		err("Unhandled/Unknown Response: [0x%x]", command);
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_sms_notification(struct custom_data *ctx,
	CoreObject *source, TelephonyObjectSkeleton *object,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonySms *sms;
	const char *cp_name;

	if (!object) {
		warn("object is NULL");
		return FALSE;
	}

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	sms = telephony_object_peek_sms(TELEPHONY_OBJECT(object));
	if (sms == NULL) {
		err("sms object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_SMS_INCOM_MSG: {
		const struct tnoti_sms_incoming_msg *noti = data;
		gchar *sca = NULL;
		gchar *tpdu = NULL;

		info("[%s] SMS_INCOM_MSG (len[%d])", cp_name, data_len);

		sca = g_base64_encode((const guchar *)(noti->msgInfo.sca), SMS_SMSP_ADDRESS_LEN);
		tpdu = g_base64_encode((const guchar *)(noti->msgInfo.tpduData), SMS_SMDATA_SIZE_MAX + 1);

		telephony_sms_emit_incomming_msg(sms,
			noti->msgInfo.format,
			sca,
			noti->msgInfo.msgLength,
			tpdu);

		g_free(sca);
		g_free(tpdu);
	}
	break;

	case TNOTI_SMS_CB_INCOM_MSG: {
		const struct tnoti_sms_cellBroadcast_msg *noti = data;
		gchar *tpdu = NULL;

		info("[%s] SMS_CB_INCOM_MSG (len[%d])", cp_name, data_len);

		tpdu = g_base64_encode((const guchar*)(noti->cbMsg.msgData), SMS_CB_SIZE_MAX+1);

		telephony_sms_emit_incomming_cb_msg(sms,
			noti->cbMsg.cbMsgType,
			noti->cbMsg.length,
			tpdu);

		g_free(tpdu);
	}
	break;

	case TNOTI_SMS_ETWS_INCOM_MSG: {
		const struct tnoti_sms_etws_msg *noti = data;
		GVariant *msg_data = NULL, *packet_msg_data = NULL;
		GVariantBuilder b;
		unsigned int i;

		info("[%s] ETWS_INCOM_MSG (len[%d])", cp_name, data_len);

		g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));

		for (i = 0; i < SMS_ETWS_SIZE_MAX + 1; i++)
			g_variant_builder_add(&b, "y", noti->etwsMsg.msgData[i]);
		msg_data = g_variant_builder_end(&b);
		packet_msg_data = g_variant_new("v", msg_data);

		telephony_sms_emit_incomming_etws_msg(sms,
			noti->etwsMsg.etwsMsgType,
			noti->etwsMsg.length,
			packet_msg_data);
	}
	break;

	case TNOTI_SMS_INCOM_EX_MSG: {
		info("[%s] SMS_INCOM_EX_MSG (len[%d])", cp_name, data_len);
	}
	break;

	case TNOTI_SMS_CB_INCOM_EX_MSG: {
		info("[%s] CB_INCOM_EX_MSG (len[%d])", cp_name, data_len);
	}
	break;

	case TNOTI_SMS_MEMORY_STATUS: {
		const struct tnoti_sms_memory_status *noti = data;

		info("[%s] SMS_MEMORY_STATUS (%d)", cp_name, noti->status);

		telephony_sms_emit_memory_status(sms, noti->status);
	}
	break;

	case TNOTI_SMS_DEVICE_READY: {
		const struct tnoti_sms_ready_status *noti = data;

		info("[%s] SMS_DEVICE_READY (%d)", cp_name, noti->status);

#ifdef ENABLE_KPI_LOGS
		if (noti->status != SMS_READY_STATUS_NONE)
			TIME_CHECK("[%s] SMS Service Ready", cp_name);
#endif

		telephony_sms_emit_sms_ready(sms, noti->status);
	}
	break;

	default:
		err("Unhandled/Unknown Notification: [0x%x]", command);
	break;
	}

	return TRUE;
}
