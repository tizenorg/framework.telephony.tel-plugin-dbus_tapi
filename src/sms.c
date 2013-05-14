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
#include <co_sms.h>

#include "generated-code.h"
#include "common.h"

TReturn	ret = TCORE_RETURN_SUCCESS;

static gboolean
on_sms_send_msg(TelephonySms *sms, GDBusMethodInvocation *invocation,
	const gchar *sca,
	gint tpdu_length,
	const gchar *tpdu_data,
	gint moreMsg,
	gpointer user_data)
{
	struct treq_sms_send_umts_msg sendUmtsMsg;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	gsize length;
	guchar *decoded_buff = NULL;

	if (check_access_control(invocation, AC_SMS, "x") == FALSE)
		return FALSE;

	memset(&sendUmtsMsg, 0 , sizeof(struct treq_sms_send_umts_msg));

	decoded_buff = g_base64_decode(sca, &length);
	if (length > SMS_ENCODED_SCA_LEN_MAX)
		goto invalid_param;
	memcpy(&(sendUmtsMsg.msgDataPackage.sca[0]), decoded_buff, length);
	g_free(decoded_buff);

	sendUmtsMsg.msgDataPackage.msgLength = tpdu_length;
	dbg("tpdu_length = 0x%x", tpdu_length);

	decoded_buff = g_base64_decode(tpdu_data, &length);
	if (length > SMS_SMDATA_SIZE_MAX + 1)
		goto invalid_param;
	memcpy(&(sendUmtsMsg.msgDataPackage.tpduData[0]), decoded_buff, length);
	g_free(decoded_buff);

	sendUmtsMsg.more = moreMsg;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_send_umts_msg), &sendUmtsMsg);
	tcore_user_request_set_command(ur, TREQ_SMS_SEND_UMTS_MSG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_send_msg(sms, invocation, SMS_DEVICE_FAILURE);
		tcore_user_request_unref(ur);
	}

	return TRUE;

invalid_param:
	g_free(decoded_buff);

	telephony_sms_complete_send_msg(sms, invocation, SMS_INVALID_PARAMETER);
	tcore_user_request_unref(ur);

	return TRUE;
}

static gboolean
on_sms_read_msg(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_index,
	gpointer user_data)
{
	struct treq_sms_read_msg readMsg = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "r") == FALSE)
		return FALSE;

	readMsg.index = arg_index;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_read_msg), &readMsg);
	tcore_user_request_set_command(ur, TREQ_SMS_READ_MSG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_read_msg(sms, invocation, SMS_DEVICE_FAILURE, -1, -1, NULL, 0, NULL);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_save_msg(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_msg_status,
	const gchar * arg_sca,
	gint arg_tpdu_length,
	const gchar * arg_tpdu_data,
	gpointer user_data)
{
        struct treq_sms_save_msg saveMsg = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	gsize length;
	guchar *decoded_buff = NULL;

	if (check_access_control(invocation, AC_SMS, "w") == FALSE)
		return FALSE;

	saveMsg.simIndex = 0xffff;
	saveMsg.msgStatus = arg_msg_status;

	decoded_buff = g_base64_decode(arg_sca, &length);
	if (length > SMS_ENCODED_SCA_LEN_MAX)
		goto invalid_param;
	memcpy(&(saveMsg.msgDataPackage.sca[0]), decoded_buff, length);
	g_free(decoded_buff);

	saveMsg.msgDataPackage.msgLength = arg_tpdu_length;

	decoded_buff = g_base64_decode(arg_tpdu_data, &length);
	if (length > SMS_SMDATA_SIZE_MAX + 1)
		goto invalid_param;
	memcpy(&(saveMsg.msgDataPackage.tpduData[0]), decoded_buff, length);
	g_free(decoded_buff);

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_save_msg), &saveMsg);
	tcore_user_request_set_command(ur, TREQ_SMS_SAVE_MSG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_save_msg(sms, invocation, SMS_DEVICE_FAILURE, -1);
		tcore_user_request_unref(ur);
	}

	return TRUE;

invalid_param:
	g_free(decoded_buff);

	telephony_sms_complete_save_msg(sms, invocation,
				SMS_INVALID_PARAMETER, -1);
	tcore_user_request_unref(ur);

	return TRUE;
}

static gboolean
on_sms_delete_msg(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_index,
	gpointer user_data)
{
        struct treq_sms_delete_msg deleteMsg = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "x") == FALSE)
		return FALSE;

	deleteMsg.index = arg_index;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_delete_msg), &deleteMsg);
	tcore_user_request_set_command(ur, TREQ_SMS_DELETE_MSG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_delete_msg(sms, invocation, SMS_DEVICE_FAILURE, -1);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_get_msg_count(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
        struct treq_sms_get_msg_count getMsgCnt;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_get_msg_count), &getMsgCnt);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_COUNT);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_get_msg_count(sms, invocation, SMS_DEVICE_FAILURE, 0, -1, NULL);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_get_sca(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_index,
	gpointer user_data)
{
        struct treq_sms_get_sca getSca = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "r") == FALSE)
		return FALSE;

	getSca.index = arg_index;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_get_sca), &getSca);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_SCA);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_get_sca(sms, invocation, SMS_DEVICE_FAILURE, -1, -1, 0, NULL);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_set_sca(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_index,
	gint arg_ton,
	gint arg_npi,
	gint arg_dialNumberLength,
	const gchar *arg_dialNumber,
	gpointer user_data)
{
        struct treq_sms_set_sca setSca;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	guchar *decoded_sca = NULL;

	if (check_access_control(invocation, AC_SMS, "w") == FALSE)
		return FALSE;

	memset(&setSca, 0, sizeof(struct treq_sms_set_sca));

	setSca.index = arg_index;
	setSca.scaInfo.dialNumLen = arg_dialNumberLength;
	setSca.scaInfo.typeOfNum = arg_ton;
	setSca.scaInfo.numPlanId = arg_npi;

	if ((setSca.scaInfo.dialNumLen <= 0)
			|| (setSca.scaInfo.dialNumLen > SMS_SMSP_ADDRESS_LEN)) {
		err("[tcore_SMS] TAPI_API_INVALID_INPUT !!!");
		return  FALSE;
	}
	else if(setSca.index != 0) {
		err("[tcore_SMS] Index except 0 is supported");
		// api_err = TAPI_API_NOT_SUPPORTED;
		return  FALSE;
	} else {
		gsize length;

		decoded_sca = g_base64_decode(arg_dialNumber, &length);
		if (length > SMS_SMSP_ADDRESS_LEN)
			goto invalid_param;
		memcpy(&(setSca.scaInfo.diallingNum[0]), decoded_sca, length);
		g_free(decoded_sca);

		ur = MAKE_UR(ctx, sms, invocation);
		tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_sca), &setSca);
		tcore_user_request_set_command(ur, TREQ_SMS_SET_SCA);

		ret = tcore_communicator_dispatch_request(ctx->comm, ur);
		if (ret != TCORE_RETURN_SUCCESS) {
			telephony_sms_complete_set_sca(sms, invocation, SMS_DEVICE_FAILURE);
			tcore_user_request_unref(ur);
		}
	}

	return TRUE;

invalid_param:
	g_free(decoded_sca);

	telephony_sms_complete_set_sca(sms, invocation, SMS_INVALID_PARAMETER);
	tcore_user_request_unref(ur);

	return TRUE;
}

static gboolean
on_sms_get_cb_config(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct treq_sms_get_cb_config getCbConfig;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_get_cb_config), &getCbConfig);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_CB_CONFIG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		GVariant *gv = NULL;
		GVariantBuilder b;
		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		gv = g_variant_builder_end(&b);
		telephony_sms_complete_get_cb_config(sms, invocation, SMS_DEVICE_FAILURE, -1, -1, 0, 0, gv);
		g_variant_unref(gv);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_set_cb_config(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_net3gppType,
	gboolean arg_cbEnable,
	gint arg_msgIdMaxCount,
	gint arg_msgIdRangeCount,
	const gchar *arg_msgId,
	gpointer user_data)
{
    struct treq_sms_set_cb_config setCbConfig = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	gsize length;
	guchar *decoded_msgId = NULL;

	if (check_access_control(invocation, AC_SMS, "w") == FALSE)
		return FALSE;

	setCbConfig.net3gppType = arg_net3gppType;
	setCbConfig.cbEnabled = arg_cbEnable;
	setCbConfig.msgIdMaxCount = arg_msgIdMaxCount;
	setCbConfig.msgIdRangeCount = arg_msgIdRangeCount;

	decoded_msgId = g_base64_decode(arg_msgId, &length);
	if (length > SMS_GSM_SMS_CBMI_LIST_SIZE_MAX * 5)
		goto invalid_param;
	memcpy(&(setCbConfig.msgIDs[0]), decoded_msgId, length);
	g_free(decoded_msgId);

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_cb_config), &setCbConfig);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_CB_CONFIG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_set_cb_config(sms, invocation, SMS_DEVICE_FAILURE);
		tcore_user_request_unref(ur);
	}

	return TRUE;

invalid_param:
	g_free(decoded_msgId);

	telephony_sms_complete_set_cb_config(sms, invocation,
					SMS_INVALID_PARAMETER);
	tcore_user_request_unref(ur);

	return TRUE;
}

static gboolean
on_sms_set_mem_status(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_memoryStatus,
	gpointer user_data)
{
        struct treq_sms_set_mem_status memStatus = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "w") == FALSE)
		return FALSE;

	memStatus.memory_status = arg_memoryStatus;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_mem_status), &memStatus);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_MEM_STATUS);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_set_mem_status(sms, invocation, SMS_DEVICE_FAILURE);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_get_pref_bearer(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
        struct treq_sms_get_pref_bearer getPrefBearer;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_get_pref_bearer), &getPrefBearer);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_PREF_BEARER);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_get_pref_bearer(sms, invocation, SMS_DEVICE_FAILURE);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_set_pref_bearer(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_bearerType,
	gpointer user_data)
{
        struct treq_sms_set_pref_bearer setPrefBearer = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "w") == FALSE)
		return FALSE;

	setPrefBearer.svc = arg_bearerType;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_pref_bearer), &setPrefBearer);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_PREF_BEARER);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_set_pref_bearer(sms, invocation, SMS_DEVICE_FAILURE);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_set_delivery_report(TelephonySms *sms, GDBusMethodInvocation *invocation,
	const gchar *arg_sca,
	gint arg_tpdu_length,
	const gchar *arg_tpdu_data,
	gint arg_rpCause,
	gpointer user_data)
{
        struct treq_sms_set_delivery_report deliveryReport;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	gsize length;
	guchar *decoded_buff = NULL;

	if (check_access_control(invocation, AC_SMS, "w") == FALSE)
		return FALSE;

	memset(&deliveryReport, 0, sizeof(struct treq_sms_set_delivery_report));

	decoded_buff = g_base64_decode(arg_sca, &length);
	if (length > SMS_ENCODED_SCA_LEN_MAX)
		goto invalid_param;
	memcpy(&(deliveryReport.dataInfo.sca[0]), decoded_buff, length);
	g_free(decoded_buff);

	deliveryReport.dataInfo.msgLength = arg_tpdu_length;

	decoded_buff = g_base64_decode(arg_tpdu_data, &length);
	if (length > SMS_SMDATA_SIZE_MAX + 1)
		goto invalid_param;
	memcpy(&(deliveryReport.dataInfo.tpduData[0]), decoded_buff, length);
	g_free(decoded_buff);

	deliveryReport.rspType = arg_rpCause;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_delivery_report), &deliveryReport);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_DELIVERY_REPORT);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_set_delivery_report(sms, invocation, SMS_DEVICE_FAILURE);
		tcore_user_request_unref(ur);
	}

	return TRUE;

invalid_param:
	g_free(decoded_buff);

	telephony_sms_complete_set_delivery_report(sms, invocation,
						SMS_INVALID_PARAMETER);
	tcore_user_request_unref(ur);

	return TRUE;
}

static gboolean
on_sms_set_msg_status(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_index,
	gint arg_msgStatus,
	gpointer user_data)
{
        struct treq_sms_set_msg_status msgStatus = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "w") == FALSE)
		return FALSE;

	msgStatus.index = arg_index;
	msgStatus.msgStatus = arg_msgStatus;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_msg_status), &msgStatus);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_MSG_STATUS);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_set_msg_status(sms, invocation, SMS_DEVICE_FAILURE);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_get_sms_params(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_index,
	gpointer user_data)
{
        struct treq_sms_get_params getParams = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "r") == FALSE)
		return FALSE;

	getParams.index = arg_index;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_get_params), &getParams);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_PARAMS);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_get_sms_params(sms, invocation, SMS_DEVICE_FAILURE,
		0, 0, 0, NULL, 0, 0, -1, -1, NULL, 0, -1, -1, NULL, 0, 0, 0);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_set_sms_params(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_recordIndex,
	gint arg_recordLen,
	gint arg_alphaIdLen,
	const gchar *arg_alphaId,
	gint arg_paramIndicator,
	gint arg_destAddr_DialNumLen,
	gint arg_destAddr_Ton,
	gint arg_destAddr_Npi,
	const gchar *arg_destAddr_DiallingNum,
	gint arg_svcCntrAddr_DialNumLen,
	gint arg_SvcCntrAddr_Ton,
	gint arg_svcCntrAddr_Npi,
	const gchar *arg_svcCntrAddr_DialNum,
	gint arg_protocolId,
	gint arg_dataCodingScheme,
	gint arg_validityPeriod,
	gpointer user_data)
{
	struct treq_sms_set_params setParams;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	gsize length;
	guchar *decoded_buff = NULL;

	if (check_access_control(invocation, AC_SMS, "w") == FALSE)
		return FALSE;

	memset(&setParams, 0, sizeof(struct treq_sms_set_params));

	setParams.params.recordIndex = arg_recordIndex;
	setParams.params.recordLen = arg_recordLen;
	setParams.params.alphaIdLen = arg_alphaIdLen;

	decoded_buff = g_base64_decode(arg_alphaId, &length);
	if (length > SMS_SMSP_ALPHA_ID_LEN_MAX + 1)
		goto invalid_param;
	memcpy(&(setParams.params.szAlphaId[0]), decoded_buff, length);
	g_free(decoded_buff);

	setParams.params.paramIndicator = arg_paramIndicator;
	setParams.params.tpDestAddr.dialNumLen = arg_destAddr_DialNumLen;
	setParams.params.tpDestAddr.typeOfNum = arg_destAddr_Ton;
	setParams.params.tpDestAddr.numPlanId = arg_destAddr_Npi;

	decoded_buff = g_base64_decode(arg_destAddr_DiallingNum, &length);
	if (length > SMS_SMSP_ADDRESS_LEN + 1)
		goto invalid_param;
	memcpy(&(setParams.params.tpDestAddr.diallingNum[0]),
					decoded_buff, length);
	g_free(decoded_buff);

	setParams.params.tpSvcCntrAddr.dialNumLen = arg_svcCntrAddr_DialNumLen;
	setParams.params.tpSvcCntrAddr.typeOfNum = arg_SvcCntrAddr_Ton;
	setParams.params.tpSvcCntrAddr.numPlanId = arg_svcCntrAddr_Npi;

	decoded_buff = g_base64_decode(arg_svcCntrAddr_DialNum, &length);
	if (length > SMS_SMSP_ADDRESS_LEN + 1)
		goto invalid_param;
	memcpy(&(setParams.params.tpSvcCntrAddr.diallingNum[0]),
					decoded_buff, length);
	g_free(decoded_buff);

	setParams.params.tpProtocolId = arg_protocolId;
	setParams.params.tpDataCodingScheme = arg_dataCodingScheme;
	setParams.params.tpValidityPeriod = arg_validityPeriod;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_params), &setParams);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_PARAMS);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_set_sms_params(sms, invocation, SMS_DEVICE_FAILURE);
		tcore_user_request_unref(ur);
	}

	return TRUE;

invalid_param:
	g_free(decoded_buff);

	telephony_sms_complete_set_sms_params(sms, invocation,
					SMS_INVALID_PARAMETER);
	tcore_user_request_unref(ur);

	return TRUE;
}

static gboolean
on_sms_get_sms_param_cnt(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
        struct treq_sms_get_paramcnt getParamCnt;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (check_access_control(invocation, AC_SMS, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_get_paramcnt), &getParamCnt);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_PARAMCNT);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_sms_complete_get_sms_param_cnt(sms, invocation, SMS_DEVICE_FAILURE, -1);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_get_sms_ready_status(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sms = NULL;
	TcorePlugin *plugin = NULL;
	char *cp_name = GET_PLUGIN_NAME(invocation);

	dbg("Func Entrance");

	plugin = tcore_server_find_plugin(ctx->server, cp_name);
	co_sms = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SMS);
	if (!co_sms) {
		dbg("error- co_sms is NULL");
		return FALSE;
	}

	telephony_sms_complete_get_sms_ready_status(sms, invocation, tcore_sms_get_ready_status(co_sms));

	return TRUE;
}

gboolean dbus_plugin_setup_sms_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonySms *sms;

	sms = telephony_sms_skeleton_new();
	telephony_object_skeleton_set_sms(object, sms);
	g_object_unref(sms);

	dbg("sms = %p", sms);

	g_signal_connect(sms, "handle-send-msg", G_CALLBACK (on_sms_send_msg), ctx);
	g_signal_connect(sms, "handle-read-msg", G_CALLBACK (on_sms_read_msg), ctx);
	g_signal_connect(sms, "handle-save-msg", G_CALLBACK (on_sms_save_msg), ctx);
	g_signal_connect(sms, "handle-delete-msg", G_CALLBACK (on_sms_delete_msg), ctx);
	g_signal_connect(sms, "handle-get-msg-count", G_CALLBACK (on_sms_get_msg_count), ctx);
	g_signal_connect(sms, "handle-get-sca", G_CALLBACK (on_sms_get_sca), ctx);
	g_signal_connect(sms, "handle-set-sca", G_CALLBACK (on_sms_set_sca), ctx);
	g_signal_connect(sms, "handle-get-cb-config", G_CALLBACK (on_sms_get_cb_config), ctx);
	g_signal_connect(sms, "handle-set-cb-config", G_CALLBACK (on_sms_set_cb_config), ctx);
	g_signal_connect(sms, "handle-set-mem-status", G_CALLBACK (on_sms_set_mem_status), ctx);
	g_signal_connect(sms, "handle-get-pref-bearer", G_CALLBACK (on_sms_get_pref_bearer), ctx);
	g_signal_connect(sms, "handle-set-pref-bearer", G_CALLBACK (on_sms_set_pref_bearer), ctx);
	g_signal_connect(sms, "handle-set-delivery-report", G_CALLBACK (on_sms_set_delivery_report), ctx);
	g_signal_connect(sms, "handle-set-msg-status", G_CALLBACK (on_sms_set_msg_status), ctx);
	g_signal_connect(sms, "handle-get-sms-params", G_CALLBACK (on_sms_get_sms_params), ctx);
	g_signal_connect(sms, "handle-set-sms-params", G_CALLBACK (on_sms_set_sms_params), ctx);
	g_signal_connect(sms, "handle-get-sms-param-cnt", G_CALLBACK (on_sms_get_sms_param_cnt), ctx);
	g_signal_connect(sms, "handle-get-sms-ready-status", G_CALLBACK (on_sms_get_sms_ready_status), ctx);

	return TRUE;
}

gboolean dbus_plugin_sms_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	CoreObject *co_sms;
	char *modem_name = NULL;
	TcorePlugin *p = NULL;
	int i;

	modem_name = tcore_user_request_get_modem_name(ur);
	if (!modem_name)
		return FALSE;

	p = tcore_server_find_plugin(ctx->server, modem_name);
	free(modem_name);
	if (!p)
		return FALSE;

	co_sms = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SMS);
	if (!co_sms)
		return FALSE;

	switch (command) {
		case TRESP_SMS_SEND_UMTS_MSG: {
			const struct tresp_sms_send_umts_msg *resp = data;


			dbg("receive TRESP_SMS_SEND_UMTS_MSG");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_send_msg(dbus_info->interface_object, dbus_info->invocation, resp->result);

			}
			break;

		case TRESP_SMS_READ_MSG: {
			const struct tresp_sms_read_msg *resp = data;
			gchar *sca = NULL;
			gchar *tpdu = NULL;

			dbg("receive TRESP_SMS_READ_MSG");
			dbg("resp->result = 0x%x", resp->result);

			sca = g_base64_encode((const guchar *)&(resp->dataInfo.smsData.sca[0]), SMS_ENCODED_SCA_LEN_MAX);
			if (sca == NULL) {
				dbg("g_base64_encode: Failed to Enocde the SCA.");
				sca = g_strdup("");
			}

			tpdu = g_base64_encode((const guchar *)&(resp->dataInfo.smsData.tpduData[0]), SMS_SMDATA_SIZE_MAX + 1);
			if (tpdu == NULL) {
				dbg("g_base64_encode: Failed to Enocde the TPDU.");
				tpdu = g_strdup("");
			}

			telephony_sms_complete_read_msg(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->dataInfo.simIndex,
				resp->dataInfo.msgStatus,
				sca,
				resp->dataInfo.smsData.msgLength,
				tpdu);

			if (sca)
				g_free(sca);

			if (tpdu)
				g_free(tpdu);

			}
			break;

		case TRESP_SMS_SAVE_MSG: {
			const struct tresp_sms_save_msg *resp = data;

			dbg("receive TRESP_SMS_SAVE_MSG");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_save_msg (dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->index);
			}
			break;

		case TRESP_SMS_DELETE_MSG: {
			const struct tresp_sms_delete_msg *resp = data;

			dbg("receive TRESP_SMS_DELETE_MSG");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_delete_msg(dbus_info->interface_object, dbus_info->invocation,
				resp->result, resp->index);

			}
			break;

		case TRESP_SMS_GET_STORED_MSG_COUNT: {
			const struct tresp_sms_get_storedMsgCnt *resp = data;
			gchar *msgCnt = NULL;

			dbg("receive TRESP_SMS_GET_STORED_MSG_COUNT");
			dbg("resp->result = 0x%x", resp->result);

			msgCnt = g_base64_encode((const guchar *)&(resp->storedMsgCnt.indexList[0]), SMS_GSM_SMS_MSG_NUM_MAX + 1);
			if (msgCnt == NULL) {
				dbg("g_base64_encode: Failed to Enocde storedMsgCnt.indexList");
				msgCnt = g_strdup("");
			}

			telephony_sms_complete_get_msg_count(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->storedMsgCnt.totalCount,
				resp->storedMsgCnt.usedCount,
				msgCnt);

			if (msgCnt)
				g_free(msgCnt);
			}

			break;

		case TRESP_SMS_GET_SCA: {
			const struct tresp_sms_get_sca *resp = data;
			gchar *sca = NULL;

			dbg("receive TRESP_SMS_GET_SCA");
			dbg("resp->result = 0x%x", resp->result);

			sca = g_base64_encode((const guchar *)&(resp->scaAddress.diallingNum[0]), SMS_SMSP_ADDRESS_LEN + 1);
			if (sca == NULL) {
				dbg("g_base64_encode: Failed to Enocde scaAddress.diallingNum");
				sca = g_strdup("");
			}

			telephony_sms_complete_get_sca(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->scaAddress.typeOfNum,
				resp->scaAddress.numPlanId,
				resp->scaAddress.dialNumLen,
				sca);

			if (sca)
				g_free(sca);

			}
			break;

		case TRESP_SMS_SET_SCA: {
			const struct tresp_sms_set_sca *resp = data;

			dbg("receive TRESP_SMS_SET_SCA");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_set_sca(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_GET_CB_CONFIG: {
			const struct tresp_sms_get_cb_config *resp = data;
			GVariant *result = NULL;
			GVariantBuilder b;

			dbg("receive TRESP_SMS_GET_CB_CONFIG");
			dbg("resp->result = 0x%x", resp->result);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i = 0; i < resp->cbConfig.msgIdRangeCount; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

				if( resp->cbConfig.net3gppType == SMS_NETTYPE_3GPP ) {
					g_variant_builder_add(&b, "{sv}", "FromMsgId", g_variant_new_uint16(resp->cbConfig.msgIDs[i].net3gpp.fromMsgId));
					g_variant_builder_add(&b, "{sv}", "ToMsgId", g_variant_new_uint16(resp->cbConfig.msgIDs[i].net3gpp.toMsgId));
				} else if( resp->cbConfig.net3gppType == SMS_NETTYPE_3GPP2) {
					g_variant_builder_add(&b, "{sv}", "CBCategory", g_variant_new_uint16(resp->cbConfig.msgIDs[i].net3gpp2.cbCategory));
					g_variant_builder_add(&b, "{sv}", "CBLanguage", g_variant_new_uint16(resp->cbConfig.msgIDs[i].net3gpp2.cbLanguage));
				} else {
					dbg("Unknown 3gpp type");
					return FALSE;
				}

				g_variant_builder_add(&b, "{sv}", "Selected", g_variant_new_byte(resp->cbConfig.msgIDs[i].net3gpp.selected));

				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_sms_complete_get_cb_config(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->cbConfig.net3gppType,
				resp->cbConfig.cbEnabled,
				resp->cbConfig.msgIdMaxCount,
				resp->cbConfig.msgIdRangeCount,
				result);
			}
			break;

		case TRESP_SMS_SET_CB_CONFIG: {
			const struct tresp_sms_set_cb_config *resp = data;

			dbg("receive TRESP_SMS_SET_CB_CONFIG");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_set_cb_config(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_SET_MEM_STATUS: {
			const struct tresp_sms_set_mem_status *resp = data;

			dbg("receive TRESP_SMS_SET_MEM_STATUS");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_set_mem_status(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;
		case TRESP_SMS_GET_PREF_BEARER: {
			const struct tresp_sms_get_pref_bearer *resp = data;

			dbg("receive TRESP_SMS_GET_PREF_BEARER");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_get_pref_bearer(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_SET_PREF_BEARER: {
			const struct tresp_sms_set_pref_bearer *resp = data;

			dbg("receive TRESP_SMS_SET_PREF_BEARER");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_set_pref_bearer(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_SET_DELIVERY_REPORT: {
			const struct tresp_sms_set_delivery_report *resp = data;

			dbg("receive TRESP_SMS_SET_DELIVERY_REPORT");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_set_delivery_report(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_SET_MSG_STATUS: {
			const struct tresp_sms_set_mem_status *resp = data;

			dbg("receive TRESP_SMS_SET_MSG_STATUS");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_set_msg_status(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_GET_PARAMS: {
			const struct tresp_sms_get_params *resp = data;
			gchar *alphaId = NULL;
			gchar *destDialNum = NULL;
			gchar *scaDialNum = NULL;

			dbg("receive TRESP_SMS_GET_PARAMS");
			dbg("resp->result = 0x%x", resp->result);

			alphaId = g_base64_encode((const guchar *)&(resp->paramsInfo.szAlphaId[0]), SMS_SMSP_ALPHA_ID_LEN_MAX + 1);
			if (alphaId == NULL) {
				dbg("g_base64_encode: Failed to Enocde paramsInfo.szAlphaId");
				alphaId = g_strdup("");
			}

			destDialNum = g_base64_encode((const guchar *)&(resp->paramsInfo.tpDestAddr.diallingNum[0]), SMS_SMSP_ADDRESS_LEN + 1);
			if (destDialNum == NULL) {
				dbg("g_base64_encode: Failed to Enocde paramsInfo.tpDestAddr.diallingNum");
				destDialNum = g_strdup("");
			}

			scaDialNum = g_base64_encode((const guchar *)&(resp->paramsInfo.tpSvcCntrAddr.diallingNum[0]), SMS_SMSP_ADDRESS_LEN + 1);
			if (scaDialNum == NULL) {
				dbg("g_base64_encode: Failed to Enocde paramsInfo.tpSvcCntrAddr.diallingNum");
				scaDialNum = g_strdup("");
			}

			telephony_sms_complete_get_sms_params(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->paramsInfo.recordIndex,
				resp->paramsInfo.recordLen,
				resp->paramsInfo.alphaIdLen,
				alphaId,
				resp->paramsInfo.paramIndicator,
				resp->paramsInfo.tpDestAddr.dialNumLen,
				resp->paramsInfo.tpDestAddr.typeOfNum,
				resp->paramsInfo.tpDestAddr.numPlanId,
				destDialNum,
				resp->paramsInfo.tpSvcCntrAddr.dialNumLen,
				resp->paramsInfo.tpSvcCntrAddr.typeOfNum,
				resp->paramsInfo.tpSvcCntrAddr.numPlanId,
				scaDialNum,
				resp->paramsInfo.tpProtocolId,
				resp->paramsInfo.tpDataCodingScheme,
				resp->paramsInfo.tpValidityPeriod);

			if(alphaId)
				g_free(alphaId);

			if(destDialNum)
				g_free(destDialNum);

			if(scaDialNum)
				g_free(scaDialNum);

			}
			break;

		case TRESP_SMS_SET_PARAMS:{
			const struct tresp_sms_set_params *resp = data;

			dbg("receive TRESP_SMS_SET_PARAMS");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_set_sms_params(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_GET_PARAMCNT: {
			const struct tresp_sms_get_paramcnt *resp = data;

			dbg("receive TRESP_SMS_GET_PARAMCNT");
			dbg("resp->result = 0x%x", resp->result);

			telephony_sms_complete_get_sms_param_cnt(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->recordCount);

			}
			break;

		default:
			break;
	}

	return TRUE;
}

gboolean dbus_plugin_sms_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonySms *sms;

	if (!object)
	{
		dbg("object is NULL");
		return FALSE;
	}

	sms = telephony_object_peek_sms(TELEPHONY_OBJECT(object));
	dbg("sms = %p", sms);

	dbg("[tcore_SMS]notification !!! (command = 0x%x, data_len = %d)", command, data_len);

	switch (command) {
		case TNOTI_SMS_INCOM_MSG: {
			const struct tnoti_sms_umts_msg *noti = data;

			gchar *sca = NULL;
			gchar *tpdu = NULL;

			sca = g_base64_encode((const guchar *)&(noti->msgInfo.sca[0]), SMS_ENCODED_SCA_LEN_MAX);
			if (sca == NULL) {
				dbg("g_base64_encode: Failed to Enocde msgInfo.sca");
				sca = g_strdup("");
			}

			tpdu = g_base64_encode((const guchar *)&(noti->msgInfo.tpduData[0]), SMS_SMDATA_SIZE_MAX + 1);
			if (tpdu == NULL) {
				dbg("g_base64_encode: Failed to Enocde msgInfo.tpduData");
				tpdu = g_strdup("");
			}

			telephony_sms_emit_incomming_msg(sms,
				sca,
				noti->msgInfo.msgLength,
				tpdu);

			if(sca)
				g_free(sca);

			if(tpdu)
				g_free(tpdu);

			}
			break;

		case TNOTI_SMS_CB_INCOM_MSG: {
			const struct tnoti_sms_cellBroadcast_msg *noti = data;
			gchar *msgData = NULL;

			msgData = g_base64_encode((const guchar *)&(noti->cbMsg.msgData[0]), SMS_CB_SIZE_MAX + 1);
			if (msgData == NULL) {
				dbg("g_base64_encode: Failed to Enocde cbMsg.msgData");
				msgData = g_strdup("");
			}

			telephony_sms_emit_incomming_cb_msg(sms,
				noti->cbMsg.cbMsgType,
				noti->cbMsg.length,
				msgData);

			if(msgData)
				g_free(msgData);

			}
			break;

		case TNOTI_SMS_ETWS_INCOM_MSG: {
			const struct tnoti_sms_etws_msg *noti = data;
			gchar *msgData = NULL;

			msgData = g_base64_encode((const guchar *)&(noti->etwsMsg.msgData[0]), SMS_ETWS_SIZE_MAX + 1);
			if (msgData == NULL) {
				dbg("g_base64_encode: Failed to Enocde etwsMsg.msgData");
				msgData = g_strdup("");
			}

			telephony_sms_emit_incomming_etws_msg(sms,
				noti->etwsMsg.etwsMsgType,
				noti->etwsMsg.length,
				msgData);

			if(msgData)
				g_free(msgData);
			}
			break;

		case TNOTI_SMS_INCOM_EX_MSG:
			break;

		case TNOTI_SMS_CB_INCOM_EX_MSG:
			break;

		case TNOTI_SMS_MEMORY_STATUS: {
			const struct tnoti_sms_memory_status *noti = data;

			telephony_sms_emit_memory_status(sms, noti->status);

			}
			break;

		case TNOTI_SMS_DEVICE_READY: {
			const struct tnoti_sms_ready_status *noti = data;

			dbg("SMS Device Ready: [%s]", (noti->status ? "YES" : "NO"));

			telephony_sms_emit_sms_ready(sms, noti->status);

			}
			break;

		default:
			dbg("unknown notification");
			return FALSE;
			break;
	}

	return TRUE;
}
