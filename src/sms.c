/*
 * tel-plugin-socket-communicator
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
	GVariant *sca,
	gint tpdu_length,
	GVariant *tpdu_data,
	gint moreMsg,
	gpointer user_data)
{
	struct treq_sms_send_umts_msg sendUmtsMsg;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	int i = 0;
	GVariantIter *iter = 0;
	GVariant *inner_gv = 0;

	if (!check_access_control (invocation, AC_SMS, "x"))
		return TRUE;

	memset(&sendUmtsMsg, 0 , sizeof(struct treq_sms_send_umts_msg));

	inner_gv = g_variant_get_variant( sca );
	g_variant_get(inner_gv, "ay", &iter);
	while( g_variant_iter_loop(iter, "y", &sendUmtsMsg.msgDataPackage.sca[i] ) ) {
		i++;
		if( i >= SMS_SMSP_ADDRESS_LEN )
			break;
	}

	sendUmtsMsg.msgDataPackage.msgLength = tpdu_length;

	i = 0;
	inner_gv = g_variant_get_variant( tpdu_data );
	g_variant_get(inner_gv, "ay", &iter);
	while( g_variant_iter_loop(iter, "y", &sendUmtsMsg.msgDataPackage.tpduData[i] ) ) {
		i++;
		if( i >= SMS_SMDATA_SIZE_MAX + 1 )
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	sendUmtsMsg.more = moreMsg;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_send_umts_msg), &sendUmtsMsg);
	tcore_user_request_set_command(ur, TREQ_SMS_SEND_UMTS_MSG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return  TRUE;
}
/*

static gboolean
on_sms_send_cdma_msg(TelephonySms *sms, GDBusMethodInvocation *invocation,
	const gchar *sca,
	gint tpdu_length,
	const gchar *tpdu_data,
	gint moreMsg,
	gpointer user_data)
{
#if 0
	cdmaMsg.more = sipc_util_marshal_object_get_int(in_obj, "More");
	cdmaMsg.cdmaMsgInfo.ParamMask = sipc_util_marshal_object_get_int(in_obj, "ParamMask");
	cdmaMsg.cdmaMsgInfo.MsgType = sipc_util_marshal_object_get_int(in_obj, "MsgType");

	switch(cdmaMsg.cdmaMsgInfo.MsgType)
	{
		case SMS_MESSAGETYPE_SUBMIT: {
			gchar *dstAddr_szAddress;
			gchar *dstSubAddr_szAddress;
			gchar *szData;
			gchar *callBackNumer_szAddress;

			 Origination address
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstAddr.Digit = sipc_util_marshal_object_get_int(in_obj, "DstAddr.Digit");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstAddr.NumberMode = sipc_util_marshal_object_get_int(in_obj, "DstAddr.NumberMode");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstAddr.NumberType = sipc_util_marshal_object_get_int(in_obj, "DstAddr.NumberType");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstAddr.NumberPlan = sipc_util_marshal_object_get_int(in_obj, "DstAddr.NumberPlan");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstAddr.szAddrLength = sipc_util_marshal_object_get_char(in_obj, "DstAddr.szAddrLength");
			dstAddr_szAddress = sipc_util_marshal_object_get_string(in_obj, "DstAddr.szAddress");
			memcpy(&(cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstAddr.szAddress[0]), dstAddr_szAddress, SMS_MAXLENGTH_SMS_ADDRESS);

			 Origination subaddress
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstSubAddr.SubType = sipc_util_marshal_object_get_int(in_obj, "DstSubAddr.SubType");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstSubAddr.Odd = sipc_util_marshal_object_get_char(in_obj, "DstSubAddr.Odd");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstSubAddr.szAddrLength = sipc_util_marshal_object_get_char(in_obj, "DstSubAddr.szAddrLength");
			dstSubAddr_szAddress = sipc_util_marshal_object_get_string(in_obj, "DstSubAddr.szAddress");
			memcpy(&(cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DstSubAddr.szAddress[0]), dstSubAddr_szAddress, SMS_MAXLENGTH_SMS_ADDRESS);

			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.TeleService = sipc_util_marshal_object_get_int(in_obj, "TeleService");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.bBearerReplySeqRequest = sipc_util_marshal_object_get_int(in_obj, "bBearerReplySeqRequest");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.ReplySeqNumber = sipc_util_marshal_object_get_char(in_obj, "ReplySeqNumber");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.MsgId = sipc_util_marshal_object_get_int(in_obj, "MsgId");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.MsgEncoding = sipc_util_marshal_object_get_int(in_obj, "MsgEncoding");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.MsgLength = sipc_util_marshal_object_get_int(in_obj, "MsgLength");
			szData = sipc_util_marshal_object_get_string(in_obj, "szData");
			memcpy(&(cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.szData[0]), szData, SMS_MAXLENGTH_SMS_MO_USER_DATA);

			 Validity period - Absolute
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.ValidityPeriodAbs.year = sipc_util_marshal_object_get_int(in_obj, "ValidityPeriodAbs.year");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.ValidityPeriodAbs.month = sipc_util_marshal_object_get_int(in_obj, "ValidityPeriodAbs.month");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.ValidityPeriodAbs.day = sipc_util_marshal_object_get_int(in_obj, "ValidityPeriodAbs.day");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.ValidityPeriodAbs.hours = sipc_util_marshal_object_get_int(in_obj, "ValidityPeriodAbs.hours");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.ValidityPeriodAbs.minutes = sipc_util_marshal_object_get_int(in_obj, "ValidityPeriodAbs.minutes");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.ValidityPeriodAbs.seconds = sipc_util_marshal_object_get_int(in_obj, "ValidityPeriodAbs.seconds");

			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.ValidityPeriodRel = sipc_util_marshal_object_get_char(in_obj, "ValidityPeriodRel");

			 Deferred delivery time - Absolute (not supported)
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DeferredDelTimeAbs.year = sipc_util_marshal_object_get_int(in_obj, "DeferredDelTimeAbs.year");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DeferredDelTimeAbs.month = sipc_util_marshal_object_get_int(in_obj, "DeferredDelTimeAbs.month");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DeferredDelTimeAbs.day = sipc_util_marshal_object_get_int(in_obj, "DeferredDelTimeAbs.day");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DeferredDelTimeAbs.hours = sipc_util_marshal_object_get_int(in_obj, "DeferredDelTimeAbs.hours");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DeferredDelTimeAbs.minutes = sipc_util_marshal_object_get_int(in_obj, "DeferredDelTimeAbs.minutes");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DeferredDelTimeAbs.seconds = sipc_util_marshal_object_get_int(in_obj, "DeferredDelTimeAbs.seconds");

			 Deferred delivery time - Relative (not supported)
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.DeferredDelTimeRel = sipc_util_marshal_object_get_char(in_obj, "DeferredDelTimeRel");

			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.Priority = sipc_util_marshal_object_get_int(in_obj, "Priority");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.Privacy = sipc_util_marshal_object_get_int(in_obj, "Privacy");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.bUserAckRequest = sipc_util_marshal_object_get_int(in_obj, "bUserAckRequest");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.bDeliveryAckRequest = sipc_util_marshal_object_get_int(in_obj, "bDeliveryAckRequest");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.AlertPriority= sipc_util_marshal_object_get_int(in_obj, "AlertPriority");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.MsgLang= sipc_util_marshal_object_get_int(in_obj, "MsgLang");

			 Callback number address
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.CallBackNumber.Digit = sipc_util_marshal_object_get_int(in_obj, "CallBackNumer.Digit");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.CallBackNumber.NumberMode = sipc_util_marshal_object_get_int(in_obj, "CallBackNumer.NumberMode");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.CallBackNumber.NumberType = sipc_util_marshal_object_get_int(in_obj, "CallBackNumer.NumberType");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.CallBackNumber.NumberPlan = sipc_util_marshal_object_get_int(in_obj, "CallBackNumer.NumberPlan");
			cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.CallBackNumber.szAddrLength = sipc_util_marshal_object_get_char(in_obj, "CallBackNumer.szAddrLength");
			callBackNumer_szAddress = sipc_util_marshal_object_get_string(in_obj, "CallBackNumer.szAddress");
			memcpy(&(cdmaMsg.cdmaMsgInfo.MsgData.outSubmit.CallBackNumber.szAddress[0]), callBackNumer_szAddress, SMS_MAXLENGTH_SMS_ADDRESS);

			}
			break;

		case SMS_MESSAGETYPE_CANCEL: {
			gchar *dstAddr_szAddress;
			gchar *dstSubAddr_szAddress;

			 Origination address
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstAddr.Digit = sipc_util_marshal_object_get_int(in_obj, "DstAddr.Digit");
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstAddr.NumberMode = sipc_util_marshal_object_get_int(in_obj, "DstAddr.NumberMode");
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstAddr.NumberType = sipc_util_marshal_object_get_int(in_obj, "DstAddr.NumberType");
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstAddr.NumberPlan = sipc_util_marshal_object_get_int(in_obj, "DstAddr.NumberPlan");
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstAddr.szAddrLength = sipc_util_marshal_object_get_char(in_obj, "DstAddr.szAddrLength");
			dstAddr_szAddress = sipc_util_marshal_object_get_string(in_obj, "DstAddr.szAddress");
			memcpy(&(cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstAddr.szAddress[0]), dstAddr_szAddress, SMS_MAXLENGTH_SMS_ADDRESS);

			 Origination subaddress
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstSubAddr.SubType = sipc_util_marshal_object_get_int(in_obj, "DstSubAddr.SubType");
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstSubAddr.Odd = sipc_util_marshal_object_get_char(in_obj, "DstSubAddr.Odd");
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstSubAddr.szAddrLength = sipc_util_marshal_object_get_char(in_obj, "DstSubAddr.szAddrLength");
			dstSubAddr_szAddress = sipc_util_marshal_object_get_string(in_obj, "DstSubAddr.szAddress");
			memcpy(&(cdmaMsg.cdmaMsgInfo.MsgData.outCancel.DstSubAddr.szAddress[0]), dstSubAddr_szAddress, SMS_MAXLENGTH_SMS_ADDRESS);

			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.TeleService = sipc_util_marshal_object_get_int(in_obj, "TeleService");
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.bBearerReplySeqRequest = sipc_util_marshal_object_get_int(in_obj, "bBearerReplySeqRequest");
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.ReplySeqNumber = sipc_util_marshal_object_get_char(in_obj, "ReplySeqNumber");
			cdmaMsg.cdmaMsgInfo.MsgData.outCancel.MsgId = sipc_util_marshal_object_get_int(in_obj, "MsgId");

			}
			break;

		case SMS_MESSAGETYPE_USER_ACK: {
			gchar *dstAddr_szAddress;
			gchar *dstSubAddr_szAddress;
			gchar *szData;

			 Origination address
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstAddr.Digit = sipc_util_marshal_object_get_int(in_obj, "DstAddr.Digit");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstAddr.NumberMode = sipc_util_marshal_object_get_int(in_obj, "DstAddr.NumberMode");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstAddr.NumberType = sipc_util_marshal_object_get_int(in_obj, "DstAddr.NumberType");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstAddr.NumberPlan = sipc_util_marshal_object_get_int(in_obj, "DstAddr.NumberPlan");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstAddr.szAddrLength = sipc_util_marshal_object_get_char(in_obj, "DstAddr.szAddrLength");
			dstAddr_szAddress = sipc_util_marshal_object_get_string(in_obj, "DstAddr.szAddress");
			memcpy(&(cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstAddr.szAddress[0]), dstAddr_szAddress, SMS_MAXLENGTH_SMS_ADDRESS);

			 Origination subaddress
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstSubAddr.SubType = sipc_util_marshal_object_get_int(in_obj, "DstSubAddr.SubType");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstSubAddr.Odd = sipc_util_marshal_object_get_char(in_obj, "DstSubAddr.Odd");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstSubAddr.szAddrLength = sipc_util_marshal_object_get_char(in_obj, "DstSubAddr.szAddrLength");
			dstSubAddr_szAddress = sipc_util_marshal_object_get_string(in_obj, "DstSubAddr.szAddress");
			memcpy(&(cdmaMsg.cdmaMsgInfo.MsgData.outAck.DstSubAddr.szAddress[0]), dstSubAddr_szAddress, SMS_MAXLENGTH_SMS_ADDRESS);

			cdmaMsg.cdmaMsgInfo.MsgData.outAck.TeleService = sipc_util_marshal_object_get_int(in_obj, "TeleService");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.bBearerReplySeqRequest = sipc_util_marshal_object_get_int(in_obj, "bBearerReplySeqRequest");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.ReplySeqNumber = sipc_util_marshal_object_get_char(in_obj, "ReplySeqNumber");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.MsgId = sipc_util_marshal_object_get_int(in_obj, "MsgId");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.MsgEncoding = sipc_util_marshal_object_get_int(in_obj, "MsgEncoding");
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.MsgLength = sipc_util_marshal_object_get_int(in_obj, "MsgLength");
			szData = sipc_util_marshal_object_get_string(in_obj, "szData");
			memcpy(&(cdmaMsg.cdmaMsgInfo.MsgData.outAck.szData[0]), szData, SMS_MAXLENGTH_SMS_MO_USER_DATA);
			cdmaMsg.cdmaMsgInfo.MsgData.outAck.UserResponseCode = sipc_util_marshal_object_get_char(in_obj, "UserResponseCode");

			}
			break;
		default:
			break;
	}

	tcore_user_request_set_data(ur, sizeof(struct treq_sms_send_cdma_msg), &cdmaMsg);
	tcore_user_request_set_command(ur, TREQ_SMS_SEND_CDMA_MSG);

	ret = tcore_communicator_dispatch_request(comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		// api_err = TAPI_API_OPERATION_FAILED;
		err("[tcore_SMS] communicator_dispatch_request is fail [0x%x] !!!", ret);
		return  FALSE;
	}
#endif
	return TRUE;
}

*/

static gboolean
on_sms_read_msg(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_index,
	gpointer user_data)
{
	struct treq_sms_read_msg readMsg = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (!check_access_control (invocation, AC_SMS, "r"))
		return TRUE;

	readMsg.index = arg_index;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_read_msg), &readMsg);
	tcore_user_request_set_command(ur, TREQ_SMS_READ_MSG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_save_msg(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_msg_status,
	GVariant * arg_sca,
	gint arg_tpdu_length,
	GVariant * arg_tpdu_data,
	gpointer user_data)
{
	struct treq_sms_save_msg saveMsg = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	int i = 0;
	GVariantIter *iter = 0;
	GVariant *inner_gv = 0;

	if (!check_access_control (invocation, AC_SMS, "w"))
		return TRUE;

	saveMsg.simIndex = 0xffff;
	saveMsg.msgStatus = arg_msg_status;

	inner_gv = g_variant_get_variant( arg_sca );
	g_variant_get(inner_gv, "ay", &iter);
	while( g_variant_iter_loop(iter, "y", &saveMsg.msgDataPackage.sca[i] ) ) {
		i++;
		if( i >= SMS_SMSP_ADDRESS_LEN )
			break;
	}

	i = 0;
	inner_gv = g_variant_get_variant( arg_tpdu_data );
	g_variant_get(inner_gv, "ay", &iter);
	while( g_variant_iter_loop(iter, "y", &saveMsg.msgDataPackage.tpduData[i] ) ) {
		i++;
		if( i >= SMS_SMDATA_SIZE_MAX + 1 )
			break;
	}
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	saveMsg.msgDataPackage.msgLength = arg_tpdu_length;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_save_msg), &saveMsg);
	tcore_user_request_set_command(ur, TREQ_SMS_SAVE_MSG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

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

	if (!check_access_control (invocation, AC_SMS, "x"))
		return TRUE;

	deleteMsg.index = arg_index;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_delete_msg), &deleteMsg);
	tcore_user_request_set_command(ur, TREQ_SMS_DELETE_MSG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_get_msg_count(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (!check_access_control (invocation, AC_SMS, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_COUNT);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
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

	if (!check_access_control (invocation, AC_SMS, "r"))
		return TRUE;

	getSca.index = arg_index;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_get_sca), &getSca);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_SCA);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
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
	GVariant *arg_dialNumber,
	gpointer user_data)
{
	struct treq_sms_set_sca setSca;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	int i = 0;
	GVariantIter *iter = 0;
	GVariant *inner_gv = 0;

	if (!check_access_control (invocation, AC_SMS, "w"))
		return TRUE;

	memset(&setSca, 0, sizeof(struct treq_sms_set_sca));

	setSca.index = arg_index;
	setSca.scaInfo.dialNumLen = arg_dialNumberLength;
	setSca.scaInfo.typeOfNum = arg_ton;
	setSca.scaInfo.numPlanId = arg_npi;

	if ((setSca.scaInfo.dialNumLen <= 0) || (setSca.scaInfo.dialNumLen > (SMS_MAX_SMS_SERVICE_CENTER_ADDR + 1)))
	{
		err("[tcore_SMS] TAPI_API_INVALID_INPUT !!!");
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		return  TRUE;
	}
	else if(setSca.index != 0)
	{
		err("[tcore_SMS] Index except 0 is supported");
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		return  TRUE;
	}
	else
	{
		inner_gv = g_variant_get_variant( arg_dialNumber );
		g_variant_get(inner_gv, "ay", &iter);
		while( g_variant_iter_loop(iter, "y", &setSca.scaInfo.diallingNum[i] ) ) {
			i++;
			if( i >= SMS_SMSP_ADDRESS_LEN + 1 )
				break;
		}

		ur = MAKE_UR(ctx, sms, invocation);
		tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_sca), &setSca);
		tcore_user_request_set_command(ur, TREQ_SMS_SET_SCA);

		g_variant_iter_free(iter);
		g_variant_unref(inner_gv);

		ret = tcore_communicator_dispatch_request(ctx->comm, ur);
		if (ret != TCORE_RETURN_SUCCESS) {
			FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
			tcore_user_request_unref(ur);
		}
	}

	return TRUE;
}

static gboolean
on_sms_get_cb_config(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (!check_access_control (invocation, AC_SMS, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_CB_CONFIG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
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
	GVariant *arg_mdgId,
	gpointer user_data)
{
    struct treq_sms_set_cb_config setCbConfig = {0,};
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	GVariant *value = NULL;
	GVariant *inner_gv = 0;
	GVariantIter *iter = NULL;
	GVariantIter *iter_row = NULL;
	const gchar *key = NULL;
	int i = 0;

	if (!check_access_control (invocation, AC_SMS, "w"))
		return TRUE;

	setCbConfig.net3gppType = arg_net3gppType;
	setCbConfig.cbEnabled = arg_cbEnable;
	setCbConfig.msgIdMaxCount = arg_msgIdMaxCount;
	setCbConfig.msgIdRangeCount = arg_msgIdRangeCount;

	inner_gv = g_variant_get_variant( arg_mdgId );
	g_variant_get(inner_gv, "aa{sv}", &iter);

	while (g_variant_iter_next(iter, "a{sv}", &iter_row)) {
		while (g_variant_iter_loop(iter_row, "{sv}", &key, &value)) {
			if (!g_strcmp0(key, "FromMsgId")) {
				setCbConfig.msgIDs[i].net3gpp.fromMsgId = g_variant_get_uint16(value);
			}
			if (!g_strcmp0(key, "ToMsgId")) {
				setCbConfig.msgIDs[i].net3gpp.toMsgId = g_variant_get_uint16(value);
			}
			if (!g_strcmp0(key, "CBCategory")) {
				setCbConfig.msgIDs[i].net3gpp2.cbCategory = g_variant_get_uint16(value);
			}
			if (!g_strcmp0(key, "CBLanguage")) {
				setCbConfig.msgIDs[i].net3gpp2.cbLanguage = g_variant_get_uint16(value);
			}
			if (!g_strcmp0(key, "Selected")) {
				setCbConfig.msgIDs[i].net3gpp2.selected = g_variant_get_byte(value);
			}
		}
		i++;
		g_variant_iter_free(iter_row);
		if ( i >= SMS_GSM_SMS_CBMI_LIST_SIZE_MAX )
			break;
	}
	g_variant_iter_free(iter);

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_cb_config), &setCbConfig);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_CB_CONFIG);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

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

	if (!check_access_control (invocation, AC_SMS, "w"))
		return TRUE;

	memStatus.memory_status = arg_memoryStatus;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_mem_status), &memStatus);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_MEM_STATUS);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
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

	if (!check_access_control (invocation, AC_SMS, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_get_pref_bearer), &getPrefBearer);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_PREF_BEARER);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
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

	if (!check_access_control (invocation, AC_SMS, "w"))
		return TRUE;

	setPrefBearer.svc = arg_bearerType;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_pref_bearer), &setPrefBearer);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_PREF_BEARER);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_set_delivery_report(TelephonySms *sms, GDBusMethodInvocation *invocation,
	GVariant *arg_sca,
	gint arg_tpdu_length,
	GVariant *arg_tpdu_data,
	gint arg_rpCause,
	gpointer user_data)
{
	struct treq_sms_set_delivery_report deliveryReport;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	int i = 0;
	GVariantIter *iter = 0;
	GVariant *inner_gv = 0;

	if (!check_access_control (invocation, AC_SMS, "w"))
		return TRUE;

	memset(&deliveryReport, 0, sizeof(struct treq_sms_set_delivery_report));

	inner_gv = g_variant_get_variant( arg_sca );
	g_variant_get(inner_gv, "ay", &iter);
	while( g_variant_iter_loop(iter, "y", &deliveryReport.dataInfo.sca[i] ) ) {
		i++;
		if( i >= SMS_SMSP_ADDRESS_LEN )
			break;
	}

	i = 0;
	inner_gv = g_variant_get_variant( arg_tpdu_data );
	g_variant_get(inner_gv, "ay", &iter);
	while( g_variant_iter_loop(iter, "y", &deliveryReport.dataInfo.tpduData[i] ) ) {
		i++;
		if( i >= SMS_SMDATA_SIZE_MAX + 1 )
			break;
	}

	deliveryReport.dataInfo.msgLength = arg_tpdu_length;

	deliveryReport.rspType = arg_rpCause;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_delivery_report), &deliveryReport);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_DELIVERY_REPORT);

	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

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

	if (!check_access_control (invocation, AC_SMS, "w"))
		return TRUE;

	msgStatus.index = arg_index;
	msgStatus.msgStatus = arg_msgStatus;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_msg_status), &msgStatus);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_MSG_STATUS);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
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

	if (!check_access_control (invocation, AC_SMS, "r"))
		return TRUE;

	getParams.index = arg_index;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_get_params), &getParams);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_PARAMS);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_set_sms_params(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gint arg_recordIndex,
	gint arg_recordLen,
	gint arg_alphaIdLen,
	GVariant *arg_alphaId,
	gint arg_paramIndicator,
	gint arg_destAddr_DialNumLen,
	gint arg_destAddr_Ton,
	gint arg_destAddr_Npi,
	GVariant *arg_destAddr_DiallingNum,
	gint arg_svcCntrAddr_DialNumLen,
	gint arg_SvcCntrAddr_Ton,
	gint arg_svcCntrAddr_Npi,
	GVariant *arg_svcCntrAddr_DialNum,
	gint arg_protocolId,
	gint arg_dataCodingScheme,
	gint arg_validityPeriod,
	gpointer user_data)
{
	struct treq_sms_set_params setParams;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	int i = 0;
	GVariantIter *iter = 0;
	GVariant *inner_gv = 0;

	if (!check_access_control (invocation, AC_SMS, "w"))
		return TRUE;

	memset(&setParams, 0, sizeof(struct treq_sms_set_params));

	setParams.params.recordIndex = arg_recordIndex;
	setParams.params.recordLen = arg_recordLen;
	setParams.params.alphaIdLen = arg_alphaIdLen;

	inner_gv = g_variant_get_variant( arg_alphaId );
	g_variant_get(inner_gv, "ay", &iter);
	while( g_variant_iter_loop(iter, "y", &setParams.params.szAlphaId[i] ) ) {
		i++;
		if( i >= SMS_SMSP_ALPHA_ID_LEN_MAX + 1 )
			break;
	}

	setParams.params.paramIndicator = arg_paramIndicator;

	setParams.params.tpDestAddr.dialNumLen = arg_destAddr_DialNumLen;
	setParams.params.tpDestAddr.typeOfNum = arg_destAddr_Ton;
	setParams.params.tpDestAddr.numPlanId = arg_destAddr_Npi;

	i = 0;
	inner_gv = g_variant_get_variant( arg_destAddr_DiallingNum );
	g_variant_get(inner_gv, "ay", &iter);
	while( g_variant_iter_loop(iter, "y", &setParams.params.tpDestAddr.diallingNum[i] ) ) {
		i++;
		if( i >= SMS_SMSP_ADDRESS_LEN + 1 )
			break;
	}

	setParams.params.tpSvcCntrAddr.dialNumLen = arg_svcCntrAddr_DialNumLen;
	setParams.params.tpSvcCntrAddr.typeOfNum = arg_SvcCntrAddr_Ton;
	setParams.params.tpSvcCntrAddr.numPlanId = arg_svcCntrAddr_Npi;

	i = 0;
	inner_gv = g_variant_get_variant( arg_svcCntrAddr_DialNum );
	g_variant_get(inner_gv, "ay", &iter);
	while( g_variant_iter_loop(iter, "y", &setParams.params.tpSvcCntrAddr.diallingNum[i] ) ) {
		i++;
		if( i >= SMS_SMSP_ADDRESS_LEN + 1 )
			break;
	}

	setParams.params.tpProtocolId = arg_protocolId;
	setParams.params.tpDataCodingScheme = arg_dataCodingScheme;
	setParams.params.tpValidityPeriod = arg_validityPeriod;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sms_set_params), &setParams);
	tcore_user_request_set_command(ur, TREQ_SMS_SET_PARAMS);

	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_get_sms_param_cnt(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	if (!check_access_control (invocation, AC_SMS, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, sms, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_SMS_GET_PARAMCNT);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sms_get_sms_ready_status(TelephonySms *sms, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	GSList *co_list = NULL;
	CoreObject *co_sms = NULL;
	TcorePlugin *plugin = NULL;
	gboolean ready_status = FALSE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_SMS);
	if (!co_list) {
		dbg("error- co_list is NULL");
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}

	co_sms = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	if (!co_sms) {
		dbg("error- co_sms is NULL");
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}

	ready_status = tcore_sms_get_ready_status(co_sms);
	dbg("ready_status = %d", ready_status);
	telephony_sms_complete_get_sms_ready_status(sms, invocation, ready_status);

	return TRUE;
}

gboolean dbus_plugin_setup_sms_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonySms *sms;

	sms = telephony_sms_skeleton_new();
	telephony_object_skeleton_set_sms(object, sms);
	g_object_unref(sms);

	g_signal_connect(sms,
			"handle-send-msg",
			G_CALLBACK (on_sms_send_msg),
			ctx);

	g_signal_connect(sms,
			"handle-read-msg",
			G_CALLBACK (on_sms_read_msg),
			ctx);

	g_signal_connect(sms,
			"handle-save-msg",
			G_CALLBACK (on_sms_save_msg),
			ctx);

	g_signal_connect(sms,
			"handle-delete-msg",
			G_CALLBACK (on_sms_delete_msg),
			ctx);

	g_signal_connect(sms,
			"handle-get-msg-count",
			G_CALLBACK (on_sms_get_msg_count),
			ctx);

	g_signal_connect(sms,
			"handle-get-sca",
			G_CALLBACK (on_sms_get_sca),
			ctx);

	g_signal_connect(sms,
			"handle-set-sca",
			G_CALLBACK (on_sms_set_sca),
			ctx);

	g_signal_connect(sms,
			"handle-get-cb-config",
			G_CALLBACK (on_sms_get_cb_config),
			ctx);

	g_signal_connect(sms,
			"handle-set-cb-config",
			G_CALLBACK (on_sms_set_cb_config),
			ctx);

	g_signal_connect(sms,
			"handle-set-mem-status",
			G_CALLBACK (on_sms_set_mem_status),
			ctx);

	g_signal_connect(sms,
		"handle-get-pref-bearer",
		G_CALLBACK (on_sms_get_pref_bearer),
		ctx);

	g_signal_connect(sms,
			"handle-set-pref-bearer",
			G_CALLBACK (on_sms_set_pref_bearer),
			ctx);

	g_signal_connect(sms,
			"handle-set-delivery-report",
			G_CALLBACK (on_sms_set_delivery_report),
			ctx);

	g_signal_connect(sms,
			"handle-set-msg-status",
			G_CALLBACK (on_sms_set_msg_status),
			ctx);

	g_signal_connect(sms,
			"handle-get-sms-params",
			G_CALLBACK (on_sms_get_sms_params),
			ctx);

	g_signal_connect(sms,
			"handle-set-sms-params",
			G_CALLBACK (on_sms_set_sms_params),
			ctx);

	g_signal_connect(sms,
			"handle-get-sms-param-cnt",
			G_CALLBACK (on_sms_get_sms_param_cnt),
			ctx);

	g_signal_connect(sms,
			"handle-get-sms-ready-status",
			G_CALLBACK (on_sms_get_sms_ready_status),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_sms_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	GSList *co_list;
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

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_SMS);
	if (!co_list) {
		return FALSE;
	}

	co_sms = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	if (!co_sms) {
		return FALSE;
	}

	switch (command) {
		case TRESP_SMS_SEND_UMTS_MSG: {
			const struct tresp_sms_send_umts_msg *resp = data;

			dbg("receive TRESP_SMS_SEND_UMTS_MSG (result:[0x%x])", resp->result);
			telephony_sms_complete_send_msg(dbus_info->interface_object, dbus_info->invocation, resp->result);

			}
			break;

		case TRESP_SMS_SEND_CDMA_MSG: {
			const struct tresp_sms_send_cdma_msg *resp = data;

			dbg("receive TRESP_SMS_SEND_CDMA_MSG (result:[0x%x])", resp->result);
			}
			break;

		case TRESP_SMS_READ_MSG: {
			const struct tresp_sms_read_msg *resp = data;
			GVariant *sca = 0, *packet_sca = 0;
			GVariant *tpdu = 0, *packet_tpdu = 0;
			GVariantBuilder b;

			dbg("receive TRESP_SMS_READ_MSG (result:[0x%x])", resp->result);
			g_variant_builder_init (&b, G_VARIANT_TYPE("ay"));

			for( i=0; i<SMS_SMSP_ADDRESS_LEN; i++) {
				g_variant_builder_add(&b, "y", resp->dataInfo.smsData.sca[i] );
			}
			sca = g_variant_builder_end(&b);

			g_variant_builder_init (&b, G_VARIANT_TYPE("ay"));

			for( i=0; i<SMS_SMDATA_SIZE_MAX + 1; i++) {
				g_variant_builder_add(&b, "y", resp->dataInfo.smsData.tpduData[i] );
			}
			tpdu = g_variant_builder_end(&b);

			packet_sca = g_variant_new("v", sca);
			packet_tpdu = g_variant_new("v", tpdu);

			telephony_sms_complete_read_msg(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->dataInfo.simIndex,
				resp->dataInfo.msgStatus,
				packet_sca,
				resp->dataInfo.smsData.msgLength,
				packet_tpdu);
			}
			break;

		case TRESP_SMS_SAVE_MSG: {
			const struct tresp_sms_save_msg *resp = data;

			dbg("receive TRESP_SMS_SAVE_MSG (result:[0x%x])", resp->result);
			telephony_sms_complete_save_msg (dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->index);
			}
			break;

		case TRESP_SMS_DELETE_MSG: {
			const struct tresp_sms_delete_msg *resp = data;

			dbg("receive TRESP_SMS_DELETE_MSG (result:[0x%x])", resp->result);
			telephony_sms_complete_delete_msg(dbus_info->interface_object, dbus_info->invocation,
				resp->result, resp->index);

			}
			break;

		case TRESP_SMS_GET_STORED_MSG_COUNT: {
			const struct tresp_sms_get_storedMsgCnt *resp = data;
			GVariant *list;
			GVariantBuilder b;
			unsigned int loop_var;

			dbg("receive TRESP_SMS_GET_STORED_MSG_COUNT (result:[0x%x])", resp->result);
			g_variant_builder_init (&b, G_VARIANT_TYPE("ai"));

			for (loop_var=0; loop_var<resp->storedMsgCnt.totalCount; loop_var++) {
				g_variant_builder_add(&b, "i", resp->storedMsgCnt.indexList[loop_var]);
			}
			list = g_variant_builder_end(&b);

			telephony_sms_complete_get_msg_count(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->storedMsgCnt.totalCount,
				resp->storedMsgCnt.usedCount,
				list);
			}
			break;

		case TRESP_SMS_GET_SCA: {
			const struct tresp_sms_get_sca *resp = data;
			GVariant *sca = 0, *packet_sca = 0;
			GVariantBuilder b;

			dbg("receive TRESP_SMS_GET_SCA (result:[0x%x])", resp->result);
			g_variant_builder_init (&b, G_VARIANT_TYPE("ay"));

			for( i=0; i<SMS_SMSP_ADDRESS_LEN + 1; i++) {
				g_variant_builder_add(&b, "y", resp->scaAddress.diallingNum[i] );
			}
			sca = g_variant_builder_end(&b);

			packet_sca = g_variant_new("v", sca);

			telephony_sms_complete_get_sca(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
				resp->scaAddress.typeOfNum,
				resp->scaAddress.numPlanId,
				resp->scaAddress.dialNumLen,
				packet_sca);
			}
			break;

		case TRESP_SMS_SET_SCA: {
			const struct tresp_sms_set_sca *resp = data;

			dbg("receive TRESP_SMS_SET_SCA (result:[0x%x])", resp->result);
			telephony_sms_complete_set_sca(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_GET_CB_CONFIG: {
			const struct tresp_sms_get_cb_config *resp = data;
			GVariant *result = NULL;
			GVariantBuilder b;

			dbg("receive TRESP_SMS_GET_CB_CONFIG (result:[0x%x])", resp->result);
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

			dbg("receive TRESP_SMS_SET_CB_CONFIG (result:[0x%x])", resp->result);
			telephony_sms_complete_set_cb_config(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_SET_MEM_STATUS: {
			const struct tresp_sms_set_mem_status *resp = data;

			dbg("receive TRESP_SMS_SET_MEM_STATUS (result:[0x%x])", resp->result);
			telephony_sms_complete_set_mem_status(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;
		case TRESP_SMS_GET_PREF_BEARER: {
			const struct tresp_sms_get_pref_bearer *resp = data;

			dbg("receive TRESP_SMS_GET_PREF_BEARER (result:[0x%x])", resp->result);
			telephony_sms_complete_get_pref_bearer(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_SET_PREF_BEARER: {
			const struct tresp_sms_set_pref_bearer *resp = data;

			dbg("receive TRESP_SMS_SET_PREF_BEARER (result:[0x%x])", resp->result);
			telephony_sms_complete_set_pref_bearer(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_SET_DELIVERY_REPORT: {
			const struct tresp_sms_set_delivery_report *resp = data;

			dbg("receive TRESP_SMS_SET_DELIVERY_REPORT (result:[0x%x])", resp->result);
			telephony_sms_complete_set_delivery_report(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_SET_MSG_STATUS: {
			const struct tresp_sms_set_mem_status *resp = data;

			dbg("receive TRESP_SMS_SET_MSG_STATUS (result:[0x%x])", resp->result);
			telephony_sms_complete_set_msg_status(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_GET_PARAMS: {
			const struct tresp_sms_get_params *resp = data;
			GVariant *alphaId = 0, *packet_alphaId = 0;
			GVariant *destDialNum = 0, *packet_destDialNum = 0;
			GVariant *scaDialNum = 0, *packet_scaDialNum = 0;
			GVariantBuilder b;

			dbg("receive TRESP_SMS_GET_PARAMS (result:[0x%x])", resp->result);
			g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));
			for( i=0; i<SMS_SMSP_ALPHA_ID_LEN_MAX + 1; i++) {
				g_variant_builder_add(&b, "y", resp->paramsInfo.szAlphaId[i] );
			}
			alphaId = g_variant_builder_end(&b);

			g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));
			for( i=0; i<SMS_SMSP_ADDRESS_LEN + 1; i++) {
				g_variant_builder_add(&b, "y", resp->paramsInfo.tpDestAddr.diallingNum[i] );
			}
			destDialNum = g_variant_builder_end(&b);

			g_variant_builder_init(&b, G_VARIANT_TYPE("ay"));
			for( i=0; i<SMS_SMSP_ADDRESS_LEN + 1; i++) {
				g_variant_builder_add(&b, "y", resp->paramsInfo.tpSvcCntrAddr.diallingNum[i] );
			}
			scaDialNum = g_variant_builder_end(&b);

			packet_alphaId = g_variant_new("v", alphaId);
			packet_destDialNum = g_variant_new("v", destDialNum);
			packet_scaDialNum = g_variant_new("v", scaDialNum);

			telephony_sms_complete_get_sms_params(dbus_info->interface_object, dbus_info->invocation,
				resp->result,
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

			dbg("receive TRESP_SMS_SET_PARAMS (result:[0x%x])", resp->result);
			telephony_sms_complete_set_sms_params(dbus_info->interface_object, dbus_info->invocation,
				resp->result);

			}
			break;

		case TRESP_SMS_GET_PARAMCNT: {
			const struct tresp_sms_get_paramcnt *resp = data;

			dbg("receive TRESP_SMS_GET_PARAMCNT (result:[0x%x])", resp->result);
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

gboolean dbus_plugin_sms_notification(struct custom_data *ctx, CoreObject *source, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonySms *sms;
	const char *cp_name;

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	sms = telephony_object_peek_sms(TELEPHONY_OBJECT(object));

	switch (command) {
		case TNOTI_SMS_INCOM_MSG: {
			const struct tnoti_sms_umts_msg *noti = data;

			GVariant *sca = 0, *packet_sca = 0;
			GVariant *tpdu = 0, *packet_tpdu = 0;
			GVariantBuilder b;
			unsigned int i;

			info("[DBUSINFO][%s] SMS_INCOM_MSG (len[%d])", cp_name, data_len);

			g_variant_builder_init (&b, G_VARIANT_TYPE("ay"));
			for( i=0; i<SMS_SMSP_ADDRESS_LEN; i++) {
				g_variant_builder_add(&b, "y", noti->msgInfo.sca[i] );
			}
			sca = g_variant_builder_end(&b);

			g_variant_builder_init (&b, G_VARIANT_TYPE("ay"));
			for( i=0; i<SMS_SMDATA_SIZE_MAX + 1; i++) {
				g_variant_builder_add(&b, "y", noti->msgInfo.tpduData[i] );
			}
			tpdu = g_variant_builder_end(&b);

			packet_sca = g_variant_new("v", sca);
			packet_tpdu = g_variant_new("v", tpdu);

			telephony_sms_emit_incomming_msg(sms,
				packet_sca,
				noti->msgInfo.msgLength,
				packet_tpdu);
			}
			break;

		case TNOTI_SMS_CB_INCOM_MSG: {
			const struct tnoti_sms_cellBroadcast_msg *noti = data;
			GVariant *msgData = 0, *packet_msgData = 0;
			GVariantBuilder b;
			int i;

			info("[DBUSINFO][%s] SMS_CB_INCOM_MSG (len[%d])", cp_name, data_len);

			g_variant_builder_init (&b, G_VARIANT_TYPE("ay"));

			for( i=0; i < (int)noti->cbMsg.length + 1; i++) {
				g_variant_builder_add(&b, "y", noti->cbMsg.msgData[i] );
			}
			msgData = g_variant_builder_end(&b);
			packet_msgData = g_variant_new("v", msgData);

			telephony_sms_emit_incomming_cb_msg(sms,
				noti->cbMsg.cbMsgType,
				noti->cbMsg.length,
				packet_msgData);
			}
			break;

		case TNOTI_SMS_ETWS_INCOM_MSG: {
			const struct tnoti_sms_etws_msg *noti = data;
			GVariant *msgData = 0, *packet_msgData = 0;
			GVariantBuilder b;
			unsigned int i;

			info("[DBUSINFO][%s] ETWS_INCOM_MSG (len[%d])", cp_name, data_len);

			g_variant_builder_init (&b, G_VARIANT_TYPE("ay"));

			for( i=0; i<SMS_ETWS_SIZE_MAX + 1; i++) {
				g_variant_builder_add(&b, "y", noti->etwsMsg.msgData[i] );
			}
			msgData = g_variant_builder_end(&b);
			packet_msgData = g_variant_new("v", msgData);

			telephony_sms_emit_incomming_etws_msg(sms,
				noti->etwsMsg.etwsMsgType,
				noti->etwsMsg.length,
				packet_msgData);
			}
			break;

		case TNOTI_SMS_INCOM_EX_MSG: {
			info("[DBUSINFO][%s] SMS_INCOM_EX_MSG (len[%d])", cp_name, data_len);
			}
			break;

		case TNOTI_SMS_CB_INCOM_EX_MSG: {
			info("[DBUSINFO][%s] CB_INCOM_EX_MSG (len[%d])", cp_name, data_len);
			}
			break;

		case TNOTI_SMS_MEMORY_STATUS: {
			const struct tnoti_sms_memory_status *noti = data;
			info("[DBUSINFO][%s] SMS_MEMORY_STATUS (%d)", cp_name, noti->status);
			telephony_sms_emit_memory_status(sms, noti->status);
			}
			break;

		case TNOTI_SMS_DEVICE_READY: {
			const struct tnoti_sms_ready_status *noti = data;
			info("[DBUSINFO][%s] SMS_DEVICE_READY (%d)", cp_name, noti->status);
#ifdef ENABLE_KPI_LOGS
			if (noti->status == TRUE)
				TIME_CHECK("[%s] SMS Service Ready", cp_name);
#endif
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
