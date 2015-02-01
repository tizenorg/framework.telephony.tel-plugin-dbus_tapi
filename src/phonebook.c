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
#include <errno.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <hal.h>
#include <communicator.h>
#include <core_object.h>
#include <queue.h>
#include <user_request.h>
#include <util.h>
#include <co_phonebook.h>
#include <co_sim.h>

#include "generated-code.h"
#include "common.h"
#include "sat_manager.h"

static const char* dbg_dbus_pb_type_name[] = {"PB_TYPE_FDN", "PB_TYPE_ADN", "PB_TYPE_SDN",
		"PB_TYPE_USIM", "PB_TYPE_AAS", "PB_TYPE_GAS", };
static const char* dbg_dbus_pb_adf_field_name[] = { "NO VALUE 0", "PB_FIELD_NAME", "PB_FIELD_NUMBER",
		"PB_FIELD_ANR1", "PB_FIELD_ANR2", "PB_FIELD_ANR3", "PB_FIELD_EMAIL1",
		"PB_FIELD_EMAIL2", "PB_FIELD_EMAIL3", "PB_FIELD_EMAIL4", "PB_FIELD_SNE",
		"PB_FIELD_GRP", "PB_FIELD_PBC" };
static const char* dbg_dbus_pb_ton_name[] = { "PB_TON_UNKNOWN", "PB_TON_INTERNATIONAL",
		"PB_TON_NATIONAL", "PB_TON_NETWORK_SPECIFIC", "PB_TON_DEDICATED_ACCESS",
		"PB_TON_ALPHA_NUMERIC", "PB_TON_ABBREVIATED_NUMBER",
		"PB_TON_RESERVED_FOR_EXT", };

static gboolean on_phonebook_get_init_status(TelephonyPhonebook *phonebook, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	gboolean pb_status = FALSE;
	struct tel_phonebook_support_list *list = NULL;
	GSList *co_list = NULL;
	CoreObject *co_pb = NULL;
	TcorePlugin *plugin = NULL;

	if (!check_access_control (invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_PHONEBOOK);
	if (!co_list) {
		dbg("error- co_list is NULL");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}
	co_pb = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	if (!co_pb) {
		dbg("error- co_pb is NULL");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}

	pb_status = tcore_phonebook_get_status(co_pb);
	list = tcore_phonebook_get_support_list(co_pb);

	dbg("fdn[%d],adn[%d],sdn[%d],usim[%d],aas[%d],gas[%d]"
		,list->b_fdn,list->b_adn,list->b_sdn,list->b_usim,list->b_aas,list->b_gas);

	telephony_phonebook_complete_get_init_status(phonebook, invocation,
			pb_status,
			list->b_fdn,
			list->b_adn,
			list->b_sdn,
			list->b_usim,
			list->b_aas,
			list->b_gas);

	g_free(list);

	return TRUE;
}

static gboolean on_phonebook_get_count(TelephonyPhonebook *phonebook, GDBusMethodInvocation *invocation, gint arg_req_type, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_phonebook_get_count pb_count;
	TcorePlugin *plugin = NULL;
	GSList *co_list = NULL;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control (invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_PHONEBOOK);
	if (!co_list) {
		dbg("error- co_list is NULL");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}
	co_pb = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	pb_status = tcore_phonebook_get_status(co_pb);

	if(pb_status == FALSE) {
		dbg("pb_init is not completed yet.");
		telephony_phonebook_complete_get_count(phonebook, invocation, PB_ACCESS_CONDITION_NOT_SATISFIED, 0, 0, 0);
		return TRUE;
	}

	ur = MAKE_UR(ctx, phonebook, invocation);
	memset(&pb_count, 0, sizeof(struct treq_phonebook_get_count));

	pb_count.phonebook_type = arg_req_type;
	dbg("req phonebook_type[%d][%s]", pb_count.phonebook_type, dbg_dbus_pb_type_name[pb_count.phonebook_type]);
	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_get_count), &pb_count);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_GETCOUNT);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}
	return TRUE;
}

static gboolean on_phonebook_get_info(TelephonyPhonebook *phonebook, GDBusMethodInvocation *invocation, gint arg_req_type, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_phonebook_get_info pb_info;
	TcorePlugin *plugin = NULL;
	GSList *co_list = NULL;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control (invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_PHONEBOOK);
	if (!co_list) {
		dbg("error- co_list is NULL");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}
	co_pb = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	pb_status = tcore_phonebook_get_status(co_pb);

	if(pb_status == FALSE) {
		dbg("pb_init is not completed yet.");
		telephony_phonebook_complete_get_info(phonebook, invocation, PB_ACCESS_CONDITION_NOT_SATISFIED, 0, 0, 0, 0, 0, 0);
		return TRUE;
	}

	ur = MAKE_UR(ctx, phonebook, invocation);
	memset(&pb_info, 0, sizeof(struct treq_phonebook_get_info));

	pb_info.phonebook_type = arg_req_type;
	dbg("req phonebook_type[%d][%s]", pb_info.phonebook_type, dbg_dbus_pb_type_name[pb_info.phonebook_type]);
	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_get_info), &pb_info);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_GETMETAINFO);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_phonebook_get_usim_info(TelephonyPhonebook *phonebook, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	TcorePlugin *plugin = NULL;
	GSList *co_list = NULL;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control (invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_PHONEBOOK);
	if (!co_list) {
		dbg("error- co_list is NULL");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}
	co_pb = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	pb_status = tcore_phonebook_get_status(co_pb);

	if(pb_status == FALSE) {
		GVariant *gv = NULL;
		GVariantBuilder b;
		dbg("pb_init is not completed yet.");
		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		gv = g_variant_builder_end(&b);
		telephony_phonebook_complete_get_usim_meta_info (phonebook, invocation, PB_ACCESS_CONDITION_NOT_SATISFIED, gv);
		return TRUE;
	}

	ur = MAKE_UR(ctx, phonebook, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_GETUSIMINFO);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}
	return TRUE;
}

static gboolean on_phonebook_read_record(TelephonyPhonebook *phonebook, GDBusMethodInvocation *invocation,
		gint arg_req_type, gint arg_index, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_phonebook_read_record pb_read;
	TcorePlugin *plugin = NULL;
	GSList *co_list = NULL;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control (invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_PHONEBOOK);
	if (!co_list) {
		dbg("error- co_list is NULL");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}
	co_pb = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	pb_status = tcore_phonebook_get_status(co_pb);

	if(pb_status == FALSE) {
		dbg("pb_init is not completed yet.");
		telephony_phonebook_complete_read_record(phonebook, invocation, PB_ACCESS_CONDITION_NOT_SATISFIED,
				0, 0, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, 0);
		return TRUE;
	}

	ur = MAKE_UR(ctx, phonebook, invocation);
	memset(&pb_read, 0, sizeof(struct treq_phonebook_read_record));

	pb_read.index = (unsigned short)arg_index;
	pb_read.phonebook_type = arg_req_type;
	dbg("req phonebook_type[%d][%s] index[%d]",
		pb_read.phonebook_type, dbg_dbus_pb_type_name[pb_read.phonebook_type], pb_read.index);

	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_read_record), &pb_read);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_READRECORD);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}
	return TRUE;
}

static gboolean on_phonebook_update_record(TelephonyPhonebook *phonebook, GDBusMethodInvocation *invocation,
		gint arg_type, gint arg_index, const gchar *arg_name, gint arg_dcs,
		const gchar *arg_number, gint arg_ton,
		const gchar *arg_sne, gint arg_sne_dcs,
		const gchar *arg_number2, gint arg_number2_ton,
		const gchar *arg_number3,gint arg_number3_ton, const gchar *arg_number4, gint arg_number4_ton,
		const gchar *arg_email1, const gchar *arg_email2, const gchar *arg_email3, const gchar *arg_email4,
		gint arg_group_index, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_phonebook_update_record pb_update;
	TcorePlugin *plugin = NULL;
	GSList *co_list = NULL;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;
	int temp_len = 0;

	if (!check_access_control (invocation, AC_PHONEBOOK, "x"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_PHONEBOOK);
	if (!co_list) {
		dbg("error- co_list is NULL");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}
	co_pb = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	pb_status = tcore_phonebook_get_status(co_pb);

	if(pb_status == FALSE) {
		dbg("pb_init is not completed yet.");
		telephony_phonebook_complete_update_record(phonebook, invocation, PB_ACCESS_CONDITION_NOT_SATISFIED);
		return TRUE;
	}

	memset(&pb_update, 0, sizeof(struct treq_phonebook_update_record));

	dbg("pb_type[%d] index[%d] name[%s] number[%s] email[%s]",
		arg_type,arg_index,arg_name, arg_number, arg_email1);

	pb_update.index = (unsigned short)arg_index;
	pb_update.phonebook_type = arg_type;

	if(arg_name != NULL && strlen(arg_name)){
		pb_update.dcs = PB_TEXT_ASCII;
		pb_update.name_len = strlen(arg_name);
		if(pb_update.name_len > PHONEBOOK_NAME_BYTE_MAX)
			pb_update.name_len = PHONEBOOK_NAME_BYTE_MAX;
		memcpy(pb_update.name, arg_name, pb_update.name_len);
	}
	if(arg_sne != NULL && strlen(arg_sne)){
		pb_update.sne_dcs = PB_TEXT_ASCII;
		pb_update.sne_len = strlen(arg_sne);
		if(pb_update.sne_len > PHONEBOOK_NAME_BYTE_MAX)
			pb_update.sne_len = PHONEBOOK_NAME_BYTE_MAX;
		memcpy(pb_update.sne, arg_sne, pb_update.sne_len);
	}
	if(arg_number != NULL && (temp_len=strlen(arg_number))){
		pb_update.ton = arg_ton;
		if(temp_len > PHONEBOOK_NUMBER_BYTE_MAX)
			temp_len = PHONEBOOK_NUMBER_BYTE_MAX;
		memcpy(pb_update.number, arg_number, temp_len);
	}
	if(arg_number2 != NULL && (temp_len=strlen(arg_number2))){
		pb_update.anr1_ton = arg_number2_ton;
		if(temp_len > PHONEBOOK_NUMBER_BYTE_MAX)
			temp_len = PHONEBOOK_NUMBER_BYTE_MAX;
		memcpy(pb_update.anr1, arg_number2, temp_len);
	}

	if(arg_number3 != NULL && (temp_len=strlen(arg_number3))){
		pb_update.anr2_ton = arg_number3_ton;
		if(temp_len > PHONEBOOK_NUMBER_BYTE_MAX)
			temp_len = PHONEBOOK_NUMBER_BYTE_MAX;
		memcpy(pb_update.anr2, arg_number3, temp_len);
	}

	if(arg_number4 != NULL && (temp_len=strlen(arg_number4))){
		pb_update.anr3_ton = arg_number4_ton;
		if(temp_len > PHONEBOOK_NUMBER_BYTE_MAX)
			temp_len = PHONEBOOK_NUMBER_BYTE_MAX;
		memcpy(pb_update.anr3, arg_number4, temp_len);
	}

	if(arg_email1 != NULL && strlen(arg_email1)){
		pb_update.email1_len = strlen(arg_email1);
		if(pb_update.email1_len > PHONEBOOK_EMAIL_BYTE_MAX)
			pb_update.email1_len = PHONEBOOK_EMAIL_BYTE_MAX;
		memcpy(pb_update.email1, arg_email1, pb_update.email1_len);
	}
	/* Additional e-mail fields (email 2,3,4) cannot be used to CP*/

	pb_update.group_index = (unsigned short)arg_group_index;

	ur = MAKE_UR(ctx, phonebook, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_update_record), &pb_update);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_UPDATERECORD);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_phonebook_delete_record(TelephonyPhonebook *phonebook, GDBusMethodInvocation *invocation,
		gint arg_type, gint arg_index, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_phonebook_delete_record pb_delete;
	TcorePlugin *plugin = NULL;
	GSList *co_list = NULL;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control (invocation, AC_PHONEBOOK, "x"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));
	co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_PHONEBOOK);
	if (!co_list) {
		dbg("error- co_list is NULL");
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}
	co_pb = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	pb_status = tcore_phonebook_get_status(co_pb);

	if(pb_status == FALSE) {
		dbg("pb_init is not completed yet.");
		telephony_phonebook_complete_delete_record(phonebook, invocation, PB_ACCESS_CONDITION_NOT_SATISFIED);
		return TRUE;
	}

	ur = MAKE_UR(ctx, phonebook, invocation);
	memset(&pb_delete, 0, sizeof(struct treq_phonebook_delete_record));

	pb_delete.index = (unsigned short)arg_index;
	pb_delete.phonebook_type = arg_type;
	dbg("req phonebook_type[%d][%s] index[%d]",
		pb_delete.phonebook_type, dbg_dbus_pb_type_name[pb_delete.phonebook_type], pb_delete.index);

	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_delete_record), &pb_delete);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_DELETERECORD);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_phonebook_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonyPhonebook *phonebook;

	phonebook = telephony_phonebook_skeleton_new();
	telephony_object_skeleton_set_phonebook(object, phonebook);
	g_object_unref(phonebook);

	dbg("phonebook = %p", phonebook);

	g_signal_connect (phonebook,
			"handle-get-init-status",
			G_CALLBACK (on_phonebook_get_init_status),
			ctx);

	g_signal_connect (phonebook,
			"handle-get-count",
			G_CALLBACK (on_phonebook_get_count),
			ctx);

	g_signal_connect (phonebook,
			"handle-get-info",
			G_CALLBACK (on_phonebook_get_info),
			ctx);

	g_signal_connect (phonebook,
			"handle-get-usim-meta-info",
			G_CALLBACK (on_phonebook_get_usim_info),
			ctx);

	g_signal_connect (phonebook,
			"handle-read-record",
			G_CALLBACK (on_phonebook_read_record),
			ctx);

	g_signal_connect (phonebook,
			"handle-update-record",
			G_CALLBACK (on_phonebook_update_record),
			ctx);

	g_signal_connect (phonebook,
			"handle-delete-record",
			G_CALLBACK (on_phonebook_delete_record),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_phonebook_response(struct custom_data *ctx, UserRequest *ur,
		struct dbus_request_info *dbus_info, enum tcore_response_command command,
		unsigned int data_len, const void *data)
{
	const struct tresp_phonebook_get_count *resp_pbcnt = data;
	const struct tresp_phonebook_get_info *resp_entry = data;
	const struct tresp_phonebook_get_usim_info *resp_capa = data;
	const struct tresp_phonebook_read_record *resp_pbread = data;
	const struct tresp_phonebook_update_record *resp_pbupdate = data;
	const struct tresp_phonebook_delete_record *resp_pbdelete = data;

	switch (command) {
		case TRESP_PHONEBOOK_GETCOUNT:
			dbg("GETCOUNT (type[%d][%s] used[%d]total[%d])",
				resp_pbcnt->type, dbg_dbus_pb_type_name[resp_pbcnt->type],
				resp_pbcnt->used_count, resp_pbcnt->total_count);
			telephony_phonebook_complete_get_count(dbus_info->interface_object, dbus_info->invocation,
					resp_pbcnt->result, resp_pbcnt->type, resp_pbcnt->used_count, resp_pbcnt->total_count);
			break;

		case TRESP_PHONEBOOK_GETMETAINFO:
			dbg("GETMETAINFO (type[%d][%s])", resp_entry->type, dbg_dbus_pb_type_name[resp_entry->type]);
			dbg("index(min[%d]max[%d]), num_max[%d] text(max[%d]used[%d])",
				resp_entry->index_min, resp_entry->index_max, resp_entry->number_length_max, resp_entry->text_length_max, resp_entry->used_count);
			telephony_phonebook_complete_get_info(dbus_info->interface_object, dbus_info->invocation,
					resp_entry->result, resp_entry->type, resp_entry->index_min, resp_entry->index_max,
					resp_entry->number_length_max, resp_entry->text_length_max, resp_entry->used_count);
			break;

		case TRESP_PHONEBOOK_GETUSIMINFO:{
			GVariant *gv = NULL;
			GVariantBuilder b;
			int i;
			dbg("GETUSIMINFO");
			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for(i=0;i < resp_capa->field_count; i++){
				g_variant_builder_open(&b,G_VARIANT_TYPE("a{sv}"));
				dbg("type[%d][%s] index_max[%d] text_max[%d] used_count[%d]",
					resp_capa->field_list[i].field,
					dbg_dbus_pb_adf_field_name[resp_capa->field_list[i].field],
					resp_capa->field_list[i].index_max,
					resp_capa->field_list[i].text_max,
					resp_capa->field_list[i].used_count);
				g_variant_builder_add(&b, "{sv}", "field_type", g_variant_new_int32(resp_capa->field_list[i].field));
				g_variant_builder_add(&b, "{sv}", "index_max", g_variant_new_int32(resp_capa->field_list[i].index_max));
				g_variant_builder_add(&b, "{sv}", "text_max", g_variant_new_int32(resp_capa->field_list[i].text_max));
				g_variant_builder_add(&b, "{sv}", "used_count", g_variant_new_int32(resp_capa->field_list[i].used_count));
				g_variant_builder_close(&b);
			}
			gv = g_variant_builder_end(&b);

			telephony_phonebook_complete_get_usim_meta_info (dbus_info->interface_object, dbus_info->invocation,
					resp_capa->result,
					gv);
		}
			break;

		case TRESP_PHONEBOOK_READRECORD: {
			unsigned char dest_pb_name[PHONEBOOK_NAME_BYTE_MAX + 1];
			unsigned char dest_pb_sne[PHONEBOOK_NAME_BYTE_MAX + 1];
			unsigned char dest_pb_email1[PHONEBOOK_EMAIL_BYTE_MAX + 1];
			memset(dest_pb_name, 0x00, PHONEBOOK_NAME_BYTE_MAX + 1);
			memset(dest_pb_sne, 0x00, PHONEBOOK_NAME_BYTE_MAX + 1);
			memset(dest_pb_email1, 0x00, PHONEBOOK_EMAIL_BYTE_MAX + 1);
			/* Additional e-mail fields (email 2,3,4) cannot be used to CP*/

			dbg("READRECORD (type[%d][%s] index[%d][%d])",
				resp_pbread->phonebook_type, dbg_dbus_pb_type_name[resp_pbread->phonebook_type], resp_pbread->index,resp_pbread->next_index);

			if (resp_pbread->name_len > 0) {
				dbg("name:[%s] len:[%d]",resp_pbread->name, resp_pbread->name_len);
				memcpy(dest_pb_name,resp_pbread->name,resp_pbread->name_len);
			}

			dbg("number:[%s] ton:[%d][%s])",
				resp_pbread->number,resp_pbread->ton, dbg_dbus_pb_ton_name[resp_pbread->ton] );

			if(resp_pbread->phonebook_type == PB_TYPE_USIM) {
				if (resp_pbread->sne_len > 0) {
					dbg("sne:[%s] sne_len:[%d]", resp_pbread->sne,resp_pbread->sne_len);
					memcpy(dest_pb_sne,resp_pbread->sne,resp_pbread->sne_len);
				}

				if (strlen((const char*)resp_pbread->anr1) != 0 || strlen((const char*)resp_pbread->anr2) != 0 || strlen((const char*)resp_pbread->anr3) != 0) {
					dbg("anr1:([%s],ton[%d][%s])",resp_pbread->anr1,resp_pbread->anr1_ton, dbg_dbus_pb_ton_name[resp_pbread->anr1_ton]);
					dbg("anr2:([%s],ton[%d][%s])",resp_pbread->anr2,resp_pbread->anr2_ton, dbg_dbus_pb_ton_name[resp_pbread->anr2_ton]);
					dbg("anr3:([%s],ton[%d][%s])",resp_pbread->anr3,resp_pbread->anr3_ton, dbg_dbus_pb_ton_name[resp_pbread->anr3_ton]);
				}
				if (resp_pbread->email1_len > 0) {
					dbg("email1:[%s] len:[%d]",resp_pbread->email1, resp_pbread->email1_len);
					memcpy(dest_pb_email1, resp_pbread->email1, resp_pbread->email1_len);
				}
				/* Additional e-mail fields (email 2,3,4) cannot be used to CP*/
			}

			/*
			 * Check whether NAME, SNE string values are invalid utf-8 string or not,
			 * because if invalid it will be converted to "[INVALID UTF-8]" automatically by g_variant_new_string().
			 */
			if (g_utf8_validate((const gchar *)dest_pb_name, -1, NULL) == FALSE) {
				tcore_util_hex_dump("[INVALID_UTF8_NAME] ", strlen((const char*)dest_pb_name), dest_pb_name);
				dbg("Empty NAME field.");
				memset(dest_pb_name, 0x00, PHONEBOOK_NAME_BYTE_MAX + 1);
			}
			if(resp_pbread->phonebook_type == PB_TYPE_USIM) {
				if (g_utf8_validate((const gchar *)dest_pb_sne, -1, NULL) == FALSE) {
					tcore_util_hex_dump("[INVALID_UTF8_SNE] ", strlen((const char*)dest_pb_sne), dest_pb_sne);
					dbg("Empty SNE field.");
					memset(dest_pb_sne, 0x00, PHONEBOOK_NAME_BYTE_MAX + 1);
				}
			}

			telephony_phonebook_complete_read_record(dbus_info->interface_object, dbus_info->invocation,
								resp_pbread->result, resp_pbread->phonebook_type, resp_pbread->index, resp_pbread->next_index,
								(const gchar *)dest_pb_name, resp_pbread->dcs,
								(const gchar *)resp_pbread->number, resp_pbread->ton,
								(const gchar *)dest_pb_sne, resp_pbread->sne_dcs,
								(const gchar *)resp_pbread->anr1, resp_pbread->anr1_ton,
								(const gchar *)resp_pbread->anr2, resp_pbread->anr2_ton,
								(const gchar *)resp_pbread->anr3, resp_pbread->anr3_ton,
								(const gchar *)dest_pb_email1,
								(const gchar *)resp_pbread->email2,
								(const gchar *)resp_pbread->email3,
								(const gchar *)resp_pbread->email4,
								resp_pbread->group_index);

		}	break;

		case TRESP_PHONEBOOK_UPDATERECORD:
			dbg("UPDATERECORD (result[%d])", resp_pbupdate->result);
			telephony_phonebook_complete_update_record(dbus_info->interface_object, dbus_info->invocation,resp_pbupdate->result);
			break;

		case TRESP_PHONEBOOK_DELETERECORD:
			dbg("DELETERECORD (result[%d])", resp_pbdelete->result);
			telephony_phonebook_complete_delete_record(dbus_info->interface_object, dbus_info->invocation, resp_pbdelete->result);
			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}

gboolean dbus_plugin_phonebook_notification(struct custom_data *ctx, CoreObject *source,
		TelephonyObjectSkeleton *object, enum tcore_notification_command command,
		unsigned int data_len, const void *data)
{
	TelephonyPhonebook *phonebook;
	const struct tnoti_phonebook_status *n_pb_status = data;
	const char *cp_name;

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	phonebook = telephony_object_peek_phonebook(TELEPHONY_OBJECT(object));
	switch (command) {
		case TNOTI_PHONEBOOK_STATUS :

#ifdef ENABLE_KPI_LOGS
			if (n_pb_status->b_init == TRUE)
				TIME_CHECK("[%s] PBM Service Ready", cp_name);
#endif

			telephony_phonebook_emit_status(phonebook,
				n_pb_status->b_init,
				n_pb_status->support_list.b_fdn,
				n_pb_status->support_list.b_adn,
				n_pb_status->support_list.b_sdn,
				n_pb_status->support_list.b_usim,
				n_pb_status->support_list.b_aas,
				n_pb_status->support_list.b_gas);

			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}
