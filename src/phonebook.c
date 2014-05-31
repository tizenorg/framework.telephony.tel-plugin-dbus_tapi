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
#include <co_phonebook.h>
#include <co_sim.h>

#include "generated-code.h"
#include "common.h"
#include "sat_manager.h"

static char* dbg_dbus_pb_type_name[] = {"PB_TYPE_FDN", "PB_TYPE_ADN", "PB_TYPE_SDN",
		"PB_TYPE_USIM", "PB_TYPE_AAS", "PB_TYPE_GAS", };
static char* dbg_dbus_pb_adf_field_name[] = { "NO VALUE 0", "PB_FIELD_NAME", "PB_FIELD_NUMBER",
		"PB_FIELD_ANR1", "PB_FIELD_ANR2", "PB_FIELD_ANR3", "PB_FIELD_EMAIL1",
		"PB_FIELD_EMAIL2", "PB_FIELD_EMAIL3", "PB_FIELD_EMAIL4", "PB_FIELD_SNE",
		"PB_FIELD_GRP", "PB_FIELD_PBC" };
static char* dbg_dbus_pb_ton_name[] = { "PB_TON_UNKNOWN", "PB_TON_INTERNATIONAL",
		"PB_TON_NATIONAL", "PB_TON_NETWORK_SPECIFIC", "PB_TON_DEDICATED_ACCESS",
		"PB_TON_ALPHA_NUMERIC", "PB_TON_ABBREVIATED_NUMBER",
		"PB_TON_RESERVED_FOR_EXT", };
static char* dbg_dbus_pb_dcs_name[] = { "PB_TEXT_ASCII", "PB_TEXT_GSM7BIT",
		"PB_TEXT_UCS2", "PB_TEXT_HEX", };

static gboolean on_phonebook_get_init_status(TelephonyPhonebook *phonebook, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	gboolean pb_status = FALSE;
	struct tel_phonebook_support_list *list = NULL;
	CoreObject *co_pb = NULL;
	TcorePlugin *plugin = NULL;
	char *cp_name = GET_PLUGIN_NAME(invocation);

	if (check_access_control(invocation, AC_PHONEBOOK, "r") == FALSE)
		return FALSE;

	dbg("Func Entrance");

	plugin = tcore_server_find_plugin(ctx->server, cp_name);
	co_pb = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_PHONEBOOK);
	if (!co_pb) {
		dbg("error- co_pb is NULL");
		return FALSE;
	}

	pb_status = tcore_phonebook_get_status(co_pb);
	list = tcore_phonebook_get_support_list(co_pb);

	dbg("list->b_fdn[%d]",list->b_fdn);
	dbg("list->b_adn[%d]",list->b_adn);
	dbg("list->b_sdn[%d]",list->b_sdn);
	dbg("list->b_usim[%d]",list->b_usim);
	dbg("list->b_aas[%d]",list->b_aas);
	dbg("list->b_gas[%d]",list->b_gas);

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

	if (check_access_control(invocation, AC_PHONEBOOK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, phonebook, invocation);
	memset(&pb_count, 0, sizeof(struct treq_phonebook_get_count));

	pb_count.phonebook_type = arg_req_type;
	dbg("req phonebook_type[%d][%s]", pb_count.phonebook_type, dbg_dbus_pb_type_name[pb_count.phonebook_type]);
	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_get_count), &pb_count);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_GETCOUNT);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_phonebook_complete_get_count(phonebook, invocation, PB_FAIL, 0, 0, 0);
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

	if (check_access_control(invocation, AC_PHONEBOOK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, phonebook, invocation);
	memset(&pb_info, 0, sizeof(struct treq_phonebook_get_info));

	pb_info.phonebook_type = arg_req_type;
	dbg("req phonebook_type[%d][%s]", pb_info.phonebook_type, dbg_dbus_pb_type_name[pb_info.phonebook_type]);
	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_get_info), &pb_info);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_GETMETAINFO);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_phonebook_complete_get_info(phonebook, invocation, PB_FAIL, 0, 0, 0,	0, 0);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_phonebook_get_usim_info(TelephonyPhonebook *phonebook, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_PHONEBOOK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, phonebook, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_GETUSIMINFO);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		GVariant *gv = NULL;
		GVariantBuilder b;
		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		gv = g_variant_builder_end(&b);
		telephony_phonebook_complete_get_usim_meta_info (phonebook, invocation, PB_FAIL, gv);
		g_variant_unref(gv);
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

	if (check_access_control(invocation, AC_PHONEBOOK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, phonebook, invocation);
	memset(&pb_read, 0, sizeof(struct treq_phonebook_read_record));

	pb_read.index = (unsigned short)arg_index;
	pb_read.phonebook_type = arg_req_type;
	dbg("req phonebook_type[%d][%s]", pb_read.phonebook_type, dbg_dbus_pb_type_name[pb_read.phonebook_type]);
	dbg("req index[%d]", pb_read.index);
	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_read_record), &pb_read);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_READRECORD);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_phonebook_complete_read_record(phonebook, invocation, PB_FAIL,
				0, 0, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL, 0);
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
	int i=0;
	int dest_len = 0;
	int temp_len = 0;

	if (check_access_control(invocation, AC_PHONEBOOK, "r") == FALSE)
		return FALSE;

	memset(&pb_update, 0, sizeof(struct treq_phonebook_update_record));

	dbg("arg_type[%d]",arg_type);
	dbg("arg_index[%d]",arg_index);
	dbg("arg_name[%s]",arg_name);
	dbg("arg_dcs[%d]",arg_dcs);
	dbg("arg_number[%s]",arg_number);
	dbg("arg_ton[%d]",arg_ton);

	if(arg_type == PB_TYPE_USIM) {
		dbg("arg_sne[%s]",arg_sne);
		dbg("arg_sne_dcs[%d]",arg_sne_dcs);
		dbg("arg_number2[%s]",arg_number2 );
		dbg("arg_number2_ton[%d]",arg_number2_ton );
		dbg("arg_number3[%s]",arg_number3 );
		dbg("arg_number3_ton[%d]",arg_number3_ton );
		dbg("arg_number4[%s]",arg_number4 );
		dbg("arg_number4_ton[%d]",arg_number4_ton );
		dbg("arg_email1[%s]",arg_email1 );
		dbg("arg_email2[%s]",arg_email2 );
		dbg("arg_email3[%s]",arg_email3 );
		dbg("arg_email4[%s]",arg_email4 );
		dbg("arg_group_index[%d]",arg_group_index );
		//dbg("arg_pb_control[%d]",arg_pb_control );
	}

	pb_update.index = (unsigned short)arg_index;
	pb_update.phonebook_type = arg_type;
	dbg("req phonebook_type[%d][%s]", pb_update.phonebook_type, dbg_dbus_pb_type_name[pb_update.phonebook_type]);
	dbg("req index[%d]", pb_update.index);

	if(arg_name != NULL && (temp_len=strlen(arg_name))){
		dest_len = 0;

		if(tcore_util_convert_utf8_to_gsm(pb_update.name, &dest_len, (unsigned char*)arg_name, temp_len)) {
			pb_update.dcs = PB_TEXT_GSM7BIT;
			pb_update.name_len = temp_len;
			dbg("arg_name is converted successfully.");
			dbg("pb_update.name=[%s]", pb_update.name);
		}
		else if(tcore_util_convert_utf8_to_ucs2(pb_update.name, &dest_len, (unsigned char*)arg_name, temp_len)) {
			//swap string to a little-endian ucs2 string.	ex) ABC : 41 00 42 00 43 00
			unsigned short *src = NULL, *dest = NULL;
			src = (unsigned short*)malloc(dest_len);
			dest = (unsigned short*)malloc(dest_len);
			if(src==NULL || dest==NULL) {
				dbg("malloc is failed.");
				return FALSE;
			}
			memcpy(src, pb_update.name, dest_len);
			tcore_util_swap_byte_order(dest, src, dest_len/2);
			memcpy(pb_update.name, dest, dest_len);
			if(src!=NULL)	free(src);
			if(dest!=NULL)	free(dest);

			pb_update.dcs = PB_TEXT_UCS2;
			pb_update.name_len = dest_len;
			dbg("arg_name is converted successfully.");
			for(i=0; i<pb_update.name_len; i++) {
				dbg("pb_update.name[%d]=[%02x]", i, pb_update.name[i]);
			}
		}
		else {
			dbg("converting arg_name is failed.");
			return FALSE;
		}
	}
	if(arg_sne != NULL && (temp_len=strlen(arg_sne))){
		dest_len = 0;
		if(tcore_util_convert_utf8_to_gsm(pb_update.sne, &dest_len, (unsigned char*)arg_sne, temp_len)) {
			pb_update.sne_dcs = PB_TEXT_GSM7BIT;
			pb_update.sne_len = temp_len;
			dbg("arg_sne is converted successfully.");
			dbg("pb_update.sne=[%s]", pb_update.sne);
		}
		else if(tcore_util_convert_utf8_to_ucs2(pb_update.sne, &dest_len, (unsigned char*)arg_sne, temp_len)) {
			//swap string to a little-endian ucs2 string.	ex) ABC : 41 00 42 00 43 00
			unsigned short *src = NULL, *dest = NULL;
			src = (unsigned short*)malloc(dest_len);
			dest = (unsigned short*)malloc(dest_len);
			if(src==NULL || dest==NULL) {
				dbg("malloc is failed.");
				return FALSE;
			}
			memcpy(src, pb_update.sne, dest_len);
			tcore_util_swap_byte_order(dest, src, dest_len/2);
			memcpy(pb_update.sne, dest, dest_len);
			if(src!=NULL)	free(src);
			if(dest!=NULL)	free(dest);

			pb_update.sne_dcs = PB_TEXT_UCS2;
			pb_update.sne_len = dest_len;
			dbg("arg_sne is converted successfully.");
			for(i=0; i<pb_update.sne_len; i++) {
				dbg("pb_update.sne[%d]=[%02x]", i, pb_update.sne[i]);
			}
		}
		else {
			dbg("converting arg_sne is failed.");
			return FALSE;
		}
	}
	if(arg_number != NULL && (temp_len=strlen(arg_number))){
		dest_len = 0;
		if(arg_number[0]=='+') {
			dbg("arg_number[0] is '+'. TON should be a INTERNATIONAL number.");
			arg_number++;
			temp_len--;
			pb_update.ton = PB_TON_INTERNATIONAL;
		}
		else {
			pb_update.ton = arg_ton;
		}
		if(tcore_util_convert_utf8_to_gsm(pb_update.number, &dest_len, (unsigned char*)arg_number, temp_len) == FALSE) {
			return FALSE;
		}
		dbg("arg_number is converted successfully.");
		dbg("pb_update.number=[%s]", pb_update.number);
	}
	if(arg_number2 != NULL && (temp_len=strlen(arg_number2))){
		dest_len = 0;
		if(arg_number2[0]=='+') {
			dbg("arg_number[0] is '+'. TON should be a INTERNATIONAL number.");
			arg_number2++;
			temp_len--;
			pb_update.anr1_ton = PB_TON_INTERNATIONAL;
		}
		else {
			pb_update.anr1_ton = arg_number2_ton;
		}
		if(tcore_util_convert_utf8_to_gsm(pb_update.anr1, &dest_len, (unsigned char*)arg_number2, temp_len) == FALSE) {
			return FALSE;
		}
		dbg("arg_number2 is converted successfully.");
		dbg("pb_update.anr1=[%s]", pb_update.anr1);
	}

	if(arg_number3 != NULL && (temp_len=strlen(arg_number3))){
		dest_len = 0;
		if(arg_number3[0]=='+') {
			dbg("arg_number[0] is '+'. TON should be a INTERNATIONAL number.");
			arg_number3++;
			temp_len--;
			pb_update.anr2_ton = PB_TON_INTERNATIONAL;
		}
		else {
			pb_update.anr2_ton = arg_number3_ton;
		}
		if(tcore_util_convert_utf8_to_gsm(pb_update.anr2, &dest_len, (unsigned char*)arg_number3, temp_len) == FALSE) {
			return FALSE;
		}
		dbg("arg_number3 is converted successfully.");
		dbg("pb_update.anr2=[%s]", pb_update.anr2);
	}

	if(arg_number4 != NULL && (temp_len=strlen(arg_number4))){
		dest_len = 0;
		if(arg_number4[0]=='+') {
			dbg("arg_number[0] is '+'. TON should be a INTERNATIONAL number.");
			arg_number4++;
			temp_len--;
			pb_update.anr3_ton = PB_TON_INTERNATIONAL;
		}
		else {
			pb_update.anr3_ton = arg_number4_ton;
		}
		if(tcore_util_convert_utf8_to_gsm(pb_update.anr3, &dest_len, (unsigned char*)arg_number4, temp_len) == FALSE) {
			return FALSE;
		}
		dbg("arg_number4 is converted successfully.");
		dbg("pb_update.anr3=[%s]", pb_update.anr3);
	}

	if(arg_email1 != NULL && (temp_len=strlen(arg_email1))){
		dest_len = 0;
		if(tcore_util_convert_utf8_to_gsm(pb_update.email1, &dest_len, (unsigned char*)arg_email1, temp_len) == FALSE) {
			return FALSE;
		}
		pb_update.email1_len = dest_len;
		dbg("arg_email1 is converted successfully.");
		for(i=0; i<pb_update.email1_len; i++) {
			dbg("pb_update.email1[%d]=[%02x]", i, pb_update.email1[i]);
		}
	}

	/*doesn't support additional e-mail fields in CP team*/
	/*
	if(arg_email2 != NULL && (temp_len=strlen(arg_email2))){
		dest_len = 0;
		if(tcore_util_convert_utf8_to_gsm(pb_update.email2, &dest_len, (unsigned char*) arg_email2, strlen(arg_email2)) == FALSE) {
			return FALSE;
		}
		pb_update.email2_len = dest_len;
		dbg("arg_email2 is converted successfully.")
		for(i=0; i<pb_update.email2_len; i++) {
			dbg("pb_update.email2[%d]=[%02x]", i, pb_update.email2[i]);
		}
	}

	if(arg_email3 != NULL && (temp_len=strlen(arg_email3))){
		dest_len = 0;
		if(tcore_util_convert_utf8_to_gsm(pb_update.email3, &dest_len, (unsigned char*)arg_email3, strlen(arg_email3)) == FALSE) {
			return FALSE;
		}
		pb_update.email3_len = dest_len;
		dbg("arg_email3 is converted successfully.")
		for(i=0; i<pb_update.email3_len; i++) {
			dbg("pb_update.email3[%d]=[%02x]", i, pb_update.email3[i]);
		}
	}

	if(arg_email4 != NULL && (temp_len=strlen(arg_email4))){
		dest_len = 0;
		if(tcore_util_convert_utf8_to_gsm(pb_update.email4, &dest_len, (unsigned char*)arg_email4, strlen(arg_email4)) == FALSE) {
			return FALSE;
		}
		pb_update.email4_len = dest_len;
		dbg("arg_email4 is converted successfully.")
		for(i=0; i<pb_update.email4_len; i++) {
			dbg("pb_update.email4[%d]=[%02x]", i, pb_update.email4[i]);
		}
	}
	*/

	pb_update.group_index = (unsigned short)arg_group_index;

	ur = MAKE_UR(ctx, phonebook, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_update_record), &pb_update);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_UPDATERECORD);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_phonebook_complete_update_record(phonebook, invocation, PB_FAIL);
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

	if (check_access_control(invocation, AC_PHONEBOOK, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, phonebook, invocation);
	memset(&pb_delete, 0, sizeof(struct treq_phonebook_delete_record));

	pb_delete.index = (unsigned short)arg_index;
	pb_delete.phonebook_type = arg_type;
	dbg("req phonebook_type[%d][%s]", pb_delete.phonebook_type, dbg_dbus_pb_type_name[pb_delete.phonebook_type]);
	dbg("req index[%d]", pb_delete.index);
	tcore_user_request_set_data(ur, sizeof(struct treq_phonebook_delete_record), &pb_delete);
	tcore_user_request_set_command(ur, TREQ_PHONEBOOK_DELETERECORD);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(ret != TCORE_RETURN_SUCCESS) {
		telephony_phonebook_complete_delete_record(phonebook, invocation, PB_FAIL);
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

	dbg("application command = [0x%x], data_len = %d", command, data_len);

	switch (command) {
		case TRESP_PHONEBOOK_GETCOUNT:
			dbg("dbus comm - TRESP_PHONEBOOK_GETCOUNT");
			dbg("resp pb type[%d][%s]", resp_pbcnt->type, dbg_dbus_pb_type_name[resp_pbcnt->type]);
			dbg("used[%d]total[%d]", resp_pbcnt->used_count, resp_pbcnt->total_count);
			telephony_phonebook_complete_get_count(dbus_info->interface_object, dbus_info->invocation,
					resp_pbcnt->result, resp_pbcnt->type, resp_pbcnt->used_count, resp_pbcnt->total_count);
			break;

		case TRESP_PHONEBOOK_GETMETAINFO:
			dbg("dbus comm - TRESP_PHONEBOOK_GETMETAINFO");
			dbg("resp pb type[%d][%s]", resp_entry->type, dbg_dbus_pb_type_name[resp_entry->type]);
			dbg("index min[%d]max[%d], num len max[%d] text len max[%d]", resp_entry->index_min, resp_entry->index_max, resp_entry->number_length_max, resp_entry->text_length_max);
			telephony_phonebook_complete_get_info(dbus_info->interface_object, dbus_info->invocation,
					resp_entry->result, resp_entry->type, resp_entry->index_min, resp_entry->index_max,
					resp_entry->number_length_max, resp_entry->text_length_max);
			break;

		case TRESP_PHONEBOOK_GETUSIMINFO:{
			GVariant *gv = NULL;
			GVariantBuilder b;
			int i;
			dbg("resp comm - TRESP_PHONEBOOK_GETUSIMINFO");
			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for(i=0;i < resp_capa->field_count; i++){
				g_variant_builder_open(&b,G_VARIANT_TYPE("a{sv}"));
				dbg("resp pb field type[%d][%s]", resp_capa->field_list[i].field, dbg_dbus_pb_adf_field_name[resp_capa->field_list[i].field]);
				dbg("field_type[%d], index_max[%d], text_max[%d], used_count[%d]", resp_capa->field_list[i].field, resp_capa->field_list[i].index_max, resp_capa->field_list[i].text_max, resp_capa->field_list[i].used_count);
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
			g_variant_unref(gv);
		}
			break;

		case TRESP_PHONEBOOK_READRECORD: {
			unsigned char dest_pb_name[256];
			unsigned short dest_pb_name_len = 0;
			unsigned char dest_pb_sne[256];
			unsigned short dest_pb_sne_len = 0;
			unsigned char dest_pb_email1[256];
			unsigned short dest_pb_email1_len = 0;
			int i=0;

			memset(dest_pb_name, 0x00, sizeof(unsigned char)*256);
			memset(dest_pb_sne, 0x00, sizeof(unsigned char)*256);
			memset(dest_pb_email1, 0x00, sizeof(unsigned char)*256);

			dbg("dbus comm - TRESP_PHONEBOOK_READRECORD");
			dbg("resp_pbread->type[%d][%s]", resp_pbread->phonebook_type, dbg_dbus_pb_type_name[resp_pbread->phonebook_type]);
			dbg("resp_pbread->index[%d]",resp_pbread->index );
			dbg("resp_pbread->next_index[%d]",resp_pbread->next_index );
			dbg("resp_pbread->name_len[%d]",resp_pbread->name_len);
			for(i=0; i<resp_pbread->name_len; i++)
				dbg("resp_pbread->name[%02d][0x%02x]", i, resp_pbread->name[i]);
			dbg("resp_pbread->dcs[%d][%s]",resp_pbread->dcs, dbg_dbus_pb_dcs_name[resp_pbread->dcs] );

			if(resp_pbread->name_len>0) {
				switch(resp_pbread->dcs) {
					case PB_TEXT_ASCII:
					case PB_TEXT_GSM7BIT:
						// should implement differently whether ASCII or GSM7BIT LATER
						tcore_util_convert_string_to_utf8(dest_pb_name, &dest_pb_name_len, ALPHABET_FORMAT_8BIT_DATA, resp_pbread->name, resp_pbread->name_len);
						break;
					case PB_TEXT_UCS2: {
						//swap a little-endian ucs2 string to BIG-ENDIAN UCS2 string
						unsigned short *src = NULL, *dest = NULL;
						src = (unsigned short*)malloc(resp_pbread->name_len);
						if (NULL == src){
							dbg("src alloc is failed!");
							return FALSE;
						}
						dest = (unsigned short*)malloc(resp_pbread->name_len);
						if (NULL == dest) {
							dbg("dest alloc is failed!");
							free(src);
							return FALSE;
						}
						memcpy(src, resp_pbread->name, resp_pbread->name_len);
						tcore_util_swap_byte_order(dest, src, resp_pbread->name_len/2);
						for(i=0; i<resp_pbread->name_len; i++)
							dbg("after swap : resp_pbread->name[%02d][0x%02x]", i, dest[i]);
						tcore_util_convert_string_to_utf8(dest_pb_name, &dest_pb_name_len, ALPHABET_FORMAT_UCS2, (unsigned char*)dest, resp_pbread->name_len);
						free(src);
						free(dest);
					}	break;
					default:
						tcore_util_convert_string_to_utf8(dest_pb_name, &dest_pb_name_len, 0xff , resp_pbread->name, resp_pbread->name_len);
						break;
				}
			}

			dbg("resp_pbread->number[%s]",resp_pbread->number );
			dbg("resp_pbread->ton[%d][%s]",resp_pbread->ton, dbg_dbus_pb_ton_name[resp_pbread->ton] );

			if(resp_pbread->phonebook_type == PB_TYPE_USIM) {
				dbg("resp_pbread->sne_len[%d]",resp_pbread->sne_len);
				for(i=0; i<resp_pbread->sne_len; i++)
					dbg("resp_pbread->sne[%02d][0x%02x]", i, resp_pbread->sne[i]);
				dbg("resp_pbread->sne_dcs[%d][%s]",resp_pbread->sne_dcs, dbg_dbus_pb_dcs_name[resp_pbread->sne_dcs] );

				if(resp_pbread->sne_len>0) {
					switch(resp_pbread->sne_dcs) {
						case PB_TEXT_ASCII:
						case PB_TEXT_GSM7BIT:
							// should implement differently whether ASCII or GSM7BIT LATER
							tcore_util_convert_string_to_utf8(dest_pb_sne, &dest_pb_sne_len, ALPHABET_FORMAT_8BIT_DATA, resp_pbread->sne, resp_pbread->sne_len);
							break;
						case PB_TEXT_UCS2: {
							//swap a little-endian ucs2 string to BIG-ENDIAN UCS2 string
							unsigned short *src = NULL, *dest = NULL;
							src = (unsigned short*)malloc(resp_pbread->sne_len);
							if (NULL == src){
								dbg("src alloc is failed!");
								return FALSE;
							}
							dest = (unsigned short*)malloc(resp_pbread->sne_len);
							if (NULL == dest) {
								dbg("dest alloc is failed!");
								free(src);
								return FALSE;
							}
							memcpy(src, resp_pbread->sne, resp_pbread->sne_len);
							tcore_util_swap_byte_order(dest, src, resp_pbread->sne_len/2);
							for(i=0; i<resp_pbread->sne_len; i++)
								dbg("after swap : resp_pbread->sne[%02d][0x%02x]", i, dest[i]);
							tcore_util_convert_string_to_utf8(dest_pb_sne, &dest_pb_sne_len, ALPHABET_FORMAT_UCS2, (unsigned char*)dest, resp_pbread->sne_len);
							free(src);
							free(dest);

						}	break;
						default:
							tcore_util_convert_string_to_utf8(dest_pb_sne, &dest_pb_sne_len, 0xff , resp_pbread->sne, resp_pbread->sne_len);
							break;
					}
				}
				dbg("resp_pbread->anr1[%s]",resp_pbread->anr1 );
				dbg("resp_pbread->anr1_ton[%d][%s]",resp_pbread->anr1_ton, dbg_dbus_pb_ton_name[resp_pbread->anr1_ton] );
				dbg("resp_pbread->anr2[%s]",resp_pbread->anr2 );
				dbg("resp_pbread->anr2_ton[%d][%s]",resp_pbread->anr2_ton, dbg_dbus_pb_ton_name[resp_pbread->anr2_ton] );
				dbg("resp_pbread->anr3[%s]",resp_pbread->anr3 );
				dbg("resp_pbread->anr3_ton[%d][%s]",resp_pbread->anr3_ton, dbg_dbus_pb_ton_name[resp_pbread->anr3_ton] );

				dbg("resp_pbread->email1_len[%d]",resp_pbread->email1_len);
				for(i=0; i<resp_pbread->email1_len; i++) {
					dbg("resp_pbread->email1[%02d][0x%02x]", i, resp_pbread->email1[i]);
				}
				if(resp_pbread->email1_len > 0) {
					tcore_util_convert_string_to_utf8(dest_pb_email1, &dest_pb_email1_len, ALPHABET_FORMAT_8BIT_DATA, resp_pbread->email1, resp_pbread->email1_len);
				}
				/*doesn't support additional e-mail fields in CP team*/
				/*
				dbg("resp_pbread->email2_len[%d]",resp_pbread->email2_len);
				for(i=0; i<resp_pbread->email2_len; i++) {
					dbg("resp_pbread->email2[%02d][0x%02x]", i, resp_pbread->email2[i]);
				}
				if(resp_pbread->email2_len > 0 && resp_pbread->email2 != NULL) {
					tcore_util_convert_string_to_utf8(dest_pb_email2, &dest_pb_email2_len, ALPHABET_FORMAT_8BIT_DATA, resp_pbread->email2, resp_pbread->email2_len);
				}
				dbg("resp_pbread->email3_len[%d]",resp_pbread->email3_len);
				for(i=0; i<resp_pbread->email3_len; i++) {
					dbg("resp_pbread->email3[%02d][0x%02x]", i, resp_pbread->email3[i]);
				}
				if(resp_pbread->email3_len > 0 && resp_pbread->email3 != NULL) {
					tcore_util_convert_string_to_utf8(dest_pb_email3, &dest_pb_email3_len, ALPHABET_FORMAT_8BIT_DATA, resp_pbread->email3, resp_pbread->email3_len);
				}
				dbg("resp_pbread->email4_len[%d]",resp_pbread->email4_len);
				for(i=0; i<resp_pbread->email4_len; i++) {
					dbg("resp_pbread->email4[%02d][0x%02x]", i, resp_pbread->email4[i]);
				}
				if(resp_pbread->email4_len > 0 && resp_pbread->email4 != NULL) {
					tcore_util_convert_string_to_utf8(dest_pb_email4, &dest_pb_email4_len, ALPHABET_FORMAT_8BIT_DATA, resp_pbread->email4, resp_pbread->email4_len);
				}
				*/
				dbg("resp_pbread->group_index[%d]",resp_pbread->group_index );
				dbg("resp_pbread->pb_control[%d]",resp_pbread->pb_control );
			}

			telephony_phonebook_complete_read_record(dbus_info->interface_object, dbus_info->invocation,
								resp_pbread->result, resp_pbread->phonebook_type, resp_pbread->index, resp_pbread->next_index,
								(const gchar *)dest_pb_name, resp_pbread->dcs,
								(const gchar *)resp_pbread->number, resp_pbread->ton,
								(const gchar *)dest_pb_sne, resp_pbread->sne_dcs,
								(const gchar *)resp_pbread->anr1, resp_pbread->anr1_ton,
								(const gchar *)resp_pbread->anr2, resp_pbread->anr2_ton,
								(const gchar *)resp_pbread->anr3, resp_pbread->anr3_ton,
								(const gchar *)dest_pb_email1, //(const gchar *)resp_pbread->email1,
								(const gchar *)resp_pbread->email2, (const gchar *)resp_pbread->email3, (const gchar *)resp_pbread->email4,
								resp_pbread->group_index);

		}	break;

		case TRESP_PHONEBOOK_UPDATERECORD:
			dbg("dbus comm - TRESP_PHONEBOOK_UPDATERECORD");
			telephony_phonebook_complete_update_record(dbus_info->interface_object, dbus_info->invocation,resp_pbupdate->result);
			break;

		case TRESP_PHONEBOOK_DELETERECORD:
			dbg("dbus comm - TRESP_PHONEBOOK_DELETERECORD");
			telephony_phonebook_complete_delete_record(dbus_info->interface_object, dbus_info->invocation, resp_pbdelete->result);
			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}

gboolean dbus_plugin_phonebook_notification(struct custom_data *ctx, const char *plugin_name,
		TelephonyObjectSkeleton *object, enum tcore_notification_command command,
		unsigned int data_len, const void *data)
{
	TelephonyPhonebook *phonebook;
	const struct tnoti_phonebook_status *n_pb_status = data;

	if (!object) {
		dbg("object is NULL");
		return FALSE;
	}

	phonebook = telephony_object_peek_phonebook(TELEPHONY_OBJECT(object));
	dbg("phonebook = %p", phonebook);

	switch (command) {
		case TNOTI_PHONEBOOK_STATUS :
			telephony_phonebook_emit_status(phonebook, n_pb_status->b_init);
			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}
