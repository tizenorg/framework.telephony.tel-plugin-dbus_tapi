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
#include <string.h>

#include <glib.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <co_phonebook.h>

#include "generated-code.h"
#include "dtapi_common.h"

/*
 * Printable values for debugging/logging
 */
static const char *dbg_dbus_pb_type_name[] = {
	"PB_TYPE_FDN", "PB_TYPE_ADN", "PB_TYPE_SDN",
	"PB_TYPE_USIM", "PB_TYPE_AAS", "PB_TYPE_GAS"
};

static const char *dbg_dbus_pb_adf_field_name[] = {
	"NO VALUE 0", "PB_FIELD_NAME", "PB_FIELD_NUMBER",
	"PB_FIELD_ANR1", "PB_FIELD_ANR2", "PB_FIELD_ANR3",
	"PB_FIELD_EMAIL1", "PB_FIELD_EMAIL2", "PB_FIELD_EMAIL3", "PB_FIELD_EMAIL4",
	"PB_FIELD_SNE", "PB_FIELD_GRP", "PB_FIELD_PBC"
};

static const char *dbg_dbus_pb_ton_name[] = {
	"PB_TON_UNKNOWN",
	"PB_TON_INTERNATIONAL",
	"PB_TON_NATIONAL",
	"PB_TON_NETWORK_SPECIFIC",
	"PB_TON_DEDICATED_ACCESS",
	"PB_TON_ALPHA_NUMERIC",
	"PB_TON_ABBREVIATED_NUMBER",
	"PB_TON_RESERVED_FOR_EXT"
};

#define DBUS_PBM_GET_CO_PBM(invocation, co_pbm, server) do { \
	co_pbm = __get_pbm_co_by_cp_name(server, GET_CP_NAME(invocation)); \
	if (!co_pbm) { \
		err("[%s] PBM Core object is NULL", GET_CP_NAME(invocation)); \
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED); \
		return TRUE; \
	} \
} while (0)

static CoreObject *__get_pbm_co_by_cp_name(Server *server, char *cp_name)
{
	TcorePlugin *plugin = NULL;

	if (!server) {
		err("server is NULL");
		return NULL;
	}

	plugin = tcore_server_find_plugin(server, cp_name);
	return tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_PHONEBOOK);
}

static gboolean on_phonebook_get_init_status(TelephonyPhonebook *phonebook,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	gboolean pb_status = FALSE;
	struct tel_phonebook_support_list *list = NULL;
	CoreObject *co_pb = NULL;

	if (!check_access_control(invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	DBUS_PBM_GET_CO_PBM(invocation, co_pb, ctx->server);
	pb_status = tcore_phonebook_get_status(co_pb);
	if (pb_status == FALSE) {
		/*
		 *Phonebook is NOT initialized
		 */
		dbg("pb_init is not completed yet.");

		telephony_phonebook_complete_get_init_status(phonebook,
			invocation, pb_status,
			FALSE, /* FDN */
			FALSE, /* ADN */
			FALSE, /* SDN */
			FALSE, /* USIM */
			FALSE, /* AAS */
			FALSE); /* GAS */

		return TRUE;
	}

	list = tcore_phonebook_get_support_list(co_pb);
	if (!list) {
		err("Supported phonebook list is NULL");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}

	dbg("[%s] fdn[%d],adn[%d],sdn[%d],usim[%d],aas[%d],gas[%d]",
		GET_CP_NAME(invocation),
		list->b_fdn, list->b_adn, list->b_sdn,
		list->b_usim, list->b_aas, list->b_gas);

	telephony_phonebook_complete_get_init_status(phonebook,
		invocation, pb_status,
		list->b_fdn,
		list->b_adn,
		list->b_sdn,
		list->b_usim,
		list->b_aas,
		list->b_gas);
	g_free(list);

	return TRUE;
}

static gboolean on_phonebook_get_count(TelephonyPhonebook *phonebook,
	GDBusMethodInvocation *invocation, gint req_type, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_phonebook_get_count req;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control(invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	DBUS_PBM_GET_CO_PBM(invocation, co_pb, ctx->server);
	pb_status = tcore_phonebook_get_status(co_pb);
	if (pb_status == FALSE) {
		dbg("pb_init is not completed yet.");

		telephony_phonebook_complete_get_count(phonebook,
			invocation, PB_ACCESS_CONDITION_NOT_SATISFIED, 0, 0, 0);

		return TRUE;
	}

	memset(&req, 0x0, sizeof(struct treq_phonebook_get_count));

	req.phonebook_type = req_type;
	dbg("[%s] req phonebook_type[%d][%s]", GET_CP_NAME(invocation),
		req.phonebook_type, dbg_dbus_pb_type_name[req.phonebook_type]);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, phonebook, invocation,
		TREQ_PHONEBOOK_GETCOUNT,
		&req, sizeof(struct treq_phonebook_get_count));

	return TRUE;
}

static gboolean on_phonebook_get_info(TelephonyPhonebook *phonebook,
	GDBusMethodInvocation *invocation, gint req_type, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_phonebook_get_info req;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control(invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	DBUS_PBM_GET_CO_PBM(invocation, co_pb, ctx->server);
	pb_status = tcore_phonebook_get_status(co_pb);
	if (pb_status == FALSE) {
		dbg("pb_init is not completed yet.");

		telephony_phonebook_complete_get_info(phonebook, invocation,
			PB_ACCESS_CONDITION_NOT_SATISFIED, 0, 0, 0, 0, 0, 0);

		return TRUE;
	}

	memset(&req, 0x0, sizeof(struct treq_phonebook_get_info));

	req.phonebook_type = req_type;

	dbg("[%s] req phonebook_type[%d][%s]", GET_CP_NAME(invocation),
		req.phonebook_type,
		dbg_dbus_pb_type_name[req.phonebook_type]);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, phonebook, invocation,
		TREQ_PHONEBOOK_GETMETAINFO,
		&req, sizeof(struct treq_phonebook_get_info));

	return TRUE;
}

static gboolean on_phonebook_get_usim_info(TelephonyPhonebook *phonebook,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control(invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	DBUS_PBM_GET_CO_PBM(invocation, co_pb, ctx->server);

	pb_status = tcore_phonebook_get_status(co_pb);
	if (pb_status == FALSE) {
		GVariant *gv = NULL;
		GVariantBuilder b;

		dbg("pb_init is not completed yet.");

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		gv = g_variant_builder_end(&b);

		telephony_phonebook_complete_get_usim_meta_info(phonebook, invocation,
			PB_ACCESS_CONDITION_NOT_SATISFIED, gv);

		return TRUE;
	}

	/* Dispatch request */
	dtapi_dispatch_request(ctx, phonebook, invocation,
		TREQ_PHONEBOOK_GETUSIMINFO,
		NULL, 0);

	return TRUE;
}

static gboolean on_phonebook_read_record(TelephonyPhonebook *phonebook,
	GDBusMethodInvocation *invocation,
	gint req_type, gint index,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_phonebook_read_record req;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control(invocation, AC_PHONEBOOK, "r"))
		return TRUE;

	DBUS_PBM_GET_CO_PBM(invocation, co_pb, ctx->server);
	pb_status = tcore_phonebook_get_status(co_pb);
	if (pb_status == FALSE) {
		dbg("pb_init is not completed yet.");

		telephony_phonebook_complete_read_record(phonebook, invocation,
			PB_ACCESS_CONDITION_NOT_SATISFIED,
			0, 0, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL,
			0, NULL, 0, NULL, NULL, NULL, NULL, 0);

		return TRUE;
	}

	memset(&req, 0x0, sizeof(struct treq_phonebook_read_record));

	req.index = (unsigned short)index;
	req.phonebook_type = req_type;

	dbg("[%s] req phonebook_type[%d][%s] index[%d]", GET_CP_NAME(invocation),
		req.phonebook_type,
		dbg_dbus_pb_type_name[req.phonebook_type], req.index);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, phonebook, invocation,
		TREQ_PHONEBOOK_READRECORD,
		&req, sizeof(struct treq_phonebook_read_record));

	return TRUE;
}

static gboolean on_phonebook_update_record(TelephonyPhonebook *phonebook,
	GDBusMethodInvocation *invocation,
	gint type, gint index,
	const gchar *name, gint dcs,
	const gchar *number, gint ton,
	const gchar *sne, gint sne_dcs,
	const gchar *number2, gint number2_ton,
	const gchar *number3, gint number3_ton,
	const gchar *number4, gint number4_ton,
	const gchar *email1, const gchar *email2,
	const gchar *email3, const gchar *email4,
	gint group_index, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_phonebook_update_record req;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;
	int temp_len = 0;

	if (!check_access_control(invocation, AC_PHONEBOOK, "x"))
		return TRUE;

	DBUS_PBM_GET_CO_PBM(invocation, co_pb, ctx->server);
	pb_status = tcore_phonebook_get_status(co_pb);
	if (pb_status == FALSE) {
		dbg("pb_init is not completed yet.");

		telephony_phonebook_complete_update_record(phonebook, invocation,
			PB_ACCESS_CONDITION_NOT_SATISFIED);

		return TRUE;
	}

	memset(&req, 0x0, sizeof(struct treq_phonebook_update_record));

	dbg("[%s] pb_type[%d] index[%d] name[%s] number[%s] email[%s]",
		GET_CP_NAME(invocation), type, index,
		name, number, email1);

	req.index = (unsigned short)index;
	req.phonebook_type = type;

	if (name != NULL && strlen(name)) {
		req.dcs = PB_TEXT_ASCII;
		req.name_len = strlen(name);

		if (req.name_len > PHONEBOOK_NAME_BYTE_MAX)
			req.name_len = PHONEBOOK_NAME_BYTE_MAX;

		memcpy(req.name, name, req.name_len);
	}

	if (sne != NULL && strlen(sne)) {
		req.sne_dcs = PB_TEXT_ASCII;
		req.sne_len = strlen(sne);

		if (req.sne_len > PHONEBOOK_NAME_BYTE_MAX)
			req.sne_len = PHONEBOOK_NAME_BYTE_MAX;

		memcpy(req.sne, sne, req.sne_len);
	}

	if (number != NULL && (temp_len = strlen(number))) {
		req.ton = ton;

		if (temp_len > PHONEBOOK_NUMBER_BYTE_MAX)
			temp_len = PHONEBOOK_NUMBER_BYTE_MAX;

		memcpy(req.number, number, temp_len);
	}

	if (number2 != NULL && (temp_len = strlen(number2))) {
		req.anr1_ton = number2_ton;

		if (temp_len > PHONEBOOK_NUMBER_BYTE_MAX)
			temp_len = PHONEBOOK_NUMBER_BYTE_MAX;

		memcpy(req.anr1, number2, temp_len);
	}

	if (number3 != NULL && (temp_len = strlen(number3))) {
		req.anr2_ton = number3_ton;

		if (temp_len > PHONEBOOK_NUMBER_BYTE_MAX)
			temp_len = PHONEBOOK_NUMBER_BYTE_MAX;

		memcpy(req.anr2, number3, temp_len);
	}

	if (number4 != NULL && (temp_len = strlen(number4))) {
		req.anr3_ton = number4_ton;

		if (temp_len > PHONEBOOK_NUMBER_BYTE_MAX)
			temp_len = PHONEBOOK_NUMBER_BYTE_MAX;

		memcpy(req.anr3, number4, temp_len);
	}

	if (email1 != NULL && strlen(email1)) {
		req.email1_len = strlen(email1);

		if (req.email1_len > PHONEBOOK_EMAIL_BYTE_MAX)
			req.email1_len = PHONEBOOK_EMAIL_BYTE_MAX;

		memcpy(req.email1, email1, req.email1_len);
	}

	/* Additional e-mail fields (email 2,3,4) cannot be used to CP */

	req.group_index = (unsigned short)group_index;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, phonebook, invocation,
		TREQ_PHONEBOOK_UPDATERECORD,
		&req, sizeof(struct treq_phonebook_update_record));

	return TRUE;
}

static gboolean on_phonebook_delete_record(TelephonyPhonebook *phonebook,
	GDBusMethodInvocation *invocation,
	gint type, gint index,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_phonebook_delete_record req;
	CoreObject *co_pb = NULL;
	gboolean pb_status = FALSE;

	if (!check_access_control(invocation, AC_PHONEBOOK, "x"))
		return TRUE;

	DBUS_PBM_GET_CO_PBM(invocation, co_pb, ctx->server);
	pb_status = tcore_phonebook_get_status(co_pb);
	if (pb_status == FALSE) {
		dbg("pb_init is not completed yet.");

		telephony_phonebook_complete_delete_record(phonebook, invocation,
			PB_ACCESS_CONDITION_NOT_SATISFIED);

		return TRUE;
	}

	memset(&req, 0x0, sizeof(struct treq_phonebook_delete_record));

	req.index = (unsigned short)index;
	req.phonebook_type = type;

	dbg("[%s] req phonebook_type[%d][%s] index[%d]", GET_CP_NAME(invocation),
		req.phonebook_type,
		dbg_dbus_pb_type_name[req.phonebook_type], req.index);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, phonebook, invocation,
		TREQ_PHONEBOOK_DELETERECORD,
		&req, sizeof(struct treq_phonebook_delete_record));

	return TRUE;
}

gboolean dbus_plugin_setup_phonebook_interface(TelephonyObjectSkeleton *object,
	struct custom_data *ctx)
{
	TelephonyPhonebook *phonebook;

	phonebook = telephony_phonebook_skeleton_new();
	telephony_object_skeleton_set_phonebook(object, phonebook);
	g_object_unref(phonebook);

	dbg("phonebook = %p", phonebook);

	/*
	 * Register signal handlers for Phonebook interface
	 */
	g_signal_connect(phonebook,
		"handle-get-init-status",
		G_CALLBACK(on_phonebook_get_init_status), ctx);

	g_signal_connect(phonebook,
		"handle-get-count",
		G_CALLBACK(on_phonebook_get_count), ctx);

	g_signal_connect(phonebook,
		"handle-get-info",
		G_CALLBACK(on_phonebook_get_info), ctx);

	g_signal_connect(phonebook,
		"handle-get-usim-meta-info",
		G_CALLBACK(on_phonebook_get_usim_info), ctx);

	g_signal_connect(phonebook,
		"handle-read-record",
		G_CALLBACK(on_phonebook_read_record), ctx);

	g_signal_connect(phonebook,
		"handle-update-record",
		G_CALLBACK(on_phonebook_update_record), ctx);

	g_signal_connect(phonebook,
		"handle-delete-record",
		G_CALLBACK(on_phonebook_delete_record), ctx);

	return TRUE;
}

gboolean dbus_plugin_phonebook_response(struct custom_data *ctx,
	UserRequest *ur, struct dbus_request_info *dbus_info,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	const struct tresp_phonebook_get_count *resp_pbcnt = data;
	const struct tresp_phonebook_get_info *resp_entry = data;
	const struct tresp_phonebook_get_usim_info *resp_capa = data;
	const struct tresp_phonebook_read_record *resp_pbread = data;
	const struct tresp_phonebook_update_record *resp_pbupdate = data;
	const struct tresp_phonebook_delete_record *resp_pbdelete = data;
	char *cpname = dbus_info ? GET_CP_NAME(dbus_info->invocation) : "";

	switch (command) {
	case TRESP_PHONEBOOK_GETCOUNT:
		dbg("[%s] GETCOUNT (type[%d][%s] used[%d]total[%d])",
			cpname, resp_pbcnt->type, dbg_dbus_pb_type_name[resp_pbcnt->type],
			resp_pbcnt->used_count, resp_pbcnt->total_count);

		telephony_phonebook_complete_get_count(dbus_info->interface_object, dbus_info->invocation,
			resp_pbcnt->result, resp_pbcnt->type, resp_pbcnt->used_count, resp_pbcnt->total_count);
	break;

	case TRESP_PHONEBOOK_GETMETAINFO:
		dbg("[%s] GETMETAINFO (type[%d][%s])",
			cpname, resp_entry->type, dbg_dbus_pb_type_name[resp_entry->type]);
		dbg("index(min[%d]max[%d]), num_max[%d] text(max[%d]used[%d])",
			resp_entry->index_min, resp_entry->index_max, resp_entry->number_length_max,
			resp_entry->text_length_max, resp_entry->used_count);

		telephony_phonebook_complete_get_info(dbus_info->interface_object, dbus_info->invocation,
			resp_entry->result, resp_entry->type, resp_entry->index_min, resp_entry->index_max,
			resp_entry->number_length_max, resp_entry->text_length_max, resp_entry->used_count);
	break;

	case TRESP_PHONEBOOK_GETUSIMINFO: {
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i;

		dbg("[%s] GETUSIMINFO", cpname);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_capa->field_count; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
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

		telephony_phonebook_complete_get_usim_meta_info(dbus_info->interface_object,
			dbus_info->invocation, resp_capa->result, gv);
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

		dbg("[%s] READRECORD (type[%d][%s] index[%d][%d])",
			cpname, resp_pbread->phonebook_type,
			dbg_dbus_pb_type_name[resp_pbread->phonebook_type],
			resp_pbread->index, resp_pbread->next_index);

		if (resp_pbread->name_len > 0) {
			dbg("name:[%s] len:[%d]", resp_pbread->name, resp_pbread->name_len);
			memcpy(dest_pb_name, resp_pbread->name, resp_pbread->name_len);
		}

		dbg("number:[%s] ton:[%d][%s])",
			resp_pbread->number, resp_pbread->ton, dbg_dbus_pb_ton_name[resp_pbread->ton]);

		if (resp_pbread->phonebook_type == PB_TYPE_USIM) {
			if (resp_pbread->sne_len > 0) {
				dbg("sne:[%s] sne_len:[%d]", resp_pbread->sne, resp_pbread->sne_len);
				memcpy(dest_pb_sne, resp_pbread->sne, resp_pbread->sne_len);
			}

			if (strlen((const char*)resp_pbread->anr1) != 0
					|| strlen((const char*)resp_pbread->anr2) != 0
					|| strlen((const char*)resp_pbread->anr3) != 0) {
				dbg("anr1:([%s],ton[%d][%s])", resp_pbread->anr1,
					resp_pbread->anr1_ton, dbg_dbus_pb_ton_name[resp_pbread->anr1_ton]);
				dbg("anr2:([%s],ton[%d][%s])", resp_pbread->anr2,
					resp_pbread->anr2_ton, dbg_dbus_pb_ton_name[resp_pbread->anr2_ton]);
				dbg("anr3:([%s],ton[%d][%s])", resp_pbread->anr3,
					resp_pbread->anr3_ton, dbg_dbus_pb_ton_name[resp_pbread->anr3_ton]);
			}

			if (resp_pbread->email1_len > 0) {
				dbg("email1:[%s] len:[%d]", resp_pbread->email1, resp_pbread->email1_len);
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
		if (resp_pbread->phonebook_type == PB_TYPE_USIM) {
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
	}
	break;

	case TRESP_PHONEBOOK_UPDATERECORD:
		dbg("[%s] UPDATERECORD (result[%d])", cpname, resp_pbupdate->result);

		telephony_phonebook_complete_update_record(dbus_info->interface_object,
			dbus_info->invocation, resp_pbupdate->result);
	break;

	case TRESP_PHONEBOOK_DELETERECORD:
		dbg("[%s] DELETERECORD (result[%d])", cpname, resp_pbdelete->result);

		telephony_phonebook_complete_delete_record(dbus_info->interface_object,
			dbus_info->invocation, resp_pbdelete->result);
	break;

	default:
		err("Unhandled/Unknown Response: [0x%x]", command);
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_phonebook_notification(struct custom_data *ctx,
	CoreObject *source, TelephonyObjectSkeleton *object,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyPhonebook *phonebook;
	const char *cp_name;

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	phonebook = telephony_object_peek_phonebook(TELEPHONY_OBJECT(object));
	if (phonebook == NULL) {
		err("phonebook object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_PHONEBOOK_STATUS: {
		const struct tnoti_phonebook_status *n_pb_status = data;

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
	}
	break;

	case TNOTI_PHONEBOOK_CONTACT_CHANGE: {
		const struct tnoti_phonebook_contact_change *n_pb_contact_change = data;

		dbg("phonebook_type [%d] index [%d] operation [%d]",
			n_pb_contact_change->phonebook_type,
			n_pb_contact_change->index, n_pb_contact_change->operation);

		telephony_phonebook_emit_contact_change(phonebook,
			n_pb_contact_change->phonebook_type,
			n_pb_contact_change->index,
			n_pb_contact_change->operation);
	}
	break;

	default:
		err("Unhandled/Unknown Notification: [0x%x]", command);
	break;
	}

	return TRUE;
}
