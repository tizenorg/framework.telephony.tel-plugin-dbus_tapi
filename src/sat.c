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
#include <co_sat.h>

#include "generated-code.h"
#include "common.h"
#include "sat_manager.h"
#include "sat_ui_support/sat_ui_support.h"

static gboolean on_sat_get_main_menu_info(TelephonySAT *sat, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	GVariant *main_menu = NULL;

	gchar *title;
	gint result = 1, command_id, item_cnt;
	gboolean b_present, b_help_info, b_updated;
	GVariant *items;

	if (check_access_control(invocation, AC_SAT, "r") == FALSE)
		return FALSE;

	if(!ctx->cached_sat_main_menu){
		dbg("no main menu");
		return FALSE;
	}

	main_menu = ctx->cached_sat_main_menu;

	g_variant_get(main_menu, "(ibs@vibb)", &command_id, &b_present, &title, &items, &item_cnt,
			&b_help_info, &b_updated);

	telephony_sat_complete_get_main_menu_info(sat, invocation, result, command_id, b_present, title,
			items, item_cnt, b_help_info, b_updated);

	return TRUE;
}

static gboolean on_sat_send_display_status(TelephonySAT *sat, GDBusMethodInvocation *invocation,
		gint arg_command_id, gboolean arg_display_status,
		gpointer user_data)
{
	TcorePlugin *plg = NULL;
	char *plugin_name;
	struct custom_data *ctx = user_data;
	gboolean result = FALSE;
	gint out_param = 1;

	if (check_access_control(invocation, AC_SAT, "x") == FALSE)
		return FALSE;

	plugin_name = GET_PLUGIN_NAME(invocation);
	plg = tcore_server_find_plugin(ctx->server, plugin_name);
	if (!plg){
		dbg("there is no valid plugin at this point");
		out_param = 0;
		telephony_sat_complete_send_ui_display_status(sat, invocation, out_param);
		return TRUE;
	}

	result = sat_manager_handle_ui_display_status(ctx, plg, arg_command_id, arg_display_status);
	if(!result){
		dbg("fail to send exec result");
	}

	out_param = (result ? 1 : 0);
	telephony_sat_complete_send_ui_display_status(sat, invocation, out_param);
	return TRUE;
}

static gboolean on_sat_send_user_confirm(TelephonySAT *sat, GDBusMethodInvocation *invocation,
		gint arg_command_id, gint arg_command_type, gint arg_user_confirm_type,
		GVariant *arg_additional_data, gpointer user_data)
{
	TcorePlugin *plg = NULL;
	char *plugin_name;
	struct custom_data *ctx = user_data;

	gboolean result = FALSE;
	gint out_param = 1;
	GVariant *confirm_data = NULL;

	if (check_access_control(invocation, AC_SAT, "x") == FALSE)
		return FALSE;

	plugin_name = GET_PLUGIN_NAME(invocation);
	plg = tcore_server_find_plugin(ctx->server, plugin_name);
	if (!plg){
		dbg("there is no valid plugin at this point");
		out_param = 0;
		telephony_sat_complete_send_user_confirm(sat, invocation, out_param);
		return TRUE;
	}

	confirm_data = g_variant_new("(iiv)", arg_command_id, arg_user_confirm_type, arg_additional_data);

	result = sat_manager_handle_user_confirm(ctx, plg, confirm_data);
	if(!result){
		dbg("fail to send user confirm");
	}

	out_param = (result ? 1 : 0);
	telephony_sat_complete_send_user_confirm(sat, invocation, out_param);

	return TRUE;
}

static gboolean on_sat_send_app_exec_result(TelephonySAT *sat, GDBusMethodInvocation *invocation,
		gint arg_command_id, gint arg_command_type, GVariant *arg_exec_result,
		gpointer user_data)
{
	TcorePlugin *plg = NULL;
	char *plugin_name;
	struct custom_data *ctx = user_data;

	gboolean result = FALSE;
	gint out_param = 1;

	if (check_access_control(invocation, AC_SAT, "x") == FALSE)
		return FALSE;

	plugin_name = GET_PLUGIN_NAME(invocation);
	plg = tcore_server_find_plugin(ctx->server, plugin_name);
	if (!plg){
		dbg("there is no valid plugin at this point");
		out_param = 0;
		telephony_sat_complete_send_app_exec_result(sat, invocation, out_param);
		return TRUE;
	}

	dbg("processing app exec result");
	result = sat_manager_handle_app_exec_result(ctx, plg, arg_command_id, arg_command_type, arg_exec_result);
	if(!result){
		dbg("fail to send exec result");
	}

	out_param = (result ? 1 : 0);
	telephony_sat_complete_send_app_exec_result(sat, invocation, out_param);
	return TRUE;
}

static gboolean on_sat_select_menu(TelephonySAT *sat, GDBusMethodInvocation *invocation,
		guchar arg_item_identifier, gboolean arg_help_request,
		gpointer user_data)
{
	TReturn rv;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;

	struct treq_sat_envelop_cmd_data envelop_data;

	if (check_access_control(invocation, AC_SAT, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sat, invocation);
	memset(&envelop_data, 0, sizeof(struct treq_sat_envelop_cmd_data));
	envelop_data.sub_cmd = ENVELOP_MENU_SELECTION;
	envelop_data.envelop_data.menu_select.device_identitie.src = DEVICE_ID_KEYPAD;
	envelop_data.envelop_data.menu_select.device_identitie.dest = DEVICE_ID_SIM;
	envelop_data.envelop_data.menu_select.item_identifier.item_identifier = arg_item_identifier;
	envelop_data.envelop_data.menu_select.help_request = arg_help_request;

	tcore_user_request_set_data(ur, sizeof(struct treq_sat_envelop_cmd_data), &envelop_data);
	tcore_user_request_set_command(ur, TREQ_SAT_REQ_ENVELOPE);
	rv = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(rv != TCORE_RETURN_SUCCESS){
		telephony_sat_complete_select_menu(sat, invocation, -1, ENVELOPE_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sat_download_event(TelephonySAT *sat, GDBusMethodInvocation *invocation,
		gint arg_event_download_type, gint arg_src_device,gint arg_dest_device,
		GVariant *arg_download_data, gpointer user_data)
{
	TReturn rv;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	struct treq_sat_envelop_cmd_data envelop_data;

	if (check_access_control(invocation, AC_SAT, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, sat, invocation);
	memset(&envelop_data, 0, sizeof(struct treq_sat_envelop_cmd_data));
	envelop_data.sub_cmd = ENVELOP_EVENT_DOWNLOAD;
	envelop_data.envelop_data.event_download.event = arg_event_download_type;
	sat_manager_handle_event_download_envelop(arg_event_download_type, arg_src_device, arg_dest_device,
			&envelop_data.envelop_data.event_download, arg_download_data);

	tcore_user_request_set_data(ur, sizeof(struct treq_sat_envelop_cmd_data), &envelop_data);
	tcore_user_request_set_command(ur, TREQ_SAT_REQ_ENVELOPE);
	rv = tcore_communicator_dispatch_request(ctx->comm, ur);
	if(rv != TCORE_RETURN_SUCCESS){
		telephony_sat_complete_download_event(sat, invocation, -1, ENVELOPE_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_sat_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonySAT *sat;

	sat = telephony_sat_skeleton_new();
	telephony_object_skeleton_set_sat(object, sat);
	g_object_unref(sat);

	dbg("sat = %p", sat);

	g_signal_connect (sat,
			"handle-get-main-menu-info",
			G_CALLBACK (on_sat_get_main_menu_info),
			ctx);

	g_signal_connect (sat,
			"handle-send-ui-display-status",
			G_CALLBACK (on_sat_send_display_status),
			ctx);

	g_signal_connect (sat,
			"handle-send-user-confirm",
			G_CALLBACK (on_sat_send_user_confirm),
			ctx);

	g_signal_connect (sat,
			"handle-send-app-exec-result",
			G_CALLBACK (on_sat_send_app_exec_result),
			ctx);

	g_signal_connect (sat,
			"handle-select-menu",
			G_CALLBACK (on_sat_select_menu),
			ctx);

	g_signal_connect (sat,
			"handle-download-event",
			G_CALLBACK (on_sat_download_event),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_sat_response(struct custom_data *ctx, UserRequest *ur,
		struct dbus_request_info *dbus_info, enum tcore_response_command command,
		unsigned int data_len, const void *data)
{
	const struct tresp_sat_envelop_data *envelop_rsp = NULL;

	dbg("sat response command = [0x%x], data_len = %d", command, data_len);

	switch (command) {
		case TRESP_SAT_REQ_ENVELOPE: {
			envelop_rsp = (struct tresp_sat_envelop_data *)data;

			dbg("envelop sub_cmd(%d) result(%d) rsp(%d)", envelop_rsp->sub_cmd, envelop_rsp->result, envelop_rsp->envelop_resp);

			if(envelop_rsp->sub_cmd == ENVELOP_MENU_SELECTION){
				telephony_sat_complete_select_menu(dbus_info->interface_object, dbus_info->invocation,
						envelop_rsp->result, envelop_rsp->envelop_resp);
			}
			else if(envelop_rsp->sub_cmd == ENVELOP_EVENT_DOWNLOAD){
				telephony_sat_complete_download_event(dbus_info->interface_object, dbus_info->invocation,
						envelop_rsp->result, envelop_rsp->envelop_resp);
			}
		} break;

		case TRESP_SAT_REQ_TERMINALRESPONSE:
			dbg("receive TRESP_SAT_REQ_TERMINALRESPONSE");
		break;

		default:
			dbg("not handled command[%d]", command);
		break;
	}
	return TRUE;
}

gboolean dbus_plugin_sat_notification(struct custom_data *ctx, const char *plugin_name,
		TelephonyObjectSkeleton *object, enum tcore_notification_command command,
		unsigned int data_len, const void *data)
{
	TcorePlugin *plg = NULL;
	TelephonySAT *sat;
	struct tnoti_sat_proactive_ind *p_ind = (struct tnoti_sat_proactive_ind *)data;

	if (!object || !ctx) {
		dbg("NULL data is detected!!");
		return FALSE;
	}

	plg = tcore_server_find_plugin(ctx->server, plugin_name);
	if (!plg){
		dbg("there is no valid plugin at this point");
		return FALSE;
	}

	sat_ui_support_storage_init(ctx->server);

	sat = telephony_object_peek_sat(TELEPHONY_OBJECT(object));
	dbg("sat = %p", sat);

	dbg("notification !!! (command = 0x%x, data_len = %d)", command, data_len);

	if (command == TNOTI_SAT_SESSION_END) {

		dbg("notified sat session end evt");
		sat_manager_init_queue(ctx);

		sat_ui_support_terminate_sat_ui();
		telephony_sat_emit_end_proactive_session(sat, SAT_PROATV_CMD_TYPE_END_PROACTIVE_SESSION);
		return TRUE;
	}

	//Proactive Command Notification
	dbg("notified sat proactive command(%d)", p_ind->cmd_type);

	switch (p_ind->cmd_type) {
		case SAT_PROATV_CMD_SETUP_MENU:{
			gboolean rv = FALSE;
			GVariant *menu_info = NULL;
			GVariant *resp = NULL;
			GVariant *exec_result = NULL;

			gchar *title;
			gint command_id, menu_cnt;
			gboolean b_present, b_helpinfo, b_updated;
			GVariant *items;

			menu_info = sat_manager_caching_setup_menu_info(ctx, plugin_name, (struct tel_sat_setup_menu_tlv*) &p_ind->proactive_ind_data.setup_menu);
			ctx->cached_sat_main_menu = menu_info;

			if(!menu_info){
				dbg("no main menu data");
				sat_ui_support_remove_desktop_file();
				sat_ui_support_terminate_sat_ui();
				telephony_sat_emit_end_proactive_session(sat, SAT_PROATV_CMD_TYPE_END_PROACTIVE_SESSION);
				return TRUE;
			}

			dbg("menu_info type_format(%s)", g_variant_get_type_string(menu_info));
			g_variant_get(menu_info, "(ibs@vibb)", &command_id, &b_present, &title, &items,
					&menu_cnt, &b_helpinfo, &b_updated);

			rv = sat_ui_support_create_desktop_file(title);

			dbg("return value (%d)", rv);
			if(rv)
				resp = g_variant_new("(i)", RESULT_SUCCESS);
			else
				resp = g_variant_new("(i)", RESULT_ME_UNABLE_TO_PROCESS_COMMAND);

			exec_result = g_variant_new_variant(resp);
			sat_manager_handle_app_exec_result(ctx, plg, command_id, SAT_PROATV_CMD_SETUP_MENU, exec_result);

			//sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_SETUP_MENU, menu_info);

			telephony_sat_emit_setup_menu(sat, command_id, b_present, title, items, menu_cnt,
					b_helpinfo, b_updated);
		} break;

		case SAT_PROATV_CMD_DISPLAY_TEXT:{
			GVariant *display_text = NULL;

			gint command_id, text_len, duration;
			gboolean high_priority, user_rsp_required, immediately_rsp;
			gchar text[SAT_TEXT_STRING_LEN_MAX];
			GVariant *icon_id = NULL;
			int ret;

			display_text = sat_manager_display_text_noti(ctx, plugin_name, (struct tel_sat_display_text_tlv*) &p_ind->proactive_ind_data.display_text);

			if(!display_text){
				dbg("no display text data");
				return TRUE;
			}

			dbg("display text type_format(%s)", g_variant_get_type_string(display_text));
			g_variant_get(display_text, "(isiibbb@v)", &command_id, &text, &text_len, &duration,
						&high_priority, &user_rsp_required, &immediately_rsp, &icon_id);

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_DISPLAY_TEXT, display_text);
			if(!ret) {
				int rv;
				dbg("fail to launch sat-ui, remove the queued data!!\n");
				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if(!rv)
					dbg("fail to dequeue data\n");
			}

			telephony_sat_emit_display_text(sat, command_id, text, text_len, duration,
					high_priority, user_rsp_required, immediately_rsp);

		} break;

		case SAT_PROATV_CMD_SELECT_ITEM:{
			GVariant *select_menu = NULL;

			gboolean help_info ;
			gchar *selected_text;
			gint command_id, default_item_id, menu_cnt, text_len =0;
			GVariant *menu_items, *icon_id, *icon_list;
			int ret;

			select_menu = sat_manager_select_item_noti(ctx, plugin_name, (struct tel_sat_select_item_tlv*) &p_ind->proactive_ind_data.select_item);

			if(!select_menu){
				dbg("no select menu data");
				return TRUE;
			}

			dbg("select menu type_format(%s)", g_variant_get_type_string(select_menu));
			g_variant_get(select_menu, "(ibsiii@v@v@v)", &command_id, &help_info, &selected_text,
					&text_len, &default_item_id, &menu_cnt, &menu_items, &icon_id, &icon_list);

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_SELECT_ITEM, select_menu);
			if(!ret) {
				int rv;
				dbg("fail to launch sat-ui, remove the queued data!!\n");
				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if(!rv)
					dbg("fail to dequeue data\n");
			}

			telephony_sat_emit_select_item (sat, command_id, help_info, selected_text, text_len,
					default_item_id, menu_cnt, menu_items);
		} break;

		case SAT_PROATV_CMD_GET_INKEY:{
			GVariant *get_inkey = NULL;
			gint command_id, key_type, input_character_mode;
			gint text_len, duration;
			gboolean b_numeric, b_help_info;
			gchar *text;
			GVariant *icon_id;
			int ret;

			get_inkey = sat_manager_get_inkey_noti(ctx, plugin_name, (struct tel_sat_get_inkey_tlv*) &p_ind->proactive_ind_data.get_inkey);

			if(!get_inkey){
				dbg("no get inkey data");
				return TRUE;
			}

			dbg("get inkey type_format(%s)", g_variant_get_type_string(get_inkey));
			g_variant_get(get_inkey, "(iiibbsii@v)", &command_id, &key_type, &input_character_mode,
					&b_numeric,&b_help_info, &text, &text_len, &duration, &icon_id);

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_GET_INKEY, get_inkey);
			if(!ret) {
				int rv;
				dbg("fail to launch sat-ui, remove the queued data!!\n");
				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if(!rv)
					dbg("fail to dequeue data\n");
			}

			telephony_sat_emit_get_inkey(sat, command_id, key_type, input_character_mode,
					b_numeric, b_help_info, text, text_len, duration);
		} break;

		case SAT_PROATV_CMD_GET_INPUT:{
			GVariant *get_input = NULL;
			gint command_id, input_character_mode;
			gint text_len, def_text_len, rsp_len_min, rsp_len_max;
			gboolean b_numeric, b_help_info, b_echo_input;
			gchar *text, *def_text;
			GVariant *icon_id;
			int ret;

			get_input = sat_manager_get_input_noti(ctx, plugin_name, (struct tel_sat_get_input_tlv*) &p_ind->proactive_ind_data.get_input);

			if(!get_input){
				dbg("no get input data");
				return TRUE;
			}

			dbg("get input type_format(%s)", g_variant_get_type_string(get_input));
			g_variant_get(get_input, "(iibbbsiiisi@v)", &command_id, &input_character_mode, &b_numeric, &b_help_info, &b_echo_input,
					&text, &text_len, &rsp_len_max, &rsp_len_min, &def_text, &def_text_len, &icon_id);

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_GET_INPUT, get_input);
			if(!ret) {
				int rv;
				dbg("fail to launch sat-ui, remove the queued data!!\n");
				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if(!rv)
					dbg("fail to dequeue data\n");
			}

			telephony_sat_emit_get_input(sat, command_id, input_character_mode, b_numeric, b_help_info,
					b_echo_input, text, text_len, rsp_len_max, rsp_len_min, def_text, def_text_len);
		} break;

		case SAT_PROATV_CMD_PLAY_TONE:{
			GVariant *play_tone = NULL;
			gint command_id, tone_type, duration;
			gint text_len;
			gchar* text;
			GVariant *icon_id;
			int ret;

			play_tone = sat_manager_play_tone_noti(ctx, plugin_name, (struct tel_sat_play_tone_tlv*) &p_ind->proactive_ind_data.play_tone);

			if(!play_tone){
				dbg("no play tone data");
				return TRUE;
			}

			dbg("play tone type_format(%s)", g_variant_get_type_string(play_tone));
			g_variant_get(play_tone, "(isi@vii)", &command_id, &text, &text_len, &icon_id, &tone_type, &duration);

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_PLAY_TONE, play_tone);
			if(!ret) {
				int rv;
				dbg("fail to launch sat-ui, remove the queued data!!\n");
				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if(!rv)
					dbg("fail to dequeue data\n");
			}

			telephony_sat_emit_play_tone(sat, command_id, text, text_len, tone_type, duration);
		} break;

		case SAT_PROATV_CMD_SEND_SMS:{
			GVariant *send_sms = NULL;

			gint command_id, ton, npi, tpdu_type;
			gboolean b_packing_required;
			gint text_len, number_len, tpdu_data_len;
			gchar* text, *dialling_number;
			GVariant *tpdu_data, *icon_id;

			send_sms = sat_manager_send_sms_noti(ctx, plugin_name, (struct tel_sat_send_sms_tlv*) &p_ind->proactive_ind_data.send_sms);

			if(!send_sms){
				dbg("no send sms data");
				return TRUE;
			}

			dbg("send sms type_format(%s)", g_variant_get_type_string(send_sms));
			g_variant_get(send_sms, "(isi@vbiisii@vi)", &command_id, &text, &text_len, &icon_id, &b_packing_required, &ton, &npi,
					&dialling_number, &number_len, &tpdu_type, &tpdu_data, &tpdu_data_len);

			dbg("check display text : text(%s) text len(%d)", text, text_len);
			if(text_len > 1 && (g_strcmp0(text,"") != 0) ){
				GVariant *ui_info = NULL;
				gboolean user_confirm = FALSE;
				int ret;
				dbg("text should be displayed by ui");
				dbg("send sms is pending!!!");

				ui_info = g_variant_new("(isib)", command_id, text, text_len, user_confirm);
				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE, ui_info);
				if(!ret) {
					int rv;
					dbg("fail to launch sat-ui, remove the queued data!!\n");
					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if(!rv)
						dbg("fail to dequeue data\n");
				}
				return TRUE;
			}

			telephony_sat_emit_send_sms(sat, command_id, text, text_len, b_packing_required,
					ton, npi, dialling_number, number_len, tpdu_type, tpdu_data, tpdu_data_len);
		} break;

		case SAT_PROATV_CMD_SEND_SS:{
			GVariant *send_ss = NULL;

			gint command_id, ton, npi;
			gint text_len, ss_str_len;
			gchar* text, *ss_string;

			GVariant *icon_id;

			send_ss = sat_manager_send_ss_noti(ctx, plugin_name, (struct tel_sat_send_ss_tlv*) &p_ind->proactive_ind_data.send_ss);

			if(!send_ss){
				dbg("no send ss data");
				return TRUE;
			}

			dbg("send ss type_format(%s)", g_variant_get_type_string(send_ss));
			g_variant_get(send_ss, "(isi@viiis)", &command_id, &text, &text_len, &icon_id,
					&ton, &npi, &ss_str_len, &ss_string);

			dbg("check display text : text(%s) text len(%d)", text, text_len);
			if(text_len > 1 && (g_strcmp0(text,"") != 0) ){
				GVariant *ui_info = NULL;
				gboolean user_confirm = FALSE;
				int ret;
				dbg("text should be displayed by ui");
				dbg("send ss is pending!!!");

				ui_info = g_variant_new("(isib)", command_id, text, text_len, user_confirm);
				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE, ui_info);
				if(!ret) {
					int rv;
					dbg("fail to launch sat-ui, remove the queued data!!\n");
					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if(!rv)
						dbg("fail to dequeue data\n");
				}
				return TRUE;
			}

			telephony_sat_emit_send_ss(sat, command_id, text, text_len, ton, npi, ss_string);

			//tizen ciss
			sat_ui_support_launch_ciss_application(SAT_PROATV_CMD_SEND_SS, send_ss);

		} break;

		case SAT_PROATV_CMD_SEND_USSD:{
			GVariant *send_ussd = NULL;

			gint command_id;
			gint text_len, ussd_str_len;
			gchar* text, *ussd_string;

			GVariant *icon_id;

			send_ussd = sat_manager_send_ussd_noti(ctx, plugin_name, (struct tel_sat_send_ussd_tlv*) &p_ind->proactive_ind_data.send_ussd);

			if(!send_ussd){
				dbg("no send ussd data");
				return TRUE;
			}

			dbg("send ussd type_format(%s)", g_variant_get_type_string(send_ussd));
			g_variant_get(send_ussd, "(isi@vis)", &command_id, &text, &text_len, &icon_id, &ussd_str_len, &ussd_string);

			dbg("check display text : text(%s) text len(%d)", text, text_len);
			if(text_len > 1 && (g_strcmp0(text,"") != 0) ){
				GVariant *ui_info = NULL;
				gboolean user_confirm = FALSE;
				int ret;
				dbg("text should be displayed by ui");
				dbg("send ussd is pending!!!");

				ui_info = g_variant_new("(isib)", command_id, text, text_len, user_confirm);
				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE, ui_info);
					if(!ret) {
					int rv;
					dbg("fail to launch sat-ui, remove the queued data!!\n");
					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if(!rv)
						dbg("fail to dequeue data\n");
				}
				return TRUE;
			}

			telephony_sat_emit_setup_ussd(sat, command_id, text, text_len, ussd_string);

			//tizen ciss ui
			sat_ui_support_launch_ciss_application(SAT_PROATV_CMD_SEND_USSD, send_ussd);
		} break;

		case SAT_PROATV_CMD_SETUP_CALL:{
			GVariant *setup_call = NULL;

			gint command_id, call_type, confirmed_text_len, text_len, duration;
			gchar *confirmed_text, *text, *call_number;
			GVariant *icon_id;

			setup_call = sat_manager_setup_call_noti(ctx, plugin_name, (struct tel_sat_setup_call_tlv*) &p_ind->proactive_ind_data.setup_call);

			if(!setup_call){
				dbg("no setup call data");
				return TRUE;
			}

			dbg("setup call type_format(%s)", g_variant_get_type_string(setup_call));
			g_variant_get(setup_call, "(isisi@visi)", &command_id, &confirmed_text, &confirmed_text_len, &text, &text_len, &icon_id, &call_type, &call_number, &duration);

			dbg("check display text : text(%s) text len(%d)", confirmed_text, confirmed_text_len);
			if(confirmed_text_len > 1 && (g_strcmp0(confirmed_text,"") != 0) ){
				GVariant *ui_info = NULL;
				gboolean user_confirm = TRUE;
				int ret;
				dbg("text should be displayed by ui");
				dbg("setup call is pending!!!");

				ui_info = g_variant_new("(isib)", command_id, confirmed_text, confirmed_text_len, user_confirm);
				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE, ui_info);
				if(!ret) {
					int rv;
					dbg("fail to launch sat-ui, remove the queued data!!\n");
					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if(!rv)
						dbg("fail to dequeue data\n");
				}
				return TRUE;
			}

			telephony_sat_emit_setup_call(sat, command_id, confirmed_text, confirmed_text_len,text, text_len, call_type, call_number, duration);
		}break;

		case SAT_PROATV_CMD_SETUP_EVENT_LIST:{
			GVariant *event_list = NULL;

			gint event_cnt;
			GVariant *evt_list;

			event_list = sat_manager_setup_event_list_noti(ctx, plugin_name, (struct tel_sat_setup_event_list_tlv*) &p_ind->proactive_ind_data.setup_event_list);

			if(!event_list){
				dbg("no setup event list data");
				return TRUE;
			}

			dbg("setup event list type_format(%s)", g_variant_get_type_string(event_list));
			g_variant_get(event_list, "(i@v)", &event_cnt, &evt_list);

			telephony_sat_emit_setup_event_list(sat, event_cnt, evt_list);

			//bip proactive command is only handled by BIP Manager
			{
				gboolean b_sig = FALSE;
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				/* TODO: SAT Event Downloader should execute event_list as well. */
				b_sig = sat_ui_support_exec_evtdw(conn, g_path, SAT_PROATV_CMD_SETUP_EVENT_LIST, event_list);

				b_sig = sat_ui_support_exec_bip(conn, g_path, SAT_PROATV_CMD_SETUP_EVENT_LIST, event_list);
			}
		} break;

		case SAT_PROATV_CMD_SETUP_IDLE_MODE_TEXT:{
			GVariant *setup_idle_mode = NULL;
			int ret;

			gint command_id, text_len;
			gchar* text;
			GVariant *icon_id;

			setup_idle_mode = sat_manager_setup_idle_mode_text_noti(ctx, plugin_name, (struct tel_sat_setup_idle_mode_text_tlv*) &p_ind->proactive_ind_data.setup_idle_mode_text);

			if(!setup_idle_mode){
				dbg("no setup idle mode text data");
				return TRUE;
			}

			dbg("setup idle mode text type_format(%s)", g_variant_get_type_string(setup_idle_mode));
			g_variant_get(setup_idle_mode, "(isi@v)", &command_id, &text, &text_len, &icon_id);

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_SETUP_IDLE_MODE_TEXT, setup_idle_mode);
			if(!ret) {
				int rv;
				dbg("fail to launch sat-ui, remove the queued data!!\n");
				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if(!rv)
					dbg("fail to dequeue data\n");
			}

			telephony_sat_emit_setup_idle_mode_text(sat, command_id, text, text_len);
		} break;

		case SAT_PROATV_CMD_OPEN_CHANNEL:{
			GVariant *open_channel = NULL;

			gint command_id, bearer_type, protocol_type, dest_addr_type;
			gboolean immediate_link, auto_reconnection, bg_mode;
			gint text_len, buffer_size, port_number;
			gchar *text, *dest_address;
			GVariant *icon_id;
			GVariant *bearer_param;
			GVariant *bearer_detail;

			open_channel = sat_manager_open_channel_noti(ctx, plugin_name, (struct tel_sat_open_channel_tlv*) &p_ind->proactive_ind_data.open_channel);

			if(!open_channel){
				dbg("no open channel data");
				return TRUE;
			}

			dbg("open channel type_format(%s)", g_variant_get_type_string(open_channel));
			g_variant_get(open_channel,"(isi@vbbbi@viiiis@v)", &command_id, &text, &text_len, &icon_id, &immediate_link, &auto_reconnection, &bg_mode,
					&bearer_type, &bearer_param, &buffer_size, &protocol_type, &port_number, &dest_addr_type, &dest_address, &bearer_detail);

			dbg("check display text : text(%s) text len(%d)", text, text_len);
			if(text_len > 1 && (g_strcmp0(text,"") != 0) ){
				GVariant *ui_info = NULL;
				gboolean user_confirm = TRUE;
				int ret;
				dbg("text should be displayed by ui");
				dbg("open channel text is displayed!!!");

				ui_info = g_variant_new("(isib)", command_id, text, text_len, user_confirm);
				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE, ui_info);
					if(!ret) {
					int rv;
					dbg("fail to launch sat-ui, remove the queued data!!\n");
					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if(!rv)
						dbg("fail to dequeue data\n");
				}
				return TRUE;
			}

			/*telephony_sat_emit_open_channel(sat, command_id, text, text_len, immediate_link, auto_reconnection, bg_mode,
						bearer_type, bearer_param, buffer_size, protocol_type, port_number, dest_addr_type, dest_address, bearer_detail);*/

			//bip proactive command is only handled by BIP Manager
			{
				gboolean b_sig = FALSE;
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				b_sig = sat_ui_support_exec_bip(conn, g_path, SAT_PROATV_CMD_OPEN_CHANNEL, open_channel);
			}

		} break;

		case SAT_PROATV_CMD_CLOSE_CHANNEL:{
			GVariant *close_channel = NULL;

			gint command_id, channel_id, text_len;
			gchar *text;
			GVariant *icon_id;

			close_channel = sat_manager_close_channel_noti(ctx, plugin_name, (struct tel_sat_close_channel_tlv*) &p_ind->proactive_ind_data.close_channel);

			if(!close_channel){
				dbg("no close channel data");
				return TRUE;
			}

			//TODO check the data for sat-ui

			dbg("close channel type_format(%s)", g_variant_get_type_string(close_channel));
			g_variant_get(close_channel, "(isi@vi)", &command_id, &text, &text_len, &icon_id, &channel_id);

			/*telephony_sat_emit_close_channel(sat, command_id, text, text_len, channel_id);*/

			//bip proactive command is only handled by BIP Manager
			{
				gboolean b_sig = FALSE;
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				b_sig = sat_ui_support_exec_bip(conn, g_path, SAT_PROATV_CMD_CLOSE_CHANNEL, close_channel);
			}

		} break;

		case SAT_PROATV_CMD_RECEIVE_DATA:{
			GVariant *receive_data = NULL;

			gint command_id, text_len, channel_id, channel_data_len = 0;
			gchar *text;
			GVariant *icon_id;

			receive_data = sat_manager_receive_data_noti(ctx, plugin_name, (struct tel_sat_receive_channel_tlv*) &p_ind->proactive_ind_data.receive_data);

			if(!receive_data){
				dbg("no receive data data");
				return TRUE;
			}

			//TODO check the data for sat-ui

			dbg("receive data type_format(%s)", g_variant_get_type_string(receive_data));
			g_variant_get(receive_data, "(isi@vii)", &command_id, &text, &text_len, &icon_id, &channel_id, &channel_data_len);

			/*telephony_sat_emit_receive_data(sat, command_id, text, text_len, channel_id, channel_data_len);*/

			//bip proactive command is only handled by BIP Manager
			{
				gboolean b_sig = FALSE;
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				b_sig = sat_ui_support_exec_bip(conn, g_path, SAT_PROATV_CMD_RECEIVE_DATA, receive_data);
			}

		} break;

		case SAT_PROATV_CMD_SEND_DATA:{
			GVariant *send_data = NULL;

			gint command_id, channel_id, text_len, channel_data_len;
			gboolean send_data_immediately;
			gchar *text;
			GVariant *channel_data;
			GVariant *icon_id;

			send_data = sat_manager_send_data_noti(ctx, plugin_name, (struct tel_sat_send_channel_tlv*) &p_ind->proactive_ind_data.send_data);

			if(!send_data){
				dbg("no send data data");
				return TRUE;
			}

			//TODO check the data for sat-ui

			dbg("send data type_format(%s)", g_variant_get_type_string(send_data));
			g_variant_get(send_data, "(isi@vib@vi)", &command_id, &text, &text_len, &icon_id, &channel_id, &send_data_immediately, &channel_data, &channel_data_len);

			/*telephony_sat_emit_send_data(sat, command_id, text, text_len, channel_id, send_data_immediately, channel_data, channel_data_len);*/

			//bip proactive command is only handled by BIP Manager
			{
				gboolean b_sig = FALSE;
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				b_sig = sat_ui_support_exec_bip(conn, g_path, SAT_PROATV_CMD_SEND_DATA, send_data);
			}
		} break;

		case SAT_PROATV_CMD_GET_CHANNEL_STATUS:{
			GVariant *channel_status = NULL;

			gint command_id;

			channel_status = sat_manager_get_channel_status_noti(ctx, plugin_name, (struct tel_sat_get_channel_status_tlv*) &p_ind->proactive_ind_data.get_channel_status);

			if(!channel_status){
				dbg("no get channel status data");
				return TRUE;
			}

			//TODO check the data for sat-ui

			dbg("get channel status type_format(%s)", g_variant_get_type_string(channel_status));
			g_variant_get(channel_status, "(i)", &command_id);

			/*telephony_sat_emit_get_channel_status(sat, command_id);*/

			//bip proactive command is only handled by BIP Manager
			{
				gboolean b_sig = FALSE;
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				b_sig = sat_ui_support_exec_bip(conn, g_path, SAT_PROATV_CMD_GET_CHANNEL_STATUS, channel_status);
			}
		} break;

		case SAT_PROATV_CMD_REFRESH:{
			GVariant *refresh = NULL;
			gint command_id = 0;
			gint refresh_type =0;
			GVariant *file_list = NULL;
			int ret;

			refresh = sat_manager_refresh_noti(ctx, plugin_name, (struct tel_sat_refresh_tlv*) &p_ind->proactive_ind_data.refresh);

			if(!refresh){
				dbg("no refresh data");
				return TRUE;
			}

			dbg("refresh type_format(%s)", g_variant_get_type_string(refresh));
			g_variant_get(refresh, "(ii@v)", &command_id, &refresh_type, &file_list);

			telephony_sat_emit_refresh(sat, command_id, refresh_type, file_list);
			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_REFRESH, refresh);
			if(!ret) {
				int rv;
				dbg("fail to launch sat-ui, remove the queued data!!\n");
				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if(!rv)
					dbg("fail to dequeue data\n");
			}
		}break;

		case SAT_PROATV_CMD_MORE_TIME:{
			sat_manager_more_time_noti(ctx, plugin_name, (struct tel_sat_more_time_tlv*) &p_ind->proactive_ind_data.more_time);
			telephony_sat_emit_more_time(sat);
		}break;

		case SAT_PROATV_CMD_SEND_DTMF:{
			GVariant *send_dtmf = NULL;
			gint command_id = 0;
			gint text_len = 0, dtmf_str_len = 0;
			gchar *text = NULL;
			gchar *dtmf_str = NULL;
			GVariant *icon_id = NULL;

			send_dtmf = sat_manager_send_dtmf_noti(ctx, plugin_name, (struct tel_sat_send_dtmf_tlv*) &p_ind->proactive_ind_data.send_dtmf);
			if(!send_dtmf){
				dbg("no send_dtmf data");
				return TRUE;
			}

			dbg("send_dtmf type_format(%s)", g_variant_get_type_string(send_dtmf));
			g_variant_get(send_dtmf, "(isi@vis)", &command_id, &text, &text_len, &icon_id, &dtmf_str_len, &dtmf_str);

			if(text_len > 1 && (g_strcmp0(text,"") != 0) ){
				GVariant *ui_info = NULL;
				gboolean user_confirm = FALSE;
				int ret;
				dbg("text should be displayed by ui");
				dbg("send dtmf is displayed!!!");

				ui_info = g_variant_new("(isib)", command_id, text, text_len, user_confirm);
				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_SEND_DTMF, ui_info);
				if(!ret) {
					int rv;
					dbg("fail to launch sat-ui, remove the queued data!!\n");
					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if(!rv)
						dbg("fail to dequeue data\n");
				}
				return TRUE;
			}

			telephony_sat_emit_send_dtmf(sat, command_id, text, text_len, dtmf_str, dtmf_str_len);
		}break;

		case SAT_PROATV_CMD_LAUNCH_BROWSER:{
			GVariant *launch_browser = NULL;
			gint command_id = 0;
			gint browser_launch_type = 0, browser_id = 0;
			gint url_len = 0, text_len = 0, gateway_proxy_len =0;
			gchar *url = NULL;
			gchar *text = NULL;
			gchar *gateway_proxy = NULL;
			GVariant *icon_id = NULL;

			launch_browser = sat_manager_launch_browser_noti(ctx, plugin_name, (struct tel_sat_launch_browser_tlv*) &p_ind->proactive_ind_data.launch_browser);
			if(!launch_browser){
				dbg("no launch_browser data");
				return TRUE;
			}

			dbg("launch_browser type_format(%s)", g_variant_get_type_string(launch_browser));
			g_variant_get(launch_browser, "(iiisisisi@v)", &command_id, &browser_launch_type, &browser_id, &url, &url_len, &gateway_proxy, &gateway_proxy_len, &text, &text_len, &icon_id);

			if(text_len > 1 && (g_strcmp0(text,"") != 0) ){
				GVariant *ui_info = NULL;
				gboolean user_confirm = TRUE;
				int ret;
				dbg("text should be displayed by ui");
				dbg("launch browser is displayed!!!");

				ui_info = g_variant_new("(isib)", command_id, text, text_len, user_confirm);
				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE, ui_info);
				if(!ret) {
					int rv;
					dbg("fail to launch sat-ui, remove the queued data!!\n");
					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if(!rv)
						dbg("fail to dequeue data\n");
				}
				return TRUE;
			}

			telephony_sat_emit_launch_browser(sat, command_id, browser_launch_type, browser_id, url, url_len, gateway_proxy, gateway_proxy_len, text, text_len);
		}break;

		case SAT_PROATV_CMD_PROVIDE_LOCAL_INFO:{
			GVariant *provide_info = NULL;
			gint info_type = 0;

			provide_info = sat_manager_provide_local_info_noti(ctx, plugin_name, (struct tel_sat_provide_local_info_tlv*) &p_ind->proactive_ind_data.provide_local_info);
			if(!provide_info){
				dbg("no provide_info data");
				return TRUE;
			}

			dbg("provide_info type_format(%s)", g_variant_get_type_string(provide_info));
			g_variant_get(provide_info, "(i)", &info_type);

			telephony_sat_emit_provide_local_info(sat, info_type);
		}break;

		case SAT_PROATV_CMD_LANGUAGE_NOTIFICATION:{
			GVariant *language_noti = NULL;
			gint command_id = 0;
			gint language = 0;
			gboolean b_specified = FALSE;

			language_noti = sat_manager_language_notification_noti(ctx, plugin_name, (struct tel_sat_language_notification_tlv*) &p_ind->proactive_ind_data.language_notification);
			if(!language_noti){
				dbg("no language_noti data");
				return TRUE;
			}

			dbg("language_noti type_format(%s)", g_variant_get_type_string(language_noti));
			g_variant_get(language_noti, "(iib)", &command_id, &language, &b_specified);

			sat_manager_update_language(ctx, plugin_name, language_noti);

			telephony_sat_emit_language_notification(sat, command_id, language, b_specified);
		}break;

		default:
			dbg("not handled ind->cmd_type[0x%x]", p_ind->cmd_type);
			break;
	}

	return TRUE;
}
