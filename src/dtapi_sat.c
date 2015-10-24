/*
 * tel-plugin-dbus
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
#include <co_sat.h>

#include "generated-code.h"
#include "dtapi_common.h"
#include "dtapi_sat_manager.h"
#include "sat_ui_support/sat_ui_support.h"

static void __sat_set_main_menu(struct custom_data *ctx,
	const char *cp_name, GVariant *main_menu)
{
	GSList *list = NULL;
	struct cached_data *object = NULL;

	for (list = ctx->cached_data; list; list = list->next) {
		object = (struct cached_data *)list->data;
		if (object && g_strcmp0(object->cp_name, cp_name) == 0) {
			/*
			 * Need to free the previous main_menu
			 */
			g_variant_unref(object->cached_sat_main_menu);
			object->cached_sat_main_menu = main_menu;

			return;
		}
	}

	/*
	 * If 'object' is NOT created,
	 * then create the object and add to the list
	 */
	object = g_try_malloc0(sizeof(struct cached_data));
	if (NULL == object) {
		err("Memory allocation failed");
		return;
	}

	object->cp_name = g_strdup(cp_name);
	object->cached_sat_main_menu = main_menu;

	/*
	 * Append the new 'object' to cached data list
	 */
	ctx->cached_data = g_slist_append(ctx->cached_data, (gpointer)object);
}

static GVariant *__sat_get_main_menu(struct custom_data *ctx,
	const char *cp_name)
{
	GSList *list = NULL;
	struct cached_data *object;

	/*
	 * List of Objects in 'ctx',
	 * compare cp_name with modem_name stored in 'ctx'
	 * if matching return main_menu of that object.
	 */
	for (list = ctx->cached_data; list; list = list->next) {
		object = (struct cached_data *)list->data;
		if (object && g_strcmp0(object->cp_name, cp_name) == 0)
			return object->cached_sat_main_menu;
	}

	return NULL;
}

static gboolean on_sat_get_main_menu_info(TelephonySAT *sat,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	GVariant *main_menu = NULL;

	gchar *title;
	gint result = 1, command_id, item_cnt;
	gboolean b_present, b_help_info, b_updated;
	GVariant *items;
#if defined(TIZEN_SUPPORT_SAT_ICON)
	GVariant *icon_id = NULL;
	GVariant *icon_list = NULL;
#endif

	if (!check_access_control(invocation, AC_SAT, "r"))
		return TRUE;

	main_menu = __sat_get_main_menu(ctx, GET_CP_NAME(invocation));
	if (!main_menu) {
		err("NO Main Menu");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}

#if defined(TIZEN_SUPPORT_SAT_ICON)
	g_variant_get(main_menu, "(ibs@vibb@v@v)", &command_id,
		&b_present, &title, &items, &item_cnt,
		&b_help_info, &b_updated, &icon_id, &icon_list);

	telephony_sat_complete_get_main_menu_info(sat, invocation,
		result, command_id, b_present, title,
		items, item_cnt, b_help_info, b_updated, icon_id, icon_list);
#else
	g_variant_get(main_menu, "(ibs@vibb)", &command_id,
		&b_present, &title, &items, &item_cnt,
		&b_help_info, &b_updated);

	telephony_sat_complete_get_main_menu_info(sat, invocation,
		result, command_id, b_present, title,
		items, item_cnt, b_help_info, b_updated);
#endif

	g_free(title);

	return TRUE;
}

static gboolean on_sat_send_display_status(TelephonySAT *sat,
	GDBusMethodInvocation *invocation,
	gint command_id, gboolean display_status, gpointer user_data)
{
	TcorePlugin *plg = NULL;
	char *cp_name;
	struct custom_data *ctx = user_data;
	gboolean result = FALSE;
	gint out_param = 0;

	if (!check_access_control(invocation, AC_SAT, "x"))
		return TRUE;

	cp_name = GET_CP_NAME(invocation);
	plg = tcore_server_find_plugin(ctx->server, cp_name);
	if (!plg) {
		dbg("There is NO valid plugin at this point");

		telephony_sat_complete_send_ui_display_status(sat,
			invocation, out_param);

		return TRUE;
	}

	result = sat_manager_handle_ui_display_status(ctx, plg,
		command_id, display_status);
	if (!result)
		dbg("Failed to send 'exec' result");

	out_param = (result ? 1 : 0);
	telephony_sat_complete_send_ui_display_status(sat,
		invocation, out_param);

	return TRUE;
}

static gboolean on_sat_send_user_confirm(TelephonySAT *sat,
	GDBusMethodInvocation *invocation,
	gint command_id, gint command_type, gint user_confirm_type,
	GVariant *additional_data, gpointer user_data)
{
	TcorePlugin *plg = NULL;
	char *cp_name;
	struct custom_data *ctx = user_data;

	gboolean result = FALSE;
	gint out_param = 0;
	GVariant *confirm_data = NULL;

	if (!check_access_control(invocation, AC_SAT, "x"))
		return TRUE;

	cp_name = GET_CP_NAME(invocation);
	plg = tcore_server_find_plugin(ctx->server, cp_name);
	if (!plg) {
		dbg("There is NO valid plugin at this point");

		telephony_sat_complete_send_user_confirm(sat,
			invocation, out_param);

		return TRUE;
	}

	confirm_data = g_variant_new("(iiv)", command_id,
		user_confirm_type, additional_data);

	result = sat_manager_handle_user_confirm(ctx,
		plg, confirm_data);
	if (!result)
		dbg("Failed to send 'user confirm'");

	out_param = (result ? 1 : 0);
	telephony_sat_complete_send_user_confirm(sat,
		invocation, out_param);

	return TRUE;
}

static gboolean on_sat_send_app_exec_result(TelephonySAT *sat,
	GDBusMethodInvocation *invocation,
	gint command_id, gint command_type,
	GVariant *exec_result, gpointer user_data)
{
	TcorePlugin *plg = NULL;
	char *cp_name;
	struct custom_data *ctx = user_data;

	gboolean result = FALSE;
	gint out_param = 0;

	if (!check_access_control(invocation, AC_SAT, "x"))
		return TRUE;

	cp_name = GET_CP_NAME(invocation);
	plg = tcore_server_find_plugin(ctx->server, cp_name);
	if (!plg) {
		dbg("There is NO valid plugin at this point");

		telephony_sat_complete_send_app_exec_result(sat,
			invocation, out_param);

		return TRUE;
	}

	dbg("Processing app 'exec' result");
	result = sat_manager_handle_app_exec_result(ctx, plg,
		command_id, command_type, exec_result);
	if (!result)
		dbg("Failed to send 'exec' result");

	out_param = (result ? 1 : 0);
	telephony_sat_complete_send_app_exec_result(sat,
		invocation, out_param);

	return TRUE;
}

static gboolean on_sat_select_menu(TelephonySAT *sat,
	GDBusMethodInvocation *invocation,
	guchar item_identifier, gboolean help_request, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_sat_envelop_cmd_data req;

	if (!check_access_control(invocation, AC_SAT, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_sat_envelop_cmd_data));

	req.sub_cmd = ENVELOP_MENU_SELECTION;
	req.envelop_data.menu_select.device_identitie.src = DEVICE_ID_KEYPAD;
	req.envelop_data.menu_select.device_identitie.dest = DEVICE_ID_SIM;
	req.envelop_data.menu_select.item_identifier.item_identifier = item_identifier;
	req.envelop_data.menu_select.help_request = help_request;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sat, invocation,
		TREQ_SAT_REQ_ENVELOPE,
		&req, sizeof(struct treq_sat_envelop_cmd_data));

	return TRUE;
}

static gboolean on_sat_download_event(TelephonySAT *sat,
	GDBusMethodInvocation *invocation,
	gint event_download_type, gint src_device, gint dest_device,
	GVariant *download_data, gpointer user_data)
{
	gboolean b_event = FALSE;
	struct custom_data *ctx = user_data;

	struct treq_sat_envelop_cmd_data req;

	if (!check_access_control(invocation, AC_SAT, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_sat_envelop_cmd_data));

	req.sub_cmd = ENVELOP_EVENT_DOWNLOAD;
	req.envelop_data.event_download.event = event_download_type;

	b_event = sat_manager_handle_event_download_envelop(event_download_type,
		src_device, dest_device,
		&req.envelop_data.event_download, download_data);
	if (!b_event) {
		err("Envelop failed");

		telephony_sat_complete_download_event(sat,
			invocation, -1, ENVELOPE_FAILED);

		return TRUE;
	}

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sat, invocation,
		TREQ_SAT_REQ_ENVELOPE,
		&req, sizeof(struct treq_sat_envelop_cmd_data));

	return TRUE;
}

gboolean dbus_plugin_setup_sat_interface(TelephonyObjectSkeleton *object,
	struct custom_data *ctx)
{
	TelephonySAT *sat;

	sat = telephony_sat_skeleton_new();
	telephony_object_skeleton_set_sat(object, sat);
	g_object_unref(sat);

	dbg("sat = %p", sat);

	/*
	 * Register signal handlers for SAT interface
	 */
	g_signal_connect(sat,
		"handle-get-main-menu-info",
		G_CALLBACK(on_sat_get_main_menu_info), ctx);

	g_signal_connect(sat,
		"handle-send-ui-display-status",
		G_CALLBACK(on_sat_send_display_status), ctx);

	g_signal_connect(sat,
		"handle-send-user-confirm",
		G_CALLBACK(on_sat_send_user_confirm), ctx);

	g_signal_connect(sat,
		"handle-send-app-exec-result",
		G_CALLBACK(on_sat_send_app_exec_result), ctx);

	g_signal_connect(sat,
		"handle-select-menu",
		G_CALLBACK(on_sat_select_menu), ctx);

	g_signal_connect(sat,
		"handle-download-event",
		G_CALLBACK(on_sat_download_event), ctx);

	return TRUE;
}

gboolean dbus_plugin_sat_response(struct custom_data *ctx,
	UserRequest *ur, struct dbus_request_info *dbus_info,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	const struct tresp_sat_envelop_data *envelop_rsp = NULL;

	switch (command) {
	case TRESP_SAT_REQ_ENVELOPE: {
		envelop_rsp = (struct tresp_sat_envelop_data *)data;

		dbg("SAT_REQ_ENVELOPE - Result: [%d] Envelop sub-cmd: [%s] Envelop response: [%s]",
			envelop_rsp->result,
			(envelop_rsp->sub_cmd == ENVELOP_MENU_SELECTION ? "MENU SELECTION" :
			(envelop_rsp->sub_cmd == ENVELOP_EVENT_DOWNLOAD ? "EVENT DOWNLOAD" :
			"UNKNOWN")),
			(envelop_rsp->envelop_resp == ENVELOPE_SUCCESS ? "Success" :
			(envelop_rsp->envelop_resp == ENVELOPE_SIM_BUSY? "SIM Busy" :
			"Fail")));

		if (envelop_rsp->sub_cmd == ENVELOP_MENU_SELECTION)
			telephony_sat_complete_select_menu(dbus_info->interface_object,
				dbus_info->invocation, envelop_rsp->result,
				envelop_rsp->envelop_resp);
		else if (envelop_rsp->sub_cmd == ENVELOP_EVENT_DOWNLOAD)
			telephony_sat_complete_download_event(dbus_info->interface_object,
				dbus_info->invocation, envelop_rsp->result,
				envelop_rsp->envelop_resp);
	}
	break;

	case TRESP_SAT_REQ_TERMINALRESPONSE:
		dbg("SAT_REQ_TERMINALRESPONSE");
	break;

	default:
		err("Unhandled/Unknown Response: [0x%x]", command);
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_sat_notification(struct custom_data *ctx,
	CoreObject *source, TelephonyObjectSkeleton *object,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonySAT *sat;
	const char *cp_name;
	enum dbus_tapi_sim_slot_id slot_id;

	if (!object || !ctx) {
		err("NULL data is detected!!");
		return FALSE;
	}

	cp_name  = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
	slot_id = get_sim_slot_id_by_cp_name(cp_name);
	dbg("Slot ID: [%d]", slot_id);

	sat = telephony_object_peek_sat(TELEPHONY_OBJECT(object));
	if (sat == NULL) {
		err("sat object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_SAT_SESSION_END: { /* Session End notification */
		dbg("[%s] SAT_SESSION_END", cp_name);

		sat_manager_init_queue(ctx, cp_name);

		/* sat_ui_support_terminate_sat_ui(); */
		telephony_sat_emit_end_proactive_session(sat,
			SAT_PROATV_CMD_TYPE_END_PROACTIVE_SESSION);
	}
	break;

	case TNOTI_SAT_CALL_CTRL_RESULT: { /* Call Control notification */
		struct tnoti_sat_call_control_result_ind *cc_result_noti = NULL;
		gint call_ctrl_result = 0, bc_repeat_indicator = 0, ton = 0x0F, npi = 0X0F;
		gchar *text = NULL, *call_num = NULL, *ss_string = NULL, *sub_addr = NULL;
		gchar *ccp1 = NULL, *ccp2 = NULL;

		cc_result_noti = (struct tnoti_sat_call_control_result_ind *)data;
		if (cc_result_noti == NULL) {
			err("Indication data is NULL");
			return FALSE;
		}

		dbg("[%s] SAT_CALL_CTRL_RESULT - Result: [%s]", cp_name,
			(cc_result_noti->cc_result == call_control_allowed_no_mod ? "No Modification" :
			(cc_result_noti->cc_result == call_control_allowed_with_mod ? "Allowed Modification" :
			"NOT Allowed")));

		call_ctrl_result = cc_result_noti->cc_result;
		bc_repeat_indicator = cc_result_noti->bc_repeat_type.bc_indi_repeat_type;

		if (cc_result_noti->address.dialing_number_len > 0) {
			ton = cc_result_noti->address.ton;
			npi = cc_result_noti->address.npi;
			if (ton == TON_INTERNATIONAL)
				call_num = g_strdup_printf("+%s", cc_result_noti->address.dialing_number);
			else
				call_num = g_strdup(cc_result_noti->address.dialing_number);
			ss_string = g_strdup("");
		} else if (cc_result_noti->ss_string.string_len > 0) {
			ton = cc_result_noti->ss_string.ton;
			npi = cc_result_noti->ss_string.npi;
			call_num = g_strdup("");
			ss_string = g_strdup(cc_result_noti->ss_string.ss_string);
		}

		if (cc_result_noti->alpha_id.alpha_data_len > 0)
			text = g_strdup(cc_result_noti->alpha_id.alpha_data);
		else
			text = g_strdup("");

		if (cc_result_noti->sub_address.subaddress_len > 0)
			sub_addr = g_strdup(cc_result_noti->sub_address.subaddress);
		else
			sub_addr = g_strdup("");

		if (cc_result_noti->ccp1.data_len > 0)
			ccp1 = g_strdup(cc_result_noti->ccp1.data);
		else
			ccp1 = g_strdup("");

		if (cc_result_noti->ccp2.data_len > 0)
			ccp2 = g_strdup(cc_result_noti->ccp2.data);
		else
			ccp2 = g_strdup("");

		telephony_sat_emit_call_control_result(sat,
			call_ctrl_result, text, ton, npi, call_num,
			ss_string, sub_addr, ccp1, ccp2, bc_repeat_indicator);

		g_free(text);
		g_free(call_num);
		g_free(ss_string);
		g_free(sub_addr);
		g_free(ccp1);
		g_free(ccp2);
	}
	break;

	case TNOTI_SAT_MO_SM_CTRL_RESULT: {
		struct tnoti_sat_mo_sm_control_result_ind *mo_sm_result_noti = NULL;
		gint call_ctrl_result = 0;
		gint rp_dst_ton = 0x0F, rp_dst_npi = 0X0F, tp_dst_ton = 0x0F, tp_dst_npi = 0X0F;
		gchar *text = NULL, *rp_dst_call_num = NULL, *tp_dst_call_num = NULL;

		mo_sm_result_noti = (struct tnoti_sat_mo_sm_control_result_ind *)data;
		if (mo_sm_result_noti == NULL) {
			err("Indication data is NULL");
			return FALSE;
		}

		dbg("[%s] SAT_MO_SM_CTRL_RESULT - Result: [%s]", cp_name,
			(mo_sm_result_noti->cc_result == call_control_allowed_no_mod ? "No Modification" :
			(mo_sm_result_noti->cc_result == call_control_allowed_with_mod ? "Allowed Modification" :
			"NOT Allowed")));

		call_ctrl_result = mo_sm_result_noti->cc_result;

		if (mo_sm_result_noti->rp_dst_address.dialing_number_len > 0) {
			rp_dst_ton = mo_sm_result_noti->rp_dst_address.ton;
			rp_dst_npi = mo_sm_result_noti->rp_dst_address.npi;
			if (rp_dst_ton == TON_INTERNATIONAL)
				rp_dst_call_num = g_strdup_printf("+%s", mo_sm_result_noti->rp_dst_address.dialing_number);
			else
				rp_dst_call_num = g_strdup(mo_sm_result_noti->rp_dst_address.dialing_number);
		} else {
			rp_dst_call_num = g_strdup("");
		}

		if (mo_sm_result_noti->tp_dst_address.dialing_number_len > 0) {
			tp_dst_ton = mo_sm_result_noti->tp_dst_address.ton;
			tp_dst_npi = mo_sm_result_noti->tp_dst_address.npi;
			if (tp_dst_ton == TON_INTERNATIONAL)
				tp_dst_call_num = g_strdup_printf("+%s", mo_sm_result_noti->tp_dst_address.dialing_number);
			else
				tp_dst_call_num = g_strdup(mo_sm_result_noti->tp_dst_address.dialing_number);
		} else {
			tp_dst_call_num = g_strdup("");
		}

		if (mo_sm_result_noti->alpha_id.alpha_data_len > 0)
			text = g_strdup(mo_sm_result_noti->alpha_id.alpha_data);
		else
			text = g_strdup("");

		telephony_sat_emit_mo_sm_control_result(sat,
			call_ctrl_result, text,
			rp_dst_ton, rp_dst_npi, rp_dst_call_num, tp_dst_ton, tp_dst_npi, tp_dst_call_num);

		g_free(text);
		g_free(rp_dst_call_num);
		g_free(tp_dst_call_num);
	}
	break;

	case TNOTI_SAT_PROACTIVE_CMD: { /* Proactive Command Notification */
		struct tnoti_sat_proactive_ind *p_ind;
		TcorePlugin *plg;

		plg = tcore_object_ref_plugin(source);
		if (plg == NULL) {
			err("there is no valid plugin at this point");
			return FALSE;
		}

		if (cp_name == NULL) {
			err("CP name is NULL");
			return FALSE;
		}

		p_ind = (struct tnoti_sat_proactive_ind *)data;
		if (p_ind == NULL) {
			err("Indication data is NULL");
			return FALSE;
		}

		dbg("[%s] SAT_PROACTIVE_CMD - [0x%02x]", cp_name, p_ind->cmd_type);

		switch (p_ind->cmd_type) {
		case SAT_PROATV_CMD_SETUP_MENU: {
			GVariant *menu_info = NULL;
			gchar *title;
			gint command_id, menu_cnt;
			gboolean b_present, b_helpinfo, b_updated;
			GVariant *items;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id = NULL;
			GVariant *icon_list = NULL;
#endif
			menu_info = sat_manager_caching_setup_menu_info(ctx, cp_name,
				(struct tel_sat_setup_menu_tlv*)&p_ind->proactive_ind_data.setup_menu);

			dbg("PROATV_CMD_SETUP_MENU - type_format: [%s]",
				g_variant_get_type_string(menu_info));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(menu_info, "(ibs@vibb@v@v)", &command_id, &b_present, &title, &items,
				&menu_cnt, &b_helpinfo, &b_updated, &icon_id, &icon_list);
#else
			g_variant_get(menu_info, "(ibs@vibb)", &command_id, &b_present, &title, &items,
				&menu_cnt, &b_helpinfo, &b_updated);
#endif
			if (!menu_cnt) {
				dbg("NO Main Menu data");

				/*
				 * No need to cache anything so make store NULL
				 * in cached_sat_main_menu
				 */
				__sat_set_main_menu(ctx, cp_name, NULL);
				g_variant_unref(menu_info);
			} else {
				__sat_set_main_menu(ctx, cp_name, menu_info);
			}

			if (b_updated) {
#if defined(TIZEN_SUPPORT_SAT_ICON)
				telephony_sat_emit_setup_menu(sat, command_id, b_present, title, items, menu_cnt,
					b_helpinfo, b_updated, icon_id, icon_list);
#else
				telephony_sat_emit_setup_menu(sat, command_id, b_present, title, items, menu_cnt,
					b_helpinfo, b_updated);
#endif
			}

			g_free(title);
		}
		break;

		case SAT_PROATV_CMD_DISPLAY_TEXT: {
			GVariant *display_text = NULL;

			gint command_id, text_len, duration;
			gboolean high_priority, user_rsp_required, immediately_rsp;
			gchar* text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id = NULL;
#endif
			int ret;

			display_text = sat_manager_display_text_noti(ctx, cp_name,
				(struct tel_sat_display_text_tlv *)&p_ind->proactive_ind_data.display_text,
				p_ind->decode_err_code);
			if (!display_text) {
				dbg("NO Display text data");
				return TRUE;
			}

			dbg("PROATV_CMD_DISPLAY_TEXT - type_format: [%s]",
				g_variant_get_type_string(display_text));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(display_text, "(isiibbb@v)", &command_id, &text, &text_len, &duration,
				&high_priority, &user_rsp_required, &immediately_rsp, &icon_id);
#else
			g_variant_get(display_text, "(isiibbb)", &command_id, &text, &text_len, &duration,
				&high_priority, &user_rsp_required, &immediately_rsp);
#endif

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_DISPLAY_TEXT,
				display_text, slot_id);
			if (!ret) {
				int rv;

				err("Failed to launch 'sat-ui', remove the queued data!!!");

				if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
					dbg("Failed to send Terminal Response!!!");

				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if (!rv)
					dbg("Failed to de-queue data\n");
			}

#if defined(TIZEN_SUPPORT_SAT_ICON)
			telephony_sat_emit_display_text(sat, command_id, text, text_len, duration,
				high_priority, user_rsp_required, immediately_rsp, icon_id);
#else
			telephony_sat_emit_display_text(sat, command_id, text, text_len, duration,
				high_priority, user_rsp_required, immediately_rsp);
#endif

			g_free(text);
		}
		break;

		case SAT_PROATV_CMD_SELECT_ITEM: {
			GVariant *select_menu = NULL;
			gboolean help_info ;
			gchar *selected_text = NULL;
			gint command_id, default_item_id, menu_cnt, text_len = 0;
			GVariant *menu_items;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id, *icon_list;
#endif
			int ret;

			select_menu = sat_manager_select_item_noti(ctx, cp_name,
				(struct tel_sat_select_item_tlv *)&p_ind->proactive_ind_data.select_item);
			if (!select_menu) {
				dbg("NO Select menu data");
				return TRUE;
			}

			dbg("PROATV_CMD_SELECT_ITEM - type_format: [%s]",
				g_variant_get_type_string(select_menu));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(select_menu, "(ibsiii@v@v@v)", &command_id, &help_info, &selected_text,
				&text_len, &default_item_id, &menu_cnt, &menu_items, &icon_id, &icon_list);
#else
			g_variant_get(select_menu, "(ibsiii@v)", &command_id, &help_info, &selected_text,
				&text_len, &default_item_id, &menu_cnt, &menu_items);
#endif
			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_SELECT_ITEM,
				select_menu, slot_id);
			if (!ret) {
				int rv;

				err("Failed to launch 'sat-ui', remove the queued data!!!");

				if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
					dbg("Failed to send Terminal Response!!!");

				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if (!rv)
					dbg("Failed to de-queue data\n");
			}

#if defined(TIZEN_SUPPORT_SAT_ICON)
			telephony_sat_emit_select_item(sat, command_id, help_info, selected_text, text_len,
				default_item_id, menu_cnt, menu_items, icon_id, icon_list);
#else
			telephony_sat_emit_select_item(sat, command_id, help_info, selected_text, text_len,
				default_item_id, menu_cnt, menu_items);
#endif

			g_free(selected_text);
		}
		break;

		case SAT_PROATV_CMD_GET_INKEY: {
			GVariant *get_inkey = NULL;
			gint command_id, key_type, input_character_mode;
			gint text_len, duration;
			gboolean b_numeric, b_help_info;
			gchar *text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif
			int ret;

			get_inkey = sat_manager_get_inkey_noti(ctx, cp_name,
				(struct tel_sat_get_inkey_tlv *)&p_ind->proactive_ind_data.get_inkey,
				p_ind->decode_err_code);

			if (!get_inkey) {
				dbg("NO Get Inkey data");
				return TRUE;
			}

			dbg("PROATV_CMD_GET_INKEY - type_format: [%s]",
				g_variant_get_type_string(get_inkey));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(get_inkey, "(iiibbsii@v)", &command_id, &key_type, &input_character_mode,
				&b_numeric, &b_help_info, &text, &text_len, &duration, &icon_id);
#else
			g_variant_get(get_inkey, "(iiibbsii)", &command_id, &key_type, &input_character_mode,
				&b_numeric, &b_help_info, &text, &text_len, &duration);
#endif

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_GET_INKEY,
				get_inkey, slot_id);
			if (!ret) {
				int rv;

				err("Failed to launch 'sat-ui', remove the queued data!!!");

				if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
					dbg("Failed to send Terminal Response!!!");

				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if (!rv)
					dbg("Failed to de-queue data\n");
			}

#if defined(TIZEN_SUPPORT_SAT_ICON)
			telephony_sat_emit_get_inkey(sat, command_id, key_type, input_character_mode,
				b_numeric, b_help_info, text, text_len, duration, icon_id);
#else
			telephony_sat_emit_get_inkey(sat, command_id, key_type, input_character_mode,
				b_numeric, b_help_info, text, text_len, duration);
#endif

			g_free(text);
		}
		break;

		case SAT_PROATV_CMD_GET_INPUT: {
			GVariant *get_input = NULL;
			gint command_id, input_character_mode;
			gint text_len, def_text_len, rsp_len_min, rsp_len_max;
			gboolean b_numeric, b_help_info, b_echo_input;
			gchar *text = NULL, *def_text = NULL;
			int ret;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif
			get_input = sat_manager_get_input_noti(ctx, cp_name,
				(struct tel_sat_get_input_tlv *)&p_ind->proactive_ind_data.get_input,
				p_ind->decode_err_code);
			if (!get_input) {
				dbg("NO Get Input data");
				return TRUE;
			}

			dbg("PROATV_CMD_GET_INPUT - type_format: [%s]",
				g_variant_get_type_string(get_input));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(get_input, "(iibbbsiiisi@v)", &command_id,
				&input_character_mode, &b_numeric, &b_help_info,
				&b_echo_input, &text, &text_len, &rsp_len_max,
				&rsp_len_min, &def_text, &def_text_len, &icon_id);
#else
			g_variant_get(get_input, "(iibbbsiiisi)", &command_id,
				&input_character_mode, &b_numeric, &b_help_info,
				&b_echo_input, &text, &text_len, &rsp_len_max,
				&rsp_len_min, &def_text, &def_text_len);
#endif

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_GET_INPUT,
				get_input, slot_id);
			if (!ret) {
				int rv;

				err("Failed to launch 'sat-ui', remove the queued data!!!");

				if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
					dbg("Failed to send Terminal Response!!!");

				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if (!rv)
					dbg("Failed to de-queue data\n");
			}

#if defined(TIZEN_SUPPORT_SAT_ICON)
			telephony_sat_emit_get_input(sat, command_id, input_character_mode, b_numeric, b_help_info,
				b_echo_input, text, text_len, rsp_len_max, rsp_len_min, def_text, def_text_len, icon_id);
#else
			telephony_sat_emit_get_input(sat, command_id, input_character_mode, b_numeric, b_help_info,
				b_echo_input, text, text_len, rsp_len_max, rsp_len_min, def_text, def_text_len);
#endif

			g_free(text);
			g_free(def_text);
		}
		break;

		case SAT_PROATV_CMD_PLAY_TONE: {
			GVariant *play_tone = NULL;
			gint command_id, tone_type, duration;
			gint text_len;
			gchar* text = NULL;
			int ret;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif

			play_tone = sat_manager_play_tone_noti(ctx, cp_name,
				(struct tel_sat_play_tone_tlv *)&p_ind->proactive_ind_data.play_tone);
			if (!play_tone) {
				dbg("NO Play Tone data");
				return TRUE;
			}

			dbg("PROATV_CMD_PLAY_TONE - type_format: [%s]",
				g_variant_get_type_string(play_tone));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(play_tone, "(isi@vii)", &command_id, &text, &text_len, &icon_id, &tone_type, &duration);
#else
			g_variant_get(play_tone, "(isiii)", &command_id, &text, &text_len, &tone_type, &duration);
#endif

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_PLAY_TONE, play_tone, slot_id);
			if (!ret) {
				int rv;

				err("Failed to launch 'sat-ui', remove the queued data!!!");

				if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
					dbg("Failed to send Terminal Response!!!");

				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if (!rv)
					dbg("Failed to de-queue data\n");
			}

#if defined(TIZEN_SUPPORT_SAT_ICON)
			telephony_sat_emit_play_tone(sat, command_id, text, text_len, icon_id, tone_type, duration);
#else
			telephony_sat_emit_play_tone(sat, command_id, text, text_len, tone_type, duration);
#endif

			g_free(text);
		}
		break;

		case SAT_PROATV_CMD_SEND_SMS: {
			GVariant *send_sms = NULL;
			gint command_id, ton, npi, tpdu_type;
			gboolean b_packing_required;
			gint text_len, number_len, tpdu_data_len;
			gchar* text = NULL, *dialling_number = NULL;
			GVariant *tpdu_data;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif

			send_sms = sat_manager_send_sms_noti(ctx, cp_name,
				(struct tel_sat_send_sms_tlv *)&p_ind->proactive_ind_data.send_sms);
			if (!send_sms) {
				dbg("NO Send SMS data");
				return TRUE;
			}

			dbg("PROATV_CMD_SEND_SMS - type_format: [%s]",
				g_variant_get_type_string(send_sms));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(send_sms, "(isi@vbiisii@vi)", &command_id,
				&text, &text_len, &icon_id, &b_packing_required, &ton, &npi,
				&dialling_number, &number_len, &tpdu_type, &tpdu_data, &tpdu_data_len);
#else
			g_variant_get(send_sms, "(isibiisii@vi)", &command_id,
				&text, &text_len, &b_packing_required, &ton, &npi,
				&dialling_number, &number_len, &tpdu_type, &tpdu_data, &tpdu_data_len);
#endif

			dbg("Display text - text: [%s] text len: [%d]", text, text_len);
			if (text_len > 1 && (g_strcmp0(text, "") != 0)) {
				GVariant *ui_info = NULL;
				gboolean user_confirm = FALSE;
				int ret;

				dbg("Text should be displayed by UI - Send SMS is pending!!!");

#if defined(TIZEN_SUPPORT_SAT_ICON)
				ui_info = g_variant_new("(isibv)", command_id, text, text_len, user_confirm, icon_id);
#else
				ui_info = g_variant_new("(isib)", command_id, text, text_len, user_confirm);
#endif

				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_SEND_SMS,
					ui_info, slot_id);
				if (!ret) {
					int rv;

					err("Failed to launch 'sat-ui', remove the queued data!!!");

					if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
						dbg("Failed to send Terminal Response!!!");

					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if (!rv)
						dbg("Failed to de-queue data\n");
				}

				g_free(text);
				g_free(dialling_number);

				return TRUE;
			}

#if !defined(TIZEN_PLATFORM_USE_QCOM_QMI)
			telephony_sat_emit_send_sms(sat, command_id, text, text_len, b_packing_required,
				ton, npi, dialling_number, number_len, tpdu_type, tpdu_data, tpdu_data_len);
#endif

			g_free(text);
			g_free(dialling_number);
		}
		break;

		case SAT_PROATV_CMD_SEND_SS: {
			GVariant *send_ss = NULL;
			gint command_id, ton, npi;
			gint text_len, ss_str_len;
			gchar* text = NULL, *ss_string = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif

			send_ss = sat_manager_send_ss_noti(ctx, cp_name,
				(struct tel_sat_send_ss_tlv *)&p_ind->proactive_ind_data.send_ss);
			if (!send_ss) {
				dbg("NO Send SS data");
				return TRUE;
			}

			dbg("PROATV_CMD_SEND_SS - type_format: [%s]",
				g_variant_get_type_string(send_ss));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(send_ss, "(isi@viiis)", &command_id, &text, &text_len, &icon_id,
							&ton, &npi, &ss_str_len, &ss_string);
#else
			g_variant_get(send_ss, "(isiiiis)", &command_id, &text, &text_len,
							&ton, &npi, &ss_str_len, &ss_string);
#endif

			dbg("Display text - text: [%s] text len: [%d]", text, text_len);
			if (text_len > 1 && (g_strcmp0(text, "") != 0)) {
				GVariant *ui_info = NULL;
				gboolean user_confirm = FALSE;
				int ret;

				dbg("Text should be displayed by UI - Send SS is pending!!!");

#if defined(TIZEN_SUPPORT_SAT_ICON)
				ui_info = g_variant_new("(isibv)", command_id, text, text_len, user_confirm, icon_id);
#else
				ui_info = g_variant_new("(isib)", command_id, text, text_len, user_confirm);
#endif

				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE,
					ui_info, slot_id);
				if (!ret) {
					int rv;

					err("Failed to launch 'sat-ui', remove the queued data!!!");

					if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
						dbg("Failed to send Terminal Response!!!");

					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if (!rv)
						dbg("Failed to de-queue data\n");
				}

				g_free(text);
				g_free(ss_string);

				return TRUE;
			}

#if !defined(TIZEN_PLATFORM_USE_QCOM_QMI)
			telephony_sat_emit_send_ss(sat,
				command_id, text, text_len, ton, npi, ss_string);

			/*
			 * Tizen CISS
			 */
			sat_ui_support_launch_ciss_application(SAT_PROATV_CMD_SEND_SS,
				send_ss, slot_id);
#endif

			g_free(text);
			g_free(ss_string);
		}
		break;

		case SAT_PROATV_CMD_SEND_USSD: {
			GVariant *send_ussd = NULL;
			gint command_id;
			gint text_len, ussd_str_len;
			guchar dcs;
			gchar* text = NULL, *ussd_string = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif

			send_ussd = sat_manager_send_ussd_noti(ctx, cp_name,
				(struct tel_sat_send_ussd_tlv *)&p_ind->proactive_ind_data.send_ussd);
			if (!send_ussd) {
				dbg("NO Send USSD data");
				return TRUE;
			}

			dbg("PROATV_CMD_SEND_USSD - type_format: [%s]",
				g_variant_get_type_string(send_ussd));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(send_ussd, "(isi@vyis)", &command_id, &text, &text_len, &icon_id, &dcs, &ussd_str_len, &ussd_string);
#else
			g_variant_get(send_ussd, "(isiyis)", &command_id, &text, &text_len, &dcs, &ussd_str_len, &ussd_string);
#endif

			dbg("Display text - text: [%s] text len: [%d]", text, text_len);
			if (text_len > 1 && (g_strcmp0(text, "") != 0)) {
				GVariant *ui_info = NULL;
				gboolean user_confirm = FALSE;
				int ret;

				dbg("Text should be displayed by UI -Send USSD is pending!!!");

#if defined(TIZEN_SUPPORT_SAT_ICON)
				ui_info = g_variant_new("(isibv)", command_id, text, text_len, user_confirm, icon_id);
#else
				ui_info = g_variant_new("(isib)", command_id, text, text_len, user_confirm);
#endif

				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE,
					ui_info, slot_id);
				if (!ret) {
					int rv;

					err("Failed to launch 'sat-ui', remove the queued data!!!");

					if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
						dbg("Failed to send Terminal Response!!!");

					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if (!rv)
						dbg("Failed to de-queue data\n");
				}

				g_free(text);
				g_free(ussd_string);

				return TRUE;
			}

#if !defined(TIZEN_PLATFORM_USE_QCOM_QMI)
			telephony_sat_emit_setup_ussd(sat,
				command_id, text, text_len, dcs, ussd_string);

			/*
			 * Tizen CISS UI
			 */
			sat_ui_support_launch_ciss_application(SAT_PROATV_CMD_SEND_USSD,
				send_ussd, slot_id);
#endif
			g_free(text);
			g_free(ussd_string);
		}
		break;

		case SAT_PROATV_CMD_SETUP_CALL: {
			GVariant *setup_call = NULL;
			gint command_id, call_type, confirmed_text_len, text_len, duration;
			gchar *confirmed_text, *text = NULL, *call_number = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif

			setup_call = sat_manager_setup_call_noti(ctx, cp_name,
				(struct tel_sat_setup_call_tlv *)&p_ind->proactive_ind_data.setup_call);
			if (!setup_call) {
				dbg("NO Setup Call data");
				return TRUE;
			}

			dbg("PROATV_CMD_SETUP_CALL - type_format: [%s]",
				g_variant_get_type_string(setup_call));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(setup_call, "(isisi@visi)", &command_id,
				&confirmed_text, &confirmed_text_len,
				&text, &text_len, &icon_id, &call_type,
				&call_number, &duration);
#else
			g_variant_get(setup_call, "(isisiisi)", &command_id,
				&confirmed_text, &confirmed_text_len,
				&text, &text_len, &call_type, &call_number, &duration);
#endif

			dbg("Display text - text: [%s] text len: [%d]", confirmed_text, confirmed_text_len);
			if (confirmed_text_len > 1 && (g_strcmp0(confirmed_text, "") != 0)) {
				GVariant *ui_info = NULL;
				gboolean user_confirm = TRUE;
				int ret;

				dbg("Text should be displayed by UI - Setup call is pending!!!");

#if defined(TIZEN_SUPPORT_SAT_ICON)
				ui_info = g_variant_new("(isibv)", command_id,
					confirmed_text, confirmed_text_len,
					user_confirm, icon_id);
#else
				ui_info = g_variant_new("(isib)", command_id,
					confirmed_text, confirmed_text_len,
					user_confirm);
#endif

				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE,
					ui_info, slot_id);
				if (!ret) {
					int rv;

					err("Failed to launch 'sat-ui', remove the queued data!!!");

					if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
						dbg("Failed to send Terminal Response!!!");

					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if (!rv)
						dbg("Failed to de-queue data\n");
				}

				g_free(text);
				g_free(call_number);

				return TRUE;
			}
			/* In case of No user confirm phase AlphaID in SETUP CALL noti.
                         * Ref.) ETSI TS 102 223 : Section 6.4.13 and 6.6.12
                         */
#if defined(TIZEN_SUPPORT_SAT_ICON)
			telephony_sat_emit_setup_call(sat,
				command_id, confirmed_text, confirmed_text_len,
				text, text_len, icon_id, call_type, call_number, duration);
#else
			telephony_sat_emit_setup_call(sat,
				command_id, confirmed_text, confirmed_text_len,
				text, text_len, call_type, call_number, duration);
#endif
			g_free(text);
			g_free(call_number);
		}
		break;

		case SAT_PROATV_CMD_SETUP_EVENT_LIST: {
			GVariant *event_list = NULL;
			guchar event_cnt;
			GVariant *evt_list;

			event_list = sat_manager_setup_event_list_noti(ctx, cp_name,
				(struct tel_sat_setup_event_list_tlv *)&p_ind->proactive_ind_data.setup_event_list);
			if (!event_list) {
				dbg("NO Setup Event list data");
				return TRUE;
			}

			dbg("PROATV_CMD_SETUP_EVENT_LIST - type_format: [%s]",
				g_variant_get_type_string(event_list));

			g_variant_get(event_list, "(y@v)", &event_cnt, &evt_list);
			telephony_sat_emit_setup_event_list(sat, event_cnt, evt_list);

			/*
			 * BIP pro-active command is only handled
			 * by BIP Manager
			 */
			{
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				/*
				 * TODO -
				 * SAT Event Downloader should execute
				 * event_list as well.
				 */
				sat_ui_support_launch_eventdownloader_application(event_list, slot_id);

				sat_ui_support_exec_bip(conn, g_path,
					SAT_PROATV_CMD_SETUP_EVENT_LIST, event_list);
			}
		}
		break;

		case SAT_PROATV_CMD_SETUP_IDLE_MODE_TEXT: {
			GVariant *setup_idle_mode = NULL;
			int ret;
			gint command_id, text_len;
			gchar* text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif
			setup_idle_mode = sat_manager_setup_idle_mode_text_noti(ctx, cp_name,
				(struct tel_sat_setup_idle_mode_text_tlv *)&p_ind->proactive_ind_data.setup_idle_mode_text,
				p_ind->decode_err_code);
			if (!setup_idle_mode) {
				dbg("NO Setup Idle mode text data");
				return TRUE;
			}

			dbg("PROATV_CMD_SETUP_IDLE_MODE_TEXT - type_format: [%s]",
				g_variant_get_type_string(setup_idle_mode));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(setup_idle_mode, "(isi@v)", &command_id,
				&text, &text_len, &icon_id);
#else
			g_variant_get(setup_idle_mode, "(isi)", &command_id,
				&text, &text_len);
#endif

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_SETUP_IDLE_MODE_TEXT,
				setup_idle_mode, slot_id);
			if (!ret) {
				int rv;

				err("Failed to launch 'sat-ui', remove the queued data!!!");

				if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
					dbg("Failed to send Terminal Response!!!");

				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if (!rv)
					dbg("Failed to de-queue data\n");
			}

#if defined(TIZEN_SUPPORT_SAT_ICON)
			telephony_sat_emit_setup_idle_mode_text(sat,
				command_id, text, text_len, icon_id);
#else
			telephony_sat_emit_setup_idle_mode_text(sat,
			command_id, text, text_len);
#endif

			g_free(text);
		}
		break;

		case SAT_PROATV_CMD_OPEN_CHANNEL: {
			GVariant *open_channel = NULL;
			gint command_id, bearer_type, protocol_type, dest_addr_type;
			gboolean immediate_link, auto_reconnection, bg_mode;
			gint text_len, buffer_size, port_number;
			gchar *text = NULL, *dest_address;
			GVariant *bearer_param;
			GVariant *bearer_detail;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif

			open_channel = sat_manager_open_channel_noti(ctx, cp_name,
				(struct tel_sat_open_channel_tlv *)&p_ind->proactive_ind_data.open_channel);
			if (!open_channel) {
				dbg("NO Open Channel data");
				return TRUE;
			}

			dbg("PROATV_CMD_OPEN_CHANNEL - type_format: [%s]",
				g_variant_get_type_string(open_channel));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(open_channel, "(isi@vbbbi@viiiis@v)", &command_id,
				&text, &text_len, &icon_id, &immediate_link, &auto_reconnection, &bg_mode,
				&bearer_type, &bearer_param, &buffer_size, &protocol_type,
				&port_number, &dest_addr_type, &dest_address, &bearer_detail);
#else
			g_variant_get(open_channel, "(isibbbi@viiiis@v)", &command_id,
				&text, &text_len, &immediate_link, &auto_reconnection, &bg_mode,
				&bearer_type, &bearer_param, &buffer_size, &protocol_type,
				&port_number, &dest_addr_type, &dest_address, &bearer_detail);
#endif

			dbg("Display text - text: [%s] text len: [%d]", text, text_len);
			if (text_len > 1 && (g_strcmp0(text, "") != 0)) {
				GVariant *ui_info = NULL;
				gboolean user_confirm = TRUE;
				int ret;

  				dbg("Text should be displayed by UI- Open Channel text is displayed!!!");

#if defined(TIZEN_SUPPORT_SAT_ICON)
				ui_info = g_variant_new("(isibv)", command_id,
					text, text_len, user_confirm, icon_id);
#else
				ui_info = g_variant_new("(isib)", command_id,
					text, text_len, user_confirm);
#endif

				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_NONE,
					ui_info, slot_id);
				if (!ret) {
					int rv;

					err("Failed to launch 'sat-ui', remove the queued data!!!");

					if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
						dbg("Failed to send Terminal Response!!!");

					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if (!rv)
						dbg("Failed to de-queue data\n");
				}

				g_free(text);
				g_free(dest_address);

				return TRUE;
			}

			g_free(text);
			g_free(dest_address);

#if 0
			telephony_sat_emit_open_channel(sat, command_id,
				text, text_len, immediate_link, auto_reconnection, bg_mode,
				bearer_type, bearer_param, buffer_size, protocol_type, port_number,
				dest_addr_type, dest_address, bearer_detail);
#endif

#if !defined(TIZEN_PLATFORM_USE_QCOM_QMI)
			/*
			 * BIP pro-active command is only handled
			 * by BIP Manager
			 */
			{
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				sat_ui_support_exec_bip(conn, g_path,
					SAT_PROATV_CMD_OPEN_CHANNEL, open_channel);
			}
#endif
		}
		break;

		case SAT_PROATV_CMD_CLOSE_CHANNEL: {
			GVariant *close_channel = NULL;
			gint command_id, channel_id, text_len;
			gchar *text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif

			close_channel = sat_manager_close_channel_noti(ctx, cp_name,
				(struct tel_sat_close_channel_tlv *)&p_ind->proactive_ind_data.close_channel);
			if (!close_channel) {
				dbg("NO Close Channel data");
				return TRUE;
			}

			/*
			 * TODO -
			 * Check the data for sat-ui
			 */
			dbg("PROATV_CMD_CLOSE_CHANNEL - type_format: [%s]",
				g_variant_get_type_string(close_channel));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(close_channel, "(isi@vi)", &command_id,
				&text, &text_len, &icon_id, &channel_id);
#else
			g_variant_get(close_channel, "(isii)", &command_id,
				&text, &text_len, &channel_id);
#endif

#if 0
			telephony_sat_emit_close_channel(sat,
				command_id, text, text_len, channel_id);
#endif

			/*
			 * BIP pro-active command is only handled
			 * by BIP Manager
			 */
			{
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				sat_ui_support_exec_bip(conn, g_path,
					SAT_PROATV_CMD_CLOSE_CHANNEL, close_channel);
			}

			g_free(text);
		}
		break;

		case SAT_PROATV_CMD_RECEIVE_DATA: {
			GVariant *receive_data = NULL;
			gint command_id, text_len, channel_id, channel_data_len = 0;
			gchar *text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif

			receive_data = sat_manager_receive_data_noti(ctx, cp_name,
				(struct tel_sat_receive_channel_tlv *)&p_ind->proactive_ind_data.receive_data);
			if (!receive_data) {
				dbg("NO Receive data data");
				return TRUE;
			}

			/*
			 * TODO -
			 * Check the data for sat-ui
			 */

			dbg("PROATV_CMD_RECEIVE_DATA - type_format: [%s]",
				g_variant_get_type_string(receive_data));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(receive_data, "(isi@vii)", &command_id,
				&text, &text_len, &icon_id, &channel_id, &channel_data_len);
#else
			g_variant_get(receive_data, "(isiii)", &command_id,
				&text, &text_len, &channel_id, &channel_data_len);
#endif

#if 0
			telephony_sat_emit_receive_data(sat,
				command_id, text, text_len, channel_id, channel_data_len);
#endif

			/*
			 * BIP pro-active command is only handled
			 * by BIP Manager
			 */
			{
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				sat_ui_support_exec_bip(conn, g_path,
					SAT_PROATV_CMD_RECEIVE_DATA, receive_data);
			}

			g_free(text);
		}
		break;

		case SAT_PROATV_CMD_SEND_DATA: {
			GVariant *send_data = NULL;
			gint command_id, channel_id, text_len, channel_data_len;
			gboolean send_data_immediately;
			gchar *text = NULL;
			GVariant *channel_data;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id;
#endif

			send_data = sat_manager_send_data_noti(ctx, cp_name,
				(struct tel_sat_send_channel_tlv *)&p_ind->proactive_ind_data.send_data);
			if (!send_data) {
				dbg("NO Send data data");
				return TRUE;
			}

			/*
			 * TODO -
			 * Check the data for sat-ui
			 */

			dbg("PROATV_CMD_SEND_DATA - type_format: [%s]",
				g_variant_get_type_string(send_data));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(send_data, "(isi@vib@vi)", &command_id,
				&text, &text_len, &icon_id, &channel_id,
				&send_data_immediately, &channel_data, &channel_data_len);
#else
			g_variant_get(send_data, "(isiib@vi)", &command_id,
				&text, &text_len, &channel_id,
				&send_data_immediately, &channel_data, &channel_data_len);
#endif

#if 0
			telephony_sat_emit_send_data(sat,
				command_id, text, text_len, channel_id,
				send_data_immediately, channel_data, channel_data_len);
#endif

			/*
			 * BIP pro-active command is only handled
			 * by BIP Manager
			 */
			{
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				sat_ui_support_exec_bip(conn, g_path,
					SAT_PROATV_CMD_SEND_DATA, send_data);
			}

			g_free(text);
		}
		break;

		case SAT_PROATV_CMD_GET_CHANNEL_STATUS: {
			GVariant *channel_status = NULL;
			gint command_id;

			channel_status = sat_manager_get_channel_status_noti(ctx, cp_name,
				(struct tel_sat_get_channel_status_tlv *)&p_ind->proactive_ind_data.get_channel_status);
			if (!channel_status) {
				dbg("NO Get Channel Status data");
				return TRUE;
			}

			/*
			 * TODO -
			 * Check the data for sat-ui
			 */

			dbg("PROATV_CMD_GET_CHANNEL_STATUS - type_format: [%s]",
				g_variant_get_type_string(channel_status));

			g_variant_get(channel_status, "(i)", &command_id);

#if 0
			telephony_sat_emit_get_channel_status(sat, command_id);
#endif

			/*
			 * BIP pro-active command is only handled
			 * by BIP Manager
			 */
			{
				GDBusConnection *conn = NULL;
				const gchar *g_path = NULL;

				conn = g_dbus_object_manager_server_get_connection(ctx->manager);
				g_path = g_dbus_object_get_object_path(G_DBUS_OBJECT(object));

				sat_ui_support_exec_bip(conn, g_path,
					SAT_PROATV_CMD_GET_CHANNEL_STATUS, channel_status);
			}
		}
		break;

		case SAT_PROATV_CMD_REFRESH: {
			GVariant *refresh = NULL;
			gint command_id = 0;
			gint refresh_type = 0;
			GVariant *file_list = NULL;
			int ret;

			refresh = sat_manager_refresh_noti(ctx, cp_name,
				(struct tel_sat_refresh_tlv *)&p_ind->proactive_ind_data.refresh);
			if (!refresh) {
				dbg("NO Refresh data");
				return TRUE;
			}

			dbg("PROATV_CMD_REFRESH - type_format: [%s]",
				g_variant_get_type_string(refresh));

			g_variant_get(refresh, "(ii@v)", &command_id,
				&refresh_type, &file_list);

			telephony_sat_emit_refresh(sat,
				command_id, refresh_type, file_list);

			ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_REFRESH,
				refresh, slot_id);
			if (!ret) {
				int rv;

				err("Failed to launch 'sat-ui', remove the queued data!!!");

				if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
					dbg("Failed to send Terminal Response!!!");

				rv = sat_manager_remove_cmd_by_id(ctx, command_id);
				if (!rv)
					dbg("Failed to de-queue data\n");
			}
		}
		break;

		case SAT_PROATV_CMD_MORE_TIME: {
			dbg("PROATV_CMD_MORE_TIME");

			sat_manager_more_time_noti(ctx, cp_name,
				(struct tel_sat_more_time_tlv *)&p_ind->proactive_ind_data.more_time);

			telephony_sat_emit_more_time(sat);
		}
		break;

		case SAT_PROATV_CMD_SEND_DTMF: {
			GVariant *send_dtmf = NULL;
			gint command_id = 0;
			gint text_len = 0, dtmf_str_len = 0;
			gchar *text = NULL;
			gchar *dtmf_str = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id = NULL;
#endif

			send_dtmf = sat_manager_send_dtmf_noti(ctx, cp_name,
				(struct tel_sat_send_dtmf_tlv *)&p_ind->proactive_ind_data.send_dtmf);
			if (!send_dtmf) {
				dbg("NO Send DTMF data");
				return TRUE;
			}

			dbg("PROATV_CMD_SEND_DTMF - type_format: [%s]",
				g_variant_get_type_string(send_dtmf));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(send_dtmf, "(isi@vis)", &command_id,
				&text, &text_len, &icon_id, &dtmf_str_len, &dtmf_str);
#else
			g_variant_get(send_dtmf, "(isiis)", &command_id,
				&text, &text_len, &dtmf_str_len, &dtmf_str);
#endif

			if (text_len > 1 && (g_strcmp0(text, "") != 0)) {
				GVariant *ui_info = NULL;
				gboolean user_confirm = FALSE;
				int ret;

				dbg("Text should be displayed by UI - Send DTMF is displayed!!!");

#if defined(TIZEN_SUPPORT_SAT_ICON)
				ui_info = g_variant_new("(isibv)", command_id,
					text, text_len, user_confirm, icon_id);
#else
				ui_info = g_variant_new("(isib)", command_id,
					text, text_len, user_confirm);
#endif

				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_SEND_DTMF,
					ui_info, slot_id);
				if (!ret) {
					int rv;

					err("Failed to launch 'sat-ui', remove the queued data!!!");

					if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
						dbg("Failed to send Terminal Response!!!");

					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if (!rv)
						dbg("Failed to de-queue data\n");
				}

				g_free(text);
				g_free(dtmf_str);

				return TRUE;
			}

#if !defined(TIZEN_PLATFORM_USE_QCOM_QMI)
			telephony_sat_emit_send_dtmf(sat,
				command_id, text, text_len, dtmf_str, dtmf_str_len);
#endif

			g_free(text);
			g_free(dtmf_str);
		}
		break;

		case SAT_PROATV_CMD_LAUNCH_BROWSER: {
			GVariant *launch_browser = NULL;
			gint command_id = 0;
			gint browser_launch_type = 0, browser_id = 0;
			gint url_len = 0, text_len = 0, gateway_proxy_len = 0;
			gchar *url = NULL;
			gchar *text = NULL;
			gchar *gateway_proxy = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
			GVariant *icon_id = NULL;
#endif

			launch_browser = sat_manager_launch_browser_noti(ctx, cp_name,
				(struct tel_sat_launch_browser_tlv *)&p_ind->proactive_ind_data.launch_browser);
			if (!launch_browser) {
				dbg("NO launch Browser data");
				return TRUE;
			}

			dbg("PROATV_CMD_LAUNCH_BROWSER - type_format: [%s]",
				g_variant_get_type_string(launch_browser));

#if defined(TIZEN_SUPPORT_SAT_ICON)
			g_variant_get(launch_browser, "(iiisisisi@v)", &command_id,
				&browser_launch_type, &browser_id, &url, &url_len,
				&gateway_proxy, &gateway_proxy_len,
				&text, &text_len, &icon_id);
#else
			g_variant_get(launch_browser, "(iiisisisi)", &command_id,
				&browser_launch_type, &browser_id, &url, &url_len,
				&gateway_proxy, &gateway_proxy_len,
				&text, &text_len);
#endif

			/*
			 * Pop-up is MANDATORY option in Browser case
			 */
			{
				GVariant *ui_info = NULL;
				gboolean user_confirm = TRUE;
				int ret;

				dbg("Text should be displayed by UI - Launch Browser is displayed!!!");

#if defined(TIZEN_SUPPORT_SAT_ICON)
				ui_info = g_variant_new("(isibv)", command_id,
					text, text_len, user_confirm, icon_id);
#else
				ui_info = g_variant_new("(isib)", command_id,
					text, text_len, user_confirm);
#endif

				ret = sat_ui_support_launch_sat_ui(SAT_PROATV_CMD_LAUNCH_BROWSER,
					ui_info, slot_id);
				if (!ret) {
					int rv;

					err("Failed to launch 'sat-ui', remove the queued data!!!");

					if (!sat_manager_handle_sat_ui_launch_fail(ctx, cp_name, p_ind))
						dbg("Failed to send Terminal Response!!!");

					rv = sat_manager_remove_cmd_by_id(ctx, command_id);
					if (!rv)
						dbg("Failed to de-queue data\n");
				}

				g_free(url);
				g_free(text);
				g_free(gateway_proxy);

				return TRUE;
			}
		}
		break;

		case SAT_PROATV_CMD_PROVIDE_LOCAL_INFO: {
			GVariant *provide_info = NULL;
			gint info_type = 0;

			provide_info = sat_manager_provide_local_info_noti(ctx, cp_name,
				(struct tel_sat_provide_local_info_tlv *)&p_ind->proactive_ind_data.provide_local_info);
			if (!provide_info) {
				dbg("NO Provide info data");
				return TRUE;
			}

			dbg("PROATV_CMD_PROVIDE_LOCAL_INFO - type_format: [%s]",
				g_variant_get_type_string(provide_info));

			g_variant_get(provide_info, "(i)", &info_type);

			telephony_sat_emit_provide_local_info(sat, info_type);
		}
		break;

		case SAT_PROATV_CMD_LANGUAGE_NOTIFICATION: {
			GVariant *language_noti = NULL;
			gint command_id = 0;
			gint language = 0;
			gboolean b_specified = FALSE;

			language_noti = sat_manager_language_notification_noti(ctx, cp_name,
				(struct tel_sat_language_notification_tlv *)&p_ind->proactive_ind_data.language_notification);
			if (!language_noti) {
				dbg("NO Language noti data");
				return TRUE;
			}

			dbg("PROATV_CMD_LANGUAGE_NOTIFICATION - type_format: [%s]",
				g_variant_get_type_string(language_noti));

			g_variant_get(language_noti, "(iib)", &command_id,
				&language, &b_specified);

			sat_manager_update_language(ctx, cp_name, language_noti);

			telephony_sat_emit_language_notification(sat,
				command_id, language, b_specified);
		}
		break;

		default: {
			gboolean rv = FALSE;

			rv = sat_manager_processing_unsupport_proactive_command(ctx, cp_name,
				(struct tel_sat_unsupproted_command_tlv *)&p_ind->proactive_ind_data.unsupport_cmd);

			err("Unhandled/Unknown Command type: [0x%x] - Send error TR Result: [%d]", p_ind->cmd_type, rv);
		}
		break;
		}
	}
	break;

	default:
		err("Unhandled/Unknown Notification: [0x%x]", command);
	break;
	}

	return TRUE;
}

