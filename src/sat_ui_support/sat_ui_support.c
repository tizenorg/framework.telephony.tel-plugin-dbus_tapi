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
#include <unistd.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <errno.h>
#include <aul.h>
#include <appsvc.h>
#include <bundle_internal.h>

#include "sat_ui_support.h"

#define CISS_APP "org.tizen.ciss"
#define EVENT_DOWNLOADER_SLOT1 "org.tizen.sat-event-downloader"
#define EVENT_DOWNLOADER_SLOT2 "org.tizen.sat-event-downloader-2"

struct sat_ui_app_launch_data {
	bundle *bundle_data; /**<bundle data*/
	char *slot_info; /**<slot info*/
};

static gpointer __launch_sat_ui_app(gpointer data)
{
	gint rv = 0;
	int i = 0;
	struct sat_ui_app_launch_data *app_data = (struct sat_ui_app_launch_data *)data;

	if (!app_data) {
		err("app_data does not exist");
		goto EXIT;
	}
	if (!app_data->bundle_data) {
		err("bundle_data not present");
		goto EXIT;
	}
	if (!app_data->slot_info) {
		err("slot_info not present");
		goto EXIT;
	}

	for (i = 0; i < RETRY_MAXCOUNT; i++) {
		if (g_str_has_suffix(app_data->slot_info , "0")) {
			dbg("slot 0");
			rv = aul_launch_app("org.tizen.sat-ui", app_data->bundle_data);
		} else if (g_str_has_suffix(app_data->slot_info , "1")) {
			dbg("slot 1");
			rv = aul_launch_app("org.tizen.sat-ui-2", app_data->bundle_data);
		} else {
			err("invalid sim slot id");
			break;
		}

		dbg("AUL return value:[%d]", rv);
		if ((rv == AUL_R_ECOMM) || (rv == AUL_R_ETERMINATING)) {
			err("Need to retry.");
			usleep(RELAUNCH_INTERVAL);
		} else {
			dbg("AUL launches SAT UI app");
			break;
		}
	}

EXIT:
	if (app_data) {
		bundle_free(app_data->bundle_data);
		g_free(app_data->slot_info);
		g_free(app_data);
		app_data = NULL;
	}
	return NULL;
}

static gboolean __dispatch_on_new_thread(gchar *name, GThreadFunc thread_cb, gpointer thread_data)
{
	GThread *thread;
	if (!name || !thread_cb) {
		err("Wrong Input Parameter");
		return FALSE;
	}
	thread = g_thread_new(name, thread_cb, thread_data);
	if (thread == NULL) {
		return FALSE;
	} else {
		dbg("Thread %p is created for %s", thread, name);
		g_thread_unref(thread);
	}

	return TRUE;
}

static gboolean __sat_ui_support_app_launch(bundle *bundle_data, char *slot_info)
{
	struct sat_ui_app_launch_data *app_data = NULL;

	app_data = g_malloc0(sizeof(struct sat_ui_app_launch_data));
	if (!app_data) {
		err("malloc failed");
		return FALSE;
	}
	app_data->bundle_data = bundle_data;
	app_data->slot_info = g_strdup(slot_info);

	if (FALSE == __dispatch_on_new_thread((gchar *)"SAT UI app", __launch_sat_ui_app, (gpointer)app_data)) {
		err("Unable to create thread");
		bundle_free(app_data->bundle_data);
		g_free(app_data->slot_info);
		g_free(app_data);
		app_data = NULL;
		return FALSE;
	}
	return TRUE;
}

static gboolean _sat_ui_support_processing_setup_menu_ind(GVariant *data, char *slot_info)
{
	gboolean rv = FALSE;
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd_type = NULL;
	struct tel_sat_setup_menu_info setup_menu;

	gchar *title = NULL;
	gint command_id, item_cnt;
	gboolean b_present, b_helpinfo, b_updated;
	GVariant *items = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
	GVariant *icon_id, *icon_list;
	int local_index = 0, icon_index = 0;
	/* Used to get menu items */
	GVariant *unbox;
	GVariantIter *iter, *iter2;
	gchar *item_str;
	gint item_id;
	/* Used to get icon data */
	gboolean is_exist;
	gint icon_quali, icon_identifier, width, height, ics, icon_data_len;
	gchar *icon_data = NULL;
	/* Used to get icon list data */
	GVariant *unbox_list, *unbox_list_info ;
	GVariant *icon_list_info;
	gboolean is_list_exist;
	gint icon_list_quali, list_cnt, icon_list_identifier, list_width, list_height, list_ics, icon_list_data_len;
	gchar *icon_list_data = NULL;
#else
	int local_index = 0;
	GVariant *unbox;
	GVariantIter *iter;
	gchar *item_str;
	gint item_id;
#endif
	memset(&setup_menu, 0, sizeof(struct tel_sat_setup_menu_info));

#if defined(TIZEN_SUPPORT_SAT_ICON)
	g_variant_get(data, "(ibs@vibb@v@v)", &command_id, &b_present, &title, &items, &item_cnt,
				&b_helpinfo, &b_updated, &icon_id, &icon_list);
#else
	g_variant_get(data, "(ibs@vibb)", &command_id, &b_present, &title, &items, &item_cnt,
				&b_helpinfo, &b_updated);
#endif
	setup_menu.commandId = command_id;
	setup_menu.bIsMainMenuPresent = (b_present ? 1 : 0);
	memcpy(setup_menu.satMainTitle, title, SAT_ALPHA_ID_LEN_MAX+1);
	g_free(title);

	setup_menu.satMainMenuNum = item_cnt;
	if (items && item_cnt > 0) {
		unbox = g_variant_get_variant(items);
		dbg("items(%p) items type_format(%s)", items, g_variant_get_type_string(unbox));

		g_variant_get(unbox, "a(si)", &iter);
		while (g_variant_iter_loop(iter, "(si)", &item_str, &item_id)) {
			setup_menu.satMainMenuItem[local_index].itemId = item_id;
			memcpy(setup_menu.satMainMenuItem[local_index].itemString, item_str, SAT_DEF_ITEM_STR_LEN_MAX + 6);
			local_index++;
		}
		g_variant_iter_free(iter);
	}
	setup_menu.bIsSatMainMenuHelpInfo = (b_helpinfo ? 1 : 0);
	setup_menu.bIsUpdatedSatMainMenu = (b_updated ? 1 : 0);

#if defined(TIZEN_SUPPORT_SAT_ICON)
	if (icon_id) {
		unbox = g_variant_get_variant(icon_id);
		g_variant_get(unbox, "a(biiiiiis)", &iter);

		while (g_variant_iter_loop(iter, "(biiiiiis)", &is_exist, &icon_quali, &icon_identifier, &width, &height, &ics, &icon_data_len, &icon_data)) {
			if (!is_exist)
				break;
			setup_menu.iconId.bIsPresent = is_exist;
			setup_menu.iconId.iconQualifier = icon_quali;
			setup_menu.iconId.iconIdentifier = icon_identifier;
			setup_menu.iconId.iconInfo.width = width;
			setup_menu.iconId.iconInfo.height = height;
			setup_menu.iconId.iconInfo.ics = ics;
			if (icon_data_len > 0) {
				setup_menu.iconId.iconInfo.iconDataLen = icon_data_len;
				memcpy(setup_menu.iconId.iconInfo.iconFile, icon_data, icon_data_len);
			}
			dbg("icon exist(%d), icon_quali: (%d), icon_id: (%d), width: (%d), height: (%d), ics: (%d), icon_data_len: (%d)", setup_menu.iconId.bIsPresent, setup_menu.iconId.iconQualifier, setup_menu.iconId.iconIdentifier, setup_menu.iconId.iconInfo.width,
				setup_menu.iconId.iconInfo.height, setup_menu.iconId.iconInfo.ics, setup_menu.iconId.iconInfo.iconDataLen);
		}
		g_variant_iter_free(iter);
	}

	if (icon_list) {
		unbox_list = g_variant_get_variant(icon_list);
		g_variant_get(unbox_list, "a(biiv)", &iter);

		while (g_variant_iter_loop(iter, "(biiv)", &is_list_exist, &icon_list_quali, &list_cnt, &icon_list_info)) {
			if (!is_list_exist)
				break;
			setup_menu.iconIdList.bIsPresent = is_list_exist;
			setup_menu.iconIdList.iconListQualifier = icon_list_quali;
			setup_menu.iconIdList.iconCount = list_cnt;

			unbox_list_info = g_variant_get_variant(icon_list_info);
			g_variant_get(unbox_list_info, "a(iiiiis)", &iter2);

			while (g_variant_iter_loop(iter2, "(iiiiis)", &icon_list_identifier, &list_width, &list_height, &list_ics, &icon_list_data_len, &icon_list_data)) {
				setup_menu.iconIdList.iconIdentifierList[icon_index] = icon_identifier;
				setup_menu.iconIdList.iconInfo[icon_index].width = list_width;
				setup_menu.iconIdList.iconInfo[icon_index].height = list_height;
				setup_menu.iconIdList.iconInfo[icon_index].ics = list_ics;
				if (icon_list_data_len > 0) {
					setup_menu.iconIdList.iconInfo[icon_index].iconDataLen = icon_list_data_len;
					memcpy(setup_menu.iconIdList.iconInfo[icon_index].iconFile, icon_list_data, icon_list_data_len);
				}
				icon_index++;
			}
			g_variant_iter_free(iter2);
		}
		g_variant_iter_free(iter);
	}
#endif
	cmd_type = g_strdup_printf("%d", SAT_PROATV_CMD_SETUP_MENU);
	encoded_data = g_base64_encode((const guchar*)&setup_menu, sizeof(struct tel_sat_setup_menu_info));

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);
	bundle_add(bundle_data, "data", encoded_data);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = __sat_ui_support_app_launch(bundle_data, slot_info);

	g_free(encoded_data);
	g_free(cmd_type);

	return rv;
}

static gboolean _sat_ui_support_processing_display_text_ind(GVariant *data, char *slot_info)
{
	gboolean rv = FALSE;
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd_type = NULL;
	struct tel_sat_display_text_ind display_text;

	gchar* text = NULL;
	gint command_id, text_len, duration;
	gboolean high_priority, user_rsp_required, immediately_rsp;
#if defined(TIZEN_SUPPORT_SAT_ICON)
	GVariant *icon_id = NULL;
	GVariant *unbox = NULL;
	gboolean is_exist;
	gint icon_quali, icon_identifier, width, height, ics, icon_data_len;
	gchar *icon_data = NULL;
	GVariantIter *iter;
#endif
	memset(&display_text, 0, sizeof(struct tel_sat_display_text_ind));

#if defined(TIZEN_SUPPORT_SAT_ICON)
	g_variant_get(data, "(isiibbb@v)", &command_id, &text, &text_len, &duration,
		&high_priority, &user_rsp_required, &immediately_rsp, &icon_id);
#else
	g_variant_get(data, "(isiibbb)", &command_id, &text, &text_len, &duration,
		&high_priority, &user_rsp_required, &immediately_rsp);
#endif
	display_text.commandId = command_id;
	memcpy(display_text.text.string, text, SAT_TEXT_STRING_LEN_MAX+1);
	g_free(text);

	display_text.text.stringLen = text_len;
	display_text.duration = duration;
	display_text.bIsPriorityHigh = (high_priority ? 1 : 0);
	display_text.bIsUserRespRequired = (user_rsp_required ? 1 : 0);
	display_text.b_immediately_resp = (immediately_rsp ? 1 : 0);

#if defined(TIZEN_SUPPORT_SAT_ICON)
	if (icon_id) {
		unbox = g_variant_get_variant(icon_id);
		g_variant_get(unbox, "a(biiiiiis)", &iter);

		while (g_variant_iter_loop(iter, "(biiiiiis)", &is_exist, &icon_quali, &icon_identifier, &width, &height, &ics, &icon_data_len, &icon_data)) {
			if (!is_exist)
				break;
			display_text.iconId.bIsPresent = is_exist;
			display_text.iconId.iconQualifier = icon_quali;
			display_text.iconId.iconIdentifier = icon_identifier;
			display_text.iconId.iconInfo.width = width;
			display_text.iconId.iconInfo.height = height;
			display_text.iconId.iconInfo.ics = ics;
			if (icon_data_len > 0) {
				display_text.iconId.iconInfo.iconDataLen = icon_data_len;
				memcpy(display_text.iconId.iconInfo.iconFile, icon_data, icon_data_len);
			}
			dbg("icon exist(%d), icon_quali: (%d), icon_id: (%d), width: (%d), height: (%d), ics: (%d), icon_data_len: (%d)", display_text.iconId.bIsPresent, display_text.iconId.iconQualifier, display_text.iconId.iconIdentifier, display_text.iconId.iconInfo.width,
				display_text.iconId.iconInfo.height, display_text.iconId.iconInfo.ics, display_text.iconId.iconInfo.iconDataLen);
		}
		g_variant_iter_free(iter);
	}
#endif
	dbg("duration(%d) user_rsp(%d) immediately_rsp(%d)", duration, user_rsp_required, immediately_rsp);

	cmd_type = g_strdup_printf("%d", SAT_PROATV_CMD_DISPLAY_TEXT);
	encoded_data = g_base64_encode((const guchar*)&display_text, sizeof(struct tel_sat_display_text_ind));

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);
	bundle_add(bundle_data, "data", encoded_data);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = __sat_ui_support_app_launch(bundle_data, slot_info);

	g_free(encoded_data);
	g_free(cmd_type);

	return rv;
}

static gboolean _sat_ui_support_processing_select_item_ind(GVariant *data, char *slot_info)
{
	gboolean rv = FALSE;
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd_type = NULL;
	struct tel_sat_select_item_ind select_item;

	gboolean help_info ;
	gchar *selected_text = NULL;
	gint command_id, default_item_id, menu_cnt, text_len = 0;
	GVariant *menu_items;
#if defined(TIZEN_SUPPORT_SAT_ICON)
	GVariant *icon_id, *icon_list;
	int local_index = 0, icon_index = 0;
	/* Used to get menu items */
	GVariant *unbox;
	GVariantIter *iter, *iter2;
	gchar *item_str;
	gint item_id, item_len;
	/* Used to get icon data */
	gboolean is_exist;
	gint icon_quali, icon_identifier, width, height, ics, icon_data_len;
	gchar *icon_data = NULL;
	/* Used to get icon list data */
	GVariant *unbox_list, *unbox_list_info ;
	GVariant *icon_list_info;
	gboolean is_list_exist;
	gint icon_list_quali, list_cnt, icon_list_identifier, list_width, list_height, list_ics, icon_list_data_len;
	gchar *icon_list_data = NULL;
#else
	int local_index = 0;
	GVariant *unbox;
	GVariantIter *iter;
	gchar *item_str;
	gint item_id, item_len;
#endif
	memset(&select_item, 0, sizeof(struct tel_sat_select_item_ind));

#if defined(TIZEN_SUPPORT_SAT_ICON)
	g_variant_get(data, "(ibsiii@v@v@v)", &command_id, &help_info, &selected_text,
		&text_len, &default_item_id, &menu_cnt, &menu_items, &icon_id, &icon_list);
#else
	g_variant_get(data, "(ibsiii@v)", &command_id, &help_info, &selected_text,
		&text_len, &default_item_id, &menu_cnt, &menu_items);
#endif
	select_item.commandId = command_id;
	select_item.bIsHelpInfoAvailable = (help_info ? 1 : 0);
	memcpy(select_item.text.string, selected_text, SAT_TEXT_STRING_LEN_MAX+1);
	g_free(selected_text);

	select_item.text.stringLen = text_len;
	select_item.defaultItemIndex = default_item_id;
	select_item.menuItemCount = menu_cnt;
	if (menu_items && menu_cnt > 0) {
		unbox = g_variant_get_variant(menu_items);
		dbg("items(%p) items type_format(%s)", menu_items, g_variant_get_type_string(unbox));

		g_variant_get(unbox, "a(iis)", &iter);
		while (g_variant_iter_loop(iter, "(iis)", &item_id, &item_len, &item_str)) {
			select_item.menuItem[local_index].itemId = item_id;
			select_item.menuItem[local_index].textLen = item_len;
			memcpy(select_item.menuItem[local_index].text, item_str, SAT_ITEM_TEXT_LEN_MAX + 1);
			local_index++;
		}
		g_variant_iter_free(iter);
	}

#if defined(TIZEN_SUPPORT_SAT_ICON)
	if (icon_id) {
		unbox = g_variant_get_variant(icon_id);
		g_variant_get(unbox, "a(biiiiiis)", &iter);

		while (g_variant_iter_loop(iter, "(biiiiiis)", &is_exist, &icon_quali, &icon_identifier, &width, &height, &ics, &icon_data_len, &icon_data)) {
			if (!is_exist)
				break;
			select_item.iconId.bIsPresent = is_exist;
			select_item.iconId.iconQualifier = icon_quali;
			select_item.iconId.iconIdentifier = icon_identifier;
			select_item.iconId.iconInfo.width = width;
			select_item.iconId.iconInfo.height = height;
			select_item.iconId.iconInfo.ics = ics;
			if (icon_data_len > 0) {
				select_item.iconId.iconInfo.iconDataLen = icon_data_len;
				memcpy(select_item.iconId.iconInfo.iconFile, icon_data, icon_data_len);
			}
			dbg("icon exist(%d), icon_quali: (%d), icon_id: (%d), width: (%d), height: (%d), ics: (%d), icon_data_len: (%d)", select_item.iconId.bIsPresent, select_item.iconId.iconQualifier, select_item.iconId.iconIdentifier, select_item.iconId.iconInfo.width,
					select_item.iconId.iconInfo.height, select_item.iconId.iconInfo.ics, select_item.iconId.iconInfo.iconDataLen);
		}
		g_variant_iter_free(iter);
	}

	if (icon_list) {
		unbox_list = g_variant_get_variant(icon_list);
		g_variant_get(unbox_list, "a(biiv)", &iter);

		while (g_variant_iter_loop(iter, "(biiv)", &is_list_exist, &icon_list_quali, &list_cnt, &icon_list_info)) {
			if (!is_list_exist)
				break;
			select_item.iconIdList.bIsPresent = is_list_exist;
			select_item.iconIdList.iconListQualifier = icon_list_quali;
			select_item.iconIdList.iconCount = list_cnt;

			unbox_list_info = g_variant_get_variant(icon_list_info);
			g_variant_get(unbox_list_info, "a(iiiiis)", &iter2);

			while (g_variant_iter_loop(iter2, "(iiiiis)", &icon_list_identifier, &list_width, &list_height, &list_ics, &icon_list_data_len, &icon_list_data)) {
				select_item.iconIdList.iconIdentifierList[icon_index] = icon_identifier;
				select_item.iconIdList.iconInfo[icon_index].width = list_width;
				select_item.iconIdList.iconInfo[icon_index].height = list_height;
				select_item.iconIdList.iconInfo[icon_index].ics = list_ics;
				if (icon_list_data_len > 0) {
					select_item.iconIdList.iconInfo[icon_index].iconDataLen = icon_list_data_len;
					memcpy(select_item.iconIdList.iconInfo[icon_index].iconFile, icon_list_data, icon_list_data_len);
				}
				icon_index++;
			}
			g_variant_iter_free(iter2);
		}
		g_variant_iter_free(iter);
	}
#endif
	cmd_type = g_strdup_printf("%d", SAT_PROATV_CMD_SELECT_ITEM);
	encoded_data = g_base64_encode((const guchar*)&select_item, sizeof(struct tel_sat_select_item_ind));

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);
	bundle_add(bundle_data, "data", encoded_data);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = __sat_ui_support_app_launch(bundle_data, slot_info);

	g_free(encoded_data);
	g_free(cmd_type);

	return rv;
}

static gboolean _sat_ui_support_processing_get_inkey_ind(GVariant *data, char *slot_info)
{
	gboolean rv = FALSE;
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd_type = NULL;
	struct tel_sat_get_inkey_ind get_inkey;

	gint command_id, key_type, input_character_mode;
	gint text_len, duration;
	gboolean b_numeric, b_help_info;
	gchar *text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
	GVariant *icon_id;
	GVariant *unbox = NULL;
	gboolean is_exist;
	gint icon_quali, icon_identifier, width, height, ics, icon_data_len;
	gchar *icon_data = NULL;
	GVariantIter *iter;
#endif
	memset(&get_inkey, 0, sizeof(struct tel_sat_get_inkey_ind));

#if defined(TIZEN_SUPPORT_SAT_ICON)
	g_variant_get(data, "(iiibbsii@v)", &command_id, &key_type, &input_character_mode,
		&b_numeric, &b_help_info, &text, &text_len, &duration, &icon_id);
#else
	g_variant_get(data, "(iiibbsii)", &command_id, &key_type, &input_character_mode,
		&b_numeric, &b_help_info, &text, &text_len, &duration);
#endif
	get_inkey.commandId = command_id;
	get_inkey.keyType = key_type;
	get_inkey.inputCharMode = input_character_mode;
	get_inkey.bIsNumeric = (b_numeric ? 1 : 0);
	get_inkey.bIsHelpInfoAvailable = (b_help_info ? 1 : 0);
	memcpy(get_inkey.text.string, text, SAT_TEXT_STRING_LEN_MAX+1);
	g_free(text);

	get_inkey.text.stringLen = text_len;
	get_inkey.duration = duration;

#if defined(TIZEN_SUPPORT_SAT_ICON)
	if (icon_id) {
		unbox = g_variant_get_variant(icon_id);
		g_variant_get(unbox, "a(biiiiiis)", &iter);

		while (g_variant_iter_loop(iter, "(biiiiiis)", &is_exist, &icon_quali, &icon_identifier, &width, &height, &ics, &icon_data_len, &icon_data)) {
			if (!is_exist)
			break;
			get_inkey.iconId.bIsPresent = is_exist;
			get_inkey.iconId.iconQualifier = icon_quali;
			get_inkey.iconId.iconIdentifier = icon_identifier;
			get_inkey.iconId.iconInfo.width = width;
			get_inkey.iconId.iconInfo.height = height;
			get_inkey.iconId.iconInfo.ics = ics;
			if (icon_data_len > 0) {
				get_inkey.iconId.iconInfo.iconDataLen = icon_data_len;
				memcpy(get_inkey.iconId.iconInfo.iconFile, icon_data, icon_data_len);
			}
			dbg("icon exist(%d), icon_quali: (%d), icon_id: (%d), width: (%d), height: (%d), ics: (%d), icon_data_len: (%d)", get_inkey.iconId.bIsPresent, get_inkey.iconId.iconQualifier, get_inkey.iconId.iconIdentifier, get_inkey.iconId.iconInfo.width,
				get_inkey.iconId.iconInfo.height, get_inkey.iconId.iconInfo.ics, get_inkey.iconId.iconInfo.iconDataLen);
		}
		g_variant_iter_free(iter);
	}
#endif
	cmd_type = g_strdup_printf("%d", SAT_PROATV_CMD_GET_INKEY);
	encoded_data = g_base64_encode((const guchar*)&get_inkey, sizeof(struct tel_sat_get_inkey_ind));

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);
	bundle_add(bundle_data, "data", encoded_data);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = __sat_ui_support_app_launch(bundle_data, slot_info);

	g_free(encoded_data);
	g_free(cmd_type);

	return rv;
}

static gboolean _sat_ui_support_processing_get_input_ind(GVariant *data, char *slot_info)
{
	gboolean rv = FALSE;
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd_type = NULL;
	struct tel_sat_get_input_ind get_input;

	gint command_id, input_character_mode;
	gint text_len, def_text_len, rsp_len_min, rsp_len_max;
	gboolean b_numeric, b_help_info, b_echo_input;
	gchar *text = NULL, *def_text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
	GVariant *icon_id;
	GVariant *unbox = NULL;
	gboolean is_exist;
	gint icon_quali, icon_identifier, width, height, ics, icon_data_len;
	gchar *icon_data = NULL;
	GVariantIter *iter;
#endif
	memset(&get_input, 0, sizeof(struct tel_sat_get_input_ind));

#if defined(TIZEN_SUPPORT_SAT_ICON)
	g_variant_get(data, "(iibbbsiiisi@v)", &command_id, &input_character_mode, &b_numeric, &b_help_info, &b_echo_input,
		&text, &text_len, &rsp_len_max, &rsp_len_min, &def_text, &def_text_len, &icon_id);
#else
	g_variant_get(data, "(iibbbsiiisi)", &command_id, &input_character_mode, &b_numeric, &b_help_info, &b_echo_input,
		&text, &text_len, &rsp_len_max, &rsp_len_min, &def_text, &def_text_len);
#endif
	get_input.commandId = command_id;
	get_input.inputCharMode = input_character_mode;
	get_input.bIsNumeric = (b_numeric ? 1 : 0);
	get_input.bIsHelpInfoAvailable = (b_help_info ? 1 : 0);
	get_input.bIsEchoInput = (b_echo_input ? 1 : 0);
	memcpy(get_input.text.string, text, SAT_TEXT_STRING_LEN_MAX+1);
	get_input.text.stringLen = text_len;
	get_input.respLen.max = rsp_len_max;
	get_input.respLen.min = rsp_len_min;
	memcpy(get_input.defaultText.string, def_text, SAT_TEXT_STRING_LEN_MAX+1);
	get_input.defaultText.stringLen = def_text_len;
	g_free(text);
	g_free(def_text);

#if defined(TIZEN_SUPPORT_SAT_ICON)
	if (icon_id) {
		unbox = g_variant_get_variant(icon_id);
		g_variant_get(unbox, "a(biiiiiis)", &iter);

		while (g_variant_iter_loop(iter, "(biiiiiis)", &is_exist, &icon_quali, &icon_identifier, &width, &height, &ics, &icon_data_len, &icon_data)) {
			if (!is_exist)
				break;
			get_input.iconId.bIsPresent = is_exist;
			get_input.iconId.iconQualifier = icon_quali;
			get_input.iconId.iconIdentifier = icon_identifier;
			get_input.iconId.iconInfo.width = width;
			get_input.iconId.iconInfo.height = height;
			get_input.iconId.iconInfo.ics = ics;
			if (icon_data_len > 0) {
				get_input.iconId.iconInfo.iconDataLen = icon_data_len;
				memcpy(get_input.iconId.iconInfo.iconFile, icon_data, icon_data_len);
			}
			dbg("icon exist(%d), icon_quali: (%d), icon_id: (%d), width: (%d), height: (%d), ics: (%d), icon_data_len: (%d)", get_input.iconId.bIsPresent, get_input.iconId.iconQualifier, get_input.iconId.iconIdentifier, get_input.iconId.iconInfo.width,
				get_input.iconId.iconInfo.height, get_input.iconId.iconInfo.ics, get_input.iconId.iconInfo.iconDataLen);
		}
		g_variant_iter_free(iter);
	}
#endif
	cmd_type = g_strdup_printf("%d", SAT_PROATV_CMD_GET_INPUT);
	encoded_data = g_base64_encode((const guchar*)&get_input, sizeof(struct tel_sat_get_input_ind));

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);
	bundle_add(bundle_data, "data", encoded_data);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = __sat_ui_support_app_launch(bundle_data, slot_info);

	g_free(encoded_data);
	g_free(cmd_type);

	return rv;
}

static gboolean _sat_ui_support_processing_refresh_ind(GVariant *data, char *slot_info)
{
	gboolean rv = FALSE;
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd_type = NULL;
	struct tel_sat_refresh_ind_ui_info refresh_info;

	gint command_id = 0;
	gint refresh_type = 0;
	GVariant *file_list = NULL;

	memset(&refresh_info, 0, sizeof(struct tel_sat_refresh_ind_ui_info));

	dbg("refresh type_format(%s)", g_variant_get_type_string(data));
	g_variant_get(data, "(ii@v)", &command_id, &refresh_type, &file_list);

	refresh_info.commandId = command_id;

	refresh_info.duration = 3000;

#if defined(TIZEN_SUPPORT_STK_HIDE_ALPHA_ID)
	refresh_info.duration = 0;
#endif

	refresh_info.refreshType = refresh_type;

	cmd_type = g_strdup_printf("%d", SAT_PROATV_CMD_REFRESH);
	encoded_data = g_base64_encode((const guchar*)&refresh_info, sizeof(struct tel_sat_refresh_ind_ui_info));

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);
	bundle_add(bundle_data, "data", encoded_data);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = __sat_ui_support_app_launch(bundle_data, slot_info);

	g_free(encoded_data);
	g_free(cmd_type);

	return rv;
}

static gboolean _sat_ui_support_processing_play_tone_ind(GVariant *data, char *slot_info)
{
	gboolean rv = FALSE;
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd_type = NULL;
	struct tel_sat_play_tone_ind play_tone_info;

	gint command_id, tone_type, duration;
	gint text_len;
	gchar* text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
	GVariant *icon_id;
	GVariant *unbox = NULL;
	gboolean is_exist;
	gint icon_quali, icon_identifier, width, height, ics, icon_data_len;
	gchar *icon_data = NULL;
	GVariantIter *iter;
#endif
	memset(&play_tone_info, 0, sizeof(struct tel_sat_play_tone_ind));

#if defined(TIZEN_SUPPORT_SAT_ICON)
	g_variant_get(data, "(isi@vii)", &command_id, &text, &text_len, &icon_id, &tone_type, &duration);
#else
	g_variant_get(data, "(isiii)", &command_id, &text, &text_len, &tone_type, &duration);
#endif
	play_tone_info.commandId = command_id;
	play_tone_info.duration = duration;
	play_tone_info.text.stringLen = text_len;
	memcpy(play_tone_info.text.string, text, SAT_TEXT_STRING_LEN_MAX+1);
	g_free(text);

	play_tone_info.tone.tone_type = tone_type;

#if defined(TIZEN_SUPPORT_SAT_ICON)
	if (icon_id) {
		unbox = g_variant_get_variant(icon_id);
		g_variant_get(unbox, "a(biiiiiis)", &iter);

		while (g_variant_iter_loop(iter, "(biiiiiis)", &is_exist, &icon_quali, &icon_identifier, &width, &height, &ics, &icon_data_len, &icon_data)) {
			if (!is_exist)
				break;
			play_tone_info.iconId.bIsPresent = is_exist;
			play_tone_info.iconId.iconQualifier = icon_quali;
			play_tone_info.iconId.iconIdentifier = icon_identifier;
			play_tone_info.iconId.iconInfo.width = width;
			play_tone_info.iconId.iconInfo.height = height;
			play_tone_info.iconId.iconInfo.ics = ics;
			if (icon_data_len > 0) {
				play_tone_info.iconId.iconInfo.iconDataLen = icon_data_len;
				memcpy(play_tone_info.iconId.iconInfo.iconFile, icon_data, icon_data_len);
			}
			dbg("icon exist(%d), icon_quali: (%d), icon_id: (%d), width: (%d), height: (%d), ics: (%d), icon_data_len: (%d)", play_tone_info.iconId.bIsPresent, play_tone_info.iconId.iconQualifier, play_tone_info.iconId.iconIdentifier, play_tone_info.iconId.iconInfo.width,
				play_tone_info.iconId.iconInfo.height, play_tone_info.iconId.iconInfo.ics, play_tone_info.iconId.iconInfo.iconDataLen);
		}
		g_variant_iter_free(iter);
	}
#endif
	cmd_type = g_strdup_printf("%d", SAT_PROATV_CMD_PLAY_TONE);
	encoded_data = g_base64_encode((const guchar*)&play_tone_info, sizeof(struct tel_sat_play_tone_ind));

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);
	bundle_add(bundle_data, "data", encoded_data);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = __sat_ui_support_app_launch(bundle_data, slot_info);

	g_free(encoded_data);
	g_free(cmd_type);

	return rv;
}

static gboolean _sat_ui_support_processing_idle_mode_text_ind(GVariant *data, char *slot_info)
{
	gboolean rv = FALSE;
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd_type = NULL;
	struct tel_sat_setup_idle_mode_text_ind idle_mode_text_info;

	gint command_id, text_len;
	gchar* text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
	GVariant *icon_id;
	GVariant *unbox = NULL;
	gboolean is_exist;
	gint icon_quali, icon_identifier, width, height, ics, icon_data_len;
	gchar *icon_data = NULL;
	GVariantIter *iter;
#endif
	memset(&idle_mode_text_info, 0, sizeof(struct tel_sat_setup_idle_mode_text_ind));

#if defined(TIZEN_SUPPORT_SAT_ICON)
	g_variant_get(data, "(isi@v)", &command_id, &text, &text_len, &icon_id);
#else
	g_variant_get(data, "(isi)", &command_id, &text, &text_len);
#endif
	idle_mode_text_info.commandId = command_id;
	idle_mode_text_info.text.stringLen = text_len;
	memcpy(idle_mode_text_info.text.string, text, SAT_TEXT_STRING_LEN_MAX+1);
	g_free(text);

#if defined(TIZEN_SUPPORT_SAT_ICON)
	if (icon_id) {
		unbox = g_variant_get_variant(icon_id);
		g_variant_get(unbox, "a(biiiiiis)", &iter);

		while (g_variant_iter_loop(iter, "(biiiiiis)", &is_exist, &icon_quali, &icon_identifier, &width, &height, &ics, &icon_data_len, &icon_data)) {
			if (!is_exist)
				break;
			idle_mode_text_info.iconId.bIsPresent = is_exist;
			idle_mode_text_info.iconId.iconQualifier = icon_quali;
			idle_mode_text_info.iconId.iconIdentifier = icon_identifier;
			idle_mode_text_info.iconId.iconInfo.width = width;
			idle_mode_text_info.iconId.iconInfo.height = height;
			idle_mode_text_info.iconId.iconInfo.ics = ics;
			if (icon_data_len > 0) {
				idle_mode_text_info.iconId.iconInfo.iconDataLen = icon_data_len;
				memcpy(idle_mode_text_info.iconId.iconInfo.iconFile, icon_data, icon_data_len);
			}
			dbg("icon exist(%d), icon_quali: (%d), icon_id: (%d), width: (%d), height: (%d), ics: (%d), icon_data_len: (%d)", idle_mode_text_info.iconId.bIsPresent, idle_mode_text_info.iconId.iconQualifier, idle_mode_text_info.iconId.iconIdentifier, idle_mode_text_info.iconId.iconInfo.width,
				idle_mode_text_info.iconId.iconInfo.height, idle_mode_text_info.iconId.iconInfo.ics, idle_mode_text_info.iconId.iconInfo.iconDataLen);
		}
		g_variant_iter_free(iter);
	}
#endif
	cmd_type = g_strdup_printf("%d", SAT_PROATV_CMD_SETUP_IDLE_MODE_TEXT);
	encoded_data = g_base64_encode((const guchar*)&idle_mode_text_info, sizeof(struct tel_sat_setup_idle_mode_text_ind));

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);
	bundle_add(bundle_data, "data", encoded_data);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = __sat_ui_support_app_launch(bundle_data, slot_info);

	g_free(encoded_data);
	g_free(cmd_type);

	/* P130527-4589 (I8800): Megafone Russia SIM cards.
	 * Need to check for debug without execption handling.
	 */
	if (rv != TRUE)
		err("result is error");

	return TRUE;
}

static gboolean _sat_ui_support_processing_ui_info_ind(enum tel_sat_proactive_cmd_type cmd, GVariant *data, char *slot_info)
{
	gboolean rv = FALSE;
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd_type = NULL;
	struct tel_sat_send_ui_info ui_info;

	gint command_id, text_len;
	gboolean user_confirm;
	gchar *text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
	GVariant *unbox = NULL;
	gboolean is_exist;
	gint icon_quali, icon_identifier, width, height, ics, icon_data_len;
	gchar *icon_data = NULL;
	GVariant *icon_id = NULL;
	GVariantIter *iter;
#endif
	memset(&ui_info, 0, sizeof(struct tel_sat_send_ui_info));

#if defined(TIZEN_SUPPORT_SAT_ICON)
	g_variant_get(data, "(isib@v)", &command_id, &text, &text_len, &user_confirm, &icon_id);
#else
	g_variant_get(data, "(isib)", &command_id, &text, &text_len, &user_confirm);
#endif
	dbg("command_id(%d) data(%s) len(%d) user_confirm(%d)", command_id, text, text_len, user_confirm);

	ui_info.commandId = command_id;
	memcpy(ui_info.text.string, text, SAT_TEXT_STRING_LEN_MAX+1);
	g_free(text);

	ui_info.text.stringLen = text_len;
	ui_info.user_confirm = (user_confirm ? 1 : 0);

#if defined(TIZEN_SUPPORT_SAT_ICON)
	if (icon_id) {
		unbox = g_variant_get_variant(icon_id);
		g_variant_get(unbox, "a(biiiiiis)", &iter);

		while (g_variant_iter_loop(iter, "(biiiiiis)", &is_exist, &icon_quali, &icon_identifier, &width, &height, &ics, &icon_data_len, &icon_data)) {
			if (!is_exist)
				break;
			ui_info.iconId.bIsPresent = is_exist;
			ui_info.iconId.iconQualifier = icon_quali;
			ui_info.iconId.iconIdentifier = icon_identifier;
			ui_info.iconId.iconInfo.width = width;
			ui_info.iconId.iconInfo.height = height;
			ui_info.iconId.iconInfo.ics = ics;
			if (icon_data_len > 0) {
				ui_info.iconId.iconInfo.iconDataLen = icon_data_len;
				memcpy(ui_info.iconId.iconInfo.iconFile, icon_data, icon_data_len);
			}
			dbg("icon exist(%d), icon_quali: (%d), icon_id: (%d), width: (%d), height: (%d), ics: (%d), icon_data_len: (%d)", ui_info.iconId.bIsPresent, ui_info.iconId.iconQualifier, ui_info.iconId.iconIdentifier, ui_info.iconId.iconInfo.width,
				ui_info.iconId.iconInfo.height, ui_info.iconId.iconInfo.ics, ui_info.iconId.iconInfo.iconDataLen);
		}
		g_variant_iter_free(iter);
	}
#endif
	cmd_type = g_strdup_printf("%d", cmd);
	encoded_data = g_base64_encode((const guchar*)&ui_info, sizeof(struct tel_sat_send_ui_info));

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);
	bundle_add(bundle_data, "data", encoded_data);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = __sat_ui_support_app_launch(bundle_data, slot_info);

	g_free(encoded_data);
	g_free(cmd_type);

	return rv;
}

gboolean sat_ui_check_app_is_running(const char* app_id)
{
	gboolean rv = FALSE;
	rv = aul_app_is_running(app_id);
	dbg("check the app(%s) is running rv(%d)", app_id, rv);
	return rv;
}

gboolean sat_ui_support_terminate_sat_ui()
{
	gint rv;
	bundle *bundle_data = 0;
	gchar *cmd_type = NULL;

	cmd_type = g_strdup_printf("%d", SAT_PROATV_CMD_TYPE_END_PROACTIVE_SESSION);

	bundle_data = bundle_create();
	bundle_add(bundle_data, "KEY_EXEC_TYPE", "1");
	bundle_add(bundle_data, "cmd_type", cmd_type);

	rv = aul_launch_app("org.tizen.sat-ui", bundle_data);
	dbg("session end aul (%d)", rv);

	bundle_free(bundle_data);
	g_free(cmd_type);

	return TRUE;
}

gboolean sat_ui_support_launch_sat_ui(enum tel_sat_proactive_cmd_type cmd_type, GVariant *data, enum dbus_tapi_sim_slot_id slot_id)
{
	gboolean result = FALSE;
	char slot_info[2] = {0,};

	snprintf(slot_info, 2, "%d", slot_id);
	dbg("slot_id : [%s]", slot_info);

	switch (cmd_type) {
	case SAT_PROATV_CMD_NONE:
	case SAT_PROATV_CMD_SEND_DTMF:
	case SAT_PROATV_CMD_LAUNCH_BROWSER:
	case SAT_PROATV_CMD_SEND_SMS:
		result = _sat_ui_support_processing_ui_info_ind(cmd_type, data, slot_info);
	break;
	case SAT_PROATV_CMD_SETUP_MENU:
		result = _sat_ui_support_processing_setup_menu_ind(data, slot_info);
	break;
	case SAT_PROATV_CMD_DISPLAY_TEXT:
		result = _sat_ui_support_processing_display_text_ind(data, slot_info);
	break;
	case SAT_PROATV_CMD_SELECT_ITEM:
		result = _sat_ui_support_processing_select_item_ind(data, slot_info);
	break;
	case SAT_PROATV_CMD_GET_INKEY:
		result = _sat_ui_support_processing_get_inkey_ind(data, slot_info);
	break;
	case SAT_PROATV_CMD_GET_INPUT:
		result = _sat_ui_support_processing_get_input_ind(data, slot_info);
	break;
	case SAT_PROATV_CMD_REFRESH:
		result = _sat_ui_support_processing_refresh_ind(data, slot_info);
	break;
	case SAT_PROATV_CMD_PLAY_TONE:
		result = _sat_ui_support_processing_play_tone_ind(data, slot_info);
	break;
	case SAT_PROATV_CMD_SETUP_IDLE_MODE_TEXT:
		result = _sat_ui_support_processing_idle_mode_text_ind(data, slot_info);
	break;
	case SAT_PROATV_CMD_SETUP_EVENT_LIST:
	break;
	default:
		dbg("does not need to launch sat-ui");
	break;
	}

	return result;
}

gboolean sat_ui_support_launch_browser_application(enum tel_sat_proactive_cmd_type cmd_type, GVariant *data, enum dbus_tapi_sim_slot_id slot_id)
{
	char buffer[300];
	char slot_info[2] = {0,};
	bundle *bundle_data = 0;

	dbg("launch browser application by aul");
	bundle_data = bundle_create();

	appsvc_set_pkgname(bundle_data, "org.tizen.browser");

	switch (cmd_type) {
	case SAT_PROATV_CMD_LAUNCH_BROWSER: {
		gint command_id, launch_type, browser_id;
		gint url_len, text_len, gateway_proxy_len;
		gchar *url = NULL, *text = NULL, *gateway_proxy = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
		GVariant *icon_id = NULL;
#endif
		dbg("launch_browser type_format(%s)", g_variant_get_type_string(data));
#if defined(TIZEN_SUPPORT_SAT_ICON)
		g_variant_get(data, "(iiisisisi@v)", &command_id, &launch_type, &browser_id, &url, &url_len, &gateway_proxy, &gateway_proxy_len, &text, &text_len, &icon_id);
#else
		g_variant_get(data, "(iiisisisi)", &command_id, &launch_type, &browser_id, &url, &url_len, &gateway_proxy, &gateway_proxy_len, &text, &text_len);
#endif
		if (!url || strlen(url) < 7) {
			g_free(url);
			url = g_strdup("http://");
		}
		dbg("url (%s)", url);
		appsvc_set_uri(bundle_data, url);
		g_free(url);

		snprintf(buffer, 300, "%d", TRUE);
		appsvc_add_data(bundle_data, "sat", buffer);

		snprintf(buffer, 300, "%d", command_id);
		appsvc_add_data(bundle_data, "cmd_id", buffer);
		dbg("cmd_id(%s)", buffer);

		snprintf(buffer, 300, "%d", launch_type);
		appsvc_add_data(bundle_data, "launch_type", buffer);
		dbg("launch_type(%s)", buffer);

		snprintf(buffer, 300, "%s", gateway_proxy);
		appsvc_add_data(bundle_data, "proxy", buffer);
		dbg("proxy(%s)", buffer);

		g_free(text);
		g_free(gateway_proxy);
	} break;

	default:
		bundle_free(bundle_data);
		return FALSE;
	break;
	}

	snprintf(slot_info, 2, "%d", slot_id);
	appsvc_add_data(bundle_data, "slot_id", slot_info);
	dbg("slot_id(%s)", slot_info);

	appsvc_run_service(bundle_data, 0, NULL, NULL);
	dbg("browser app is called");
	bundle_free(bundle_data);

	return TRUE;
}

gboolean sat_ui_support_launch_ciss_application(enum tel_sat_proactive_cmd_type cmd_type, GVariant *data, enum dbus_tapi_sim_slot_id slot_id)
{
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL, *cmd = NULL;
	char slot_info[2] = {0,};

	dbg("launch ciss application by aul");
	bundle_data = bundle_create();
	appsvc_set_pkgname(bundle_data, CISS_APP);

	switch (cmd_type) {
	case SAT_PROATV_CMD_SEND_SS: {
		struct tel_sat_send_ss_ind_ss_data ss_info;
		gint command_id, ton, npi;
		gint text_len, ss_str_len;
		gchar* text = NULL, *ss_string = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
		GVariant *icon_id;
#endif
		dbg("launch ciss ui for send ss proactive cmd");

		memset(&ss_info, 0, sizeof(struct tel_sat_send_ss_ind_ss_data));

		dbg("send ss type_format(%s)", g_variant_get_type_string(data));
#if defined(TIZEN_SUPPORT_SAT_ICON)
		g_variant_get(data, "(isi@viiis)", &command_id, &text, &text_len, &icon_id, &ton, &npi, &ss_str_len, &ss_string);
#else
		g_variant_get(data, "(isiiiis)", &command_id, &text, &text_len, &ton, &npi, &ss_str_len, &ss_string);
#endif
		ss_info.commandId = command_id;
		ss_info.ton = ton;
		ss_info.npi = npi;
		memcpy(ss_info.ssString, ss_string, SAT_SS_STRING_LEN_MAX+1);
		ss_info.ssStringLen = ss_str_len;
		g_free(text);
		g_free(ss_string);

		cmd = g_strdup_printf("%d", cmd_type);
		encoded_data = g_base64_encode((const guchar*)&ss_info, sizeof(struct tel_sat_send_ss_ind_ss_data));
	} break;

	case SAT_PROATV_CMD_SEND_USSD:{
		struct tel_sat_send_ussd_ind_ussd_data ussd_info;
		gint command_id;
		gint text_len, ussd_str_len;
		guchar dcs;
		gchar* text = NULL, *ussd_string = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
		GVariant *icon_id;
#endif
		dbg("launch ciss ui for send ussd proactive cmd");

		memset(&ussd_info, 0, sizeof(struct tel_sat_send_ussd_ind_ussd_data));

		dbg("send ussd type_format(%s)", g_variant_get_type_string(data));
#if defined(TIZEN_SUPPORT_SAT_ICON)
		g_variant_get(data, "(isi@vyis)", &command_id, &text, &text_len, &icon_id, &dcs, &ussd_str_len, &ussd_string);
#else
		g_variant_get(data, "(isiyis)", &command_id, &text, &text_len, &dcs, &ussd_str_len, &ussd_string);
#endif
		ussd_info.commandId = command_id;
		ussd_info.rawDcs = dcs;
		memcpy(ussd_info.ussdString, ussd_string, SAT_USSD_STRING_LEN_MAX+1);
		ussd_info.ussdStringLen = ussd_str_len;
		g_free(text);
		g_free(ussd_string);

		cmd = g_strdup_printf("%d", cmd_type);
		encoded_data = g_base64_encode((const guchar*)&ussd_info, sizeof(struct tel_sat_send_ussd_ind_ussd_data));
	} break;

	default:
		bundle_free(bundle_data);
		return FALSE;
	break;
	}

	snprintf(slot_info, 2, "%d", slot_id);
	dbg("slot_id : [%s]", slot_info);

	appsvc_add_data(bundle_data, "CISS_LAUNCHING_MODE", "RESP");
	appsvc_add_data(bundle_data, "KEY_EVENT_TYPE", cmd);
	appsvc_add_data(bundle_data, "KEY_ENCODED_DATA", encoded_data);
	appsvc_add_data(bundle_data, "KEY_SLOT_ID", slot_info);
	g_free(encoded_data);
	g_free(cmd);

	appsvc_run_service(bundle_data, 0, NULL, NULL);
	dbg("ciss is called");
	bundle_free(bundle_data);

	return TRUE;
}

gboolean sat_ui_support_launch_eventdownloader_application(GVariant *data, enum dbus_tapi_sim_slot_id slot_id)
{
	bundle *bundle_data = 0;
	gchar *encoded_data = NULL;
	struct tel_sat_event_list eventinfo;
	guchar event_count;
	GVariant *sat_event_list;
	GVariant *unbox;
	GVariantIter *iter;
	unsigned int local_index = 0;
	gint event_id = 0;

	dbg("Launch SAT Event Downloader application by aul");
	bundle_data = bundle_create();

	if (slot_id == SIM_SLOT_PRIMARY) {
		appsvc_set_pkgname(bundle_data, EVENT_DOWNLOADER_SLOT1);
	} else if(slot_id == SIM_SLOT_SECONDARY) {
		appsvc_set_pkgname(bundle_data, EVENT_DOWNLOADER_SLOT2);
	} else {
		err("wrong slot info");
		if(bundle_data)
			bundle_free(bundle_data);
		return FALSE;
	}
	memset(&eventinfo, 0, sizeof(struct tel_sat_event_list));

	dbg("sat event download type_format(%s)", g_variant_get_type_string(data));
	g_variant_get(data, "(y@v)", &event_count, &sat_event_list);

	eventinfo.event_list_cnt = event_count;
	if (eventinfo.event_list_cnt > 0) {
		unbox = g_variant_get_variant(sat_event_list);

		g_variant_get(unbox, "ai", &iter);
		while (g_variant_iter_loop(iter, "i", &event_id)) {
			eventinfo.evt_list[local_index] = event_id;
			local_index++;
		}
		g_variant_iter_free(iter);
	}

	encoded_data = g_base64_encode((const guchar*)&eventinfo, sizeof(struct tel_sat_event_list));

	appsvc_add_data(bundle_data, "EVENT_LIST_DATA", encoded_data);
	g_free(encoded_data);

	appsvc_run_service(bundle_data, 0, NULL, NULL);
	dbg("event downloader app is called");
	bundle_free(bundle_data);

	return TRUE;

}


gboolean sat_ui_support_launch_setting_application(enum tel_sat_proactive_cmd_type cmd_type, GVariant *data, enum dbus_tapi_sim_slot_id slot_id)
{
	gint rv;
	char buffer[300];
	bundle *bundle_data = 0;
	char slot_info[2] = {0,};

	dbg("launch setting application by aul");

	/*TODO : need to make a sync with app engineer*/

	switch (cmd_type) {
	case SAT_PROATV_CMD_LANGUAGE_NOTIFICATION: {
		gint command_id, call_type, text_len, duration;
		gchar *text = NULL, *call_number = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
		GVariant *icon_id;
#endif
		dbg("setup call type_format(%s)", g_variant_get_type_string(data));
#if defined(TIZEN_SUPPORT_SAT_ICON)
		g_variant_get(data, "(isi@visi)", &command_id, &text, &text_len, &icon_id, &call_type, &call_number, &duration);
#else
		g_variant_get(data, "(isiisi)", &command_id, &text, &text_len, &call_type, &call_number, &duration);
#endif
		bundle_add(bundle_data, "launch-type", "SATSETUPCALL");

		snprintf(buffer, 300, "%d", command_id);
		bundle_add(bundle_data, "cmd_id", buffer);
		dbg("cmd_id(%s)", buffer);

		snprintf(buffer, 300, "%d", call_type);
		bundle_add(bundle_data, "cmd_qual", buffer);
		dbg("cmd_qual(%s)", buffer);

		snprintf(buffer, 300, "%s", text);
		bundle_add(bundle_data, "disp_text", buffer);
		dbg("disp_text(%s)", buffer);

		snprintf(buffer, 300, "%s", call_number);
		bundle_add(bundle_data, "call_num", buffer);
		dbg("call_num(%s)", buffer);

		snprintf(buffer, 300, "%d", duration);
		bundle_add(bundle_data, "dur", buffer);
		dbg("dur(%s)", buffer);

		g_free(text);
		g_free(call_number);
	} break;

	case SAT_PROATV_CMD_PROVIDE_LOCAL_INFO:
		break;

	default:
		return FALSE;
		break;
	}

	snprintf(slot_info, 2, "%d", slot_id);
	dbg("slot_id : [%s]", slot_info);
	bundle_add(bundle_data, "slot_id", slot_info);

	rv = aul_launch_app("org.tizen.call", bundle_data);
	dbg("rv of aul_launch_app()=[%d]", rv);
	bundle_free(bundle_data);

	return TRUE;
}

gboolean sat_ui_support_exec_bip(GDBusConnection *connection, const gchar *path, enum tel_sat_proactive_cmd_type cmd_type, GVariant *data)
{
	gboolean rv = FALSE;
	gchar *signal_name = NULL;
	GVariant *out_param = NULL;

	switch (cmd_type) {
	case SAT_PROATV_CMD_OPEN_CHANNEL:{
		gint command_id, bearer_type, protocol_type, dest_addr_type;
		gboolean immediate_link, auto_reconnection, bg_mode;
		gint text_len, buffer_size, port_number;
		gchar *text = NULL, *dest_address = NULL;
		GVariant *bearer_param;
		GVariant *bearer_detail;
#if defined(TIZEN_SUPPORT_SAT_ICON)
		GVariant *icon_id;
#endif
		dbg("open channel type_format(%s)", g_variant_get_type_string(data));
#if defined(TIZEN_SUPPORT_SAT_ICON)
		g_variant_get(data, "(isi@vbbbiviiiisv)", &command_id, &text,
			&text_len, &icon_id, &immediate_link, &auto_reconnection,
			&bg_mode, &bearer_type, &bearer_param, &buffer_size,
			&protocol_type, &port_number, &dest_addr_type, &dest_address, &bearer_detail);
#else
		g_variant_get(data, "(isibbbiviiiisv)", &command_id, &text,
			&text_len, &immediate_link, &auto_reconnection, &bg_mode,
			&bearer_type, &bearer_param, &buffer_size, &protocol_type,
			&port_number, &dest_addr_type, &dest_address, &bearer_detail);
#endif
		out_param = g_variant_new("(isibbbiviiiisv)", command_id, text,
			text_len, immediate_link, auto_reconnection, bg_mode,
			bearer_type, bearer_param, buffer_size, protocol_type,
			port_number, dest_addr_type, dest_address, bearer_detail);
		signal_name = g_strdup("OpenChannel");

		g_free(text);
		g_free(dest_address);
	} break;
	case SAT_PROATV_CMD_CLOSE_CHANNEL:{
		gint command_id, channel_id, text_len;
		gchar *text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
		GVariant *icon_id;
#endif
		dbg("close channel type_format(%s)", g_variant_get_type_string(data));
#if defined(TIZEN_SUPPORT_SAT_ICON)
		g_variant_get(data, "(isi@vi)", &command_id, &text, &text_len, &icon_id, &channel_id);
#else
		g_variant_get(data, "(isii)", &command_id, &text, &text_len, &channel_id);
#endif
		out_param = g_variant_new("(isii)", command_id, text, text_len, channel_id);
		signal_name = g_strdup("CloseChannel");

		g_free(text);
	} break;
	case SAT_PROATV_CMD_RECEIVE_DATA:{
		gint command_id, text_len, channel_id, channel_data_len = 0;
		gchar *text = NULL;
#if defined(TIZEN_SUPPORT_SAT_ICON)
		GVariant *icon_id;
#endif
		dbg("receive data type_format(%s)", g_variant_get_type_string(data));
#if defined(TIZEN_SUPPORT_SAT_ICON)
		g_variant_get(data, "(isi@vii)", &command_id, &text, &text_len, &icon_id, &channel_id, &channel_data_len);
#else
		g_variant_get(data, "(isiii)", &command_id, &text, &text_len, &channel_id, &channel_data_len);
#endif
		out_param = g_variant_new("(isiii)", command_id, text, text_len, channel_id, channel_data_len);
		signal_name = g_strdup("ReceiveData");

		g_free(text);
	} break;
	case SAT_PROATV_CMD_SEND_DATA:{
		gint command_id, channel_id, text_len, channel_data_len;
		gboolean send_data_immediately;
		gchar *text = NULL;
		GVariant *channel_data;
#if defined(TIZEN_SUPPORT_SAT_ICON)
		GVariant *icon_id;
#endif
		dbg("send data type_format(%s)", g_variant_get_type_string(data));
#if defined(TIZEN_SUPPORT_SAT_ICON)
		g_variant_get(data, "(isi@vibvi)", &command_id, &text,
			&text_len, &icon_id, &channel_id, &send_data_immediately,
			&channel_data, &channel_data_len);
#else
		g_variant_get(data, "(isiibvi)", &command_id, &text,
			&text_len, &channel_id, &send_data_immediately,
			&channel_data, &channel_data_len);
#endif
		out_param = g_variant_new("(isiibvi)", command_id, text,
			text_len, channel_id, send_data_immediately, channel_data, channel_data_len);
		signal_name = g_strdup("SendData");

		g_free(text);
	} break;
	case SAT_PROATV_CMD_GET_CHANNEL_STATUS:{
		gint command_id;

		dbg("get channel status type_format(%s)", g_variant_get_type_string(data));
		g_variant_get(data, "(i)", &command_id);

		out_param = g_variant_new("(i)", command_id);
		signal_name = g_strdup("GetChannelStatus");
	} break;
	case SAT_PROATV_CMD_SETUP_EVENT_LIST:{
		gint event_cnt;
		GVariant *evt_list;

		dbg("setup event list type_format(%s)", g_variant_get_type_string(data));
		g_variant_get(data, "(y@v)", &event_cnt, &evt_list);

		out_param = g_variant_new("(yv)", event_cnt, evt_list);
		signal_name = g_strdup("SetupEventList");
	} break;
	default:
		dbg("no matched command");
		return FALSE;
	break;
	}

	dbg("dbus conn(%p), path(%s)", connection, path);
	rv = g_dbus_connection_emit_signal(connection, "org.tizen.bip-manager", path, "org.tizen.telephony.SAT", signal_name, out_param, NULL);
	g_free(signal_name);

	dbg("send signal to bip-mananger result (%d)", rv);

	return rv;
}

