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

#ifndef __SAT_UI_SUPPORT_H__
#define __SAT_UI_SUPPORT_H__

#include <glib.h>
#include <gio/gio.h>

#include <tcore.h>
#include <storage.h>
#include <server.h>
#include "../dtapi_common.h"

#define PKG_ID_SAT_UI "org.tizen.sat-ui"
#define PKG_ID_SAT_UI_2 "org.tizen.sat-ui-2"

#define RELAUNCH_INTERVAL 50*1000 //100ms
#define RETRY_MAXCOUNT 3

/**
 * @brief The structure type defining menu item info for the setup menu.
 * @since_tizen 2.3
 */
struct tel_sat_menu_info {
	char itemString[SAT_DEF_ITEM_STR_LEN_MAX + 6]; /**< menu item character data */
	char itemId; /**< identifies the item on the menu that user selected */
};

/**
 * @brief The structure type defining the icon data object.
 * @since_tizen 2.3
 */
struct tel_sat_icon_identifier_info {
	int bIsPresent; /**< Flag for checking whether the icon identifier exists */
	enum icon_qualifier iconQualifier; /**< Icon qualifier type */
	unsigned char iconIdentifier; /**< Icon identifier */
	struct tel_sat_icon iconInfo; /**< Icon info */
};

/**
 * @brief The structure type defining the icon identifier data object.
 * @since_tizen 2.3
 */
struct tel_sat_icon_identifier_list_info {
	int bIsPresent; /**< Flag for checking whether the icon identifier exists */
	enum icon_qualifier iconListQualifier; /**< Icon list qualifier */
	unsigned char iconCount; /**< Icon count */
	unsigned char iconIdentifierList[SAT_ICON_LIST_MAX_COUNT]; /**< Icon identifier list */
	struct tel_sat_icon iconInfo[SAT_ICON_LIST_MAX_COUNT]; /**< Icon list info */
};

/**
 * @brief The structure type defining SAT main menu info.
 * @since_tizen 2.3
 */
struct tel_sat_setup_menu_info {
	int commandId; /**< Proactive Command Number sent by USIM */
	int bIsMainMenuPresent;
	char satMainTitle[SAT_ALPHA_ID_LEN_MAX + 1]; /**< menu title text */
	struct tel_sat_menu_info satMainMenuItem[SAT_MENU_ITEM_COUNT_MAX]; /**< menu items */
	unsigned short satMainMenuNum; /**< number of menu items */
	int bIsSatMainMenuHelpInfo; /**< flag for help information request */
	int bIsUpdatedSatMainMenu;
	struct tel_sat_icon_identifier_info iconId; /**< con Identifier */
	struct tel_sat_icon_identifier_list_info iconIdList; /**< List of Icon Identifiers */
};

/**
 * @brief The structure type defining character data for the SAT engine data structure.
 * @since_tizen 2.3
 */
struct tel_sat_text_info {
	unsigned short stringLen; /**< Character data length */
	unsigned char string[SAT_TEXT_STRING_LEN_MAX + 1]; /**< Character data */
};

/**
 * @brief The structure type defining the display text proactive command for SAT UI.
 * @since_tizen 2.3
 */
struct tel_sat_display_text_ind {
	int commandId; /**< Proactive Command Number sent by USIM */
	struct tel_sat_text_info text; /**< Character data to display on screen */
	unsigned int duration; /**< The duration of the display */
	int bIsPriorityHigh; /**< Flag that indicates whether text is to be displayed if some other app is using the screen */
	int bIsUserRespRequired; /**< Flag that indicates whether user response is required */
	int b_immediately_resp; /**< TBD */
	struct tel_sat_icon_identifier_info iconId; /**< Icon Identifier */
};

/**
 * @brief The structure type defining the menu item data object.
 * @since_tizen 2.3
 */
struct tel_sat_menu_item_info {
	unsigned char itemId; /**< Item identifier */
	unsigned char textLen; /**< Text length */
	unsigned char text[SAT_ITEM_TEXT_LEN_MAX + 1]; /**< Text information */
};

/**
 * @brief The structure type defining select item proactive command data for SAT UI.
 * @since_tizen 2.3
 */
struct tel_sat_select_item_ind {
	int commandId; /**< Proactive Command Number sent by USIM */
	int bIsHelpInfoAvailable; /**< Flag for a help information request */
	struct tel_sat_text_info text; /**< Menu title text */
	char defaultItemIndex; /**< Selected default item - default value is @c 0 */
	char menuItemCount; /**< Number of menu items */
	struct tel_sat_menu_item_info menuItem[SAT_MENU_ITEM_COUNT_MAX]; /**< Menu items */
	struct tel_sat_icon_identifier_info iconId; /**< Icon Identifier */
	struct tel_sat_icon_identifier_list_info iconIdList; /**< List of Icon Identifiers */
};

/**
 * @brief The structure type defining get inkey proactive command data for SAT UI.
 * @since_tizen 2.3
 */
struct tel_sat_get_inkey_ind {
	int commandId; /**< Proactive Command Number sent by USIM */
	enum inkey_type keyType; /**< Input Type: Character Set or Yes/No */
	enum input_alphabet_type inputCharMode; /**< Input character mode(SMS default, UCS2) */
	int bIsNumeric; /**< Is input character numeric(0-9, *, # and +) */
	int bIsHelpInfoAvailable; /**< Help info request flag */
	struct tel_sat_text_info text; /**< Character data to display on the screen */
	unsigned int duration; /**< Duration of the display */
	struct tel_sat_icon_identifier_info iconId; /**< Icon Identifier */
};

/**
 * @brief The structure type defining get input proactive command data for SAT UI.
 * @since_tizen 2.3
 */
struct tel_sat_get_input_ind {
	int commandId; /**< Proactive Command Number sent by USIM */
	enum input_alphabet_type inputCharMode; /**< Input character mode(SMS default, UCS2) */
	int bIsNumeric; /**< Is input character numeric(0-9, *, # and +) */
	int bIsHelpInfoAvailable; /**< Help info request flag */
	int bIsEchoInput; /**< Flag that indicates whether to show input data on the screen */
	struct tel_sat_text_info text; /**< Character data to display on the screen*/
	struct tel_sat_response_length respLen; /**< Input data min, max length */
	struct tel_sat_text_info defaultText; /**< Default input character data */
	struct tel_sat_icon_identifier_info iconId; /**< Icon Identifier */
};

/**
 * @brief The structure type defining refresh proactive command data for SAT UI.
 * @since_tizen 2.3
 */
struct tel_sat_refresh_ind_ui_info {
	int commandId; /**< Proactive Command Number sent by USIM */
	unsigned int duration; /**< Duration of the display */
	enum tel_sim_refresh_command refreshType; /**< Refresh mode */
};

/**
 * @brief The structure type defining play tone proactive command data for an application.
 * @since_tizen 2.3
 */
struct tel_sat_play_tone_ind {
	int commandId; /**< Proactive Command Number sent by USIM */
	struct tel_sat_text_info text; /**< Character data to display on the screen */
	struct tel_sat_tone tone; /**< Tone info */
	unsigned int duration; /**< Duration for playing the tone */
	struct tel_sat_icon_identifier_info iconId; /**< Icon Identifier */
};

/**
 * @brief The structure type defining the setup idle mode text proactive command for the idle application.
 * @since_tizen 2.3
 */
struct tel_sat_setup_idle_mode_text_ind {
	int commandId; /**< Proactive Command Number sent by USIM */
	struct tel_sat_text_info text; /**< Character data to display on the screen */
	struct tel_sat_icon_identifier_info iconId; /**< TBD */
};

/**
 * @brief The structure type defining data for SAT UI.
 * @since_tizen 2.3
 */
struct tel_sat_send_ui_info {
	int commandId; /**< Proactive Command Number sent by USIM */
	int user_confirm; /**< TBD */
	struct tel_sat_text_info text; /**< Character data to display on the screen */
	struct tel_sat_icon_identifier_info iconId; /**< Icon Identifier */
};

/**
 * @brief The structure type defining send SS proactive command data for the SS application.
 * @since_tizen 2.3
 */
struct tel_sat_send_ss_ind_ss_data {
	int commandId; /**< Proactive Command Number sent by USIM */
	enum tel_sim_ton ton; /**< Type of number */
	enum tel_sim_npi npi; /**< Number plan identity */
	unsigned short ssStringLen; /**< TBD */
	unsigned char ssString[SAT_SS_STRING_LEN_MAX + 1]; /**< TBD */
};

/**
 * @brief The structure type defining send USSD proactive command data for the USSD application.
 * @since_tizen 2.3
 */
struct tel_sat_send_ussd_ind_ussd_data {
	int commandId; /**< Proactive Command Number sent by USIM */
	unsigned char rawDcs; /**< Data coding scheme */
	unsigned short ussdStringLen; /**< TBD */
	unsigned char ussdString[SAT_USSD_STRING_LEN_MAX + 1]; /**< TBD */
};

gboolean sat_ui_support_terminate_sat_ui(void);
gboolean sat_ui_check_app_is_running(const char* app_id);
gboolean sat_ui_support_launch_browser_application(enum tel_sat_proactive_cmd_type cmd_type,
	GVariant *data, enum dbus_tapi_sim_slot_id slot_id);
gboolean sat_ui_support_launch_ciss_application(enum tel_sat_proactive_cmd_type cmd_type,
	GVariant *data, enum dbus_tapi_sim_slot_id slot_id);
gboolean sat_ui_support_launch_setting_application(enum tel_sat_proactive_cmd_type cmd_type,
	GVariant *data, enum dbus_tapi_sim_slot_id slot_id);
gboolean sat_ui_support_launch_sat_ui(enum tel_sat_proactive_cmd_type cmd_type,
	GVariant *data, enum dbus_tapi_sim_slot_id slot_id);
gboolean sat_ui_support_exec_bip(GDBusConnection *connection,
	const gchar *path, enum tel_sat_proactive_cmd_type cmd_type, GVariant *data);
gboolean sat_ui_support_storage_init(Server *server);
gboolean sat_ui_support_launch_eventdownloader_application(GVariant *data, enum dbus_tapi_sim_slot_id slot_id);


#endif /* __SAT_UI_SUPPORT_H__ */
