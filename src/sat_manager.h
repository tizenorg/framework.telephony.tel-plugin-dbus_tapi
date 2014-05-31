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

#ifndef SAT_MANAGER_H_
#define SAT_MANAGER_H_

#include <tcore.h>
#include <type/sat.h>
#include "common.h"


typedef union {
	struct tel_sat_display_text_tlv displayTextInd; /**<	Parsed proactive command info from TLV to Telephony data type - display text	*/
	struct tel_sat_get_inkey_tlv getInkeyInd; /**<	Parsed proactive command info from TLV to Telephony data type - getInkey	*/
	struct tel_sat_get_input_tlv getInputInd; /**<	Parsed proactive command info from TLV to Telephony data type - getInput	*/
	struct tel_sat_play_tone_tlv play_tone;
	struct tel_sat_setup_menu_tlv setupMenuInd; /**<	Parsed proactive command info from TLV to Telephony data type - setup menu	*/
	struct tel_sat_select_item_tlv selectItemInd; /**<	Parsed proactive command info from TLV to Telephony data type - select item	*/
	struct tel_sat_send_sms_tlv sendSMSInd;
	struct tel_sat_send_ss_tlv send_ss;
	struct tel_sat_send_ussd_tlv send_ussd;
	struct tel_sat_setup_call_tlv setup_call;
	struct tel_sat_refresh_tlv refresh;
	struct tel_sat_provide_local_info_tlv provide_local_info;
	struct tel_sat_setup_idle_mode_text_tlv idle_mode;
	struct tel_sat_send_dtmf_tlv send_dtmf;
	struct tel_sat_language_notification_tlv language_notification;
	struct tel_sat_launch_browser_tlv launch_browser;
	struct tel_sat_open_channel_tlv open_channel;
	struct tel_sat_close_channel_tlv close_channel;
	struct tel_sat_receive_channel_tlv receive_data;
	struct tel_sat_send_channel_tlv send_data;
	struct tel_sat_get_channel_status_tlv get_channel_status;
} sat_manager_proactive_data;

/**
 * This structure defines the Command Queue Info.
 */
struct sat_manager_queue_data {
	enum tel_sat_proactive_cmd_type cmd_type; /**<Type of Command*/
	int cmd_id; /**<Command Id*/
	sat_manager_proactive_data cmd_data; /**<Proactive Cmd Ind Info*/
};


/*================================================================================================*/

// queue handling
void sat_manager_init_queue(struct custom_data *ctx);
gboolean sat_manager_remove_cmd_by_id(struct custom_data *ctx, int cmd_id);

//application request handling
gboolean sat_manager_handle_user_confirm(struct custom_data *ctx, TcorePlugin *plg, GVariant *user_confirm_data);
gboolean sat_manager_handle_app_exec_result(struct custom_data *ctx, TcorePlugin *plg, gint command_id, gint command_type, GVariant *exec_result);
gboolean sat_manager_handle_ui_display_status(struct custom_data *ctx, TcorePlugin *plg, gint command_id, gboolean display_status);
gboolean sat_manager_handle_event_download_envelop(int event_type, int src_dev, int dest_dev, struct tel_sat_envelop_event_download_tlv *evt_download, GVariant *download_data);
gboolean sat_manager_update_language(struct custom_data *ctx, const char *plugin_name, GVariant *language_noti);

//proactive command processing
GVariant* sat_manager_caching_setup_menu_info(struct custom_data *ctx, const char *plugin_name, struct tel_sat_setup_menu_tlv* setup_menu_tlv);
GVariant* sat_manager_display_text_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_display_text_tlv* display_text_tlv);
GVariant* sat_manager_select_item_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_select_item_tlv* select_item_tlv);
GVariant* sat_manager_get_inkey_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_get_inkey_tlv* get_inkey_tlv);
GVariant* sat_manager_get_input_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_get_input_tlv* get_input_tlv);
GVariant* sat_manager_play_tone_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_play_tone_tlv* play_tone_tlv);
GVariant* sat_manager_send_sms_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_send_sms_tlv* send_sms_tlv);
GVariant* sat_manager_send_ss_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_send_ss_tlv* send_ss_tlv);
GVariant* sat_manager_send_ussd_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_send_ussd_tlv* send_ussd_tlv);
GVariant* sat_manager_setup_call_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_setup_call_tlv* setup_call_tlv);
GVariant* sat_manager_setup_event_list_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_setup_event_list_tlv *event_list_tlv);
GVariant* sat_manager_setup_idle_mode_text_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_setup_idle_mode_text_tlv *idle_mode_tlv);
GVariant* sat_manager_open_channel_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_open_channel_tlv *open_channel_tlv);
GVariant* sat_manager_close_channel_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_close_channel_tlv *close_channel_tlv);
GVariant* sat_manager_receive_data_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_receive_channel_tlv *receive_data_tlv);
GVariant* sat_manager_send_data_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_send_channel_tlv *send_data_tlv);
GVariant* sat_manager_get_channel_status_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_get_channel_status_tlv *get_channel_status_tlv);
GVariant* sat_manager_refresh_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_refresh_tlv *refresh_tlv);
void sat_manager_more_time_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_more_time_tlv *more_time_tlv);
GVariant* sat_manager_send_dtmf_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_send_dtmf_tlv *send_dtmf_tlv);
GVariant* sat_manager_launch_browser_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_launch_browser_tlv *launch_browser_tlv);
GVariant* sat_manager_provide_local_info_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_provide_local_info_tlv *provide_local_info_tlv);
GVariant* sat_manager_language_notification_noti(struct custom_data *ctx, const char *plugin_name, struct tel_sat_language_notification_tlv *language_notification_tlv);

#endif /* SAT_MANAGER_H_ */
