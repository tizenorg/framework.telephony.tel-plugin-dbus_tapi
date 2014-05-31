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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

#include "type/sim.h"

#include "generated-code.h"

#define MY_DBUS_PATH "/org/tizen/telephony"
#define MY_DBUS_SERVICE "org.tizen.telephony"

#define AC_MANAGER	"telephony_framework::api_manager"
#define AC_CALL		"telephony_framework::api_call"
#define AC_GPS		"telephony_framework::api_gps"
#define AC_MODEM	"telephony_framework::api_modem"
#define AC_NETWORK	"telephony_framework::api_network"
#define AC_PHONEBOOK	"telephony_framework::api_phonebook"
#define AC_SAP		"telephony_framework::api_sap"
#define AC_SAT		"telephony_framework::api_sat"
#define AC_SIM		"telephony_framework::api_sim"
#define AC_SMS		"telephony_framework::api_sms"
#define AC_SS		"telephony_framework::api_ss"

struct custom_data {
	TcorePlugin *plugin;
	Communicator *comm;
	Server *server;

	GHashTable *objects;
	GDBusObjectManagerServer *manager;

	GQueue queue_sat;
	gint sat_character_format;
	gpointer cached_sat_main_menu;
	struct tel_sim_ecc_list cached_sim_ecc;
};

struct dbus_request_info {
	void *interface_object;
	GDBusMethodInvocation *invocation;
};

#define GET_PLUGIN_NAME(invocation) dbus_plugin_get_plugin_name_by_object_path(g_dbus_method_invocation_get_object_path(invocation))
#define MAKE_UR(ctx,object,invocation) dbus_plugin_macro_user_request_new(ctx, object, invocation)

char *dbus_plugin_get_plugin_name_by_object_path(const char *object_path);
UserRequest *dbus_plugin_macro_user_request_new(struct custom_data *ctx, void *object, GDBusMethodInvocation *invocation);
gboolean check_access_control(GDBusMethodInvocation *invoc, const char *label, const char *perm);

gboolean dbus_plugin_setup_network_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_network_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_network_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

gboolean dbus_plugin_setup_sap_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_sap_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_sap_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

gboolean dbus_plugin_setup_phonebook_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_phonebook_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_phonebook_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

gboolean dbus_plugin_setup_sim_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_sim_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_sim_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

gboolean dbus_plugin_setup_sat_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_sat_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_sat_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

gboolean dbus_plugin_setup_sms_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_sms_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_sms_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

gboolean dbus_plugin_setup_call_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_call_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_call_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

gboolean dbus_plugin_setup_ss_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_ss_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_ss_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

gboolean dbus_plugin_setup_modem_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_modem_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_modem_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

gboolean dbus_plugin_setup_gps_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx);
gboolean dbus_plugin_gps_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data);
gboolean dbus_plugin_gps_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data);

#endif
