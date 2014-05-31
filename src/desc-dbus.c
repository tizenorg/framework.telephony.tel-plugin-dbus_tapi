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
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <hal.h>
#include <communicator.h>
#include <storage.h>
#include <queue.h>
#include <user_request.h>
#include <co_network.h>
#include <co_sim.h>
#include <co_ps.h>

#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION 1
#endif

#include "generated-code.h"
#include "common.h"

static void set_telephony_ready(Server *server)
{
	static Storage *strg;
	gboolean rv;

	strg = tcore_server_find_storage(server, "vconf");
	rv = tcore_storage_set_bool(strg, STORAGE_KEY_TELEPHONY_READY, TRUE);

	dbg("Set Telephony Ready (TRUE) to registry - %s", rv ? "SUCCESS"
								: "FAIL");
}

static void add_modem(struct custom_data *ctx, TcorePlugin *p)
{
	TelephonyObjectSkeleton *object;
	CoreObject *co_sim;
	char *path = NULL;
	const char *cp_name;
	dbg("Entry");

	/* Get CP Name */
	cp_name = tcore_server_get_cp_name_by_plugin(p);
	if (cp_name == NULL) {
		err("CP Name is NULL");
		return;
	}

	path = g_strdup_printf("%s/%s", MY_DBUS_PATH, cp_name);
	dbg("PATH: [%s]", path);

	object = g_hash_table_lookup(ctx->objects, path);
	if (object == NULL) {
		/* Create new DBUS Interface object */
		object = telephony_object_skeleton_new(path);

		/* Insert the Object to DBUS interfaces HASH Table */
		dbg("New DBUS Interface object created!!! (object = %p)", object);
		if (object == NULL)
			goto OUT;

		g_hash_table_insert(ctx->objects, g_strdup(path), object);
	} else
		dbg("DBUS Interface object already created!!! (object = %p)", object);


	/* Add DBUS Interfaces for all Modules supported */

	/* MODEM */
	dbus_plugin_setup_modem_interface(object, ctx);

	/* CALL */
	if (tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL) != NULL)
		dbus_plugin_setup_call_interface(object, ctx);

	/* NETWORK */
	if (tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_NETWORK) != NULL)
		dbus_plugin_setup_network_interface(object, ctx);

	/* SS */
	if (tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SS) != NULL)
		dbus_plugin_setup_ss_interface(object, ctx);

	/* SMS */
	if (tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SMS) != NULL)
		dbus_plugin_setup_sms_interface(object, ctx);

	/* SIM */
	co_sim = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SIM);
	if (co_sim != NULL)
		dbus_plugin_setup_sim_interface(object, ctx);

	/* SAT */
	if ((co_sim != NULL) && (tcore_sim_get_status(co_sim) >= SIM_STATUS_INITIALIZING))
		if (tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SAT) != NULL)
			dbus_plugin_setup_sat_interface(object, ctx);

	/* PHONEBOOK */
	if (tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_PHONEBOOK) != NULL)
		dbus_plugin_setup_phonebook_interface(object, ctx);

	/* SAP */
	if (tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SAP) != NULL)
		dbus_plugin_setup_sap_interface(object, ctx);

	/* GPS */
	if (tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_GPS) != NULL)
		dbus_plugin_setup_gps_interface(object, ctx);

	/* Export the Object to Manager */
	g_dbus_object_manager_server_export(ctx->manager, G_DBUS_OBJECT_SKELETON(object));

	if (g_dbus_object_manager_server_get_connection (ctx->manager) != NULL)
		set_telephony_ready(ctx->server);

OUT:
	/* Freeing memory */
	g_free(path);
}

static gboolean refresh_object(gpointer user_data)
{
	struct custom_data *ctx = user_data;
	GSList *plugins;
	GSList *cur;
	TcorePlugin *p;
	CoreObject *co;
	dbg("Entry");

	if (ctx->manager == NULL) {
		err("not ready..");
		return FALSE;
	}

	plugins = tcore_server_ref_plugins(ctx->server);
	if (plugins == NULL)
		return FALSE;

	cur = plugins;
	for (cur = plugins; cur; cur = cur->next) {
		p = cur->data;
		/* AT Standard Plug-in is not considered */
		if ((p == NULL)
				|| (strcmp(tcore_plugin_ref_plugin_name(p), "AT") == 0)) {
			dbg("Plug-in Name: [%s]", tcore_plugin_ref_plugin_name(p));
			continue;
		}

		co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_MODEM);
		if (co == NULL)
			continue;

		/* Add modem */
		add_modem(ctx, p);
	}

	return FALSE;
}

static TReturn send_response(Communicator *comm, UserRequest *ur, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	struct custom_data *ctx = NULL;
	const struct tcore_user_info *ui;

	dbg("Response Command = [0x%x], data_len = %d", command, data_len);

	ctx = tcore_communicator_ref_user_data(comm);
	if (ctx == NULL) {
		dbg("user_data is NULL");
		return FALSE;
	}

	ui = tcore_user_request_ref_user_info(ur);

	switch (command & (TCORE_RESPONSE | 0x0FF00000)) {
		case TRESP_CALL:
			dbus_plugin_call_response(ctx, ur, ui->user_data, command, data_len, data);
			break;

		case TRESP_SS:
			dbus_plugin_ss_response(ctx, ur, ui->user_data, command, data_len, data);
			break;

		case TRESP_PS:
			break;

		case TRESP_SIM:
			dbus_plugin_sim_response(ctx, ur, ui->user_data, command, data_len, data);
			break;

		case TRESP_SAP:
			dbus_plugin_sap_response(ctx, ur, ui->user_data, command, data_len, data);
			break;

		case TRESP_PHONEBOOK:
			dbus_plugin_phonebook_response(ctx, ur, ui->user_data, command, data_len, data);
			break;

		case TRESP_MODEM:
			dbus_plugin_modem_response(ctx, ur, ui->user_data, command, data_len, data);
			break;

		case TRESP_SMS:
			dbus_plugin_sms_response(ctx, ur, ui->user_data, command, data_len, data);
			break;

		case TRESP_SAT:
			dbus_plugin_sat_response(ctx, ur, ui->user_data, command, data_len, data);
			break;
		case TRESP_CUSTOM:
			break;

		case TRESP_NETWORK:
			dbus_plugin_network_response(ctx, ur, ui->user_data, command, data_len, data);
			break;

		case TRESP_GPS:
			dbus_plugin_gps_response(ctx, ur, ui->user_data, command, data_len, data);
			break;

		default:
			warn("unknown command (0x%x)", command);
			break;
	}

	return FALSE;
}

static TReturn send_notification(Communicator *comm, CoreObject *source, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	struct custom_data *ctx = NULL;
	TelephonyObjectSkeleton *object;
	TcorePlugin *p;
	const char *cp_name;
	char *path = NULL;

	dbg("Notification!!! (command = 0x%x, data_len = %d)", command, data_len);

	ctx = tcore_communicator_ref_user_data(comm);
	if (ctx == NULL) {
		dbg("user_data is NULL");
		return TCORE_RETURN_FAILURE;
	}

	/*
	 * Modem binary is not embedded in the platform. Telephony needs to
	 * be set to ready for pwlock. This is temporary solution for
	 * tizen_2.1.
	 * This problem needs to be addressed in pwlock in the future.
	 */
	if (command == TNOTI_SERVER_MODEM_ERR) {
		err("Modem interface plugin init failed");
		set_telephony_ready(ctx->server);

		return TCORE_RETURN_SUCCESS;
	}

	if (command == TNOTI_SERVER_ADDED_PLUGIN)
		p = (TcorePlugin *)data;
	else
		p = tcore_object_ref_plugin(source);

	cp_name = tcore_server_get_cp_name_by_plugin(p);
	if (cp_name == NULL)
		return TCORE_RETURN_FAILURE;
	dbg("CP Name: [%s]", cp_name);

	if (cp_name) {
		path = g_strdup_printf("%s/%s", MY_DBUS_PATH, cp_name);
	}
	else {
		path = g_strdup_printf("%s", MY_DBUS_PATH);
	}
	dbg("PATH: [%s]", path);

	object = g_hash_table_lookup(ctx->objects, path);
	dbg("DBUS interface Object = [0x%x]", object);

	switch (command & (TCORE_NOTIFICATION | 0x0FF00000)) {
		case TNOTI_CALL:
			dbus_plugin_call_notification(ctx, cp_name, object, command, data_len, data);
			break;

		case TNOTI_SS:
			dbus_plugin_ss_notification(ctx, cp_name, object, command, data_len, data);
			break;

		case TNOTI_PS:
			break;

		case TNOTI_SIM:
			dbus_plugin_sim_notification(ctx, cp_name, object, command, data_len, data);
			break;

		case TNOTI_SAP:
			dbus_plugin_sap_notification(ctx, cp_name, object, command, data_len, data);
			break;

		case TNOTI_PHONEBOOK:
			dbus_plugin_phonebook_notification(ctx, cp_name, object, command, data_len, data);
			break;

		case TNOTI_MODEM:
			dbus_plugin_modem_notification(ctx, cp_name, object, command, data_len, data);
			break;

		case TNOTI_SMS:
			dbus_plugin_sms_notification(ctx, cp_name, object, command, data_len, data);
			break;

		case TNOTI_SAT:
			dbus_plugin_sat_notification(ctx, cp_name, object, command, data_len, data);
			break;
		case TNOTI_CUSTOM:
			break;

		case TNOTI_NETWORK:
			dbus_plugin_network_notification(ctx, cp_name, object, command, data_len, data);
			break;

		case TNOTI_GPS:
			dbus_plugin_gps_notification(ctx, cp_name, object, command, data_len, data);
			break;

		case TNOTI_SERVER:
			dbg("Server Notification");
			if (command == TNOTI_SERVER_ADDED_PLUGIN) {
				dbg("Plug-in is added... Refresh the context");
				g_idle_add(refresh_object, ctx);
			}
			break;

		default:
			warn("unknown command (0x%x)", command);
			break;
	}

	return FALSE;
}


static gboolean
on_manager_getmodems (TelephonyManager *mgr,
		GDBusMethodInvocation  *invocation,
		gpointer                user_data)
{
	struct custom_data *ctx = user_data;
	GSList *cp_name_list;
	gchar **list;
	const char *name = NULL;
	int count;
	dbg("Entry");

	cp_name_list = tcore_server_get_cp_name_list(ctx->server);
	if (cp_name_list == NULL) {
		telephony_manager_complete_get_modems(mgr, invocation, &name);
		return TRUE;
	}

	count = g_slist_length(cp_name_list);
	if (count == 0) {
		err("No Modems present");
		telephony_manager_complete_get_modems(mgr, invocation, &name);
		return TRUE;
	}

	dbg("count: %d", count);
	list = g_try_malloc0(sizeof(gchar *) * (count+1));
	if (list == NULL) {
		err("Failed to allocate memory");
		g_slist_free_full(cp_name_list, g_free);

		telephony_manager_complete_get_modems(mgr, invocation, &name);
		return TRUE;
	}

	count = 0;
	for ( ; cp_name_list ; cp_name_list = cp_name_list->next) {
		name = cp_name_list->data;
		if (name == NULL)
			continue;

		list[count] = g_strdup(name);
		dbg("list[%d]: %s", count, list[count]);
		count++;
	}

	telephony_manager_complete_get_modems(mgr, invocation, (const gchar **)list);

	/* Free memory */
	for (;count >= 0; count--)
		g_free(list[count]);

	g_free(list);

	/* Freeing the received list of CP names */
	g_slist_free_full(cp_name_list, g_free);

	return TRUE;
}

static void on_bus_acquired(GDBusConnection *conn, const gchar *name, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	TelephonyManager *mgr;

	info("DBUS Registered");

	/* Add interface to default object path */
	mgr = telephony_manager_skeleton_new();
	g_signal_connect (mgr,
			"handle-get-modems",
			G_CALLBACK (on_manager_getmodems),
			ctx); /* user_data */

	g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(mgr), conn, MY_DBUS_PATH, NULL);

	g_dbus_object_manager_server_set_connection (ctx->manager, conn);

	dbg("Aquire DBUS - COMPLETE");

	/* Refresh Object */
	g_idle_add(refresh_object, ctx);
}

struct tcore_communitor_operations ops = {
	.send_response = send_response,
	.send_notification = send_notification,
};

static gboolean on_load()
{
	dbg("i'm load!");

	return TRUE;
}

static gboolean on_init(TcorePlugin *p)
{
	Communicator *comm;
	struct custom_data *data;
	guint id;

	if (p == NULL)
		return FALSE;

	dbg("i'm init!");

	data = calloc(sizeof(struct custom_data), 1);
	if (data == NULL) {
		return FALSE;
	}

	data->plugin = p;

	comm = tcore_communicator_new(p, "dbus", &ops);
	tcore_communicator_link_user_data(comm, data);

	data->comm = comm;
	data->server = tcore_plugin_ref_server(p);

	data->objects = g_hash_table_new(g_str_hash, g_str_equal);
	data->cached_sat_main_menu = NULL;

	dbg("data = %p", data);

	id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
			MY_DBUS_SERVICE,
			G_BUS_NAME_OWNER_FLAGS_REPLACE,
			on_bus_acquired,
			NULL, NULL,
			data,
			NULL);

	data->manager = g_dbus_object_manager_server_new (MY_DBUS_PATH);

	g_idle_add(refresh_object, data);

	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	struct custom_data *data;
	Communicator *comm;

	if (p == NULL)
		return;

	dbg("i'm unload");

	comm = tcore_server_find_communicator(tcore_plugin_ref_server(p), "dbus");
	if (comm == NULL)
		return;

	data = tcore_communicator_ref_user_data(comm);
	if (data == NULL)
		return;

	g_hash_table_destroy(data->objects);

	free(data);
}

struct tcore_plugin_define_desc plugin_define_desc =
{
	.name = "NEW_DBUS_COMMUNICATOR",
	.priority = TCORE_PLUGIN_PRIORITY_HIGH,
	.version = PLUGIN_VERSION,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
