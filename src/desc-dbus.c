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
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <glib.h>
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

#include "sat_ui_support.h"

#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION 1
#endif

#include "generated-code.h"
#include "common.h"

static void add_modem(struct custom_data *ctx, TcorePlugin *p)
{
	TelephonyObjectSkeleton *object;
	char *path = NULL;
	GSList *co_list;
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
	if (object) {
		dbg("DBUS interface object already created (object: %p)", object);
		goto OUT;
	}

	object = telephony_object_skeleton_new(path);
	dbg("New DBUS object created (object: [%p])", object);
	g_hash_table_insert(ctx->objects, g_strdup(path), object);

	/* Add interfaces */
	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_MODEM);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_modem_interface(object, ctx);
	}

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_CALL);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_call_interface(object, ctx);
	}

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_NETWORK);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_network_interface(object, ctx);
	}

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_SS);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_ss_interface(object, ctx);
	}

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_SMS);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_sms_interface(object, ctx);
	}

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_SAT);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_sat_interface(object, ctx);
	}

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_PHONEBOOK);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_phonebook_interface(object, ctx);
	}

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_SAP);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_sap_interface(object, ctx);
	}

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_SIM);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_sim_interface(object, ctx);
	}

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_GPS);
	if (co_list) {
		g_slist_free(co_list);
		dbus_plugin_setup_gps_interface(object, ctx);
	}
	dbus_plugin_setup_oem_interface(object, ctx);
	/* Export the Object to Manager */
	g_dbus_object_manager_server_export (ctx->manager, G_DBUS_OBJECT_SKELETON (object));


OUT:
	/* Freeing memory */
	g_free(path);
}

static void refresh_object(struct custom_data *ctx)
{
	GSList *modem_plg_list;
	TcorePlugin *modem_plg;
	GSList *cur;

	if (!ctx->manager) {
		dbg("Telephony not ready...");
		return;
	}

	modem_plg_list = tcore_server_get_modem_plugin_list(ctx->server);
	for (cur = modem_plg_list; cur; cur = cur->next) {
		modem_plg = cur->data;
		if (modem_plg == NULL) {
			dbg("No Modem Plug-in");
			continue;
		}

		/* Add modem */
		add_modem(ctx, modem_plg);
	}
	g_slist_free(modem_plg_list);
}

static TReturn send_response(Communicator *comm, UserRequest *ur, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	struct custom_data *ctx = NULL;
	struct dbus_request_info *dbus_info;
	gboolean ret = FALSE;

	dbg("Response Command = [0x%x], data_len = %d", command, data_len);


	ctx = tcore_communicator_ref_user_data(comm);
	if (!ctx) {
		dbg("user_data is NULL");
		return TCORE_RETURN_EINVAL;
	}

	dbus_info = (struct dbus_request_info *)tcore_user_request_ref_user_info(ur);
	if (!dbus_info) {
		dbg("dbus_info is NULL");
		return TCORE_RETURN_EINVAL;
	}

	if (!data) {
		g_dbus_method_invocation_return_error (dbus_info->invocation,
				G_DBUS_ERROR,
				G_DBUS_ERROR_FAILED,
				"Request failed");
		return TCORE_RETURN_SUCCESS;
	}

	switch (command & (TCORE_RESPONSE | 0x0FF00000)) {
		case TRESP_CALL:
			ret = dbus_plugin_call_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_SS:
			ret = dbus_plugin_ss_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_PS:
			break;

		case TRESP_SIM:
			ret = dbus_plugin_sim_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_SAP:
			ret = dbus_plugin_sap_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_PHONEBOOK:
			ret = dbus_plugin_phonebook_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_MODEM:
			ret = dbus_plugin_modem_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_SMS:
			ret = dbus_plugin_sms_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_SAT:
			ret = dbus_plugin_sat_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_CUSTOM:
			ret = dbus_plugin_oem_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_NETWORK:
			ret = dbus_plugin_network_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		case TRESP_GPS:
			ret = dbus_plugin_gps_response(ctx, ur, dbus_info, command, data_len, data);
			break;

		default:
			warn("unknown command (0x%x)", command);
			break;
	}

	if (ret == TRUE)
		return TCORE_RETURN_SUCCESS;
	else
		return TCORE_RETURN_FAILURE;
}

static TReturn send_notification(Communicator *comm, CoreObject *source, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	struct custom_data *ctx = NULL;
	unsigned int noti = 0;
	gboolean ret = FALSE;

	ctx = tcore_communicator_ref_user_data(comm);
	if (ctx == NULL) {
		err("user_data is NULL");
		return TCORE_RETURN_EINVAL;
	}

	noti = (command & (TCORE_NOTIFICATION | 0x0FF00000));

	/*
	 * Notifications are classified into -
	 *	Server (System) notifications
	 *	Module notifications
	 */
	if (noti == TNOTI_SERVER) {
		dbg("Server (System) Notification");

		switch (command) {
		case TNOTI_SERVER_ADDED_MODEM_PLUGIN: {
			const char *cp_name;

			cp_name = tcore_server_get_cp_name_by_plugin((TcorePlugin*)data);
			dbg("Modem Plug-in (%s) is added... Exporting interfaces for the modem", cp_name);
			add_modem(ctx, (TcorePlugin*)data);

			ret = TRUE;
			break;
		}

		case TNOTI_SERVER_ADDED_MODEM_PLUGIN_COMPLETED: {
			Storage *strg;
			gboolean b_set;
			int *count;

			if (data == NULL) {
				err("data is NULL");
				break;
			}

			count = (int *)data;
			dbg("[%d] Modem plug-ins are added...", *count);

			strg = tcore_server_find_storage(ctx->server, "vconf");

			b_set = tcore_storage_set_int(strg, STORAGE_KEY_TELEPHONY_SIM_SLOT_COUNT, *count);
			if (b_set == FALSE) {
				err("Fail to set the sim slot count vconf");

				/* Reset STORAGE_KEY_TELEPHONY_READY */
				b_set = tcore_storage_set_bool(strg, STORAGE_KEY_TELEPHONY_READY, FALSE);
				warn("Reset TELEPHONY_READY!!!");
			} else {
				if (ctx->name_acquired == TRUE
					&& tcore_storage_get_bool(strg, STORAGE_KEY_TELEPHONY_READY) == FALSE) {
					b_set = tcore_storage_set_bool(strg, STORAGE_KEY_TELEPHONY_READY, TRUE);
					if (b_set == FALSE) {
						err("Fail to set telephony ready");

						/* Reset STORAGE_KEY_TELEPHONY_SIM_SLOT_COUNT */
						b_set = tcore_storage_set_int(strg, STORAGE_KEY_TELEPHONY_SIM_SLOT_COUNT, -1);
						warn("Reset STORAGE_KEY_TELEPHONY_SIM_SLOT_COUNT!!!");
					} else {
#ifdef ENABLE_KPI_LOGS
						TIME_CHECK("Setting VCONFKEY_TELEPHONY_READY to TRUE");
#else
						msg("Setting VCONFKEY_TELEPHONY_READY to TRUE");
#endif
					}
				}
				dbg("Bus acquired...[%s]", (ctx->name_acquired)?"YES":"NO" );
			}
			ret = TRUE;
			break;
		}

		default:
			warn("Unsupported System notification: (0x%x)", command);
			break;
		}
	}
	else {
		TelephonyObjectSkeleton *object;
		const char *cp_name;
		char *path;

		cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
		if (cp_name == NULL) {
			err("CP name is NULL");
			return TCORE_RETURN_FAILURE;
		}

		path = g_strdup_printf("%s/%s", MY_DBUS_PATH, cp_name);

		/* Look-up Hash table for Object */
		object = g_hash_table_lookup(ctx->objects, path);

		dbg("[%s]:(cmd[0x%x] data[%p] len[%d] obj[%p])",
			cp_name, command, data, data_len, object);

		g_free(path);
		if (object == NULL) {
			err("Object is NOT defined!!!");
			return TCORE_RETURN_FAILURE;
		}

		switch (noti) {
		case TNOTI_CALL:
			ret = dbus_plugin_call_notification(ctx, source, object, command, data_len, data);
			break;

		case TNOTI_SS:
			ret = dbus_plugin_ss_notification(ctx, source, object, command, data_len, data);
			break;

 		case TNOTI_PS:
 			warn("PS Notification (0x%x)... Not handled!!!", noti);
			break;

		case TNOTI_SIM:
			ret = dbus_plugin_sim_notification(ctx, source, object, command, data_len, data);
			break;

		case TNOTI_SAP:
			ret = dbus_plugin_sap_notification(ctx, source, object, command, data_len, data);
			break;

		case TNOTI_PHONEBOOK:
			ret = dbus_plugin_phonebook_notification(ctx, source, object, command, data_len, data);
			break;

		case TNOTI_MODEM:
			ret = dbus_plugin_modem_notification(ctx, source, object, command, data_len, data);
			break;

		case TNOTI_SMS:
			ret = dbus_plugin_sms_notification(ctx, source, object, command, data_len, data);
			break;

		case TNOTI_SAT:
			ret = dbus_plugin_sat_notification(ctx, source, object, command, data_len, data);
			break;

		case TNOTI_NETWORK:
			ret = dbus_plugin_network_notification(ctx, source, object, command, data_len, data);
			break;

		case TNOTI_GPS:
			ret = dbus_plugin_gps_notification(ctx, source, object, command, data_len, data);
			break;

		default:
			if ((command & (TCORE_NOTIFICATION | 0x0F000000)) == (TNOTI_CUSTOM)) {
				dbg("Custom Notification: [0x%x]", command);
				ret = dbus_plugin_oem_notification(ctx, source, object, command, data_len, data);
			} else {
				warn("Unknown/Unhandled Notification: [0x%x]", command);
			}

			break;
		}
	}

	if (ret == TRUE)
		return TCORE_RETURN_SUCCESS;
	else
		return TCORE_RETURN_FAILURE;
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
	list = g_try_malloc0(sizeof(gchar *) * (count+1));
	if (list == NULL) {
		err("Memory allocation failed!!");
		telephony_manager_complete_get_modems(mgr, invocation, &name);
		g_slist_free_full(cp_name_list, g_free);
		return TRUE;
	}

	count = 0;
	for ( ; cp_name_list ; cp_name_list = cp_name_list->next) {
		name = cp_name_list->data;
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

static void on_name_lost(GDBusConnection *conn, const gchar *name, gpointer user_data)
{
	info("Lost the name %s on the session bus\n", name);
}

static void on_name_acquired(GDBusConnection *conn, const gchar *name, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	Storage *strg;
	gboolean b_set;
	int count;

	ctx->name_acquired = TRUE; /* Setting Bus acquried flag after Bus name is acquired */

	info("Acquired the name %s on the session bus", name);
	strg = tcore_server_find_storage(ctx->server, "vconf");

	count = tcore_storage_get_int(strg, STORAGE_KEY_TELEPHONY_SIM_SLOT_COUNT);
	if (count < 0) {
		err("SIM slot count not yet set");
	} else {
		if (tcore_storage_get_bool(strg, STORAGE_KEY_TELEPHONY_READY) == FALSE) {
			b_set = tcore_storage_set_bool(strg, STORAGE_KEY_TELEPHONY_READY, TRUE);
			if (b_set == FALSE) {
				err("Fail to set telephony ready");

				/* Reset STORAGE_KEY_TELEPHONY_SIM_SLOT_COUNT */
				b_set = tcore_storage_set_int(strg, STORAGE_KEY_TELEPHONY_SIM_SLOT_COUNT, -1);
				warn("Reset STORAGE_KEY_TELEPHONY_SIM_SLOT_COUNT!!!");
			} else {
#ifdef ENABLE_KPI_LOGS
				TIME_CHECK("Setting VCONFKEY_TELEPHONY_READY to TRUE");
#else
				msg("Setting VCONFKEY_TELEPHONY_READY to TRUE");
#endif
			}
		}
	}
}

static void on_bus_acquired(GDBusConnection *conn, const gchar *name, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	info("dbus registered");

	refresh_object(ctx);

	/* Add interface to default object path */
	ctx->mgr = telephony_manager_skeleton_new();
	g_signal_connect (ctx->mgr,
			"handle-get-modems",
			G_CALLBACK (on_manager_getmodems),
			ctx); /* user_data */

	g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(ctx->mgr), conn, MY_DBUS_PATH, NULL);

	g_dbus_object_manager_server_set_connection (ctx->manager, conn);

	dbg("Aquire DBUS - COMPLETE");


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

	if (!p)
		return FALSE;

	dbg("i'm init!");

	data = calloc(1, sizeof(struct custom_data));
	if (!data) {
		return FALSE;
	}

	data->plugin = p;

	comm = tcore_communicator_new(p, "dbus", &ops);
	tcore_communicator_link_user_data(comm, data);

	data->comm = comm;
	data->server = tcore_plugin_ref_server(p);

	data->objects = g_hash_table_new(g_str_hash, g_str_equal);
	data->cached_data = NULL;

	dbg("data = %p", data);

	id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
			MY_DBUS_SERVICE,
			G_BUS_NAME_OWNER_FLAGS_REPLACE,
			on_bus_acquired,
			on_name_acquired, on_name_lost,
			data,
			NULL);

	data->owner_id = id;
	dbg("owner id=[%d]", data->owner_id);

	data->manager = g_dbus_object_manager_server_new (MY_DBUS_PATH);
	refresh_object(data);

	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	struct custom_data *data = 0;
	Communicator *comm = 0;
	Server *s = tcore_plugin_ref_server(p);
	GSList *list = NULL;
	struct cached_data *object = NULL;

	if (!p)
		return;

	dbg("i'm unload");

	comm = tcore_server_find_communicator(s, "dbus");
	if (!comm)
		return;

	data = tcore_communicator_ref_user_data(comm);
	if (!data)
		return;

	if(data->owner_id > 0) {
		g_bus_unown_name(data->owner_id);
	}

	g_hash_table_destroy(data->objects);

	for (list = data->cached_data; list; list = list->next) {
		object = (struct cached_data *)list->data;
		if (object == NULL)
			continue;

		g_variant_unref(object->cached_sat_main_menu);
		g_free(object->cp_name);
		g_free(object);
	}
	g_slist_free(data->cached_data);

	free(data);

	tcore_server_remove_communicator(s, comm);
}

EXPORT_API struct tcore_plugin_define_desc plugin_define_desc =
{
	.name = "NEW_DBUS_COMMUNICATOR",
	.priority = TCORE_PLUGIN_PRIORITY_HIGH,
	.version = PLUGIN_VERSION,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
