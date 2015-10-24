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
#include <time.h>

#include <glib.h>
#include <gio/gio.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <communicator.h>
#include <storage.h>
#include <user_request.h>
#include <co_network.h>
#include <co_sim.h>
#include <co_ps.h>

#include "generated-code.h"
#include "dtapi_common.h"

static void __dtapi_initialize_properties(CoreObject *source,
	TelephonyObjectSkeleton *object)
{
	TelephonyNetwork *network;
	TelephonyModem *modem;
	TelephonySim *sim;

	if (!object) {
		err("object is NULL");
		return;
	}

	/* initialize network dbus properties */
	network = telephony_object_peek_network(TELEPHONY_OBJECT(object));
	if (network == NULL) {
		err("Network object is NULL!!!");
	} else {
		telephony_network_set_access_technology(network, NETWORK_ACT_UNKNOWN);
		telephony_network_set_cell_id(network, 0);
		telephony_network_set_ims_voice_status(network, NETWORK_IMS_VOICE_UNKNOWN);
		telephony_network_set_circuit_status(network, NETWORK_SERVICE_DOMAIN_STATUS_NO);
		telephony_network_set_lac(network, 0);
		telephony_network_set_name_option(network, NETWORK_NAME_OPTION_NONE);
		telephony_network_set_packet_status(network, NETWORK_SERVICE_DOMAIN_STATUS_NO);
		telephony_network_set_sig_dbm(network, 0);
		telephony_network_set_roaming_status(network, FALSE);
		telephony_network_set_ps_type(network, TELEPHONY_HSDPA_OFF);
		telephony_network_set_service_type(network, NETWORK_SERVICE_TYPE_UNKNOWN);
		telephony_network_set_sig_level(network, 0);
		telephony_network_set_plmn(network, NULL);
		telephony_network_set_spn_name(network, NULL);
		telephony_network_set_network_name(network, NULL);
	}

	/* initialize modem dbus properties */
	modem = telephony_object_peek_modem(TELEPHONY_OBJECT(object));
	if (modem == NULL) {
		err("Modem object is NULL!!!");
	} else {
		telephony_modem_set_dongle_status(modem, 0);
		telephony_modem_set_dongle_login(modem, 0);
		telephony_modem_set_power(modem, MODEM_STATE_UNKNOWN);
	}

	/* initialize sim dbus properties */
	sim = telephony_object_peek_sim(TELEPHONY_OBJECT(object));
	if (sim == NULL)
		err("Sim object is NULL!!!");
	else
		telephony_sim_set_cf_state(sim, FALSE);
}

static void __dtapi_add_modem(struct custom_data *ctx, TcorePlugin *p)
{
	TelephonyObjectSkeleton *object;
	char *path = NULL;
	CoreObject *co;
	const char *cp_name;

	/* Get CP Name */
	cp_name = tcore_server_get_cp_name_by_plugin(p);
	if (cp_name == NULL) {
		err("CP Name is NULL");
		return;
	}

	path = g_strdup_printf("%s/%s", MY_DBUS_PATH, cp_name);

	object = g_hash_table_lookup(ctx->objects, path);
	if (object) {
		dbg("DBUS interface object(%p) already created (path: %s)", object, path);

		/* Freeing memory */
		g_free(path);

		return;
	}

	object = telephony_object_skeleton_new(path);
	if (object == NULL) {
		err("New DBUS object is NULL");

		/* Freeing memory */
		g_free(path);

		return;
	}

	info("New DBUS object(%p) created (path: %s)", object, path);
	g_hash_table_insert(ctx->objects, g_strdup(path), object);

	/* Freeing memory */
	g_free(path);

	/*
	 * Add interfaces
	 *
	 * Interfaces are exposed only if Core object is available (supported)
	 */
	/* Modem interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_MODEM);
	if (co)
		dbus_plugin_setup_modem_interface(object, ctx);

	/* Call interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL);
	if (co)
		dbus_plugin_setup_call_interface(object, ctx);

	/* Network interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_NETWORK);
	if (co)
		dbus_plugin_setup_network_interface(object, ctx);

	/* SS interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SS);
	if (co)
		dbus_plugin_setup_ss_interface(object, ctx);

	/* SMS interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SMS);
	if (co)
		dbus_plugin_setup_sms_interface(object, ctx);

	/* SAT interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SAT);
	if (co)
		dbus_plugin_setup_sat_interface(object, ctx);

	/* Phonebook interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_PHONEBOOK);
	if (co)
		dbus_plugin_setup_phonebook_interface(object, ctx);

	/* SAP interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SAP);
	if (co)
		dbus_plugin_setup_sap_interface(object, ctx);

	/* SIM interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SIM);
	if (co)
		dbus_plugin_setup_sim_interface(object, ctx);

	/* OEM interface */
	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CUSTOM);
	if (co)
		dbus_plugin_setup_oem_interface(object, ctx);

	/* Export the Object to Manager */
	g_dbus_object_manager_server_export(ctx->manager,
	G_DBUS_OBJECT_SKELETON(object));
}

static void __dtapi_refresh_object(struct custom_data *ctx)
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
		if (modem_plg)
			__dtapi_add_modem(ctx, modem_plg); /* Add modem */
	}
	g_slist_free(modem_plg_list);
}

static gboolean on_manager_getmodems(TelephonyManager *mgr,
	GDBusMethodInvocation  *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	GSList *cp_name_list;
	gchar **list;
	const char *name = NULL;
	int count;

	cp_name_list = tcore_server_get_cp_name_list(ctx->server);
	if (cp_name_list == NULL) {
		telephony_manager_complete_get_modems(mgr, invocation, &name);
		return TRUE;
	}

	count = g_slist_length(cp_name_list);
	list = g_try_malloc0(sizeof(gchar *) * (count + 1));
	if (list == NULL) {
		err("Failed to allocate list");
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		/* Freeing the received list of CP names */
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
	for (; count >= 0; count--)
		g_free(list[count]);
	g_free(list);

	/* Freeing the received list of CP names */
	g_slist_free_full(cp_name_list, g_free);

	return TRUE;
}

static void on_name_lost(GDBusConnection *conn,
	const gchar *name, gpointer user_data)
{
	info("Lost the name '%s' on the Session bus!!!", name);
}

static void on_name_acquired(GDBusConnection *conn,
	const gchar *name, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	Storage *strg;
	int count;

	ctx->name_acquired = TRUE; /* Setting Bus acquried flag after Bus name is acquired */

	info("Acquired the name '%s' on the Session bus", name);
	strg = tcore_server_find_storage(ctx->server, "vconf");

	count = tcore_storage_get_int(strg, STORAGE_KEY_TELEPHONY_SIM_SLOT_COUNT);
	if (count < 0) {
		err("SIM slot count not yet set");
	} else {
		if (tcore_storage_get_bool(strg, STORAGE_KEY_TELEPHONY_READY) == FALSE) {
			gboolean b_set;

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

static void on_bus_acquired(GDBusConnection *conn,
	const gchar *name, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	info("dbus registered");

	/*
	 * Refresh object
	 */
	__dtapi_refresh_object(ctx);

	/*
	 * Add interface to 'default' object path
	 */
	ctx->mgr = telephony_manager_skeleton_new();

	/*
	 * Register Manager signal handler(s)
	 */
	g_signal_connect(ctx->mgr,
		"handle-get-modems",
		G_CALLBACK(on_manager_getmodems),
		ctx); /* user_data */

	/*
	 * Export interface onto Connection (conn) with 'path' (MY_DBUS_PATH)
	 */
	g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(ctx->mgr),
		conn, MY_DBUS_PATH, NULL);

	/*
	 * Exports all objects managed by 'manager' on Connection (conn)
	 */
	g_dbus_object_manager_server_set_connection(ctx->manager, conn);

	dbg("Aquire DBUS - COMPLETE");
}

static TReturn dtapi_send_response(Communicator *comm, UserRequest *ur,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	struct custom_data *ctx = NULL;
	struct dbus_request_info *dbus_info;
	gboolean ret = FALSE;

	ctx = tcore_communicator_ref_user_data(comm);
	if (!ctx) {
		err("user_data is NULL");
		return TCORE_RETURN_EINVAL;
	}

	dbus_info = (struct dbus_request_info *)tcore_user_request_ref_user_info(ur);
	if (!dbus_info) {
		err("dbus_info is NULL");
		return TCORE_RETURN_EINVAL;
	}

	if (!data) {
		err("data is NULL");
		FAIL_RESPONSE(dbus_info->invocation, "Request failed");

		return TCORE_RETURN_SUCCESS;
	}

	dbg("cmd[0x%x] len[%d]", command, data_len);

	switch (command & (TCORE_RESPONSE | 0x0FF00000)) {
	case TRESP_CALL:
		ret = dbus_plugin_call_response(ctx, ur, dbus_info, command, data_len, data);
	break;

	case TRESP_SS:
		ret = dbus_plugin_ss_response(ctx, ur, dbus_info, command, data_len, data);
	break;

	case TRESP_PS:
		warn("Unhandled command (0x%x)", command);
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

	default:
		warn("unknown command (0x%x)", command);
	break;
	}

	if (ret == TRUE)
		return TCORE_RETURN_SUCCESS;
	else
		return TCORE_RETURN_FAILURE;
}

static TReturn dtapi_send_notification(Communicator *comm, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
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
		dbg("Server (System) Notification (0x%x)", command);

		switch (command) {
		case TNOTI_SERVER_ADDED_MODEM_PLUGIN: {
			const char *cp_name;

			cp_name = tcore_server_get_cp_name_by_plugin((TcorePlugin *)data);
			dbg("Modem Plug-in (%s) is added... Exporting interfaces for the modem", cp_name);

			__dtapi_add_modem(ctx, (TcorePlugin *)data); /* Add modem */

			ret = TRUE;
		}
		break;

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
				dbg("Bus acquired...[%s]", (ctx->name_acquired) ? "YES" : "NO");
			}
			ret = TRUE;
		}
		break;

		case TNOTI_SERVER_REMOVED_MODEM_PLUGIN: {
			TcorePlugin *plugin = tcore_communicator_ref_plugin(comm);
			TelephonyObjectSkeleton *object;
			const char *cp_name;
			char *path;

			dbg("plugin: [%p]", plugin);
			cp_name = tcore_server_get_cp_name_by_plugin((TcorePlugin *)data);
			if (cp_name == NULL) {
				warn("CP name is NULL. cmd:(0x%x)", command);
				return TCORE_RETURN_FAILURE;
			}

			path = g_strdup_printf("%s/%s", MY_DBUS_PATH, cp_name);

			/* Look-up Hash table for Object */
			object = g_hash_table_lookup(ctx->objects, path);

			__dtapi_initialize_properties(source, object);

			g_free(path);
		}
		break;

		case TNOTI_SERVER_RUN:
			dbg("TNOTI_SERVER_RUN");
		break;

		case TNOTI_SERVER_ADDED_PLUGIN:
			dbg("TNOTI_SERVER_ADDED_PLUGIN");
		break;

		case TNOTI_SERVER_ADDED_COMMUNICATOR:
			dbg("TNOTI_SERVER_ADDED_COMMUNICATOR");
		break;

		case TNOTI_SERVER_ADDED_HAL:
			dbg("TNOTI_SERVER_ADDED_HAL");
		break;

		case TNOTI_SERVER_EXIT: {
			Storage *strg = NULL;

			dbg("TNOTI_SERVER_EXIT");

			/* Reset STORAGE_KEY_TELEPHONY_READY */
			strg = tcore_server_find_storage(ctx->server, "vconf");
			tcore_storage_set_bool(strg, STORAGE_KEY_TELEPHONY_READY, FALSE);

			/*
			 * Exit Telephony daemon
			 */
			if (TCORE_RETURN_SUCCESS == tcore_server_exit(ctx->server))
				ret = TRUE;
		}
		break;

		default:
			warn("Unsupported System notification: (0x%x)", command);
		break;
		}
	} else {
		TelephonyObjectSkeleton *object;
		const char *cp_name;
		char *path;

		cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
		if (cp_name == NULL) {
			warn("CP name is NULL. cmd:(0x%x)", command);
			return TCORE_RETURN_FAILURE;
		}

		path = g_strdup_printf("%s/%s", MY_DBUS_PATH, cp_name);

		/* Look-up Hash table for Object */
		object = g_hash_table_lookup(ctx->objects, path);

		dbg("[%s]:(cmd[0x%x] len[%d])", cp_name, command, data_len);

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
			/* dbg("PS Notification (0x%x)... Not handled!!!", noti); */
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

		default:
			if ((command & (TCORE_NOTIFICATION | 0x0F000000)) == TNOTI_CUSTOM)
				ret = dbus_plugin_oem_notification(ctx, source, object, command, data_len, data);
			else
				warn("Unknown/Unhandled Notification: [0x%x]", command);

		break;
		}
	}

	if (ret == TRUE)
		return TCORE_RETURN_SUCCESS;
	else
		return TCORE_RETURN_FAILURE;
}

/*
 * DBUS communicator operations
 */
struct tcore_communicator_operations dbus_ops = {
	.send_response = dtapi_send_response,
	.send_notification = dtapi_send_notification,
};

gboolean dtapi_init(TcorePlugin *p)
{
	Communicator *comm;
	struct custom_data *data;
	guint id;

	dbg("Enter");

	data = calloc(1, sizeof(struct custom_data));
	if (!data)
		return FALSE;

	data->plugin = p;

	comm = tcore_communicator_new(p, "dbus", &dbus_ops);
	tcore_communicator_link_user_data(comm, data);

	data->comm = comm;
	data->server = tcore_plugin_ref_server(p);

	data->objects = g_hash_table_new(g_str_hash, g_str_equal);
	data->cached_data = NULL;

	dbg("data = %p", data);

	id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
		MY_DBUS_SERVICE,
		G_BUS_NAME_OWNER_FLAGS_REPLACE,
		on_bus_acquired,
		on_name_acquired, on_name_lost,
		data,
		NULL);

	data->owner_id = id;
	dbg("owner id=[%d]", data->owner_id);

	data->manager = g_dbus_object_manager_server_new(MY_DBUS_PATH);
	__dtapi_refresh_object(data);

	return TRUE;
}

void dtapi_deinit(TcorePlugin *p)
{
	struct custom_data *data = 0;
	Communicator *comm = 0;
	Server *s = tcore_plugin_ref_server(p);
	GSList *list = NULL;
	struct cached_data *object = NULL;

	dbg("Enter");

	comm = tcore_server_find_communicator(s, "dbus");
	if (!comm)
		return;

	data = tcore_communicator_ref_user_data(comm);
	if (!data)
		return;

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

