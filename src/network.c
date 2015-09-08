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

#include "generated-code.h"
#include "common.h"

static int __convert_act_to_systemtype(enum telephony_network_access_technology act)
{
	switch (act) {
	case NETWORK_ACT_UNKNOWN:
		return 0;

	case NETWORK_ACT_GSM:
		return 1;

	case NETWORK_ACT_GPRS:
		return 2;

	case NETWORK_ACT_EGPRS:
		return 3;

	case NETWORK_ACT_UMTS:
		return 5;

	case NETWORK_ACT_GSM_UTRAN:
		return 6;

	case NETWORK_ACT_IS95A:
		return 8;

	case NETWORK_ACT_IS95B:
		return 9;

	case NETWORK_ACT_CDMA_1X:
		return 10;

	case NETWORK_ACT_EVDO_REV0:
		return 11;

	case NETWORK_ACT_CDMA_1X_EVDO_REV0:
		return 12;

	case NETWORK_ACT_EVDO_REVA:
		return 13;

	case NETWORK_ACT_CDMA_1X_EVDO_REVA:
		return 14;

	case NETWORK_ACT_EVDV:
		return 15;

	case NETWORK_ACT_LTE:
		return 16;

	default:
	break;
	}

	return 0;
}

static void __update_network_name (TelephonyNetwork *network, CoreObject *o, const char *cp_name)
{
	char *spnname = NULL, *nwname = NULL;
	enum telephony_network_service_type svc_type;
	enum telephony_network_access_technology svc_act;
	enum tcore_network_name_priority network_name_priority;

	tcore_network_get_service_type (o, &svc_type);
	if (svc_type != NETWORK_SERVICE_TYPE_3G) {
		telephony_network_set_ps_type (network, TELEPHONY_HSDPA_OFF);
	}

	tcore_network_get_access_technology (o, &svc_act);
	telephony_network_set_access_technology (network, __convert_act_to_systemtype(svc_act));

	tcore_network_get_network_name_priority (o, &network_name_priority);
	switch (network_name_priority) {
	case TCORE_NETWORK_NAME_PRIORITY_SPN:
		telephony_network_set_name_option (network, NETWORK_NAME_OPTION_SPN);
	break;

	case TCORE_NETWORK_NAME_PRIORITY_NETWORK:
		telephony_network_set_name_option (network, NETWORK_NAME_OPTION_OPERATOR);
	break;

	case TCORE_NETWORK_NAME_PRIORITY_ANY:
		telephony_network_set_name_option (network, NETWORK_NAME_OPTION_ANY);
	break;

	default:
		telephony_network_set_name_option (network, NETWORK_NAME_OPTION_NONE);
	break;
	}

	do {
		/* spn */
		spnname = tcore_network_get_network_name(o, TCORE_NETWORK_NAME_TYPE_SPN);
		if (spnname) {
			telephony_network_set_spn_name (network, spnname);
		}

		/* nitz */
		nwname = tcore_network_get_network_name(o, TCORE_NETWORK_NAME_TYPE_FULL);
		if (nwname && strlen(nwname) > 0) {
			info("[DBUSINFO][%s] SPN:[%s] FULL:[%s] prio:[%d] act:[%d] svc_type:[%d]",
					cp_name, spnname?spnname:"", nwname, network_name_priority, svc_act, svc_type);
			telephony_network_set_network_name (network, nwname);
			break;
		}
		else {
			g_free(nwname);
			nwname = tcore_network_get_network_name(o, TCORE_NETWORK_NAME_TYPE_SHORT);
			if (nwname) {
				info("[DBUSINFO][%s] SPN:[%s] SHORT:[%s] prio:[%d] act:[%d] svc_type:[%d]",
						cp_name, spnname?spnname:"", nwname, network_name_priority, svc_act, svc_type);
				telephony_network_set_network_name (network, nwname);
				break;
			}
		}
		info("[DBUSINFO][%s] NW name is not fixed yet. SPN:[%s] prio:[%d] act:[%d] svc_type:[%d]",
			cp_name, spnname?spnname:"", network_name_priority, svc_act, svc_type);
	}while(0);
	g_free(spnname);
	g_free(nwname);
}

static enum tcore_hook_return on_hook_ps_protocol_status(Server *s,
	CoreObject *source, enum tcore_notification_command command,
	unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_ps_protocol_status *protocol_status = data;

	TelephonyObjectSkeleton *object;
	TelephonyNetwork *network = NULL;
	struct custom_data *ctx = user_data;
	const char *cp_name;
	char *path;

	enum telephony_ps_protocol_status ps_protocol_status = TELEPHONY_HSDPA_OFF;

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
	if (cp_name == NULL) {
		err("CP name is NULL");
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	info("[DBUSINFO][%s] PS_PROTOCOL_STATUS (status:[%d])", cp_name, protocol_status->status);

	path = g_strdup_printf("%s/%s", MY_DBUS_PATH, cp_name);

	/* Look-up Hash table for Object */
	object = g_hash_table_lookup(ctx->objects, path);
	g_free(path);
	if (object == NULL) {
		err("Object is NOT defined!!!");
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	network = telephony_object_peek_network(TELEPHONY_OBJECT(object));
	if (network == NULL) {
		err("Network object is NULL!!!");
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	if (telephony_network_get_service_type (network) < NETWORK_SERVICE_TYPE_2G) {
		telephony_network_set_ps_type(network, TELEPHONY_HSDPA_OFF);
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	switch (protocol_status->status) {
	case TELEPHONY_HSDPA_OFF:
		ps_protocol_status = TELEPHONY_HSDPA_OFF;
		break;

	case TELEPHONY_HSDPA_ON:
		ps_protocol_status = TELEPHONY_HSDPA_ON;
		break;

	case TELEPHONY_HSUPA_ON:
		ps_protocol_status = TELEPHONY_HSUPA_ON;
		break;

	case TELEPHONY_HSPA_ON:
		ps_protocol_status = TELEPHONY_HSPA_ON;
		break;

	case TELEPHONY_HSPAP_ON:
		ps_protocol_status = TELEPHONY_HSPAP_ON;
		break;
	default:
		err("Unhandled protocol status!");
	break;
	}

	/* Check and Set - To avoid double update */
	if (telephony_network_get_ps_type(network) != (gint)ps_protocol_status)
		telephony_network_set_ps_type(network, ps_protocol_status);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static gboolean
on_network_search (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_SEARCH);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_search_cancel (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_CANCEL_MANUAL_SEARCH);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_selection_mode (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_PLMN_SELECTION_MODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_set_selection_mode (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
		gint mode, const gchar *plmn, gint act, gpointer user_data)
{
	struct treq_network_set_plmn_selection_mode req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "w"))
		return TRUE;

	memset(&req, 0, sizeof(struct treq_network_set_plmn_selection_mode));

	if (mode == 0) {	/* Automatic */
		req.mode = NETWORK_SELECT_MODE_AUTOMATIC;
	}
	else if (mode == 1) {	/* Manual */
		req.mode = NETWORK_SELECT_MODE_MANUAL;
		snprintf(req.plmn, 7, "%s", plmn);
		req.act = act;
	}
	else {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}
	dbg("Mode: [%d] PLMN: [%s] AcT: [%d]", req.mode, req.plmn, req.act);

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_plmn_selection_mode), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_PLMN_SELECTION_MODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}


static gboolean
on_network_set_service_domain (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gint domain, gpointer user_data)
{
	struct treq_network_set_service_domain req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	req.domain = domain;

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_service_domain), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_SERVICE_DOMAIN);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_service_domain (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_SERVICE_DOMAIN);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_set_band (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gint band, gint mode, gpointer user_data)
{
	struct treq_network_set_band req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	req.mode = mode;
	req.band = band;

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_band), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_BAND);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_band (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_BAND);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_set_mode (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gint mode, gpointer user_data)
{
	struct treq_network_set_mode req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	req.mode = mode;

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_mode), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_MODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_mode (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_MODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_set_preferred_plmn (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gint mode, gint ef_index, gint act, const gchar *plmn, gpointer user_data)
{
	struct treq_network_set_preferred_plmn req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	req.operation = mode;
	req.ef_index = ef_index;
	req.act = act;

	memcpy(req.plmn, plmn, 6);

	if (strlen(plmn) <= 5) {
		req.plmn[5] = '#';
	}

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_preferred_plmn), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_PREFERRED_PLMN);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_preferred_plmn (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_PREFERRED_PLMN);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_serving_network (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_SERVING_NETWORK);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_neighboring_cell_info (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_NEIGHBORING_CELL_INFO);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_set_default_data_subscription (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_DEFAULT_DATA_SUBSCRIPTION);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_default_data_subscription (TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_NETWORK, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command( ur, TREQ_NETWORK_GET_DEFAULT_DATA_SUBSCRIPTION );
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_network_set_default_subs(TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gint preferred_subscription, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_NETWORK, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command( ur, TREQ_NETWORK_SET_DEFAULT_SUBSCRIPTION );
	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_network_get_default_subs(TelephonyNetwork *network, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_NETWORK, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_command( ur, TREQ_NETWORK_GET_DEFAULT_SUBSCRIPTION );
	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_network_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonyNetwork *network;

	network = telephony_network_skeleton_new();
	telephony_object_skeleton_set_network(object, network);
	g_object_unref(network);

	g_signal_connect (network,
			"handle-search",
			G_CALLBACK (on_network_search),
			ctx);

	g_signal_connect (network,
			"handle-search-cancel",
			G_CALLBACK (on_network_search_cancel),
			ctx);

	g_signal_connect (network,
			"handle-set-selection-mode",
			G_CALLBACK (on_network_set_selection_mode),
			ctx);

	g_signal_connect (network,
			"handle-get-selection-mode",
			G_CALLBACK (on_network_get_selection_mode),
			ctx);

	g_signal_connect (network,
			"handle-set-service-domain",
			G_CALLBACK (on_network_set_service_domain),
			ctx);

	g_signal_connect (network,
			"handle-get-service-domain",
			G_CALLBACK (on_network_get_service_domain),
			ctx);

	g_signal_connect (network,
			"handle-set-band",
			G_CALLBACK (on_network_set_band),
			ctx);

	g_signal_connect (network,
			"handle-get-band",
			G_CALLBACK (on_network_get_band),
			ctx);

	g_signal_connect (network,
			"handle-set-mode",
			G_CALLBACK (on_network_set_mode),
			ctx);

	g_signal_connect (network,
			"handle-get-mode",
			G_CALLBACK (on_network_get_mode),
			ctx);

	g_signal_connect (network,
			"handle-set-preferred-plmn",
			G_CALLBACK (on_network_set_preferred_plmn),
			ctx);

	g_signal_connect (network,
			"handle-get-preferred-plmn",
			G_CALLBACK (on_network_get_preferred_plmn),
			ctx);

	g_signal_connect (network,
			"handle-get-serving-network",
			G_CALLBACK (on_network_get_serving_network),
			ctx);

	g_signal_connect (network,
			"handle-get-ngbr-cell-info",
			G_CALLBACK (on_network_get_neighboring_cell_info),
			ctx);

	g_signal_connect (network,
			"handle-set-default-data-subscription",
			G_CALLBACK (on_network_set_default_data_subscription),
			ctx);

	g_signal_connect (network,
			"handle-get-default-data-subscription",
			G_CALLBACK (on_network_get_default_data_subscription),
			ctx);

	g_signal_connect (network,
			"handle-set-default-subscription",
			G_CALLBACK (on_network_set_default_subs),
			ctx);

	g_signal_connect (network,
			"handle-get-default-subscription",
			G_CALLBACK (on_network_get_default_subs),
			ctx);

	tcore_server_add_notification_hook(ctx->server,
		TNOTI_PS_PROTOCOL_STATUS, on_hook_ps_protocol_status, ctx);

	return TRUE;
}

gboolean dbus_plugin_network_response(struct custom_data *ctx, UserRequest *ur,
	struct dbus_request_info *dbus_info, enum tcore_response_command command,
	unsigned int data_len, const void *data)
{
	dbg("Response!!! Command: [0x%x] CP Name: [%s]",
		command, GET_CP_NAME(dbus_info->invocation));

	switch (command) {
	case TRESP_NETWORK_SEARCH: {
		const struct tresp_network_search *resp_network_search = data;
		GVariant *network_search_result = NULL;
		GVariantBuilder b;
		int i = 0;

		dbg("TRESP_NETWORK_SEARCH - Result: [%s] Count: [%d]",
			(resp_network_search->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_network_search->list_count);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_network_search->list_count; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

			g_variant_builder_add(&b, "{sv}", "plmn", g_variant_new_string(resp_network_search->list[i].plmn));
			g_variant_builder_add(&b, "{sv}", "act", g_variant_new_int32(resp_network_search->list[i].act));
			g_variant_builder_add(&b, "{sv}", "type", g_variant_new_int32(resp_network_search->list[i].status));
			g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string(resp_network_search->list[i].name));

			g_variant_builder_close(&b);
		}
		network_search_result = g_variant_builder_end(&b);

		telephony_network_complete_search(dbus_info->interface_object, dbus_info->invocation,
			network_search_result, resp_network_search->result);
	}
	break;

	case TRESP_NETWORK_SET_PLMN_SELECTION_MODE: {
		const struct tresp_network_set_plmn_selection_mode *resp_set_plmn_selection_mode = data;

		dbg("TRESP_SET_PLMN_SELECTION_MODE - Result: [%s]",
			(resp_set_plmn_selection_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_selection_mode(dbus_info->interface_object, dbus_info->invocation,
			resp_set_plmn_selection_mode->result);
	}
	break;

	case TRESP_NETWORK_GET_PLMN_SELECTION_MODE: {
		const struct tresp_network_get_plmn_selection_mode *resp_get_plmn_selection_mode = data;

		dbg("TRESP_GET_PLMN_SELECTION_MODE - Result: [%s] Mode: [%s]",
			(resp_get_plmn_selection_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			(resp_get_plmn_selection_mode->mode == NETWORK_SELECT_MODE_AUTOMATIC ? "Auto" :
			(resp_get_plmn_selection_mode->mode == NETWORK_SELECT_MODE_MANUAL ? "Manual" :
			"Unknown")));

		switch (resp_get_plmn_selection_mode->mode) {
		case NETWORK_SELECT_MODE_AUTOMATIC:
			telephony_network_complete_get_selection_mode(dbus_info->interface_object, dbus_info->invocation,
				0, resp_get_plmn_selection_mode->result);
		break;

		case NETWORK_SELECT_MODE_MANUAL:
			telephony_network_complete_get_selection_mode(dbus_info->interface_object, dbus_info->invocation,
				1, resp_get_plmn_selection_mode->result);
		break;

		default:
			telephony_network_complete_get_selection_mode(dbus_info->interface_object, dbus_info->invocation,
				-1, resp_get_plmn_selection_mode->result);
		break;
		}
	}
	break;

	case TRESP_NETWORK_SET_SERVICE_DOMAIN: {
		const struct tresp_network_set_service_domain *resp_set_service_domain = data;

		dbg("TRESP_NETWORK_SET_SERVICE_DOMAIN - Result: [%s]",
			(resp_set_service_domain->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_service_domain(dbus_info->interface_object, dbus_info->invocation,
			resp_set_service_domain->result);
	}
	break;

	case TRESP_NETWORK_GET_SERVICE_DOMAIN: {
		const struct tresp_network_get_service_domain *resp_get_service_domain = data;

		dbg("TRESP_NETWORK_GET_SERVICE_DOMAIN - Result: [%s] Domain: [%d]",
			(resp_get_service_domain->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_get_service_domain->domain);

		telephony_network_complete_get_service_domain(dbus_info->interface_object, dbus_info->invocation,
			resp_get_service_domain->domain, resp_get_service_domain->result);
	}
	break;

	case TRESP_NETWORK_SET_BAND: {
		const struct tresp_network_set_band *resp_set_band = data;

		dbg("TRESP_NETWORK_SET_BAND - Result: [%s]",
			(resp_set_band->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_band(dbus_info->interface_object, dbus_info->invocation,
			resp_set_band->result);
	}
	break;

	case TRESP_NETWORK_GET_BAND: {
		const struct tresp_network_get_band *resp_get_band = data;

		dbg("TRESP_NETWORK_GET_BAND - Result: [%s] Mode: [%s] Band: [%d]",
			(resp_get_band->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			(resp_get_band->mode == NETWORK_BAND_MODE_PREFERRED ? "Preferred" :
			(resp_get_band->mode == NETWORK_BAND_MODE_ONLY ? "Only" :
			"Unknown")), resp_get_band->band);

		telephony_network_complete_get_band(dbus_info->interface_object, dbus_info->invocation,
			resp_get_band->band, resp_get_band->mode, resp_get_band->result);
	}
	break;

	case TRESP_NETWORK_SET_MODE: {
		const struct tresp_network_set_mode *resp_set_mode = data;

		dbg("TRESP_NETWORK_SET_MODE - Result: [%s]",
			(resp_set_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_mode(dbus_info->interface_object, dbus_info->invocation,
			resp_set_mode->result);
	}
	break;

	case TRESP_NETWORK_GET_MODE: {
		const struct tresp_network_get_mode *resp_get_mode = data;

		dbg("TRESP_NETWORK_GET_MODE - Result: [%s] Mode: [%d]",
			(resp_get_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_get_mode->mode);

		telephony_network_complete_get_mode(dbus_info->interface_object, dbus_info->invocation,
			resp_get_mode->mode, resp_get_mode->result);
	}
	break;

	case TRESP_NETWORK_GET_NEIGHBORING_CELL_INFO: {
		const struct tresp_network_get_neighboring_cell_info *resp_get_ngbr_cell_info = data;
		GVariant *neighboring_cell_info_result = NULL;
		GVariant *value = NULL;
		GVariantBuilder b;
		enum telephony_network_access_technology act;
		int i = 0;

		dbg("TRESP_NETWORK_GET_NEIGHBORING_CELL_INFO - Result: [%s]",
			(resp_get_ngbr_cell_info->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		act = resp_get_ngbr_cell_info->info.serving.act;

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

		/* Fill Serving cell parameter */
		value = g_variant_new("(iii)",
				resp_get_ngbr_cell_info->info.serving.act,
				resp_get_ngbr_cell_info->info.serving.mcc,
				resp_get_ngbr_cell_info->info.serving.mnc);
		g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
		g_variant_builder_add(&b, "{sv}", "serving", value);
		g_variant_builder_close(&b);

		if (act >= NETWORK_ACT_GSM && act <= NETWORK_ACT_EGPRS) {
			value = g_variant_new("(iiiii)",
					resp_get_ngbr_cell_info->info.serving.cell.geran.cell_id,
					resp_get_ngbr_cell_info->info.serving.cell.geran.lac,
					resp_get_ngbr_cell_info->info.serving.cell.geran.bcch,
					resp_get_ngbr_cell_info->info.serving.cell.geran.bsic,
					resp_get_ngbr_cell_info->info.serving.cell.geran.rxlev);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "g_serving", value);
			g_variant_builder_close(&b);

		}
		else if (act >= NETWORK_ACT_UMTS && act <= NETWORK_ACT_GSM_UTRAN) {
			value = g_variant_new("(iiiii)",
					resp_get_ngbr_cell_info->info.serving.cell.umts.cell_id,
					resp_get_ngbr_cell_info->info.serving.cell.umts.lac,
					resp_get_ngbr_cell_info->info.serving.cell.umts.arfcn,
					resp_get_ngbr_cell_info->info.serving.cell.umts.psc,
					resp_get_ngbr_cell_info->info.serving.cell.umts.rscp);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "u_serving", value);
			g_variant_builder_close(&b);
		}
		else if (act == NETWORK_ACT_LTE) {
			value = g_variant_new("(iiiii)",
					resp_get_ngbr_cell_info->info.serving.cell.lte.cell_id,
					resp_get_ngbr_cell_info->info.serving.cell.lte.lac,
					resp_get_ngbr_cell_info->info.serving.cell.lte.earfcn,
					resp_get_ngbr_cell_info->info.serving.cell.lte.tac,
					resp_get_ngbr_cell_info->info.serving.cell.lte.rssi);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "l_serving", value);
			g_variant_builder_close(&b);
		}

		/* Fill GERAN neighbor cell parameter */
		for (i = 0; i < resp_get_ngbr_cell_info->info.geran_list_count; i++) {
			value = g_variant_new("(iiiii)",
				resp_get_ngbr_cell_info->info.geran_list[i].cell_id,
				resp_get_ngbr_cell_info->info.geran_list[i].lac,
				resp_get_ngbr_cell_info->info.geran_list[i].bcch,
				resp_get_ngbr_cell_info->info.geran_list[i].bsic,
				resp_get_ngbr_cell_info->info.geran_list[i].rxlev);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "geran", value);
			g_variant_builder_close(&b);
		}

		/* Fill UMTS neighbor cell parameter */
		for (i = 0; i < resp_get_ngbr_cell_info->info.umts_list_count; i++) {
			value = g_variant_new("(iiiii)",
				resp_get_ngbr_cell_info->info.umts_list[i].cell_id,
				resp_get_ngbr_cell_info->info.umts_list[i].lac,
				resp_get_ngbr_cell_info->info.umts_list[i].arfcn,
				resp_get_ngbr_cell_info->info.umts_list[i].psc,
				resp_get_ngbr_cell_info->info.umts_list[i].rscp);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "umts", value);
			g_variant_builder_close(&b);
		}
		neighboring_cell_info_result = g_variant_builder_end(&b);

		telephony_network_complete_get_ngbr_cell_info(dbus_info->interface_object, dbus_info->invocation,
			neighboring_cell_info_result, resp_get_ngbr_cell_info->result);
	}
	break;

	case TRESP_NETWORK_SET_PREFERRED_PLMN: {
		const struct tresp_network_set_preferred_plmn *resp_set_preferred_plmn = data;

		dbg("TRESP_NETWORK_SET_PREFERRED_PLMN - Result: [%s]",
			(resp_set_preferred_plmn->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_preferred_plmn(dbus_info->interface_object, dbus_info->invocation,
			resp_set_preferred_plmn->result);
	}
	break;

	case TRESP_NETWORK_GET_PREFERRED_PLMN: {
		const struct tresp_network_get_preferred_plmn *resp_get_preferred_plmn = data;
		GVariant *preferred_plmn_result = NULL;
		GVariantBuilder b;
		int i = 0;

		dbg("TRESP_NETWORK_GET_PREFERRED_PLMN - Result: [%s] Count: [%d]",
			(resp_get_preferred_plmn->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_get_preferred_plmn->list_count);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_get_preferred_plmn->list_count; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

			g_variant_builder_add(&b, "{sv}", "plmn",
					g_variant_new_string(resp_get_preferred_plmn->list[i].plmn));
			g_variant_builder_add(&b, "{sv}", "act", g_variant_new_int32(resp_get_preferred_plmn->list[i].act));
			g_variant_builder_add(&b, "{sv}", "index",
					g_variant_new_int32(resp_get_preferred_plmn->list[i].ef_index));
			g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string(resp_get_preferred_plmn->list[i].name));

			g_variant_builder_close(&b);
		}
		preferred_plmn_result = g_variant_builder_end(&b);

		telephony_network_complete_get_preferred_plmn(dbus_info->interface_object, dbus_info->invocation,
				preferred_plmn_result, resp_get_preferred_plmn->result);
	}
	break;

	case TRESP_NETWORK_SET_CANCEL_MANUAL_SEARCH: {
		const struct tresp_network_set_cancel_manual_search *resp_set_cancel_manual_search = data;

		dbg("TRESP_NETWORK_SET_CANCEL_MANUAL_SEARCH - Result: [%s]",
			(resp_set_cancel_manual_search->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_search_cancel(dbus_info->interface_object, dbus_info->invocation,
			resp_set_cancel_manual_search->result);
	}
	break;

	case TRESP_NETWORK_GET_SERVING_NETWORK: {
		const struct tresp_network_get_serving_network *resp_get_serving_network = data;

		dbg("TRESP_NETWORK_GET_SERVING_NETWORK - Result: [%s] AcT: [%d] PLMN: [%s] LAC: [%d])",
			(resp_get_serving_network->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_get_serving_network->act, resp_get_serving_network->plmn, resp_get_serving_network->gsm.lac);

		telephony_network_complete_get_serving_network(dbus_info->interface_object, dbus_info->invocation,
				resp_get_serving_network->act, resp_get_serving_network->plmn,
				resp_get_serving_network->gsm.lac, resp_get_serving_network->result);
	}
	break;

	case TRESP_NETWORK_SET_DEFAULT_DATA_SUBSCRIPTION: {
		const struct tresp_network_set_default_data_subscription *resp_set_default_data_subs = data;

		dbg("TRESP_NETWORK_SET_DEFAULT_SUBSCRIPTION - Result: [%s]",
			(resp_set_default_data_subs->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_default_data_subscription(dbus_info->interface_object, dbus_info->invocation,
			resp_set_default_data_subs->result);
	}
	break;

	case TRESP_NETWORK_GET_DEFAULT_DATA_SUBSCRIPTION: {
		const struct tresp_network_get_default_data_subs *resp_get_default_data_subs = data;

		dbg("TRESP_NETWORK_GET_DEFAULT_SUBSCRIPTION - Result: [%s] 'default' Data subscription: [%s]",
			(resp_get_default_data_subs->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			(resp_get_default_data_subs->default_subs == NETWORK_DEFAULT_DATA_SUBS_SIM1 ? "SIM1" :
			(resp_get_default_data_subs->default_subs == NETWORK_DEFAULT_DATA_SUBS_SIM2 ? "SIM2" :
			"Unknown")));

		telephony_network_complete_get_default_data_subscription(dbus_info->interface_object, dbus_info->invocation,
			resp_get_default_data_subs->default_subs, resp_get_default_data_subs->result);
	}
	break;

	case TRESP_NETWORK_SET_DEFAULT_SUBSCRIPTION: {
		const struct tresp_network_set_default_subs *resp_set_default_subs = data;

		dbg("TRESP_NETWORK_SET_DEFAULT_SUBSCRIPTION - Result: [%s]",
			(resp_set_default_subs->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_default_subscription(dbus_info->interface_object, dbus_info->invocation,
			resp_set_default_subs->result );
	}
	break;

	case TRESP_NETWORK_GET_DEFAULT_SUBSCRIPTION: {
		const struct tresp_network_get_default_subs *resp_get_default_subs = data;

		dbg("TRESP_NETWORK_GET_DEFAULT_SUBSCRIPTION - Result: [%s] 'default' subscription: [%s]",
			(resp_get_default_subs->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			(resp_get_default_subs->default_subs == NETWORK_DEFAULT_SUBS_SIM1 ? "SIM1" :
			(resp_get_default_subs->default_subs == NETWORK_DEFAULT_SUBS_SIM2 ? "SIM2" :
			"Unknown")));

		telephony_network_complete_get_default_subscription(dbus_info->interface_object, dbus_info->invocation,
			resp_get_default_subs->default_subs, resp_get_default_subs->result );
	}
	break;

	default:
		err("Unhandled/Unknown Response!!!");
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_network_notification(struct custom_data *ctx, CoreObject *source,
	TelephonyObjectSkeleton *object, enum tcore_notification_command command,
	unsigned int data_len, const void *data)
{
	TelephonyNetwork *network;
	const char *cp_name;

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	network = telephony_object_peek_network(TELEPHONY_OBJECT(object));
	if (network == NULL) {
		err("Network object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_NETWORK_REGISTRATION_STATUS: {
		const struct tnoti_network_registration_status *reg = data;

		info("[DBUSINFO][%s] NET_REGI_STATUS. (cs:[%d] ps:[%d] svc:[%d] roam:[%d])",
			cp_name, reg->cs_domain_status, reg->ps_domain_status, reg->service_type, reg->roaming_status);

#ifdef ENABLE_KPI_LOGS
		/* We ignore No SIM present case for KPI */
		if (reg->cs_domain_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL
			&& telephony_network_get_circuit_status(network) != NETWORK_SERVICE_DOMAIN_STATUS_FULL)
			TIME_CHECK("[%s] CS Network Full", cp_name);

		if (reg->ps_domain_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL
			&& telephony_network_get_packet_status(network) != NETWORK_SERVICE_DOMAIN_STATUS_FULL)
			TIME_CHECK("[%s] PS Network Full", cp_name);
#endif

		/* Update properties */
		telephony_network_set_circuit_status (network, reg->cs_domain_status);
		telephony_network_set_packet_status (network, reg->ps_domain_status);
		telephony_network_set_service_type (network, reg->service_type);
		telephony_network_set_roaming_status (network, reg->roaming_status);

		/* Update Network name */
		__update_network_name(network, source, cp_name);

		/* Emit Signal */
		telephony_network_emit_registration_status(network,
				reg->cs_domain_status,
				reg->ps_domain_status,
				reg->service_type,
				reg->roaming_status);
	}
	break;

	case TNOTI_NETWORK_CHANGE: {
		const struct tnoti_network_change *change = data;

		info("[DBUSINFO][%s] NET_CHANGE. (plmn:[%s] lac:[%d])",
			cp_name, change->plmn, change->gsm.lac);

		/* Update properties */
		telephony_network_set_plmn (network, change->plmn);
		telephony_network_set_lac (network, change->gsm.lac);

		/* Update Network name */
		__update_network_name(network, source, cp_name);

		/* Emit Signal */
		telephony_network_emit_change(network,
				change->act,
				change->plmn);
	}
	break;

	case TNOTI_NETWORK_TIMEINFO: {
		const struct tnoti_network_timeinfo *time_info = data;

		info("[DBUSINFO][%s] NET_TIMEINFO", cp_name);

		/* Emit signal */
		telephony_network_emit_time_info(network,
				time_info->year,
				time_info->month,
				time_info->day,
				time_info->hour,
				time_info->minute,
				time_info->second,
				time_info->wday,
				time_info->gmtoff,
				time_info->dstoff,
				time_info->isdst,
				time_info->plmn);
	}
	break;

	case TNOTI_NETWORK_ICON_INFO: {
		const struct tnoti_network_icon_info *icon_info = data;

		/* Update property */
		if (icon_info->type & NETWORK_ICON_INFO_RSSI) {
			info("[DBUSINFO][%s] NET_ICON_INFO (Ant:[%d])", cp_name, icon_info->rssi);
			telephony_network_set_sig_level (network, icon_info->rssi);
		}
	}
	break;

	case TNOTI_NETWORK_IDENTITY: {
		const struct tnoti_network_identity *identity = data;

		info("[DBUSINFO][%s] NET_IDENTITY (long:[%s] short:[%s] plmn:[%s])",
			cp_name, identity->full_name, identity->short_name, identity->plmn);

		/* Update properties */
		telephony_network_set_plmn (network, identity->plmn);

		/* Update Network name */
		__update_network_name (network, source, cp_name);

		/* Emit Signal */
		telephony_network_emit_identity(network,
				identity->plmn,
				identity->short_name,
				identity->full_name);
	}
	break;

	case TNOTI_NETWORK_LOCATION_CELLINFO: {
		const struct tnoti_network_location_cellinfo *location = data;

		info("[DBUSINFO][%s] NET_LOCATION_CELLINFO (lac:[%d] cell_id:[%d])",
			cp_name, location->lac, location->cell_id);

		/* Update properties */
		telephony_network_set_lac (network, location->lac);
		telephony_network_set_cell_id (network, location->cell_id);

		/* Emit signal */
		telephony_network_emit_cell_info(network,
				location->lac,
				location->cell_id);
	}
	break;

	case TNOTI_NETWORK_SIGNAL_STRENGTH: {
		const struct tnoti_network_signal_strength *signal_strength = data;

		info("[DBUSINFO][%s] NET_SIGNAL_STRENGTH (dbm:[%d])", cp_name, signal_strength->dbm);

		/* Update properties */
		telephony_network_set_sig_dbm (network, signal_strength->dbm);

		/* Emit signal */
		telephony_network_emit_signal_strength(network,
				signal_strength->dbm);
	}
	break;

	case TNOTI_NETWORK_DEFAULT_DATA_SUBSCRIPTION: {
		const struct tnoti_network_default_data_subs *default_data_subs_info = data;

		info("[DBUSINFO][%s] NET_DEFAULT_DATA_SUBSCRIPTION (default:[%d])", cp_name, default_data_subs_info->default_subs);

		/* Emit signal */
		telephony_network_emit_default_data_subscription(network,
				default_data_subs_info->default_subs);
	}
	break;

	case TNOTI_NETWORK_DEFAULT_SUBSCRIPTION: {
		const struct tnoti_network_default_subs *default_subs_info = data;

		info("[DBUSINFO][%s] NET_DEFAULT_SUBSCRIPTION (default:[%d])", cp_name, default_subs_info->default_subs);

		/* Emit signal */
		telephony_network_emit_default_subscription(network,
				default_subs_info->default_subs);
	}
	break;

	default:
		err("Unhandled/Unknown Notification!!!");
	break;
	}

	return TRUE;
}

