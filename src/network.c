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

#include "generated-code.h"
#include "common.h"

static inline GVariant *network_build_empty_array()
{
	GVariantBuilder b;

	g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

	return g_variant_builder_end(&b);
}

static char *_get_network_name_by_plmn(CoreObject *o, const char *plmn)
{
	struct tcore_network_operator_info *noi = NULL;
	char mcc[4] = { 0, };
	char mnc[4] = { 0, };

	if (!plmn)
		return NULL;

	snprintf(mcc, 4, "%s", plmn);
	snprintf(mnc, 4, "%s", plmn+3);

	if (mnc[2] == '#')
		mnc[2] = '\0';

	noi = tcore_network_operator_info_find(o, mcc, mnc);
	if (noi) {
		dbg("%s-%s: country=[%s], oper=[%s]", mcc, mnc, noi->country, noi->name);
		return noi->name;
	}
	else {
		dbg("%s-%s: no network operator name", mcc, mnc);
	}

	return NULL;
}


static enum tcore_hook_return on_hook_location_cellinfo(Server *s, CoreObject *source, enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_network_location_cellinfo *info = data;
	TelephonyNetwork *network = user_data;

	if (!network)
		return TCORE_HOOK_RETURN_CONTINUE;

	telephony_network_set_lac(network, info->lac);
	telephony_network_set_cell_id(network, info->cell_id);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static enum tcore_hook_return on_hook_icon_info(Server *s, CoreObject *source, enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_network_icon_info *info = data;
	TelephonyNetwork *network = user_data;

	if (!network)
		return TCORE_HOOK_RETURN_CONTINUE;

	telephony_network_set_rssi(network, info->rssi);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static enum tcore_hook_return on_hook_registration_status(Server *s, CoreObject *source, enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_network_registration_status *info = data;
	TelephonyNetwork *network = user_data;

	if (!network)
		return TCORE_HOOK_RETURN_CONTINUE;

	telephony_network_set_circuit_status(network, info->cs_domain_status);
	telephony_network_set_packet_status(network, info->ps_domain_status);
	telephony_network_set_service_type(network, info->service_type);
	telephony_network_set_roaming_status(network, info->roaming_status);

	switch (info->service_type) {
		case NETWORK_SERVICE_TYPE_UNKNOWN:
		case NETWORK_SERVICE_TYPE_NO_SERVICE:
			telephony_network_set_network_name(network, "No Service");
			break;

		case NETWORK_SERVICE_TYPE_EMERGENCY:
			telephony_network_set_network_name(network, "EMERGENCY");
			break;

		case NETWORK_SERVICE_TYPE_SEARCH:
			telephony_network_set_network_name(network, "Searching...");
			break;

		default:
			break;
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

static enum tcore_hook_return on_hook_change(Server *s, CoreObject *source, enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_network_change *info = data;
	TelephonyNetwork *network = user_data;
	struct tcore_network_operator_info *noi = NULL;
	char mcc[4] = { 0, };
	char mnc[4] = { 0, };
	enum telephony_network_service_type svc_type;
	enum tcore_network_name_priority network_name_priority;
	char *tmp;

	if (!network)
		return TCORE_HOOK_RETURN_CONTINUE;

	telephony_network_set_plmn(network, info->plmn);
	telephony_network_set_lac(network, info->gsm.lac);

	snprintf(mcc, 4, "%s", info->plmn);
	snprintf(mnc, 4, "%s", info->plmn+3);

	if (mnc[2] == '#')
		mnc[2] = '\0';

	tcore_network_get_network_name_priority(source, &network_name_priority);
	telephony_network_set_name_priority(network, network_name_priority);

	tmp = tcore_network_get_network_name(source, TCORE_NETWORK_NAME_TYPE_SPN);
	if (tmp) {
		telephony_network_set_spn_name(network, tmp);
		free(tmp);
	}

	tcore_network_get_service_type(source, &svc_type);
	switch(svc_type) {
		case NETWORK_SERVICE_TYPE_UNKNOWN:
		case NETWORK_SERVICE_TYPE_NO_SERVICE:
			telephony_network_set_network_name(network, "No Service");
			break;

		case NETWORK_SERVICE_TYPE_EMERGENCY:
			telephony_network_set_network_name(network, "EMERGENCY");
			break;

		case NETWORK_SERVICE_TYPE_SEARCH:
			telephony_network_set_network_name(network, "Searching...");
			break;

		default:
			tmp = tcore_network_get_network_name(source, TCORE_NETWORK_NAME_TYPE_SHORT);
			if (tmp) {
				telephony_network_set_network_name(network, tmp);
				free(tmp);
			}
			else {
				/* pre-defined table */
				noi = tcore_network_operator_info_find(source, mcc, mnc);
				if (noi) {
					dbg("%s-%s: country=[%s], oper=[%s]", mcc, mnc, noi->country, noi->name);
					dbg("NWNAME = pre-define table[%s]", noi->name);
					telephony_network_set_network_name(network, noi->name);
				}
				else {
					dbg("%s-%s: no network operator name", mcc, mnc);
					telephony_network_set_network_name(network, info->plmn);
				}
			}
			break;
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

static enum tcore_hook_return on_hook_ps_protocol_status(Server *s, CoreObject *source, enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_ps_protocol_status *info = data;
	TelephonyNetwork *network = user_data;

	if (!network)
		return TCORE_HOOK_RETURN_CONTINUE;

	telephony_network_set_network_type(network, info->status);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static gboolean
on_network_search (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SEARCH);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		GVariant *network_response = network_build_empty_array();
		telephony_network_complete_search(network, invocation, network_response, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_search_cancel (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_CANCEL_MANUAL_SEARCH);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_search_cancel(network, invocation, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_selection_mode (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_PLMN_SELECTION_MODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_get_selection_mode(network, invocation, -1, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_set_selection_mode (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gint mode,
		const gchar *plmn,
		gint act,
		gpointer user_data)
{
	struct treq_network_set_plmn_selection_mode req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "w") == FALSE)
		return FALSE;

	memset(&req, 0, sizeof(struct treq_network_set_plmn_selection_mode));

	if (mode == 0) {
		/* Automatic */
		req.mode = NETWORK_SELECT_MODE_AUTOMATIC;
	}
	else if (mode == 1) {
		/* Manual */
		req.mode = NETWORK_SELECT_MODE_MANUAL;
		snprintf(req.plmn, 7, "%s", plmn);
		if (strlen(plmn) <= 5)
			req.plmn[5] = '#';
		req.act = act;
	}
	else {
		telephony_network_complete_set_selection_mode(network, invocation, -1);
		return TRUE;
	}

	dbg("mode = %d, plmn = [%s], act = %d",
			req.mode, req.plmn, req.act);

	ur = MAKE_UR(ctx, network, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_plmn_selection_mode), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_PLMN_SELECTION_MODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_set_selection_mode(network, invocation, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}


static gboolean
on_network_set_service_domain (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gint domain,
		gpointer user_data)
{
	struct treq_network_set_service_domain req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);

	req.domain = domain;

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_service_domain), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_SERVICE_DOMAIN);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_set_service_domain(network, invocation, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_service_domain (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_SERVICE_DOMAIN);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_get_service_domain(network, invocation, -1, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_set_band (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gint band,
		gint mode,
		gpointer user_data)
{
	struct treq_network_set_band req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);

	req.mode = mode;
	req.band = band;

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_band), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_BAND);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_set_band(network, invocation, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_band (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_BAND);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_get_band(network, invocation, -1, -1, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_set_mode (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gint mode,
		gpointer user_data)
{
	struct treq_network_set_mode req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);

	req.mode = mode;

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_mode), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_MODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_set_mode(network, invocation, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_mode (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_MODE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_get_mode(network, invocation, -1, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_set_preferred_plmn (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gint mode,
		gint index,
		gint act,
		const gchar *plmn,
		gpointer user_data)
{
	struct treq_network_set_preferred_plmn req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);

	req.operation = mode;
	req.index = index;
	req.act = act;

	memcpy(req.plmn, plmn, 6);

	if (strlen(plmn) <= 5) {
		req.plmn[5] = '#';
	}

	tcore_user_request_set_data(ur, sizeof(struct treq_network_set_preferred_plmn), &req);
	tcore_user_request_set_command(ur, TREQ_NETWORK_SET_PREFERRED_PLMN);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_set_preferred_plmn(network, invocation, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_preferred_plmn (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_PREFERRED_PLMN);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		GVariant *network_response = network_build_empty_array();
		telephony_network_complete_get_preferred_plmn(network, invocation, network_response, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_serving_network (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_SERVING_NETWORK);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		telephony_network_complete_get_serving_network(network, invocation, 0, NULL, 0, ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_network_get_neighboring_cell_info (TelephonyNetwork *network,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (check_access_control(invocation, AC_NETWORK, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, network, invocation);
	tcore_user_request_set_data(ur, 0, NULL);
	tcore_user_request_set_command(ur, TREQ_NETWORK_GET_NEIGHBORING_CELL_INFO);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		GVariant *network_response = network_build_empty_array();
		telephony_network_complete_get_ngbr_cell_info(network, invocation, network_response, ret);
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

	dbg("network = %p", network);

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

	tcore_server_add_notification_hook(ctx->server, TNOTI_NETWORK_LOCATION_CELLINFO, on_hook_location_cellinfo, network);
	tcore_server_add_notification_hook(ctx->server, TNOTI_NETWORK_ICON_INFO, on_hook_icon_info, network);
	tcore_server_add_notification_hook(ctx->server, TNOTI_NETWORK_REGISTRATION_STATUS, on_hook_registration_status, network);
	tcore_server_add_notification_hook(ctx->server, TNOTI_NETWORK_CHANGE, on_hook_change, network);
	tcore_server_add_notification_hook(ctx->server, TNOTI_PS_PROTOCOL_STATUS, on_hook_ps_protocol_status, network);

	return TRUE;
}

gboolean dbus_plugin_network_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	const struct tresp_network_search *resp_network_search = data;
	const struct tresp_network_set_cancel_manual_search *resp_set_cancel_manual_search = data;
	const struct tresp_network_get_plmn_selection_mode *resp_get_plmn_selection_mode = data;
	const struct tresp_network_set_plmn_selection_mode *resp_set_plmn_selection_mode = data;
	const struct tresp_network_set_service_domain *resp_set_service_domain = data;
	const struct tresp_network_get_service_domain *resp_get_service_domain = data;
	const struct tresp_network_set_band *resp_set_band = data;
	const struct tresp_network_get_band *resp_get_band = data;
	const struct tresp_network_set_preferred_plmn *resp_set_preferred_plmn = data;
	const struct tresp_network_get_preferred_plmn *resp_get_preferred_plmn = data;
	const struct tresp_network_get_serving_network *resp_get_serving_network = data;
	const struct tresp_network_set_mode *resp_set_mode = data;
	const struct tresp_network_get_mode *resp_get_mode = data;
	const struct tresp_network_get_neighboring_cell_info *resp_get_ngbr_cell_info = data;

	int i = 0;
	char *buf;

	CoreObject *co_network;
	char *modem_name = NULL;
	TcorePlugin *p = NULL;

	modem_name = tcore_user_request_get_modem_name(ur);
	if (!modem_name)
		return FALSE;

	p = tcore_server_find_plugin(ctx->server, modem_name);
	free(modem_name);
	if (!p)
		return FALSE;

	co_network = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_NETWORK);
	if (!co_network)
		return FALSE;

	switch (command) {
		case TRESP_NETWORK_SEARCH: {
			GVariant *result = NULL;
			GVariantBuilder b;

			dbg("receive TRESP_NETWORK_SEARCH");
			dbg("resp->result = %d", resp_network_search->result);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i = 0; i < resp_network_search->list_count; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

				g_variant_builder_add(&b, "{sv}", "plmn", g_variant_new_string(resp_network_search->list[i].plmn));
				g_variant_builder_add(&b, "{sv}", "act", g_variant_new_int32(resp_network_search->list[i].act));
				g_variant_builder_add(&b, "{sv}", "type", g_variant_new_int32(resp_network_search->list[i].status));

				if (strlen(resp_network_search->list[i].name) > 0) {
					g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string(resp_network_search->list[i].name));
				}
				else {
					buf = _get_network_name_by_plmn(co_network, resp_network_search->list[i].plmn);
					if (buf)
						g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string(buf));
					else
						g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string(resp_network_search->list[i].plmn));
				}

				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_network_complete_search(dbus_info->interface_object, dbus_info->invocation, result, resp_network_search->result);
		}

			break;

		case TRESP_NETWORK_SET_PLMN_SELECTION_MODE:
			dbg("receive TRESP_SET_PLMN_SELECTION_MODE");
			dbg("resp->result = %d", resp_set_plmn_selection_mode->result);
			telephony_network_complete_set_selection_mode(dbus_info->interface_object, dbus_info->invocation, resp_set_plmn_selection_mode->result);
			break;

		case TRESP_NETWORK_GET_PLMN_SELECTION_MODE:
			dbg("receive TRESP_GET_PLMN_SELECTION_MODE");
			dbg("resp->mode = %d", resp_get_plmn_selection_mode->mode);
			switch (resp_get_plmn_selection_mode->mode) {
				case NETWORK_SELECT_MODE_AUTOMATIC:
					telephony_network_complete_get_selection_mode(dbus_info->interface_object, dbus_info->invocation, 0, resp_get_plmn_selection_mode->result);
					break;

				case NETWORK_SELECT_MODE_MANUAL:
					telephony_network_complete_get_selection_mode(dbus_info->interface_object, dbus_info->invocation, 1, resp_get_plmn_selection_mode->result);
					break;

				default:
					telephony_network_complete_get_selection_mode(dbus_info->interface_object, dbus_info->invocation, -1, resp_get_plmn_selection_mode->result);
					break;
			}
			break;

		case TRESP_NETWORK_SET_SERVICE_DOMAIN:
			dbg("receive TRESP_NETWORK_SET_SERVICE_DOMAIN");
			dbg("resp->result = %d", resp_set_service_domain->result);
			telephony_network_complete_set_service_domain(dbus_info->interface_object, dbus_info->invocation, resp_set_service_domain->result);
			break;

		case TRESP_NETWORK_GET_SERVICE_DOMAIN:
			dbg("receive TRESP_NETWORK_GET_SERVICE_DOMAIN");
			dbg("resp->domain = %d", resp_get_service_domain->domain);
			telephony_network_complete_get_service_domain(dbus_info->interface_object, dbus_info->invocation, resp_get_service_domain->domain, resp_get_service_domain->result);
			break;

		case TRESP_NETWORK_SET_BAND:
			dbg("receive TRESP_NETWORK_SET_BAND");
			dbg("resp->result = %d", resp_set_band->result);
			telephony_network_complete_set_band(dbus_info->interface_object, dbus_info->invocation, resp_set_band->result);
			break;

		case TRESP_NETWORK_GET_BAND:
			dbg("receive TRESP_NETWORK_GET_BAND");
			dbg("resp->mode = %d", resp_get_band->mode);
			dbg("resp->band = %d", resp_get_band->band);
			telephony_network_complete_get_band(dbus_info->interface_object, dbus_info->invocation, resp_get_band->band, resp_get_band->mode, resp_get_band->result);
			break;

		case TRESP_NETWORK_SET_MODE:
			dbg("receive TRESP_NETWORK_SET_MODE");
			dbg("resp->result = %d", resp_set_mode->result);
			telephony_network_complete_set_mode(dbus_info->interface_object, dbus_info->invocation, resp_set_mode->result);
			break;

		case TRESP_NETWORK_GET_MODE:
			dbg("receive TRESP_NETWORK_GET_MODE");
			dbg("resp->mode = %d", resp_get_mode->mode);
			telephony_network_complete_get_mode(dbus_info->interface_object, dbus_info->invocation, resp_get_mode->mode, resp_get_mode->result);
			break;

		case TRESP_NETWORK_GET_NEIGHBORING_CELL_INFO:
			{
				GVariant *result = NULL;
				GVariant *value = NULL;
				GVariantBuilder b;

				dbg("receive TRESP_NETWORK_GET_NEIGHBORING_CELL_INFO. result=%d", resp_get_ngbr_cell_info->result);

				g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

				for (i = 0; i < resp_get_ngbr_cell_info->info.geran_list_count; i++) {
					value = g_variant_new("(iiiii)", resp_get_ngbr_cell_info->info.geran_list[i].cell_id,
						resp_get_ngbr_cell_info->info.geran_list[i].lac,
						resp_get_ngbr_cell_info->info.geran_list[i].bcch,
						resp_get_ngbr_cell_info->info.geran_list[i].bsic,
						resp_get_ngbr_cell_info->info.geran_list[i].rxlev);
					g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
					g_variant_builder_add(&b, "{sv}", "geran", value);
					g_variant_builder_close(&b);
				}

				for (i = 0; i < resp_get_ngbr_cell_info->info.umts_list_count; i++) {
					value = g_variant_new("(iiiii)", resp_get_ngbr_cell_info->info.umts_list[i].cell_id,
						resp_get_ngbr_cell_info->info.umts_list[i].lac,
						resp_get_ngbr_cell_info->info.umts_list[i].arfcn,
						resp_get_ngbr_cell_info->info.umts_list[i].psc,
						resp_get_ngbr_cell_info->info.umts_list[i].rscp);
					g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
					g_variant_builder_add(&b, "{sv}", "umts", value);
					g_variant_builder_close(&b);
				}

				result = g_variant_builder_end(&b);
				telephony_network_complete_get_ngbr_cell_info(dbus_info->interface_object, dbus_info->invocation, result, resp_get_ngbr_cell_info->result);
		}
			break;

		case TRESP_NETWORK_SET_PREFERRED_PLMN:
			dbg("receive TRESP_NETWORK_SET_PREFERRED_PLMN");
			dbg("resp->result = %d", resp_set_preferred_plmn->result);
			telephony_network_complete_set_preferred_plmn(dbus_info->interface_object, dbus_info->invocation, resp_set_preferred_plmn->result);
			break;

		case TRESP_NETWORK_GET_PREFERRED_PLMN:
			dbg("receive TRESP_NETWORK_GET_PREFERRED_PLMN");
			dbg("resp->result = %d", resp_get_preferred_plmn->result);
			{
				GVariant *result = NULL;
				GVariantBuilder b;

				g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

				for (i = 0; i < resp_get_preferred_plmn->list_count; i++) {
					g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

					g_variant_builder_add(&b, "{sv}", "plmn",
							g_variant_new_string(resp_get_preferred_plmn->list[i].plmn));
					g_variant_builder_add(&b, "{sv}", "act", g_variant_new_int32(resp_get_preferred_plmn->list[i].act));
					g_variant_builder_add(&b, "{sv}", "index",
							g_variant_new_int32(resp_get_preferred_plmn->list[i].index));

					buf = _get_network_name_by_plmn(co_network, resp_get_preferred_plmn->list[i].plmn);
					if (buf)
						g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string(buf));
					else
						g_variant_builder_add(&b, "{sv}", "name",
								g_variant_new_string(resp_get_preferred_plmn->list[i].plmn));

					g_variant_builder_close(&b);
				}

				result = g_variant_builder_end(&b);

				telephony_network_complete_get_preferred_plmn(dbus_info->interface_object, dbus_info->invocation,
						result, resp_get_preferred_plmn->result);
			}
			break;

		case TRESP_NETWORK_SET_CANCEL_MANUAL_SEARCH:
			dbg("receive TRESP_NETWORK_SET_CANCEL_MANUAL_SEARCH");
			dbg("resp->result = %d", resp_set_cancel_manual_search->result);
			telephony_network_complete_search_cancel(dbus_info->interface_object, dbus_info->invocation, resp_set_cancel_manual_search->result);
			break;

		case TRESP_NETWORK_GET_SERVING_NETWORK:
			dbg("receive TRESP_NETWORK_GET_SERVING_NETWORK");
			dbg("resp->act = %d", resp_get_serving_network->act);
			dbg("resp->plmn = %s", resp_get_serving_network->plmn);
			dbg("resp->lac = %d", resp_get_serving_network->gsm.lac);
			telephony_network_complete_get_serving_network(dbus_info->interface_object, dbus_info->invocation,
					resp_get_serving_network->act,
					resp_get_serving_network->plmn,
					resp_get_serving_network->gsm.lac,
					resp_get_serving_network->result);
			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}

gboolean dbus_plugin_network_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyNetwork *network;
	const struct tnoti_network_registration_status *registration = data;
	const struct tnoti_network_change *change = data;
	const struct tnoti_network_icon_info *icon_info = data;
	const struct tnoti_network_timeinfo *time_info = data;
	const struct tnoti_network_identity *identity = data;
	const struct tnoti_network_location_cellinfo *location = data;

	if (!object) {
		dbg("object is NULL");
		return FALSE;
	}

	network = telephony_object_peek_network(TELEPHONY_OBJECT(object));
	dbg("network = %p", network);

	switch (command) {
		case TNOTI_NETWORK_REGISTRATION_STATUS:
			telephony_network_emit_registration_status(network,
					registration->cs_domain_status,
					registration->ps_domain_status,
					registration->service_type,
					registration->roaming_status);
			break;

		case TNOTI_NETWORK_CHANGE:
			telephony_network_emit_change(network,
					change->act,
					change->plmn,
					change->gsm.lac);
			break;

		case TNOTI_NETWORK_ICON_INFO:
			telephony_network_emit_info(network,
					icon_info->rssi,
					icon_info->battery);
			break;

		case TNOTI_NETWORK_TIMEINFO:
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
			break;

		case TNOTI_NETWORK_IDENTITY:
			telephony_network_emit_identity(network,
					identity->plmn,
					identity->short_name,
					identity->full_name);
			break;

		case TNOTI_NETWORK_LOCATION_CELLINFO:
			telephony_network_emit_cell_info(network,
					location->lac,
					location->cell_id);
			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}

