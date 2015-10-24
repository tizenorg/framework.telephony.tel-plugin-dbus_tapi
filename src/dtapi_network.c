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

#include <glib.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <co_network.h>

#include "generated-code.h"
#include "dtapi_common.h"

/*
 * Application used properties
 */
#define NET_PROP_NONE		0x0000
#define NET_PROP_SVC_TYPE	0x0001
#define NET_PROP_ROAM		0x0002
#define NET_PROP_PLMN		0x0004
#define NET_PROP_NAME_OPTION 0x0100
#define NET_PROP_SPN		0x0200
#define NET_PROP_NWNAME	0x0400
#define NET_PROP_EMIT		0x0FFF

/*
 * Extra properties
 */
#define NET_PROP_CS		0x1000
#define NET_PROP_PS		0x2000
#define NET_PROP_ACT		0x4000
#define NET_PROP_ALL		0xFFFF

typedef struct {
	int type;
	int svc_type;
	int ps_type;
	gboolean roaming;
	int act;
	int cs;
	int ps;
	int name_option;
	char *plmn;
	char *spn;
	char *nwname;
} NetworkPropertyInfo;

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

	case NETWORK_ACT_EVDO_REVB:
		return 15;

	case NETWORK_ACT_CDMA_1X_EVDO_REVB:
		return 16;

	case NETWORK_ACT_EVDV:
		return 17;

	case NETWORK_ACT_EHRPD:
		return 18;

	case NETWORK_ACT_LTE:
		return 19;

	default:
	break;
	}

	return 0;
}

static int __convert_name_priority_to_option(enum tcore_network_name_priority priority)
{
	switch (priority) {
	case TCORE_NETWORK_NAME_PRIORITY_SPN:
		return 1; /* NETWORK_NAME_OPTION_SPN */

	case TCORE_NETWORK_NAME_PRIORITY_NETWORK:
		return 2; /* NETWORK_NAME_OPTION_OPERATOR */

	case TCORE_NETWORK_NAME_PRIORITY_ANY:
		return 3; /* NETWORK_NAME_OPTION_ANY */

	default:
	break;
	}

	return 0; /* NETWORK_NAME_OPTION_NONE */
}

static void __get_current_network_status(CoreObject *o,
	NetworkPropertyInfo *current, int req_type)
{
	if (!o || !current)
		return;

	if (req_type & NET_PROP_SVC_TYPE) {
		enum telephony_network_service_type svc_type;

		tcore_network_get_service_type(o, &svc_type);
		current->svc_type = svc_type;
	}

	if (req_type & NET_PROP_ROAM)
		current->roaming = tcore_network_get_roaming_state(o);

	if (req_type & NET_PROP_PLMN)
		current->plmn = tcore_network_get_plmn(o);

	if (req_type & NET_PROP_NAME_OPTION) {
		enum tcore_network_name_priority priority = TCORE_NETWORK_NAME_PRIORITY_UNKNOWN;

		tcore_network_get_network_name_priority(o, &priority);
		current->name_option = __convert_name_priority_to_option(priority);
	}

	if (req_type & NET_PROP_SPN)
		current->spn = tcore_network_get_network_name(o, TCORE_NETWORK_NAME_TYPE_SPN);

	if (req_type & NET_PROP_NWNAME) {
		char *nwname = tcore_network_get_network_name(o, TCORE_NETWORK_NAME_TYPE_FULL);

		if (!nwname || strlen(nwname) == 0)
			nwname = tcore_network_get_network_name(o, TCORE_NETWORK_NAME_TYPE_SHORT);
		current->nwname = nwname;
	}

	if (req_type & NET_PROP_CS) {
		enum telephony_network_service_domain_status cs;
		tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, &cs);

		current->cs = cs;
	}

	if (req_type & NET_PROP_PS) {
		enum telephony_network_service_domain_status ps;

		tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_PACKET, &ps);
		current->ps = ps;
	}

	if (req_type & NET_PROP_ACT) {
		enum telephony_network_access_technology act = NETWORK_ACT_UNKNOWN;

		tcore_network_get_access_technology(o, &act);
		current->act = __convert_act_to_systemtype(act);
	}
}

static int __check_property_change(TelephonyNetwork *network, CoreObject *o,
	NetworkPropertyInfo *current, int req_type)
{
	int changed_type = NET_PROP_NONE;

	if (!current || !o)
		return NET_PROP_NONE;

	__get_current_network_status(o, current, req_type);

	if (req_type & NET_PROP_SVC_TYPE)
		if (telephony_network_get_service_type(network) != current->svc_type)
			changed_type |= NET_PROP_SVC_TYPE;

	if (req_type & NET_PROP_ROAM)
		if (telephony_network_get_roaming_status(network) != current->roaming)
			changed_type |= NET_PROP_ROAM;

	if (req_type & NET_PROP_PLMN) {
		if (current->plmn) {
			const gchar *prev_plmn = telephony_network_get_plmn(network);

			if (!prev_plmn || strcmp(prev_plmn, current->plmn) != 0)
				changed_type |= NET_PROP_PLMN;
		}
	}

	if (req_type & NET_PROP_NAME_OPTION)
		if (telephony_network_get_name_option(network) != current->name_option)
			changed_type |= NET_PROP_NAME_OPTION;

	if (req_type & NET_PROP_SPN) {
		if (current->spn) {
			const gchar *prev_spn = telephony_network_get_spn_name(network);

			if (!prev_spn || strcmp(prev_spn, current->spn) != 0)
				changed_type |= NET_PROP_SPN;
		}
	}

	if (req_type & NET_PROP_NWNAME) {
		if (current->nwname) {
			const gchar *prev_nwname = telephony_network_get_network_name(network);

			if (!prev_nwname || strcmp(prev_nwname, current->nwname) != 0)
				changed_type |= NET_PROP_NWNAME;
		}
	}

	if (req_type & NET_PROP_CS)
		if (telephony_network_get_circuit_status(network) != current->cs)
			changed_type |= NET_PROP_CS;

	if (req_type & NET_PROP_PS)
		if (telephony_network_get_packet_status(network) != current->ps)
			changed_type |= NET_PROP_PS;

	if (req_type & NET_PROP_ACT)
		if (telephony_network_get_access_technology(network) != current->act)
			changed_type |= NET_PROP_ACT;

	return changed_type;
}

static void __update_network_properties(TelephonyNetwork *network,
	const char *cp_name, NetworkPropertyInfo *current, int update_type)
{
	if (!current)
		return;

	if (update_type & NET_PROP_SVC_TYPE) {
		telephony_network_set_service_type(network, current->svc_type);

		if (current->svc_type != NETWORK_SERVICE_TYPE_3G)
			telephony_network_set_ps_type(network, TELEPHONY_HSDPA_OFF);
	}

	if (update_type & NET_PROP_ROAM)
		telephony_network_set_roaming_status(network, current->roaming);

	if (update_type & NET_PROP_PLMN)
		telephony_network_set_plmn(network, current->plmn);

	if (update_type & NET_PROP_NAME_OPTION)
		telephony_network_set_name_option(network, current->name_option);

	if (update_type & NET_PROP_SPN)
		telephony_network_set_spn_name(network, current->spn);

	if (update_type & NET_PROP_NWNAME)
		telephony_network_set_network_name(network, current->nwname);

	if (update_type & NET_PROP_CS)
		telephony_network_set_circuit_status(network, current->cs);

	if (update_type & NET_PROP_PS)
		telephony_network_set_packet_status(network, current->ps);

	if (update_type & NET_PROP_ACT)
		telephony_network_set_access_technology(network, current->act);
}

static int __add_default_property_type(TelephonyNetwork *network, CoreObject *o, int req_type)
{
	/*
	 * If SVC_TYPE was changed,
	 * other properties (ACT, OPTION, SPN, NWNAME) may also be changed together
	 */
	if (req_type & NET_PROP_SVC_TYPE) {
		NetworkPropertyInfo current = {0, -1, -1, 0, -1, -1, -1, -1, NULL, NULL, NULL};

		if (__check_property_change(network, o, &current, NET_PROP_SVC_TYPE)) {
			/*
			 * If SVC_TYPE was really changed,
			 * we should add others to default checking value
			 */
			req_type |= (NET_PROP_ACT | NET_PROP_NAME_OPTION | NET_PROP_SPN | NET_PROP_NWNAME);
		}
	}

	/*
	 * If PLMN was changed,
	 * other properties (ROAM,OPTION,SPN,NWNAME) may also be changed together
	 */
	if (req_type & NET_PROP_PLMN) {
		NetworkPropertyInfo current = {0, -1, -1, 0, -1, -1, -1, -1, NULL, NULL, NULL};

		if (__check_property_change(network, o, &current, NET_PROP_PLMN)) {
			/*
			 * If PLMN was really changed,
			 * we should add anothers to default checking value
			 */
			req_type |= (NET_PROP_ROAM | NET_PROP_NAME_OPTION | NET_PROP_SPN | NET_PROP_NWNAME);
		}
		g_free(current.plmn);
	}

	return req_type;
}

static void __check_network_properties(TelephonyNetwork *network, CoreObject *o,
	const char *cp_name, int req_type)
{
	int changed_type = NET_PROP_NONE;
	int emit_type = NET_PROP_NONE;
	NetworkPropertyInfo current = {0, -1, -1, 0, -1, -1, -1, -1, NULL, NULL, NULL};

	req_type = __add_default_property_type(network, o, req_type);
	changed_type = __check_property_change(network, o, &current, req_type);

	if (changed_type)
		__update_network_properties(network, cp_name, &current, changed_type);

	emit_type = (changed_type & NET_PROP_EMIT);
	if (emit_type) {
		info("[%s] PROPTYPE: [%04x] svc: [%d] roam: [%s] plmn: [%s] prio: [%d] spn: [%s] nwname: [%s]",
			cp_name, emit_type, current.svc_type,
			(current.roaming ? "YES" : "NO"), current.plmn,
			current.name_option, current.spn, current.nwname);

		telephony_network_emit_property_info(network, emit_type,
			current.svc_type, current.roaming, current.name_option,
			current.plmn, current.spn, current.nwname);
	}

	g_free(current.plmn);
	g_free(current.spn);
	g_free(current.nwname);
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

	info("[%s] PS_PROTOCOL_STATUS - Status: [%d]", cp_name, protocol_status->status);

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

	/*
	 * Do not check service_type.
	 * In case of +CGREG is invoked before +CREG(Z1 device),
	 * ps_type is not set because service_type is unknown yet.
	 *
	if (telephony_network_get_service_type (network) < NETWORK_SERVICE_TYPE_2G) {
		telephony_network_set_ps_type(network, TELEPHONY_HSDPA_OFF);
		return TCORE_HOOK_RETURN_CONTINUE;
	}
	*/

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

	telephony_network_set_ps_type(network, ps_protocol_status);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static gboolean on_network_search(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "x"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SEARCH,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_search_cancel(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "x"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_CANCEL_MANUAL_SEARCH,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_get_selection_mode(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_PLMN_SELECTION_MODE,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_set_selection_mode(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation,
	gint mode, const gchar *plmn, gint act, gpointer user_data)
{
	struct treq_network_set_plmn_selection_mode req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_network_set_plmn_selection_mode));

	if (mode == 0) {	/* Automatic */
		req.mode = NETWORK_SELECT_MODE_AUTOMATIC;
	} else if (mode == 1) {	/* Manual */
		req.mode = NETWORK_SELECT_MODE_MANUAL;
		snprintf(req.plmn, 7, "%s", plmn);
		req.act = act;
	} else {
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}
	dbg("Mode: [%d] PLMN: [%s] AcT: [%d]", req.mode, req.plmn, req.act);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_PLMN_SELECTION_MODE,
		&req, sizeof(struct treq_network_set_plmn_selection_mode));

	return TRUE;
}


static gboolean on_network_set_service_domain(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gint domain, gpointer user_data)
{
	struct treq_network_set_service_domain req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "w"))
		return TRUE;

	req.domain = domain;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_SERVICE_DOMAIN,
		&req, sizeof(struct treq_network_set_service_domain));

	return TRUE;
}

static gboolean on_network_get_service_domain(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_SERVICE_DOMAIN,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_set_band(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation,
	gint band, gint mode, gpointer user_data)
{
	struct treq_network_set_band req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "w"))
		return TRUE;

	req.mode = mode;
	req.band = band;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_BAND,
		&req, sizeof(struct treq_network_set_band));

	return TRUE;
}

static gboolean on_network_get_band(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_BAND,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_set_mode(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gint mode, gpointer user_data)
{
	struct treq_network_set_mode req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "w"))
		return TRUE;

	req.mode = mode;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_MODE,
		&req, sizeof(struct treq_network_set_mode));

	return TRUE;
}

static gboolean on_network_get_mode(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_MODE,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_set_preferred_plmn(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation,
	gint mode, gint ef_index, gint act, const gchar *plmn, gpointer user_data)
{
	struct treq_network_set_preferred_plmn req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "w"))
		return TRUE;

	req.operation = mode;
	req.ef_index = ef_index;
	req.act = act;

	memcpy(req.plmn, plmn, 6);

	if (strlen(plmn) <= 5)
		req.plmn[5] = '#';

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_PREFERRED_PLMN,
		&req, sizeof(struct treq_network_set_preferred_plmn));

	return TRUE;
}

static gboolean on_network_get_preferred_plmn(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_PREFERRED_PLMN,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_get_serving_network(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_SERVING_NETWORK,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_get_neighboring_cell_info(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_NEIGHBORING_CELL_INFO,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_set_default_data_subscription(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "w"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_DEFAULT_DATA_SUBSCRIPTION,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_get_default_data_subscription(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_DEFAULT_DATA_SUBSCRIPTION,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_set_default_subs(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "w"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_DEFAULT_SUBSCRIPTION,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_get_default_subs(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_DEFAULT_SUBSCRIPTION,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_set_emergency_callback_mode(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gint mode, gpointer user_data)
{
	struct treq_network_set_emergency_callback_mode req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "w"))
		return TRUE;

	req.mode = mode;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_EMERGENCY_CALLBACK_MODE,
		&req, sizeof(struct treq_network_set_emergency_callback_mode));

	return TRUE;
}

static gboolean on_network_set_roaming_preference(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation,  gint roam_pref, gpointer user_data)
{
	struct treq_network_set_roaming_preference req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "w"))
		return TRUE;

	req.roam_pref = roam_pref;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_SET_ROAMING_PREFERENCE,
		&req, sizeof(struct treq_network_set_roaming_preference));

	return TRUE;
}

static gboolean on_network_get_roaming_preference(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	/* Dispatch request */
	dtapi_dispatch_request(ctx, network, invocation,
		TREQ_NETWORK_GET_ROAMING_PREFERENCE,
		NULL, 0);

	return TRUE;
}

static gboolean on_network_get_network_info(TelephonyNetwork *network,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	TcorePlugin *plugin;
	CoreObject *co_network;
	NetworkPropertyInfo network_info;
	char *cpname;
	TReturn result = TCORE_RETURN_SUCCESS;

	if (!check_access_control(invocation, AC_NETWORK, "r"))
		return TRUE;

	cpname = GET_CP_NAME(invocation);

	plugin = tcore_server_find_plugin(ctx->server, cpname);
	co_network = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_NETWORK);

	memset(&network_info, 0x0, sizeof(NetworkPropertyInfo));

	/* Fetch Network information */
	__get_current_network_status(co_network, &network_info,
		NET_PROP_SVC_TYPE | NET_PROP_ROAM | NET_PROP_PLMN
		| NET_PROP_NAME_OPTION | NET_PROP_SPN | NET_PROP_NWNAME);

	network_info.type = (NET_PROP_SVC_TYPE|NET_PROP_ROAM|NET_PROP_NAME_OPTION);

	if (network_info.plmn && strlen(network_info.plmn) != 0)
		network_info.type |= NET_PROP_PLMN;
	if (network_info.spn && strlen(network_info.spn) != 0)
		network_info.type |= NET_PROP_SPN;
	if (network_info.nwname && strlen(network_info.nwname) != 0)
		network_info.type |= NET_PROP_NWNAME;

	info("[%s] type:[0x%x] SVC:[%d] Roam:[%d] Name option:[%d] PLMN:[%s] SPN:[%s] NW name:[%s]",
		cpname, network_info.type, network_info.svc_type, network_info.roaming, network_info.name_option,
		network_info.plmn, network_info.spn, network_info.nwname);

	/* Send response */
	telephony_network_complete_get_network_info(network,
		invocation,
		network_info.type, network_info.svc_type,
		network_info.roaming, network_info.name_option,
		network_info.plmn, network_info.spn, network_info.nwname,
		result);

	return TRUE;
}

gboolean dbus_plugin_setup_network_interface(TelephonyObjectSkeleton *object,
	struct custom_data *ctx)
{
	TelephonyNetwork *network;

	network = telephony_network_skeleton_new();
	telephony_object_skeleton_set_network(object, network);
	g_object_unref(network);

	dbg("network = %p", network);

	/*
	 * Register signal handlers for Network interface
	 */
	g_signal_connect(network,
		"handle-search",
		G_CALLBACK(on_network_search), ctx);

	g_signal_connect(network,
		"handle-search-cancel",
		G_CALLBACK(on_network_search_cancel), ctx);

	g_signal_connect(network,
		"handle-set-selection-mode",
		G_CALLBACK(on_network_set_selection_mode), ctx);

	g_signal_connect(network,
		"handle-get-selection-mode",
		G_CALLBACK(on_network_get_selection_mode), ctx);

	g_signal_connect(network,
		"handle-set-service-domain",
		G_CALLBACK(on_network_set_service_domain), ctx);

	g_signal_connect(network,
		"handle-get-service-domain",
		G_CALLBACK(on_network_get_service_domain), ctx);

	g_signal_connect(network,
		"handle-set-band",
		G_CALLBACK(on_network_set_band), ctx);

	g_signal_connect(network,
		"handle-get-band",
		G_CALLBACK(on_network_get_band), ctx);

	g_signal_connect(network,
		"handle-set-mode",
		G_CALLBACK(on_network_set_mode), ctx);

	g_signal_connect(network,
		"handle-get-mode",
		G_CALLBACK(on_network_get_mode), ctx);

	g_signal_connect(network,
		"handle-set-preferred-plmn",
		G_CALLBACK(on_network_set_preferred_plmn), ctx);

	g_signal_connect(network,
		"handle-get-preferred-plmn",
		G_CALLBACK(on_network_get_preferred_plmn), ctx);

	g_signal_connect(network,
		"handle-get-serving-network",
		G_CALLBACK(on_network_get_serving_network), ctx);

	g_signal_connect(network,
		"handle-get-ngbr-cell-info",
		G_CALLBACK(on_network_get_neighboring_cell_info), ctx);

	g_signal_connect(network,
		"handle-set-default-data-subscription",
		G_CALLBACK(on_network_set_default_data_subscription), ctx);

	g_signal_connect(network,
		"handle-get-default-data-subscription",
		G_CALLBACK(on_network_get_default_data_subscription), ctx);

	g_signal_connect(network,
		"handle-set-default-subscription",
		G_CALLBACK(on_network_set_default_subs), ctx);

	g_signal_connect(network,
		"handle-get-default-subscription",
		G_CALLBACK(on_network_get_default_subs), ctx);

	g_signal_connect(network,
		"handle-set-emergency-callback-mode",
		G_CALLBACK(on_network_set_emergency_callback_mode), ctx);

	g_signal_connect(network,
		"handle-set-roaming-preference",
		G_CALLBACK(on_network_set_roaming_preference), ctx);

	g_signal_connect(network,
		"handle-get-roaming-preference",
		G_CALLBACK(on_network_get_roaming_preference), ctx);

	g_signal_connect(network,
		"handle-get-network-info",
		G_CALLBACK(on_network_get_network_info), ctx);

	/*
	 * Initialize DBUS properties
	 */
	telephony_network_set_access_technology(network, NETWORK_ACT_UNKNOWN);
	telephony_network_set_cell_id(network, 0);
	telephony_network_set_ims_voice_status(network, NETWORK_IMS_VOICE_UNKNOWN);
	telephony_network_set_volte_enable(network, FALSE);
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

	tcore_server_remove_notification_hook(ctx->server, on_hook_ps_protocol_status);
	tcore_server_add_notification_hook(ctx->server,
		TNOTI_PS_PROTOCOL_STATUS, on_hook_ps_protocol_status, ctx);

	return TRUE;
}

gboolean dbus_plugin_network_response(struct custom_data *ctx,
	UserRequest *ur, struct dbus_request_info *dbus_info,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	char *cpname = dbus_info ? GET_CP_NAME(dbus_info->invocation) : "";

	switch (command) {
	case TRESP_NETWORK_SEARCH: {
		const struct tresp_network_search *resp_network_search = data;
		GVariant *network_search_result = NULL;
		GVariantBuilder b;
		int i = 0;

		info("[%s] NETWORK_SEARCH - [%s] Count: [%d]",
			cpname, (resp_network_search->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
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

		telephony_network_complete_search(dbus_info->interface_object,
			dbus_info->invocation,
			network_search_result, resp_network_search->result);
	}
	break;

	case TRESP_NETWORK_SET_PLMN_SELECTION_MODE: {
		const struct tresp_network_set_plmn_selection_mode *resp_set_plmn_selection_mode = data;

		info("[%s] NETWORK_SET_PLMN_SELECTION_MODE - [%s]", cpname,
			(resp_set_plmn_selection_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_selection_mode(dbus_info->interface_object,
			dbus_info->invocation, resp_set_plmn_selection_mode->result);
	}
	break;

	case TRESP_NETWORK_GET_PLMN_SELECTION_MODE: {
		const struct tresp_network_get_plmn_selection_mode *resp_get_plmn_selection_mode = data;

		info("[%s] NETWORK_GET_PLMN_SELECTION_MODE - [%s] Mode: [%s]", cpname,
			(resp_get_plmn_selection_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			(resp_get_plmn_selection_mode->mode == NETWORK_SELECT_MODE_AUTOMATIC ? "AUTO" :
			(resp_get_plmn_selection_mode->mode == NETWORK_SELECT_MODE_MANUAL ? "MANUAL" :
			"UNKNOWN")));

		switch (resp_get_plmn_selection_mode->mode) {
		case NETWORK_SELECT_MODE_AUTOMATIC:
			telephony_network_complete_get_selection_mode(dbus_info->interface_object,
				dbus_info->invocation, 0, resp_get_plmn_selection_mode->result);
		break;

		case NETWORK_SELECT_MODE_MANUAL:
			telephony_network_complete_get_selection_mode(dbus_info->interface_object,
				dbus_info->invocation, 1, resp_get_plmn_selection_mode->result);
		break;

		default:
			telephony_network_complete_get_selection_mode(dbus_info->interface_object,
				dbus_info->invocation, -1, resp_get_plmn_selection_mode->result);
		break;
		}
	}
	break;

	case TRESP_NETWORK_SET_SERVICE_DOMAIN: {
		const struct tresp_network_set_service_domain *resp_set_service_domain = data;

		dbg("[%s] NETWORK_SET_SERVICE_DOMAIN - [%s]", cpname,
			(resp_set_service_domain->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_service_domain(dbus_info->interface_object,
			dbus_info->invocation, resp_set_service_domain->result);
	}
	break;

	case TRESP_NETWORK_GET_SERVICE_DOMAIN: {
		const struct tresp_network_get_service_domain *resp_get_service_domain = data;

		dbg("[%s] NETWORK_GET_SERVICE_DOMAIN - [%s] Domain: [%d]", cpname,
			(resp_get_service_domain->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_get_service_domain->domain);

		telephony_network_complete_get_service_domain(dbus_info->interface_object,
			dbus_info->invocation,
			resp_get_service_domain->domain, resp_get_service_domain->result);
	}
	break;

	case TRESP_NETWORK_SET_BAND: {
		const struct tresp_network_set_band *resp_set_band = data;

		dbg("[%s] NETWORK_SET_BAND - [%s]", cpname,
			(resp_set_band->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_band(dbus_info->interface_object,
			dbus_info->invocation, resp_set_band->result);
	}
	break;

	case TRESP_NETWORK_GET_BAND: {
		const struct tresp_network_get_band *resp_get_band = data;

		dbg("[%s] NETWORK_GET_BAND - [%s] Mode: [%s] Band: [%d]", cpname,
			(resp_get_band->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			(resp_get_band->mode == NETWORK_BAND_MODE_PREFERRED ? "PREFERRED" :
			(resp_get_band->mode == NETWORK_BAND_MODE_ONLY ? "ONLY" :
			"UNKNOWN")), resp_get_band->band);

		telephony_network_complete_get_band(dbus_info->interface_object,
			dbus_info->invocation,
			resp_get_band->band, resp_get_band->mode, resp_get_band->result);
	}
	break;

	case TRESP_NETWORK_SET_MODE: {
		const struct tresp_network_set_mode *resp_set_mode = data;

		dbg("[%s] NETWORK_SET_MODE - [%s]", cpname,
			(resp_set_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_mode(dbus_info->interface_object,
			dbus_info->invocation, resp_set_mode->result);
	}
	break;

	case TRESP_NETWORK_GET_MODE: {
		const struct tresp_network_get_mode *resp_get_mode = data;

		dbg("[%s] NETWORK_GET_MODE - [%s] Mode: [%d]", cpname,
			(resp_get_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_get_mode->mode);

		telephony_network_complete_get_mode(dbus_info->interface_object,
			dbus_info->invocation,
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

		dbg("[%s] NETWORK_GET_NEIGHBORING_CELL_INFO - [%s]", cpname,
			(resp_get_ngbr_cell_info->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		act = resp_get_ngbr_cell_info->info.serving.act;

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

		/*
		 * Fill Serving cell parameter
		 */
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
		} else if (act >= NETWORK_ACT_UMTS && act <= NETWORK_ACT_GSM_UTRAN) {
			value = g_variant_new("(iiiii)",
				resp_get_ngbr_cell_info->info.serving.cell.umts.cell_id,
				resp_get_ngbr_cell_info->info.serving.cell.umts.lac,
				resp_get_ngbr_cell_info->info.serving.cell.umts.arfcn,
				resp_get_ngbr_cell_info->info.serving.cell.umts.psc,
				resp_get_ngbr_cell_info->info.serving.cell.umts.rscp);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "u_serving", value);
			g_variant_builder_close(&b);
		} else if (act == NETWORK_ACT_LTE) {
			value = g_variant_new("(iiiii)",
				resp_get_ngbr_cell_info->info.serving.cell.lte.cell_id,
				resp_get_ngbr_cell_info->info.serving.cell.lte.lac,
				resp_get_ngbr_cell_info->info.serving.cell.lte.earfcn,
				resp_get_ngbr_cell_info->info.serving.cell.lte.tac,
				resp_get_ngbr_cell_info->info.serving.cell.lte.rssi);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "l_serving", value);
			g_variant_builder_close(&b);
		} else if (act >= NETWORK_ACT_IS95A && act <= NETWORK_ACT_EHRPD) {
			value = g_variant_new("(uuuuii)",
				resp_get_ngbr_cell_info->info.serving.cell.cdma.sid,
				resp_get_ngbr_cell_info->info.serving.cell.cdma.nid,
				resp_get_ngbr_cell_info->info.serving.cell.cdma.base_id,
				resp_get_ngbr_cell_info->info.serving.cell.cdma.refpn,
				resp_get_ngbr_cell_info->info.serving.cell.cdma.base_lat,
				resp_get_ngbr_cell_info->info.serving.cell.cdma.base_long);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "c_serving", value);
			g_variant_builder_close(&b);
		}

		/*
		 * Fill GERAN neighbor cell parameter
		 */
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

		/*
		 * Fill UMTS neighbor cell parameter
		 */
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

		telephony_network_complete_get_ngbr_cell_info(dbus_info->interface_object,
			dbus_info->invocation,
			neighboring_cell_info_result, resp_get_ngbr_cell_info->result);
	}
	break;

	case TRESP_NETWORK_SET_PREFERRED_PLMN: {
		const struct tresp_network_set_preferred_plmn *resp_set_preferred_plmn = data;

		dbg("[%s] NETWORK_SET_PREFERRED_PLMN - [%s]", cpname,
			(resp_set_preferred_plmn->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_preferred_plmn(dbus_info->interface_object,
			dbus_info->invocation, resp_set_preferred_plmn->result);
	}
	break;

	case TRESP_NETWORK_GET_PREFERRED_PLMN: {
		const struct tresp_network_get_preferred_plmn *resp_get_preferred_plmn = data;
		GVariant *preferred_plmn_result = NULL;
		GVariantBuilder b;
		int i = 0;

		dbg("[%s] NETWORK_GET_PREFERRED_PLMN - [%s] Count: [%d]", cpname,
			(resp_get_preferred_plmn->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_get_preferred_plmn->list_count);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_get_preferred_plmn->list_count; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

			g_variant_builder_add(&b, "{sv}", "plmn",
				g_variant_new_string(resp_get_preferred_plmn->list[i].plmn));
			g_variant_builder_add(&b, "{sv}", "act",
				g_variant_new_int32(resp_get_preferred_plmn->list[i].act));
			g_variant_builder_add(&b, "{sv}", "index",
				g_variant_new_int32(resp_get_preferred_plmn->list[i].ef_index));
			g_variant_builder_add(&b, "{sv}", "name",
				g_variant_new_string(resp_get_preferred_plmn->list[i].name));

			g_variant_builder_close(&b);
		}
		preferred_plmn_result = g_variant_builder_end(&b);

		telephony_network_complete_get_preferred_plmn(dbus_info->interface_object,
			dbus_info->invocation,
			preferred_plmn_result, resp_get_preferred_plmn->result);
	}
	break;

	case TRESP_NETWORK_SET_CANCEL_MANUAL_SEARCH: {
		const struct tresp_network_set_cancel_manual_search *resp_set_cancel_manual_search = data;

		info("[%s] NETWORK_SET_CANCEL_MANUAL_SEARCH - [%s]", cpname,
			(resp_set_cancel_manual_search->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_search_cancel(dbus_info->interface_object,
			dbus_info->invocation, resp_set_cancel_manual_search->result);
	}
	break;

	case TRESP_NETWORK_GET_SERVING_NETWORK: {
		const struct tresp_network_get_serving_network *resp_get_serving_network = data;
		GVariant *serving_network = NULL;
		GVariant *value = NULL;
		GVariantBuilder b;

		enum telephony_network_access_technology act;

		dbg("[%s] NETWORK_GET_SERVING_NETWORK - [%s] AcT: [%d] PLMN: [%s] LAC: [%d]", cpname,
			(resp_get_serving_network->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_get_serving_network->act, resp_get_serving_network->plmn,
			resp_get_serving_network->gsm.lac);

		act = resp_get_serving_network->act;
		g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));

		/*
		 * Fill Serving cell parameter
		 */
		value = g_variant_new("(is)",
			resp_get_serving_network->act,
			resp_get_serving_network->plmn);

		g_variant_builder_add(&b, "{sv}", "serving", value);
		if ((act >= NETWORK_ACT_GSM
				&& act <= NETWORK_ACT_GSM_UTRAN)
				|| act == NETWORK_ACT_LTE) {
			dbg("lac: [%d]", resp_get_serving_network->gsm.lac);

			value = g_variant_new("(i)",
				resp_get_serving_network->gsm.lac);
			g_variant_builder_add(&b, "{sv}", "g_serving", value);
		} else if (act >= NETWORK_ACT_IS95A
				&& act <= NETWORK_ACT_EHRPD) {
			dbg("carrier: [%d] sid: [%d] nid: [%d] bs_id: [%d] " \
				"bs_lat: [%d] bs_long: [%d] reg_zone: [%d] pilot_pn: [%d]",
				resp_get_serving_network->cdma.carrier,
				resp_get_serving_network->cdma.sid,
				resp_get_serving_network->cdma.nid,
				resp_get_serving_network->cdma.bs_id,
				resp_get_serving_network->cdma.bs_lat,
				resp_get_serving_network->cdma.bs_long,
				resp_get_serving_network->cdma.reg_zone,
				resp_get_serving_network->cdma.pilot_pn);

			value = g_variant_new("(iuuuiiuu)",
				resp_get_serving_network->cdma.carrier,
				resp_get_serving_network->cdma.sid,
				resp_get_serving_network->cdma.nid,
				resp_get_serving_network->cdma.bs_id,
				resp_get_serving_network->cdma.bs_lat,
				resp_get_serving_network->cdma.bs_long,
				resp_get_serving_network->cdma.reg_zone,
				resp_get_serving_network->cdma.pilot_pn);
			g_variant_builder_add(&b, "{sv}", "c_serving", value);
		}
		serving_network = g_variant_builder_end(&b);

		telephony_network_complete_get_serving_network(dbus_info->interface_object,
			dbus_info->invocation,
			serving_network, resp_get_serving_network->result);
	}
	break;

	case TRESP_NETWORK_SET_DEFAULT_DATA_SUBSCRIPTION: {
		const struct tresp_network_set_default_data_subscription *resp_set_default_data_subs = data;

		info("[%s] NETWORK_SET_DEFAULT_DATA_SUBSCRIPTION - [%s]", cpname,
			(resp_set_default_data_subs->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_default_data_subscription(dbus_info->interface_object,
			dbus_info->invocation, resp_set_default_data_subs->result);
	}
	break;

	case TRESP_NETWORK_GET_DEFAULT_DATA_SUBSCRIPTION: {
		const struct tresp_network_get_default_data_subs *resp_get_default_data_subs = data;

		dbg("[%s] NETWORK_GET_DEFAULT_DATA_SUBSCRIPTION - [%s] 'default' Data subscription: [%s]", cpname,
			(resp_get_default_data_subs->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			(resp_get_default_data_subs->default_subs == NETWORK_DEFAULT_DATA_SUBS_SIM1 ? "SIM 1" :
			(resp_get_default_data_subs->default_subs == NETWORK_DEFAULT_DATA_SUBS_SIM2 ? "SIM 2" :
			"UNKNWON")));

		telephony_network_complete_get_default_data_subscription(dbus_info->interface_object, dbus_info->invocation,
			resp_get_default_data_subs->default_subs, resp_get_default_data_subs->result);
	}
	break;

	case TRESP_NETWORK_SET_DEFAULT_SUBSCRIPTION: {
		const struct tresp_network_set_default_subs *resp_set_default_subs = data;

		info("[%s] NETWORK_SET_DEFAULT_SUBSCRIPTION - [%s]", cpname,
			(resp_set_default_subs->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_default_subscription(dbus_info->interface_object,
			dbus_info->invocation, resp_set_default_subs->result);
	}
	break;

	case TRESP_NETWORK_GET_DEFAULT_SUBSCRIPTION: {
		const struct tresp_network_get_default_subs *resp_get_default_subs = data;

		dbg("[%s] NETWORK_GET_DEFAULT_SUBSCRIPTION - [%s] 'default' subscription: [%s]", cpname,
			(resp_get_default_subs->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			(resp_get_default_subs->default_subs == NETWORK_DEFAULT_SUBS_SIM1 ? "SIM 1" :
			(resp_get_default_subs->default_subs == NETWORK_DEFAULT_SUBS_SIM2 ? "SIM 2" :
			"UNKNOWN")));

		telephony_network_complete_get_default_subscription(dbus_info->interface_object,
			dbus_info->invocation,
			resp_get_default_subs->default_subs, resp_get_default_subs->result);
	}
	break;

	case TRESP_NETWORK_SET_EMERGENCY_CALLBACK_MODE: {
		const struct tresp_network_set_emergency_callback_mode *resp_set_emergency_callback_mode = data;

		info("[%s] NETWORK_SET_EMERGENCY_CALLBACK_MODE - [%s]", cpname,
			(resp_set_emergency_callback_mode->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_emergency_callback_mode(dbus_info->interface_object,
			dbus_info->invocation, resp_set_emergency_callback_mode->result);
	}
	break;

	case TRESP_NETWORK_SET_ROAMING_PREFERENCE: {
		const struct tresp_network_set_roaming_preference *resp_set_roam_pref = data;

		info("[%s] NETWORK_SET_ROAMING_PREFERENCE - [%s]", cpname,
			(resp_set_roam_pref->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"));

		telephony_network_complete_set_roaming_preference(dbus_info->interface_object,
			dbus_info->invocation, resp_set_roam_pref->result);
	}
	break;

	case TRESP_NETWORK_GET_ROAMING_PREFERENCE: {
		const struct tresp_network_get_roaming_preference *resp_get_roam_pref = data;

		dbg("[%s] NETWORK_GET_ROAMING_PREFERENCE - [%s] roam_pref: [%d]", cpname,
			(resp_get_roam_pref->result == TCORE_RETURN_SUCCESS ? "Success" : "Fail"),
			resp_get_roam_pref->roam_pref);

		telephony_network_complete_get_roaming_preference(dbus_info->interface_object,
			dbus_info->invocation,
			resp_get_roam_pref->roam_pref, resp_get_roam_pref->result);
	}
	break;

	default:
		err("Unhandled/Unknown Response: [0x%x]", command);
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_network_notification(struct custom_data *ctx,
	CoreObject *source, TelephonyObjectSkeleton *object,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyNetwork *network;
	const char *cp_name;

	if (!object) {
		err("object is NULL");
		return FALSE;
	}

	if (!data) {
		err("data is NULL");
		return FALSE;
	}

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
	network = telephony_object_peek_network(TELEPHONY_OBJECT(object));
	if (network == NULL) {
		err("Network object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_NETWORK_REGISTRATION_STATUS: {
		const struct tnoti_network_registration_status *reg = data;

		info("[%s] NET_REGI_STATUS - CS: [%d] PS: [%d] SVC: [%d] Roam: [%d]", cp_name,
			reg->cs_domain_status, reg->ps_domain_status,
			reg->service_type, reg->roaming_status);

#ifdef ENABLE_KPI_LOGS
		/* We ignore No SIM present case for KPI */
		if (reg->cs_domain_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL
			&& telephony_network_get_circuit_status(network) != NETWORK_SERVICE_DOMAIN_STATUS_FULL)
			TIME_CHECK("[%s] CS Network Full", cp_name);

		if (reg->ps_domain_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL
			&& telephony_network_get_packet_status(network) != NETWORK_SERVICE_DOMAIN_STATUS_FULL)
			TIME_CHECK("[%s] PS Network Full", cp_name);
#endif
		__check_network_properties(network, source, cp_name,
				(NET_PROP_CS|NET_PROP_PS|NET_PROP_SVC_TYPE|NET_PROP_ROAM));

		/* Emit Signal */
		telephony_network_emit_registration_status(network,
			reg->cs_domain_status, reg->ps_domain_status,
			reg->service_type, reg->roaming_status);
	}
	break;

	case TNOTI_NETWORK_CHANGE: {
		const struct tnoti_network_change *change = data;

		info("[%s] NET_CHANGE - plmn: [%s] lac: [%d]", cp_name,
			change->plmn, change->gsm.lac);

		/* SPN, NWNAME, NAME_OPTION would have updated on LAC change */
		__check_network_properties(network, source, cp_name,
			NET_PROP_PLMN | NET_PROP_NAME_OPTION | NET_PROP_SPN | NET_PROP_NWNAME);

		/* Emit Signal */
		telephony_network_emit_change(network,
			change->act, change->plmn);
	}
	break;

	case TNOTI_NETWORK_TIMEINFO: {
		const struct tnoti_network_timeinfo *time_info = data;

		info("[%s] NET_TIMEINFO - [%04d-%02d-%02d] [%02d:%02d:%02d]", cp_name,
			time_info->year, time_info->month, time_info->day,
			time_info->hour, time_info->minute, time_info->second);

		/* Emit signal */
		telephony_network_emit_time_info(network,
			time_info->year, time_info->month, time_info->day,
			time_info->hour, time_info->minute, time_info->second,
			time_info->wday,
			time_info->gmtoff, time_info->dstoff,
			time_info->isdst,
			time_info->plmn);
	}
	break;

	case TNOTI_NETWORK_ICON_INFO: {
		const struct tnoti_network_icon_info *icon_info = data;

		/* Update property */
		if (icon_info->type & NETWORK_ICON_INFO_RSSI) {
			info("[%s] NET_ICON_INFO - RSSI: [%d]", cp_name, icon_info->rssi);

			/* Emit signal */
			telephony_network_set_sig_level(network, icon_info->rssi);
		}
	}
	break;

	case TNOTI_NETWORK_IDENTITY: {
		const struct tnoti_network_identity *identity = data;

		info("[%s] NET_IDENTITY - long name: [%s] short name: [%s] PLMN: [%s]", cp_name,
			identity->full_name, identity->short_name, identity->plmn);

		__check_network_properties(network, source, cp_name,
			(NET_PROP_NAME_OPTION | NET_PROP_SPN | NET_PROP_NWNAME));

		/* Emit Signal */
		telephony_network_emit_identity(network,
			identity->plmn, identity->short_name, identity->full_name);
	}
	break;

	case TNOTI_NETWORK_LOCATION_CELLINFO: {
		const struct tnoti_network_location_cellinfo *location = data;

		info("[%s] NET_LOCATION_CELLINFO - LAC: [0x%x] Cell ID: [0x%x]", cp_name,
			location->lac, location->cell_id);

		/* Update properties */
		telephony_network_set_lac(network, location->lac);
		telephony_network_set_cell_id(network, location->cell_id);

		/* Emit signal */
		telephony_network_emit_cell_info(network,
			location->lac, location->cell_id);
	}
	break;

	case TNOTI_NETWORK_SIGNAL_STRENGTH: {
		const struct tnoti_network_signal_strength *signal_strength = data;

		info("[%s] NET_SIGNAL_STRENGTH - DBM: [%d]", cp_name,
			signal_strength->dbm);

		/* Update properties */
		telephony_network_set_sig_dbm(network, signal_strength->dbm);

		/* Emit signal */
		telephony_network_emit_signal_strength(network,
			signal_strength->dbm);
	}
	break;

	case TNOTI_NETWORK_DEFAULT_DATA_SUBSCRIPTION: {
		const struct tnoti_network_default_data_subs *default_data_subs_info = data;

		info("[%s] NET_DEFAULT_DATA_SUBSCRIPTION - 'default' DDS: [%s]", cp_name,
			(default_data_subs_info->default_subs == NETWORK_DEFAULT_DATA_SUBS_SIM1 ? "SIM 1" :
			(default_data_subs_info->default_subs == NETWORK_DEFAULT_DATA_SUBS_SIM2 ? "SIM 2" :
			"UNKNOWN")));

		/* Emit signal */
		telephony_network_emit_default_data_subscription(network,
			default_data_subs_info->default_subs);
	}
	break;

	case TNOTI_NETWORK_DEFAULT_SUBSCRIPTION: {
		const struct tnoti_network_default_subs *default_subs_info = data;

		info("[%s] NET_DEFAULT_SUBSCRIPTION - 'default' subscription: [%s]", cp_name,
			(default_subs_info->default_subs == NETWORK_DEFAULT_SUBS_SIM1 ? "SIM 1" :
			(default_subs_info->default_subs == NETWORK_DEFAULT_SUBS_SIM2 ? "SIM 2" :
			"UNKNOWN")));

		/* Emit signal */
		telephony_network_emit_default_subscription(network,
			default_subs_info->default_subs);
	}
	break;

	case TNOTI_NETWORK_IMS_VOICE_SUPPORT_STATUS: {
		const struct tnoti_network_ims_voice_status *status = data;

		dbg("[%s] NET_IMS_VOICE_SUPPORT_STATUS - Status: [%s]", cp_name,
			(status->status == NETWORK_IMS_VOICE_SUPPORT ? "SUPPORTED" :
			(status->status == NETWORK_IMS_VOICE_NOT_SUPPORT ? "NOT SUPPORTED" :
			"UNKNOWN")));

		/* Update properties */
		telephony_network_set_ims_voice_status(network,
			status->status);
	}
	break;

	case TNOTI_NETWORK_EMERGENCY_CALLBACK_MODE: {
		const struct tnoti_network_emergency_callback_mode *emergency_callback_mode = data;

		dbg("[%s] NET_EMERGENCY_CALLBACK_MODE - Mode: [%s]", cp_name,
			(emergency_callback_mode->mode == NETWORK_EMERGENCY_CALLBACK_MODE_ENTER ? "ENTER" :
			(emergency_callback_mode->mode == NETWORK_EMERGENCY_CALLBACK_MODE_EXIT? "EXIT" :
			"READY")));

		/* Emit signal */
		telephony_network_emit_emergency_callback_mode(network,
			emergency_callback_mode->mode);
	}
	break;

	default:
		err("Unhandled/Unknown Notification: [0x%x]", command);
	break;
	}

	return TRUE;
}


