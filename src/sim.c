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
#include <errno.h>
#include <glib.h>
#include <gio/gio.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <hal.h>
#include <communicator.h>
#include <core_object.h>
#include <queue.h>
#include <user_request.h>
#include <util.h>
#include <co_sim.h>

#include "generated-code.h"
#include "common.h"

#define DBUS_SIM_STATUS_ERROR "SIM STATUS ERROR"
#define DBUS_SIM_NOT_FOUND "SIM NOT FOUND"
#define DBUS_SIM_PERM_BLOCKED "SIM PERM BLOCKED"
#define DBUS_SIM_CARD_ERROR "SIM CARD ERROR"
#define DBUS_SIM_NOT_INITIALIZED "SIM NOT INITIALIZED"
#define DBUS_SIM_INIT_COMPLETED "SIM INIT COMPLETED"
#define DBUS_SIM_LOCKED "SIM LOCKED"
#define DBUS_SIM_NOT_READY "SIM NOT READY"
#define DBUS_SIM_RESPONSE_DATA_ERROR "SIM RESPONSE DATA ERROR"
#define DBUS_SIM_SERVICE_IS_DISABLED "SIM SERVICE IS DISABLED"

#define DBUS_SIM_GET_COSIM(invocation, co_sim, server) { \
	co_sim = __get_sim_co_by_cp_name(server, GET_CP_NAME(invocation)); \
	if (!co_sim) { \
		err("SIM Core object is NULL"); \
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED); \
		return TRUE; \
	} \
}

#define DBUS_SIM_CHECK_SIM_STATUS(op_type, co_sim) {\
	if (__check_sim_state(op_type, tcore_sim_get_status(co_sim)) == FALSE) { \
		err("Invalid SIM status"); \
		__return_fail_response(invocation, tcore_sim_get_status(co_sim)); \
		return TRUE; \
	} \
}

#define DBUS_SIM_CHECK_SIM_SERVICE_TABLE(op_type, co_sim) {\
	gboolean b_cphs = FALSE; \
	b_cphs = tcore_sim_get_cphs_status(co_sim); \
	if (b_cphs && op_type != GET_MSISDN) { \
		dbg("CPHS SIM... Do not check SST"); \
	} else { \
		struct tel_sim_service_table* svct = tcore_sim_get_service_table(co_sim); \
		if (svct != NULL) { \
			if (__check_sim_service_table(op_type, svct) == FALSE) { \
				err("'Service' is disabled in SST"); \
				FAIL_RESPONSE(invocation, DBUS_SIM_SERVICE_IS_DISABLED); \
				free(svct); \
				return TRUE; \
			} else { \
				dbg("Request to modem"); \
				free(svct); \
			} \
		} \
	} \
}

#define DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation, ur) {\
	if (ret != TCORE_RETURN_SUCCESS) { \
		if (ret == TCORE_RETURN_SIM_DISABLED_IN_SST) { \
			err("'Service' is disabled in SST"); \
			FAIL_RESPONSE (invocation, DBUS_SIM_SERVICE_IS_DISABLED); \
		} else { \
			err("Dispatch request failed: [0x%x]", ret); \
			FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED); \
		} \
		tcore_user_request_unref(ur); \
	} \
}

enum dbus_tapi_sim_gdbus_method_name {
	GET_INIT_STATUS = 1,
	GET_CARD_TYPE,
	GET_IMSI,
	GET_ECC,
	GET_ICCID = 5,
	GET_LANGUAGE,
	SET_LANGUAGE,
	GET_CALL_FORWARDING,
	SET_CALL_FORWARDING,
	GET_MESSAGE_WAITING = 10,
	SET_MESSAGE_WAITING,
	GET_MAILBOX,
	SET_MAILBOX,
	GET_CPHS_INFO,
	GET_SVCT = 15,
	GET_MSISDN,
	GET_OPLMWACT,
	GET_SPN,
	GET_CPHS_NET_NAME,
	AUTHENTICATION = 20,
	VERIFY_SEC,
	VERIFY_PUK,
	CHANGE_PIN,
	DISABLE_FACILITY,
	ENABLE_FACILITY = 25,
	GET_FACILITY,
	GET_LOCK_INFO,
	TRANSFER_APDU,
	GET_ATR,
	GET_FIELDS = 30,	//for get various data at once
	GET_GID,
	SET_POWERSTATE,

	//for notification
	STATUS = 100,
	REFRESHED,
};

#if 0
static gboolean __is_valid_sim_status(enum tel_sim_status sim_status)
{
	switch(sim_status) {
	case SIM_STATUS_INIT_COMPLETED:
	case SIM_STATUS_INITIALIZING:
	case SIM_STATUS_PIN_REQUIRED:
	case SIM_STATUS_PUK_REQUIRED:
	case SIM_STATUS_LOCK_REQUIRED:
	case SIM_STATUS_CARD_BLOCKED:
	case SIM_STATUS_NCK_REQUIRED:
	case SIM_STATUS_NSCK_REQUIRED:
	case SIM_STATUS_SPCK_REQUIRED:
	case SIM_STATUS_CCK_REQUIRED:
		return TRUE;
	default:
		return FALSE;
	}
}
#endif

static CoreObject *__get_sim_co_by_cp_name(Server *server, char *cp_name)
{
	TcorePlugin *plugin = NULL;

	if (!server) {
		err("server is NULL");
		return NULL;
	}

	plugin = tcore_server_find_plugin(server, cp_name);
	return tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SIM);
}

static CoreObject* __get_sim_co_from_ur(Server *server, UserRequest *ur)
{
	CoreObject *co_sim = NULL;
	char *modem_name = NULL;

	modem_name = tcore_user_request_get_modem_name(ur);
	if (!modem_name) {
		err("Modem name is NULL");
		return co_sim;
	}

	co_sim = __get_sim_co_by_cp_name(server, modem_name);
	free(modem_name);

	return co_sim;
}

static gboolean __check_sim_state(enum dbus_tapi_sim_gdbus_method_name method, enum tel_sim_status sim_status)
{
	gboolean ret = TRUE;

	if ((int)sim_status < SIM_STATUS_CARD_ERROR) {
		err("SIM status is NOT valid");
		return FALSE;
	}

	switch (method) {
	case GET_CARD_TYPE:
	case GET_ECC:
	case GET_ICCID:
	case GET_LANGUAGE:
	case GET_CPHS_INFO:
	case GET_SPN:
	case AUTHENTICATION:
	case TRANSFER_APDU:
	case GET_ATR:
	// Regarding Lock facilities
	case CHANGE_PIN:
	case ENABLE_FACILITY:
	case DISABLE_FACILITY:
	case GET_FACILITY:
	case GET_LOCK_INFO:
	case VERIFY_SEC:
	case VERIFY_PUK:
		if (sim_status == SIM_STATUS_CARD_ERROR
				|| sim_status == SIM_STATUS_CARD_BLOCKED
				|| sim_status == SIM_STATUS_CARD_NOT_PRESENT
				|| sim_status == SIM_STATUS_CARD_REMOVED
				|| sim_status == SIM_STATUS_UNKNOWN
				|| sim_status == SIM_STATUS_CARD_POWEROFF) {
			ret = FALSE;
		}
	break;
	case GET_IMSI:
	case GET_SVCT:
	case GET_MSISDN:
	case GET_OPLMWACT:
	case GET_CPHS_NET_NAME:
	case GET_CALL_FORWARDING:
	case SET_CALL_FORWARDING:
	case GET_MESSAGE_WAITING:
	case SET_MESSAGE_WAITING:
	case GET_MAILBOX:
	case SET_MAILBOX:
	case SET_LANGUAGE:
	case GET_FIELDS:
	case GET_GID:
		if (sim_status != SIM_STATUS_INIT_COMPLETED) {
			ret = FALSE;
		}
	break;
	case SET_POWERSTATE:
		if (sim_status != SIM_STATUS_INIT_COMPLETED
				&& sim_status != SIM_STATUS_INITIALIZING
				&& sim_status != SIM_STATUS_PIN_REQUIRED
				&& sim_status != SIM_STATUS_CARD_BLOCKED
				&& sim_status != SIM_STATUS_CARD_POWEROFF) {
			ret = FALSE;
		}
	break;
	case GET_INIT_STATUS:
	case STATUS:
	case REFRESHED:
	default:
		err("Unhandled/Unknown operation: [%d]", method);
	break;
	}
	return ret;
}

static gboolean __check_sim_service_table(enum dbus_tapi_sim_gdbus_method_name method, struct tel_sim_service_table *svct)
{
	gboolean ret = TRUE;

	switch (method) {
	case GET_MSISDN:
		if ( !(svct->sim_type == SIM_TYPE_GSM && svct->table.sst.service[SIM_SST_MSISDN]) &&
				!(svct->sim_type == SIM_TYPE_USIM && svct->table.ust.service[SIM_UST_MSISDN]) ) {
			ret = FALSE;
		}
	break;
	case GET_CALL_FORWARDING:
	case SET_CALL_FORWARDING:
		if ( !(svct->sim_type == SIM_TYPE_GSM && svct->table.sst.service[SIM_SST_CFIS]) &&
				!(svct->sim_type == SIM_TYPE_USIM && svct->table.ust.service[SIM_UST_CFIS]) ) {
			ret = FALSE;
		}
	break;
	case GET_MESSAGE_WAITING:
	case SET_MESSAGE_WAITING:
		if ( !(svct->sim_type == SIM_TYPE_GSM && svct->table.sst.service[SIM_SST_MWIS]) &&
				!(svct->sim_type == SIM_TYPE_USIM && svct->table.ust.service[SIM_UST_MWIS]) ) {
			ret = FALSE;
		}
	break;
	case GET_MAILBOX:
	case SET_MAILBOX:
		if ( !(svct->sim_type == SIM_TYPE_GSM && svct->table.sst.service[SIM_SST_MBDN]) &&
				!(svct->sim_type == SIM_TYPE_USIM && svct->table.ust.service[SIM_UST_MBDN]) ) {
			ret = FALSE;
		}
	break;
	default:
		err("Unhandled/Unknown operation: [%d]", method);
	break;
	}

	return ret;
}

static void __return_fail_response(GDBusMethodInvocation *invocation, enum tel_sim_status sim_status)
{
	dbg("SIM Status: [%d]", sim_status);

	switch (sim_status) {
	case SIM_STATUS_CARD_NOT_PRESENT:
	case SIM_STATUS_CARD_REMOVED:
		FAIL_RESPONSE(invocation, DBUS_SIM_NOT_FOUND);
	break;
	case SIM_STATUS_CARD_BLOCKED:
		FAIL_RESPONSE(invocation, DBUS_SIM_PERM_BLOCKED);
	break;
	case SIM_STATUS_CARD_ERROR:
	case SIM_STATUS_CARD_CRASHED:
		FAIL_RESPONSE(invocation, DBUS_SIM_CARD_ERROR);
	break;
	case SIM_STATUS_INITIALIZING:
		FAIL_RESPONSE(invocation, DBUS_SIM_NOT_INITIALIZED);
	break;
	case SIM_STATUS_INIT_COMPLETED:
		FAIL_RESPONSE(invocation, DBUS_SIM_INIT_COMPLETED);
	break;
	case SIM_STATUS_PIN_REQUIRED:
	case SIM_STATUS_PUK_REQUIRED:
	case SIM_STATUS_NCK_REQUIRED:
	case SIM_STATUS_NSCK_REQUIRED:
	case SIM_STATUS_SPCK_REQUIRED:
	case SIM_STATUS_CCK_REQUIRED:
	case SIM_STATUS_LOCK_REQUIRED:
		FAIL_RESPONSE(invocation, DBUS_SIM_LOCKED);
	break;
	case SIM_STATUS_UNKNOWN:
		FAIL_RESPONSE(invocation, DBUS_SIM_NOT_READY);
	break;
	default:
		dbg("Unhandled/Unknown status: [%d]", sim_status);
		FAIL_RESPONSE(invocation, DBUS_SIM_STATUS_ERROR);
	break;
	}
}

static gboolean on_sim_get_init_status(TelephonySim *sim, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	enum tel_sim_status sim_status = SIM_STATUS_UNKNOWN;
	gboolean sim_changed = FALSE;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);

	sim_status = tcore_sim_get_status(co_sim);
	sim_changed = tcore_sim_get_identification(co_sim);
	dbg("SIM - Status: [%d] Changed: [%s]",
		sim_status, (sim_changed ? "Yes" : "No"));

	telephony_sim_complete_get_init_status(sim, invocation, sim_status, sim_changed);

	return TRUE;
}

static gboolean on_sim_get_card_type(TelephonySim *sim, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	enum tel_sim_type sim_type = SIM_TYPE_UNKNOWN;
	CoreObject *co_sim = NULL;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_CARD_TYPE, co_sim);

	sim_type = tcore_sim_get_type(co_sim);

	telephony_sim_complete_get_card_type(sim, invocation, sim_type);

	return TRUE;
}

static gboolean on_sim_get_imsi(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct tel_sim_imsi *n_imsi;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_IMSI, co_sim);

	n_imsi = tcore_sim_get_imsi(co_sim);
	if (!n_imsi) {
		FAIL_RESPONSE (invocation, DBUS_SIM_RESPONSE_DATA_ERROR);
		return TRUE;
	} else {
		telephony_sim_complete_get_imsi(sim, invocation, n_imsi->plmn, n_imsi->msin);
		free(n_imsi);
	}

	return TRUE;
}

static gboolean on_sim_get_ecc(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct tel_sim_ecc_list *ecc_list = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_ECC, co_sim);

	ecc_list = tcore_sim_get_ecc_list(co_sim);
	if (!ecc_list) {
		UserRequest *ur = NULL;
		TReturn ret;
		dbg("po->ecc_list is NULL. Request to Modem.");
		ur = MAKE_UR(ctx, sim, invocation);
		tcore_user_request_set_command(ur, TREQ_SIM_GET_ECC);
		ret = tcore_communicator_dispatch_request(ctx->comm, ur);
		if (ret != TCORE_RETURN_SUCCESS) {
			FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
			tcore_user_request_unref(ur);
		}
	} else {
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i;
		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i<ecc_list->ecc_count; i++) {
			dbg("ecc[%d] : ecc_category=[0x%x], ecc_num=[%s], ecc_string=[%s]",
					i, ecc_list->ecc[i].ecc_category, ecc_list->ecc[i].ecc_num, ecc_list->ecc[i].ecc_string);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "category", g_variant_new_int32(ecc_list->ecc[i].ecc_category));
			g_variant_builder_add(&b, "{sv}", "number", g_variant_new_string(ecc_list->ecc[i].ecc_num));
			g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string(ecc_list->ecc[i].ecc_string));
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);
		if (!gv)
			dbg("error - ecc gv is NULL");

		telephony_sim_complete_get_ecc(sim, invocation, gv);

		free(ecc_list);
	}

	return TRUE;
}

static gboolean on_sim_get_iccid(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct tel_sim_iccid* iccid = NULL;

	dbg("Func Entrance");

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_ICCID, co_sim);

	iccid = tcore_sim_get_iccid(co_sim);

	if (!iccid) {
		ur = MAKE_UR(ctx, sim, invocation);

		tcore_user_request_set_command(ur, TREQ_SIM_GET_ICCID);
		ret = tcore_communicator_dispatch_request(ctx->comm, ur);

		if (ret != TCORE_RETURN_SUCCESS) {
			FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
			dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
			tcore_user_request_unref(ur);
		}
	} else {
		telephony_sim_complete_get_iccid(sim, invocation, SIM_ACCESS_SUCCESS,
										iccid->iccid);
		free(iccid);
	}

	return TRUE;
}

static gboolean on_sim_get_language(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_LANGUAGE, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);

	tcore_user_request_set_command(ur, TREQ_SIM_GET_LANGUAGE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_set_language(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gint arg_language, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_language set_language;

	if (!check_access_control (invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(SET_LANGUAGE, co_sim);

	memset(&set_language, 0, sizeof(struct treq_sim_set_language));
	set_language.language = arg_language;

	dbg("set_language.language[%d]", set_language.language);
	ur = MAKE_UR(ctx, sim, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_sim_set_language), &set_language);
	tcore_user_request_set_command(ur, TREQ_SIM_SET_LANGUAGE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_get_call_forwarding(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_CALL_FORWARDING, co_sim);
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(GET_CALL_FORWARDING, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_command(ur, TREQ_SIM_GET_CALLFORWARDING);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation, ur);

	return TRUE;
}

static gboolean on_sim_set_call_forwarding(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gboolean  arg_cphs,
		gint arg_rec_index,
		gint arg_msp_num,
		guchar arg_cfu_status,
		gint arg_ton,
		gint arg_npi,
		const gchar *arg_number,
		gint arg_cc2_id,
		gint arg_ext7_id,
		gboolean arg_cphs_line1,
		gboolean arg_cphs_line2,
		gboolean arg_cphs_fax,
		gboolean arg_cphs_data,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_callforwarding req_cf;

	if (!check_access_control (invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(SET_CALL_FORWARDING, co_sim);
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(SET_CALL_FORWARDING, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);

	memset(&req_cf, 0, sizeof(struct treq_sim_set_callforwarding));

	req_cf.b_cphs = arg_cphs;

	if (req_cf.b_cphs) {
		req_cf.cphs_cf.b_line1 = arg_cphs_line1;
		req_cf.cphs_cf.b_line2 = arg_cphs_line2;
		req_cf.cphs_cf.b_fax = arg_cphs_fax;
		req_cf.cphs_cf.b_data = arg_cphs_data;
		dbg("b_line1[%d], b_line2[%d], b_fax[%d], b_data[%d]",
				req_cf.cphs_cf.b_line1, req_cf.cphs_cf.b_line2,
				req_cf.cphs_cf.b_fax, req_cf.cphs_cf.b_data);
	} else {
		req_cf.cf.rec_index = arg_rec_index;
		req_cf.cf.msp_num = arg_msp_num;
		req_cf.cf.cfu_status = arg_cfu_status;
		req_cf.cf.ton = arg_ton;
		req_cf.cf.npi = arg_npi;
		memcpy(&req_cf.cf.cfu_num, arg_number, strlen(arg_number));
		req_cf.cf.cc2_id = arg_cc2_id;
		req_cf.cf.ext7_id = arg_ext7_id;
		dbg("rec_index[%d], msp_num[%d], cfu_status[0x%x], ton[%d], "
				"npi[%d], cfu_num[%s], cc2_id[%d], ext7_id[%d]",
				req_cf.cf.rec_index, req_cf.cf.msp_num, req_cf.cf.cfu_status, req_cf.cf.ton,
				req_cf.cf.npi, req_cf.cf.cfu_num, req_cf.cf.cc2_id, req_cf.cf.ext7_id);
	}

	tcore_user_request_set_data(ur, sizeof(struct treq_sim_set_callforwarding), &req_cf);
	tcore_user_request_set_command(ur, TREQ_SIM_SET_CALLFORWARDING);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation, ur);

	return TRUE;
}

static gboolean on_sim_get_message_waiting(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_MESSAGE_WAITING, co_sim);
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(GET_MESSAGE_WAITING, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_command(ur, TREQ_SIM_GET_MESSAGEWAITING);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation, ur);

	return TRUE;
}

static gboolean on_sim_set_message_waiting(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gboolean  arg_cphs,
		gint arg_rec_index,
		guchar arg_indicator_status,
		gint arg_voice_cnt,
		gint arg_fax_cnt,
		gint arg_email_cnt,
		gint arg_other_cnt,
		gint arg_video_cnt,
		gboolean arg_cphs_voice1,
		gboolean arg_cphs_voice2,
		gboolean arg_cphs_fax,
		gboolean arg_cphs_data,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_messagewaiting req_mw;

	if (!check_access_control (invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(SET_MESSAGE_WAITING, co_sim);
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(SET_MESSAGE_WAITING, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);

	memset(&req_mw, 0, sizeof(struct treq_sim_set_messagewaiting));

	req_mw.b_cphs = arg_cphs;

	if (req_mw.b_cphs) {
		req_mw.cphs_mw.b_voice1 = arg_cphs_voice1;
		req_mw.cphs_mw.b_voice2 = arg_cphs_voice2;
		req_mw.cphs_mw.b_fax = arg_cphs_fax;
		req_mw.cphs_mw.b_data = arg_cphs_data;
		dbg("b_voice1[%d],b_voice2[%d],b_fax[%d], b_data[%d]",
				req_mw.cphs_mw.b_voice1,
				req_mw.cphs_mw.b_voice2,
				req_mw.cphs_mw.b_fax,
				req_mw.cphs_mw.b_data);
	} else {
		req_mw.mw.rec_index = arg_rec_index;
		req_mw.mw.indicator_status = arg_indicator_status;
		req_mw.mw.voice_count = arg_voice_cnt;
		req_mw.mw.fax_count = arg_fax_cnt;
		req_mw.mw.email_count = arg_email_cnt;
		req_mw.mw.other_count = arg_other_cnt;
		req_mw.mw.video_count = arg_video_cnt;
		dbg("rec_index[%d], indicator_status[0x%x],	voice_count[%d], fax_count[%d], email_count[%d], other_count[%d], video_count[%d]",
				req_mw.mw.rec_index,
				req_mw.mw.indicator_status,
				req_mw.mw.voice_count,
				req_mw.mw.fax_count,
				req_mw.mw.email_count,
				req_mw.mw.other_count,
				req_mw.mw.video_count);
	}

	tcore_user_request_set_data(ur, sizeof(struct treq_sim_set_messagewaiting), &req_mw);
	tcore_user_request_set_command(ur, TREQ_SIM_SET_MESSAGEWAITING);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation, ur);

	return TRUE;
}

static gboolean on_sim_get_mailbox(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_MAILBOX, co_sim);
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(GET_MAILBOX, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_command(ur, TREQ_SIM_GET_MAILBOX);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation, ur);

	return TRUE;
}

static gboolean on_sim_set_mailbox(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gboolean arg_cphs,
		gint arg_type,
		gint arg_rec_index,
		gint arg_profile_number,
		gint arg_alpha_id_max_len,
		const gchar *arg_alpha_id,
		gint arg_ton,
		gint arg_npi,
		const gchar *arg_number,
		gint arg_cc_id,
		gint arg_ext1_id,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_mailbox req_mb;

	if (!check_access_control (invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(SET_MAILBOX, co_sim);
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(SET_MAILBOX, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);

	memset(&req_mb, 0, sizeof(struct treq_sim_set_mailbox));

	req_mb.b_cphs = arg_cphs;

	req_mb.mb_info.mb_type = arg_type;
	req_mb.mb_info.rec_index = arg_rec_index;
	req_mb.mb_info.profile_number = arg_profile_number;
	req_mb.mb_info.number_info.alpha_id_max_len = arg_alpha_id_max_len;
	if (strlen(arg_alpha_id))
		memcpy(&req_mb.mb_info.number_info.alpha_id, arg_alpha_id, strlen(arg_alpha_id));
	req_mb.mb_info.number_info.ton = arg_npi;
	req_mb.mb_info.number_info.npi = arg_npi;
	if (strlen(arg_number))
		memcpy(&req_mb.mb_info.number_info.num, arg_number, strlen(arg_number));
	req_mb.mb_info.number_info.cc_id = arg_ext1_id;
	req_mb.mb_info.number_info.ext1_id = arg_ext1_id;

	dbg("b_cphs[%d] mb_type[%d], rec_index[%d], profile_number[%d], alpha_id_max_len[%d], "
			"alpha_id[%s], ton[%d], npi[%d], num[%s], cc_id[%d], ext1_id[%d]",
			req_mb.b_cphs,
			req_mb.mb_info.mb_type,
			req_mb.mb_info.rec_index,
			req_mb.mb_info.profile_number,
			req_mb.mb_info.number_info.alpha_id_max_len,
			req_mb.mb_info.number_info.alpha_id,
			req_mb.mb_info.number_info.ton,
			req_mb.mb_info.number_info.npi,
			req_mb.mb_info.number_info.num,
			req_mb.mb_info.number_info.cc_id,
			req_mb.mb_info.number_info.ext1_id)

	tcore_user_request_set_data(ur, sizeof(struct treq_sim_set_mailbox), &req_mb);
	tcore_user_request_set_command(ur, TREQ_SIM_SET_MAILBOX);

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation, ur);

	return TRUE;
}

static gboolean on_sim_get_cphsinfo(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_CPHS_INFO, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);

	tcore_user_request_set_command(ur, TREQ_SIM_GET_CPHS_INFO);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_get_service_table(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct tel_sim_service_table *svct = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_SVCT, co_sim);

	svct = tcore_sim_get_service_table(co_sim);
	if (!svct) {
		UserRequest *ur = NULL;
		TReturn ret;
		ur = MAKE_UR(ctx, sim, invocation);

		dbg("Not cached. Request to modem");
		tcore_user_request_set_command(ur, TREQ_SIM_GET_SERVICE_TABLE);
		ret = tcore_communicator_dispatch_request(ctx->comm, ur);
		if (ret != TCORE_RETURN_SUCCESS) {
			FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
			tcore_user_request_unref(ur);
		}
	} else {
		GVariantBuilder builder;
		GVariant * inner_gv = NULL;
		GVariant *svct_gv = NULL;
		int i =0;
		dbg("TRESP_SIM_GET_SERVICE_TABLE");

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		if (svct->sim_type == SIM_TYPE_GSM) {
			for (i = 0; i < SIM_SST_SERVICE_CNT_MAX; i++) {
				g_variant_builder_add (&builder, "y", svct->table.sst.service[i]);
			}
		} else if (svct->sim_type == SIM_TYPE_USIM) {
			for (i = 0; i < SIM_UST_SERVICE_CNT_MAX; i++) {
				g_variant_builder_add (&builder, "y", svct->table.ust.service[i]);
			}
		} else if(svct->sim_type == SIM_TYPE_RUIM) {
			if(SIM_CDMA_SVC_TABLE == svct->table.cst.cdma_svc_table) {
				for(i = 0; i < SIM_CDMA_ST_SERVICE_CNT_MAX; i++) {
					g_variant_builder_add (&builder, "iy", svct->table.cst.cdma_svc_table,
											svct->table.cst.service.cdma_service[i]);
				}
			} else if(SIM_CSIM_SVC_TABLE == svct->table.cst.cdma_svc_table) {
				for(i = 0; i < SIM_CSIM_ST_SERVICE_CNT_MAX; i++) {
					g_variant_builder_add (&builder, "iy", svct->table.cst.cdma_svc_table,
											svct->table.cst.service.csim_service[i]);
				}
			} else {
				err("Invalid cdma_svc_table:[%d]", svct->table.cst.cdma_svc_table);
			}
		} else {
			err("Unknown SIM type: [%d]", svct->sim_type);
		}
		inner_gv = g_variant_builder_end(&builder);
		svct_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_get_service_table (sim, invocation,
				SIM_ACCESS_SUCCESS,
				svct->sim_type,
				svct_gv);

		free(svct);
	}
	return TRUE;
}

static gboolean on_sim_get_msisdn(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct tel_sim_msisdn_list *msisdn_list = NULL;
	gboolean read_from_modem = FALSE;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_MSISDN, co_sim);
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(GET_MSISDN, co_sim);

	if(SIM_TYPE_NVSIM == tcore_sim_get_type(co_sim)) {
		dbg("In NV SIM, don't use MSISDN cached");
		read_from_modem = TRUE;
	} else {
		msisdn_list = tcore_sim_get_msisdn_list(co_sim);
		if (msisdn_list)
			read_from_modem = FALSE;
		else
			read_from_modem = TRUE;
	}

	if(read_from_modem) {
		UserRequest *ur = NULL;

		ur = MAKE_UR(ctx, sim, invocation);
		dbg("Not cached. Request to modem");
		tcore_user_request_set_command(ur, TREQ_SIM_GET_MSISDN);

		ret = tcore_communicator_dispatch_request(ctx->comm, ur);
		DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation, ur);
	} else {
		GVariant *gv = NULL;
		int i;
		GVariantBuilder b;
		dbg("TRESP_SIM_GET_MSISDN");
		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

		dbg("msisdn_list->count = %d", msisdn_list->count);
		for (i = 0;i < msisdn_list->count; i++) {
			g_variant_builder_open(&b,G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string((const gchar *)msisdn_list->msisdn[i].name));
			if (msisdn_list->msisdn[i].ton == SIM_TON_INTERNATIONAL) {
				unsigned char *tmp = (unsigned char *)calloc(SIM_MSISDN_NUMBER_LEN_MAX + 1, 1);
				if (tmp!=NULL) {
					tmp[0] = '+';
					strncpy((char *)tmp+1, (const char*)msisdn_list->msisdn[i].num, SIM_MSISDN_NUMBER_LEN_MAX - 1);
					tmp[SIM_MSISDN_NUMBER_LEN_MAX] = '\0';
					g_variant_builder_add(&b, "{sv}", "number", g_variant_new_string((const gchar *)tmp));
					free(tmp);
				} else {
					dbg("calloc failed.");
					g_variant_builder_add(&b, "{sv}", "number", g_variant_new_string((const gchar *)msisdn_list->msisdn[i].num));
				}
			} else {
				g_variant_builder_add(&b, "{sv}", "number", g_variant_new_string((const gchar *)msisdn_list->msisdn[i].num));
			}
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_msisdn (sim, invocation,	SIM_ACCESS_SUCCESS, gv);
		free(msisdn_list);
	}

	return TRUE;
}

static gboolean on_sim_get_oplmnwact(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_OPLMWACT, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);

	tcore_user_request_set_command(ur, TREQ_SIM_GET_OPLMNWACT);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_get_spn(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct tel_sim_spn* spn = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_SPN, co_sim);

	spn = tcore_sim_get_spn(co_sim);

	if (!spn) {
		ur = MAKE_UR(ctx, sim, invocation);

		tcore_user_request_set_command(ur, TREQ_SIM_GET_SPN);
		ret = tcore_communicator_dispatch_request(ctx->comm, ur);

		if (ret != TCORE_RETURN_SUCCESS) {
			FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
			tcore_user_request_unref(ur);
		}
	} else {
		telephony_sim_complete_get_spn (sim, invocation, SIM_ACCESS_SUCCESS,
								spn->display_condition, (const gchar *)spn->spn);
		free(spn);
	}
	return TRUE;
}

static gboolean on_sim_get_cphs_netname(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct tel_sim_cphs_netname *cphs_netname = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_CPHS_NET_NAME, co_sim);

	cphs_netname = tcore_sim_get_cphs_netname(co_sim);

	if (!cphs_netname) {
		ur = MAKE_UR(ctx, sim, invocation);

		tcore_user_request_set_command(ur, TREQ_SIM_GET_CPHS_NETNAME);
		ret = tcore_communicator_dispatch_request(ctx->comm, ur);
		if (ret != TCORE_RETURN_SUCCESS) {
			FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
			dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
			tcore_user_request_unref(ur);
		}
	} else {
		telephony_sim_complete_get_cphs_net_name (sim, invocation, SIM_ACCESS_SUCCESS,
											(const gchar *)cphs_netname->full_name,
											(const gchar *)cphs_netname->short_name);
		free(cphs_netname);
	}

	return TRUE;
}

static gboolean on_sim_get_gid(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_GID, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);

	tcore_user_request_set_command(ur, TREQ_SIM_GET_GID);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_authentication(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gint arg_type,
	    GVariant *arg_rand,
	    GVariant *arg_autn,
	    gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	GVariantIter *iter = NULL;
	GVariant *rand_gv = NULL;
	GVariant *autn_gv = NULL;
	guchar rt_i;
	int i =0;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_req_authentication req_auth;

	if (!check_access_control (invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(AUTHENTICATION, co_sim);

	memset(&req_auth, 0, sizeof(struct treq_sim_req_authentication));

	req_auth.auth_type = arg_type;

	rand_gv = g_variant_get_variant(arg_rand);
	g_variant_get(rand_gv, "ay", &iter);
	while ( g_variant_iter_loop (iter, "y", &rt_i)) {
		req_auth.rand_data[i] = rt_i;
		i++;
	}
	req_auth.rand_length = (unsigned int)i;

	i = 0;
	autn_gv = g_variant_get_variant(arg_autn);
	g_variant_get(autn_gv, "ay", &iter);
	while ( g_variant_iter_loop (iter, "y", &rt_i)) {
		req_auth.autn_data[i] = rt_i;
		i++;
	}
	req_auth.autn_length = (unsigned int)i;

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sim_req_authentication), &req_auth);
	tcore_user_request_set_command(ur, TREQ_SIM_REQ_AUTHENTICATION);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		GVariantBuilder builder;
		GVariant *ak = NULL;
		GVariant *cp = NULL;
		GVariant *it = NULL;
		GVariant *resp = NULL;
		GVariant *ak_gv = NULL;
		GVariant *cp_gv = NULL;
		GVariant *it_gv = NULL;
		GVariant *resp_gv = NULL;

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		ak = g_variant_builder_end(&builder);
		ak_gv = g_variant_new("v", ak);

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		cp = g_variant_builder_end(&builder);
		cp_gv = g_variant_new("v", cp);

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		it = g_variant_builder_end(&builder);
		it_gv = g_variant_new("v", it);

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		resp = g_variant_builder_end(&builder);
		resp_gv = g_variant_new("v", resp);

		telephony_sim_complete_authentication (sim, invocation, SIM_ACCESS_FAILED, 0, 0,	ak_gv,	cp_gv, it_gv, resp_gv);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_verify_sec(TelephonySim *sim, GDBusMethodInvocation *invocation,
	    gint arg_type,
	    const gchar *arg_password,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_verify_pins verify_pins;

	if (!check_access_control (invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(VERIFY_SEC, co_sim);

	memset(&verify_pins, 0, sizeof(struct treq_sim_verify_pins));

	verify_pins.pin_type = arg_type;
	verify_pins.pin_length = strlen(arg_password);
	memcpy(verify_pins.pin, arg_password, verify_pins.pin_length);

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sim_verify_pins), &verify_pins);
	tcore_user_request_set_command(ur, TREQ_SIM_VERIFY_PINS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_verify_puk(TelephonySim *sim, GDBusMethodInvocation *invocation,
	    gint arg_type,
	    const gchar *arg_puk,
	    const gchar *arg_new_pin,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_verify_puks verify_puks;

	if (!check_access_control (invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(VERIFY_PUK, co_sim);

	memset(&verify_puks, 0, sizeof(struct treq_sim_verify_puks));

	verify_puks.puk_type = arg_type;
	verify_puks.puk_length = strlen(arg_puk);
	memcpy(verify_puks.puk, arg_puk, verify_puks.puk_length);
	verify_puks.pin_length = strlen(arg_new_pin);
	memcpy(verify_puks.pin, arg_new_pin, verify_puks.pin_length);

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sim_verify_puks), &verify_puks);
	tcore_user_request_set_command(ur, TREQ_SIM_VERIFY_PUKS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_change_pin(TelephonySim *sim, GDBusMethodInvocation *invocation,
	    gint arg_type,
	    const gchar *arg_old_password,
	    const gchar *arg_new_password,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_change_pins change_pins;

	if (!check_access_control (invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(CHANGE_PIN, co_sim);

	memset(&change_pins, 0, sizeof(struct treq_sim_change_pins));

	change_pins.type = arg_type;
	change_pins.old_pin_length = strlen(arg_old_password);
	memcpy(change_pins.old_pin, arg_old_password, change_pins.old_pin_length);
	change_pins.new_pin_length = strlen(arg_new_password);
	memcpy(change_pins.new_pin, arg_new_password, change_pins.new_pin_length);

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sim_change_pins), &change_pins);
	tcore_user_request_set_command(ur, TREQ_SIM_CHANGE_PINS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_disable_facility(TelephonySim *sim, GDBusMethodInvocation *invocation,
	    gint arg_type,
	    const gchar *arg_password,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_sim_disable_facility dis_facility;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(DISABLE_FACILITY, co_sim);

	memset(&dis_facility, 0, sizeof(struct treq_sim_disable_facility));

	dbg("arg_type[%d]", arg_type);
	switch (arg_type) {
		case 1:
			dis_facility.type = SIM_FACILITY_PS;
			break;
		case 3:
			dis_facility.type = SIM_FACILITY_SC;
			break;
		case 4:
			dis_facility.type = SIM_FACILITY_FD;
			break;
		case 5:
			dis_facility.type = SIM_FACILITY_PN;
			break;
		case 6:
			dis_facility.type = SIM_FACILITY_PU;
			break;
		case 7:
			dis_facility.type = SIM_FACILITY_PP;
			break;
		case 8:
			dis_facility.type = SIM_FACILITY_PC;
			break;
		default:
			err("Unhandled/Unknown type[0x%x]", arg_type);
			break;
	}
	dis_facility.password_length = strlen(arg_password);
	memcpy(dis_facility.password, arg_password, dis_facility.password_length);

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sim_disable_facility), &dis_facility);
	tcore_user_request_set_command(ur, TREQ_SIM_DISABLE_FACILITY);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_enable_facility(TelephonySim *sim, GDBusMethodInvocation *invocation,
	    gint arg_type,
	    const gchar *arg_password,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_sim_enable_facility en_facility;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(ENABLE_FACILITY, co_sim);

	memset(&en_facility, 0, sizeof(struct treq_sim_enable_facility));

	dbg("arg_type[%d]", arg_type);
	switch (arg_type) {
		case 1:
			en_facility.type = SIM_FACILITY_PS;
			break;
		case 3:
			en_facility.type = SIM_FACILITY_SC;
			break;
		case 4:
			en_facility.type = SIM_FACILITY_FD;
			break;
		case 5:
			en_facility.type = SIM_FACILITY_PN;
			break;
		case 6:
			en_facility.type = SIM_FACILITY_PU;
			break;
		case 7:
			en_facility.type = SIM_FACILITY_PP;
			break;
		case 8:
			en_facility.type = SIM_FACILITY_PC;
			break;
		default:
			err("Unhandled/Unknown type[0x%x]", arg_type);
			break;
	}
	en_facility.password_length = strlen(arg_password);
	memcpy(en_facility.password, arg_password, en_facility.password_length);

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sim_enable_facility), &en_facility);
	tcore_user_request_set_command(ur, TREQ_SIM_ENABLE_FACILITY);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_get_facility(TelephonySim *sim, GDBusMethodInvocation *invocation,
	    gint arg_type,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	struct treq_sim_get_facility_status facility;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_FACILITY, co_sim);

	memset(&facility, 0, sizeof(struct treq_sim_get_facility_status));

	dbg("arg_type[%d]", arg_type);

	switch (arg_type) {
		case 1:
			facility.type = SIM_FACILITY_PS;
			break;
		case 3:
			facility.type = SIM_FACILITY_SC;
			break;
		case 4:
			facility.type = SIM_FACILITY_FD;
			break;
		case 5:
			facility.type = SIM_FACILITY_PN;
			break;
		case 6:
			facility.type = SIM_FACILITY_PU;
			break;
		case 7:
			facility.type = SIM_FACILITY_PP;
			break;
		case 8:
			facility.type = SIM_FACILITY_PC;
			break;
		default:
			err("Unhandled/Unknown type[0x%x]", arg_type);
			break;
	}

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sim_get_facility_status), &facility);
	tcore_user_request_set_command(ur, TREQ_SIM_GET_FACILITY_STATUS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_get_lock_info(TelephonySim *sim, GDBusMethodInvocation *invocation,
	    gint arg_type,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_get_lock_info lock_info;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_LOCK_INFO, co_sim);

	memset(&lock_info, 0, sizeof(struct treq_sim_get_lock_info));

	dbg("arg_type[%d]", arg_type);
	switch (arg_type) {
		case 1:
			lock_info.type = SIM_FACILITY_PS;
			break;
		case 3:
			lock_info.type = SIM_FACILITY_SC;
			break;
		case 4:
			lock_info.type = SIM_FACILITY_FD;
			break;
		case 5:
			lock_info.type = SIM_FACILITY_PN;
			break;
		case 6:
			lock_info.type = SIM_FACILITY_PU;
			break;
		case 7:
			lock_info.type = SIM_FACILITY_PP;
			break;
		case 8:
			lock_info.type = SIM_FACILITY_PC;
			break;
		default:
			err("Unhandled/Unknown type[0x%x]", arg_type);
			break;
	}

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sim_get_lock_info), &lock_info);
	tcore_user_request_set_command(ur, TREQ_SIM_GET_LOCK_INFO);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_transfer_apdu(TelephonySim *sim, GDBusMethodInvocation *invocation,
		GVariant *arg_apdu,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	struct treq_sim_transmit_apdu send_apdu;
	GVariantIter *iter = NULL;
	GVariant *inner_gv = NULL;
	guchar rt_i;
	TReturn ret;
	CoreObject *co_sim = NULL;
	int i =0;

	if (!check_access_control (invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(TRANSFER_APDU, co_sim);

	memset(&send_apdu, 0, sizeof(struct treq_sim_transmit_apdu));

	inner_gv = g_variant_get_variant(arg_apdu);

	g_variant_get(inner_gv, "ay", &iter);
	while ( g_variant_iter_loop (iter, "y", &rt_i)) {
		send_apdu.apdu[i] = rt_i;
		i++;
	}
	send_apdu.apdu_length = (unsigned int)i;
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);
	g_variant_unref(arg_apdu);

	tcore_util_hex_dump("[APDU_REQ] ", send_apdu.apdu_length, send_apdu.apdu);

	ur = MAKE_UR(ctx, sim, invocation);
	tcore_user_request_set_data(ur, sizeof(struct treq_sim_transmit_apdu), &send_apdu);
	tcore_user_request_set_command(ur, TREQ_SIM_TRANSMIT_APDU);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_get_atr(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(GET_ATR, co_sim);

	ur = MAKE_UR(ctx, sim, invocation);

	tcore_user_request_set_command(ur, TREQ_SIM_GET_ATR);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_sim_get_fields(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct tel_sim_imsi *n_imsi = NULL;
	//struct tel_sim_msisdn_list *msisdn_list = NULL;
	//struct tel_sim_iccid *iccid = NULL;
	//struct tel_sim_spn *spn= NULL;
	CoreObject *co_sim = NULL;
	GVariantBuilder b;
	GVariant *gv_fields = NULL;

	dbg("Func Entrance");

	if (!check_access_control (invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);

	g_variant_builder_init(&b, G_VARIANT_TYPE("a{svv}}"));

	DBUS_SIM_CHECK_SIM_STATUS(GET_IMSI, co_sim);

	n_imsi = tcore_sim_get_imsi(co_sim);
	if (n_imsi != NULL) {
		g_variant_builder_add(&b, "{svv}", "imsi", g_variant_new_string("plmn"), g_variant_new_string(n_imsi->plmn));
		g_variant_builder_add(&b, "{svv}", "imsi", g_variant_new_string("msin"), g_variant_new_string(n_imsi->msin));
		free(n_imsi);
	}

	DBUS_SIM_CHECK_SIM_STATUS(GET_ICCID, co_sim);
	//n_imsi = tcore_sim_get_imsi(co_sim);
	//if (n_imsi != NULL) {
		g_variant_builder_add(&b, "{svv}", "iccid", g_variant_new_string(""), g_variant_new_string(""));
		//free(n_imsi);
	//}

	DBUS_SIM_CHECK_SIM_STATUS(GET_MSISDN, co_sim);
	g_variant_builder_add(&b, "{svv}", "msisdn", g_variant_new_string("name"), g_variant_new_string("number"));

	DBUS_SIM_CHECK_SIM_STATUS(GET_SPN, co_sim);
	g_variant_builder_add(&b, "{svv}", "spn", g_variant_new_uint16(255), g_variant_new_string("network name"));

	DBUS_SIM_CHECK_SIM_STATUS(GET_INIT_STATUS, co_sim);
	g_variant_builder_add(&b, "{svv}", "init_status", g_variant_new_uint16(0), g_variant_new_boolean(TRUE));

	gv_fields = g_variant_builder_end(&b);

	telephony_sim_complete_get_fields(sim, invocation, 0, gv_fields);

	return TRUE;
}

static gboolean on_sim_set_power_state(TelephonySim *sim, GDBusMethodInvocation *invocation,
		gint arg_state, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_powerstate set_powerstate;

	if (!check_access_control (invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(SET_POWERSTATE, co_sim);

	memset(&set_powerstate, 0, sizeof(struct treq_sim_set_powerstate));
	set_powerstate.state = arg_state;

	dbg("set_powerstate.state[%d]", set_powerstate.state);
	ur = MAKE_UR(ctx, sim, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_sim_set_powerstate), &set_powerstate);
	tcore_user_request_set_command(ur, TREQ_SIM_SET_POWERSTATE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
	 	dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_sim_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonySim *sim;

	sim = telephony_sim_skeleton_new();
	telephony_object_skeleton_set_sim(object, sim);
	g_object_unref(sim);

	dbg("sim: [%p]", sim);

	telephony_sim_set_cf_state(sim, FALSE);

	g_signal_connect (sim,
			"handle-get-init-status",
			G_CALLBACK (on_sim_get_init_status),
			ctx);

	g_signal_connect (sim,
			"handle-get-card-type",
			G_CALLBACK (on_sim_get_card_type),
			ctx);

	g_signal_connect (sim,
			"handle-get-imsi",
			G_CALLBACK (on_sim_get_imsi),
			ctx);

	g_signal_connect (sim,
			"handle-get-ecc",
			G_CALLBACK (on_sim_get_ecc),
			ctx);

	g_signal_connect (sim,
			"handle-get-iccid",
			G_CALLBACK (on_sim_get_iccid),
			ctx);

	g_signal_connect (sim,
			"handle-get-language",
			G_CALLBACK (on_sim_get_language),
			ctx);

	g_signal_connect (sim,
			"handle-set-language",
			G_CALLBACK (on_sim_set_language),
			ctx);

	g_signal_connect (sim,
			"handle-get-call-forwarding",
			G_CALLBACK (on_sim_get_call_forwarding),
			ctx);

	g_signal_connect (sim,
			"handle-set-call-forwarding",
			G_CALLBACK (on_sim_set_call_forwarding),
			ctx);

	g_signal_connect (sim,
			"handle-get-message-waiting",
			G_CALLBACK (on_sim_get_message_waiting),
			ctx);

	g_signal_connect (sim,
			"handle-set-message-waiting",
			G_CALLBACK (on_sim_set_message_waiting),
			ctx);

	g_signal_connect (sim,
			"handle-get-mailbox",
			G_CALLBACK (on_sim_get_mailbox),
			ctx);

	g_signal_connect (sim,
			"handle-set-mailbox",
			G_CALLBACK (on_sim_set_mailbox),
			ctx);

	g_signal_connect (sim,
			"handle-get-cphsinfo",
			G_CALLBACK (on_sim_get_cphsinfo),
			ctx);

	g_signal_connect (sim,
			"handle-get-service-table",
			G_CALLBACK (on_sim_get_service_table),
			ctx);

	g_signal_connect (sim,
			"handle-get-msisdn",
			G_CALLBACK (on_sim_get_msisdn),
			ctx);

	g_signal_connect (sim,
			"handle-get-oplmnwact",
			G_CALLBACK (on_sim_get_oplmnwact),
			ctx);

	g_signal_connect (sim,
			"handle-get-spn",
			G_CALLBACK (on_sim_get_spn),
			ctx);

	g_signal_connect (sim,
			"handle-get-cphs-net-name",
			G_CALLBACK (on_sim_get_cphs_netname),
			ctx);

	g_signal_connect (sim,
			"handle-get-gid",
			G_CALLBACK (on_sim_get_gid),
			ctx);

	g_signal_connect (sim,
			"handle-authentication",
			G_CALLBACK (on_sim_authentication),
			ctx);

	g_signal_connect (sim,
			"handle-verify-sec",
			G_CALLBACK (on_sim_verify_sec),
			ctx);

	g_signal_connect (sim,
			"handle-verify-puk",
			G_CALLBACK (on_sim_verify_puk),
			ctx);

	g_signal_connect (sim,
			"handle-change-pin",
			G_CALLBACK (on_sim_change_pin),
			ctx);

	g_signal_connect (sim,
			"handle-disable-facility",
			G_CALLBACK (on_sim_disable_facility),
			ctx);

	g_signal_connect (sim,
			"handle-enable-facility",
			G_CALLBACK (on_sim_enable_facility),
			ctx);

	g_signal_connect (sim,
			"handle-get-facility",
			G_CALLBACK (on_sim_get_facility),
			ctx);

	g_signal_connect (sim,
			"handle-get-lock-info",
			G_CALLBACK (on_sim_get_lock_info),
			ctx);

	g_signal_connect (sim,
			"handle-transfer-apdu",
			G_CALLBACK (on_sim_transfer_apdu),
			ctx);

	g_signal_connect (sim,
			"handle-get-atr",
			G_CALLBACK (on_sim_get_atr),
			ctx);

	g_signal_connect (sim,
			"handle-get-fields",
			G_CALLBACK (on_sim_get_fields),
			ctx);

	g_signal_connect (sim,
			"handle-set-powerstate",
			G_CALLBACK (on_sim_set_power_state),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_sim_response(struct custom_data *ctx, UserRequest *ur,
	struct dbus_request_info *dbus_info, enum tcore_response_command command,
	unsigned int data_len, const void *data)
{
	dbg("Response!!! Command: [0x%x] CP Name: [%s]",
		command, GET_CP_NAME(dbus_info->invocation));

	switch (command) {
	case TRESP_SIM_GET_ECC: {
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i = 0;

		dbg("TRESP_SIM_GET_ECC - Result: [%s])",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS) {
			tcore_sim_set_ecc_list(co_sim, &resp_read->data.ecc);
		} else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND) {
			tcore_sim_set_ecc_list(co_sim, NULL);
		}

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_read->data.ecc.ecc_count; i++) {
			dbg("ecc[%d] : ecc_category=[0x%x], ecc_num=[%s], ecc_string=[%s]", i,
				resp_read->data.ecc.ecc[i].ecc_category,
				resp_read->data.ecc.ecc[i].ecc_num,
				resp_read->data.ecc.ecc[i].ecc_string);

			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "category", g_variant_new_int32(resp_read->data.ecc.ecc[i].ecc_category));
			g_variant_builder_add(&b, "{sv}", "number", g_variant_new_string(resp_read->data.ecc.ecc[i].ecc_num));
			g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string(resp_read->data.ecc.ecc[i].ecc_string));
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_ecc (dbus_info->interface_object, dbus_info->invocation, gv);
	}
	break;

	case TRESP_SIM_GET_ICCID: {
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;

		dbg("TRESP_SIM_GET_ICCID - Result: [%s] ICCID: [%s])",
			 (resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			 resp_read->data.iccid.iccid);

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS) {
			tcore_sim_set_iccid(co_sim, &resp_read->data.iccid);
		} else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND) {
			tcore_sim_set_iccid(co_sim, NULL);
		}

		telephony_sim_complete_get_iccid(dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				resp_read->data.iccid.iccid);
	}
	break;

	case TRESP_SIM_GET_LANGUAGE: {
		const struct tresp_sim_read *resp_read = data;

		dbg("TRESP_SIM_GET_LANGUAGE - Result: [%s] Language: [0x%2x]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			resp_read->data.language.language[0]);

		telephony_sim_complete_get_language(dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				resp_read->data.language.language[0]);
	}
	break;

	case TRESP_SIM_SET_LANGUAGE: {
		const struct tresp_sim_set_data *resp_set_data = data;

		dbg("TRESP_SIM_SET_LANGUAGE - Result: [%s]",
			(resp_set_data->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_language(dbus_info->interface_object, dbus_info->invocation,
				resp_set_data->result);
	}
	break;

	case TRESP_SIM_GET_CALLFORWARDING: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv_cf = NULL;
		GVariant *gv_cphs_cf = NULL;
		GVariantBuilder b;

		dbg("TRESP_SIM_GET_CALLFORWARDING - Result: [%s] CPHS: [%s]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			(resp_read->data.cf.b_cphs ? "Yes" : "No"));

		if (resp_read->data.cf.b_cphs) {
			dbg("b_line1[%d], b_line2[%d], b_fax[%d], b_data[%d]",
				resp_read->data.cf.cphs_cf.b_line1, resp_read->data.cf.cphs_cf.b_line2,
				resp_read->data.cf.cphs_cf.b_fax, resp_read->data.cf.cphs_cf.b_data);

			g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "b_line1", g_variant_new_boolean(resp_read->data.cf.cphs_cf.b_line1));
			g_variant_builder_add(&b, "{sv}", "b_line2", g_variant_new_boolean(resp_read->data.cf.cphs_cf.b_line2));
			g_variant_builder_add(&b, "{sv}", "b_fax", g_variant_new_boolean(resp_read->data.cf.cphs_cf.b_fax));
			g_variant_builder_add(&b, "{sv}", "b_data", g_variant_new_boolean(resp_read->data.cf.cphs_cf.b_data));
			gv_cphs_cf = g_variant_builder_end(&b);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
			gv_cf = g_variant_builder_end(&b);

		} else {
			int i =0;

			dbg("profile_count[%d]",resp_read->data.cf.cf_list.profile_count);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
			for (i = 0; i < resp_read->data.cf.cf_list.profile_count; i++) {
				dbg("[%d] : rec_index[0x%x], msp_num[0x%x], cfu_status[0x%x], "
					"cfu_num[%s], ton[0x%x], npi[0x%x], cc2_id[0x%x], ext7_id[0x%x]",
					i, resp_read->data.cf.cf_list.cf[i].rec_index, resp_read->data.cf.cf_list.cf[i].msp_num,
					resp_read->data.cf.cf_list.cf[i].cfu_status, resp_read->data.cf.cf_list.cf[i].cfu_num,
					resp_read->data.cf.cf_list.cf[i].ton, resp_read->data.cf.cf_list.cf[i].npi,
					resp_read->data.cf.cf_list.cf[i].cc2_id, resp_read->data.cf.cf_list.cf[i].ext7_id);

				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "rec_index", g_variant_new_int32(resp_read->data.cf.cf_list.cf[i].rec_index));
				g_variant_builder_add(&b, "{sv}", "msp_num", g_variant_new_byte(resp_read->data.cf.cf_list.cf[i].msp_num));
				g_variant_builder_add(&b, "{sv}", "cfu_status", g_variant_new_byte(resp_read->data.cf.cf_list.cf[i].cfu_status));
				g_variant_builder_add(&b, "{sv}", "cfu_num", g_variant_new_string(resp_read->data.cf.cf_list.cf[i].cfu_num));
				g_variant_builder_add(&b, "{sv}", "ton", g_variant_new_int32(resp_read->data.cf.cf_list.cf[i].ton));
				g_variant_builder_add(&b, "{sv}", "npi", g_variant_new_int32(resp_read->data.cf.cf_list.cf[i].npi));
				g_variant_builder_add(&b, "{sv}", "cc2_id", g_variant_new_byte(resp_read->data.cf.cf_list.cf[i].cc2_id));
				g_variant_builder_add(&b, "{sv}", "ext7_id", g_variant_new_byte(resp_read->data.cf.cf_list.cf[i].ext7_id));
				g_variant_builder_close(&b);
			}
			gv_cf = g_variant_builder_end(&b);

			g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
			gv_cphs_cf = g_variant_builder_end(&b);
		}

		telephony_sim_complete_get_call_forwarding (dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				resp_read->data.cf.b_cphs,
				gv_cf,
				gv_cphs_cf);
	}
	break;

	case TRESP_SIM_SET_CALLFORWARDING: {
		const struct tresp_sim_set_data *resp_set_data = data;

		dbg("TRESP_SIM_SET_CALLFORWARDING - Result: [%s]",
			(resp_set_data->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_call_forwarding(dbus_info->interface_object, dbus_info->invocation,
				resp_set_data->result);
	}
	break;

	case TRESP_SIM_GET_MESSAGEWAITING: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv_mw = NULL;
		GVariant *gv_cphs_mw = NULL;
		GVariantBuilder b;

		dbg("TRESP_SIM_GET_MESSAGEWAITING - Result: [%s] CPHS: [%s]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			(resp_read->data.mw.b_cphs ? "Yes" : "No"));

		if (resp_read->data.mw.b_cphs) {
			dbg("b_voice1[%d], b_voice2[%d], b_fax[%d], b_data[%d]",
				resp_read->data.mw.cphs_mw.b_voice1, resp_read->data.mw.cphs_mw.b_voice2,
				resp_read->data.mw.cphs_mw.b_fax, resp_read->data.mw.cphs_mw.b_data);

			g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "b_voice1",	g_variant_new_boolean(resp_read->data.mw.cphs_mw.b_voice1));
			g_variant_builder_add(&b, "{sv}", "b_voice2",	g_variant_new_boolean(resp_read->data.mw.cphs_mw.b_voice2));
			g_variant_builder_add(&b, "{sv}", "b_fax",	g_variant_new_boolean(resp_read->data.mw.cphs_mw.b_fax));
			g_variant_builder_add(&b, "{sv}", "b_data",	g_variant_new_boolean(resp_read->data.mw.cphs_mw.b_data));
			gv_cphs_mw = g_variant_builder_end(&b);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
			gv_mw = g_variant_builder_end(&b);

		} else {
			int i =0;

			dbg("profile_count[%d]", resp_read->data.mw.mw_list.profile_count);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
			for (i = 0; i <resp_read->data.mw.mw_list.profile_count; i++) {
				dbg("[%d] : rec_index[0x%x], indicator_status[0x%x], voice_count[0x%x], "
					"fax_count[0x%x] email_count[0x%x], other_count[0x%x], video_count[0x%x]",
					i, resp_read->data.mw.mw_list.mw[i].rec_index, resp_read->data.mw.mw_list.mw[i].indicator_status,
					resp_read->data.mw.mw_list.mw[i].voice_count, resp_read->data.mw.mw_list.mw[i].fax_count,
					resp_read->data.mw.mw_list.mw[i].email_count, resp_read->data.mw.mw_list.mw[i].other_count,
					resp_read->data.mw.mw_list.mw[i].video_count);

				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b,"{sv}",	"rec_index", g_variant_new_int32(	resp_read->data.mw.mw_list.mw[i].rec_index));
				g_variant_builder_add(&b, "{sv}", "indicator_status", g_variant_new_byte(resp_read->data.mw.mw_list.mw[i].indicator_status));
				g_variant_builder_add(&b,"{sv}",	"voice_count", g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].voice_count));
				g_variant_builder_add(&b,"{sv}",	"fax_count", g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].fax_count));
				g_variant_builder_add(&b, "{sv}", "email_count", g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].email_count));
				g_variant_builder_add(&b, "{sv}", "other_count", g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].other_count));
				g_variant_builder_add(&b, "{sv}", "video_count", g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].video_count));
				g_variant_builder_close(&b);
			}
			gv_mw = g_variant_builder_end(&b);
			g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
			gv_cphs_mw = g_variant_builder_end(&b);
		}

		telephony_sim_complete_get_message_waiting(dbus_info->interface_object,	dbus_info->invocation,
									resp_read->result,
									resp_read->data.mw.b_cphs,
									gv_mw,
									gv_cphs_mw);
	}
	break;

	case TRESP_SIM_SET_MESSAGEWAITING: {
		const struct tresp_sim_set_data *resp_set_data = data;

		dbg("TRESP_SIM_SET_MESSAGEWAITING - Result: [%s]",
			(resp_set_data->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_message_waiting(dbus_info->interface_object, dbus_info->invocation,
				resp_set_data->result);
	}
	break;

	case TRESP_SIM_GET_MAILBOX: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i =0;

		dbg("TRESP_SIM_GET_MAILBOX - Result: [%s] CPHS: [%s] Count: [%d])",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			(resp_read->data.mb.b_cphs ? "Yes" : "No"),
			resp_read->data.mb.count);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i =0; i < resp_read->data.mb.count; i++) {
				dbg("resp_read->data.mb.mb[%d] : "
						"rec_index[%d], profile_number[%d], mb_type[%d], alpha_id_max_len[%d]"
						"alpha_id[%s], ton[%d], npi[%d], num[%s], cc_id[%d], ext1_id[%d]",
						i, resp_read->data.mb.mb[i].rec_index, resp_read->data.mb.mb[i].profile_number,
						resp_read->data.mb.mb[i].mb_type, resp_read->data.mb.mb[i].number_info.alpha_id_max_len,
						resp_read->data.mb.mb[i].number_info.alpha_id, resp_read->data.mb.mb[i].number_info.ton,
						resp_read->data.mb.mb[i].number_info.npi, resp_read->data.mb.mb[i].number_info.num,
						resp_read->data.mb.mb[i].number_info.cc_id, resp_read->data.mb.mb[i].number_info.ext1_id);

				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "rec_index", g_variant_new_int32(resp_read->data.mb.mb[i].rec_index));
				g_variant_builder_add(&b, "{sv}", "profile_num", g_variant_new_int32(resp_read->data.mb.mb[i].profile_number));
				g_variant_builder_add(&b, "{sv}", "mb_type", g_variant_new_int32(resp_read->data.mb.mb[i].mb_type));
				g_variant_builder_add(&b, "{sv}", "alpha_id_max_len", g_variant_new_int32(resp_read->data.mb.mb[i].number_info.alpha_id_max_len));
				g_variant_builder_add(&b, "{sv}", "alpha_id", g_variant_new_string(resp_read->data.mb.mb[i].number_info.alpha_id));
				g_variant_builder_add(&b, "{sv}", "ton", g_variant_new_int32(resp_read->data.mb.mb[i].number_info.ton));
				g_variant_builder_add(&b, "{sv}", "npi", g_variant_new_int32(resp_read->data.mb.mb[i].number_info.npi));
				g_variant_builder_add(&b, "{sv}", "num", g_variant_new_string(resp_read->data.mb.mb[i].number_info.num));
				g_variant_builder_add(&b, "{sv}", "cc_id", g_variant_new_byte(resp_read->data.mb.mb[i].number_info.cc_id));
				g_variant_builder_add(&b, "{sv}", "ext1_id", g_variant_new_byte(resp_read->data.mb.mb[i].number_info.ext1_id));
				g_variant_builder_close(&b);
		}

		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_mailbox (dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				resp_read->data.mb.b_cphs,
				gv);
	}
	break;

	case TRESP_SIM_SET_MAILBOX: {
		const struct tresp_sim_set_data *resp_set_data = data;

		dbg("TRESP_SIM_SET_MAILBOX - Result: [%s]",
			(resp_set_data->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_mailbox(dbus_info->interface_object, dbus_info->invocation,
				resp_set_data->result);
	}
	break;

	case TRESP_SIM_GET_CPHS_INFO: {
		const struct tresp_sim_read *resp_read = data;

		dbg("TRESP_SIM_GET_CPHS_INFO - Result: [%s]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_get_cphsinfo (dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				resp_read->data.cphs.CphsPhase,
				resp_read->data.cphs.CphsServiceTable.bOperatorNameShortForm,
				resp_read->data.cphs.CphsServiceTable.bMailBoxNumbers,
				resp_read->data.cphs.CphsServiceTable.bServiceStringTable,
				resp_read->data.cphs.CphsServiceTable.bCustomerServiceProfile,
				resp_read->data.cphs.CphsServiceTable.bInformationNumbers);
	}
	break;

	case TRESP_SIM_GET_SERVICE_TABLE: {
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;
		GVariantBuilder builder;
		GVariant * inner_gv = NULL;
		GVariant *svct_gv = NULL;
		int i =0;

		dbg("TRESP_SIM_GET_SERVICE_TABLE - Result: [%s]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS) {
			tcore_sim_set_service_table(co_sim, &resp_read->data.svct);
		} else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND) {
			tcore_sim_set_service_table(co_sim, NULL);
		}

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));

		if (resp_read->data.svct.sim_type == SIM_TYPE_GSM) {
			for (i = 0; i < SIM_SST_SERVICE_CNT_MAX; i++) {
				g_variant_builder_add (&builder, "y", resp_read->data.svct.table.sst.service[i]);
			}
		} else if (resp_read->data.svct.sim_type == SIM_TYPE_USIM) {
			for (i = 0; i < SIM_UST_SERVICE_CNT_MAX; i++) {
				g_variant_builder_add (&builder, "y", resp_read->data.svct.table.ust.service[i]);
			}
		} else if(resp_read->data.svct.sim_type == SIM_TYPE_RUIM) {
			if(SIM_CDMA_SVC_TABLE == resp_read->data.svct.table.cst.cdma_svc_table) {
				for(i = 0; i < SIM_CDMA_ST_SERVICE_CNT_MAX; i++) {
					g_variant_builder_add (&builder, "iy", resp_read->data.svct.table.cst.cdma_svc_table,
											resp_read->data.svct.table.cst.service.cdma_service[i]);
				}
			} else if(SIM_CSIM_SVC_TABLE == resp_read->data.svct.table.cst.cdma_svc_table) {
				for(i = 0; i < SIM_CSIM_ST_SERVICE_CNT_MAX; i++) {
					g_variant_builder_add (&builder, "iy", resp_read->data.svct.table.cst.cdma_svc_table,
											resp_read->data.svct.table.cst.service.csim_service[i]);
				}
			} else {
				err("Invalid cdma_svc_table:[%d]", resp_read->data.svct.table.cst.cdma_svc_table);
			}
		} else {
			dbg("unknown sim type.");
		}
		inner_gv = g_variant_builder_end(&builder);
		svct_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_get_service_table (dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				resp_read->data.svct.sim_type,
				svct_gv);
	}	break;

	case TRESP_SIM_GET_SPN: {
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;

		dbg("TRESP_SIM_GET_SPN - Result: [%s] Display condition: [%d] SPN: [%s]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			resp_read->data.spn.display_condition, (const gchar *)resp_read->data.spn.spn);

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS) {
			tcore_sim_set_spn(co_sim, &resp_read->data.spn);
		} else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND) {
			tcore_sim_set_spn(co_sim, NULL);
		}

		telephony_sim_complete_get_spn (dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				resp_read->data.spn.display_condition, (const gchar *)resp_read->data.spn.spn);
	}
	break;

	case TRESP_SIM_GET_CPHS_NETNAME: {
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;

		dbg("TRESP_SIM_GET_CPHS_NETNAME - Result: [%s]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS) {
			tcore_sim_set_cphs_netname(co_sim, &resp_read->data.cphs_net);
		} else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND) {
			tcore_sim_set_cphs_netname(co_sim, NULL);
		}

		telephony_sim_complete_get_cphs_net_name (dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				(const gchar *)resp_read->data.cphs_net.full_name, (const gchar *)resp_read->data.cphs_net.short_name);
	}
	break;

	case TRESP_SIM_GET_GID: {
		const struct tresp_sim_read *resp_read = data;
		GVariantBuilder *builder = NULL;
		GVariant * inner_gv = NULL;
		GVariant *gid_gv = NULL;
		int i =0;

		dbg("TRESP_SIM_GET_GID - Result: [%s]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));

		for(i = 0; i < resp_read->data.gid.GroupIdentifierLen; i++) {
			g_variant_builder_add (builder, "y", resp_read->data.gid.szGroupIdentifier[i]);
		}
		inner_gv = g_variant_builder_end(builder);
		gid_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_get_gid (dbus_info->interface_object, dbus_info->invocation,
						resp_read->result,
						resp_read->data.gid.GroupIdentifierLen,
						gid_gv);
	}
	break;

	case TRESP_SIM_GET_MSISDN:{
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i =0;

		dbg("TRESP_SIM_GET_MSISDN - Result: [%s]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		if (resp_read->result == SIM_ACCESS_SUCCESS) {
			tcore_sim_set_msisdn_list(co_sim, &resp_read->data.msisdn_list);
		} else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND) {
			tcore_sim_set_msisdn_list(co_sim, NULL);
		}

		for (i = 0; i < resp_read->data.msisdn_list.count; i++) {
			g_variant_builder_open(&b,G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "name", g_variant_new_string((const gchar *)resp_read->data.msisdn_list.msisdn[i].name));
			if (resp_read->data.msisdn_list.msisdn[i].ton == SIM_TON_INTERNATIONAL) {
				unsigned char *tmp = (unsigned char *)calloc(SIM_MSISDN_NUMBER_LEN_MAX + 1, 1);
				if (tmp!=NULL) {
					tmp[0] = '+';
					strncpy((char *)tmp+1, (const char*)resp_read->data.msisdn_list.msisdn[i].num, SIM_MSISDN_NUMBER_LEN_MAX - 1);
					tmp[SIM_MSISDN_NUMBER_LEN_MAX] = '\0';
					g_variant_builder_add(&b, "{sv}", "number", g_variant_new_string((const gchar *)tmp));
					free(tmp);
				} else {
					dbg("calloc failed.");
					g_variant_builder_add(&b, "{sv}", "number", g_variant_new_string((const gchar *)resp_read->data.msisdn_list.msisdn[i].num));
				}
			} else {
				g_variant_builder_add(&b, "{sv}", "number", g_variant_new_string((const gchar *)resp_read->data.msisdn_list.msisdn[i].num));
			}
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_msisdn (dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				gv);
	}
	break;

	case TRESP_SIM_GET_OPLMNWACT: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i =0;

		dbg("TRESP_SIM_GET_OPLMNWACT - Result: [%s]",
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0;i < resp_read->data.opwa.opwa_count; i++) {
			g_variant_builder_open(&b,G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "plmn", g_variant_new_string((const gchar *)resp_read->data.opwa.opwa[i].plmn));
			g_variant_builder_add(&b, "{sv}", "b_umts", g_variant_new_boolean(resp_read->data.opwa.opwa[i].b_umts));
			g_variant_builder_add(&b, "{sv}", "b_gsm", g_variant_new_boolean(resp_read->data.opwa.opwa[i].b_gsm));
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_oplmnwact (dbus_info->interface_object, dbus_info->invocation,
				resp_read->result,
				gv);
	}
	break;

	case TRESP_SIM_REQ_AUTHENTICATION: {
		const struct tresp_sim_req_authentication *resp_auth = data;
		GVariantBuilder builder;
		GVariant *ak = NULL;
		GVariant *cp = NULL;
		GVariant *it = NULL;
		GVariant *resp = NULL;
		GVariant *ak_gv = NULL;
		GVariant *cp_gv = NULL;
		GVariant *it_gv = NULL;
		GVariant *resp_gv = NULL;
		int i =0;

		dbg("TRESP_SIM_REQ_AUTHENTICATION - Result: [%s]",
			(resp_auth->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		tcore_util_hex_dump("[AUTH_KEY] ", resp_auth->authentication_key_length, resp_auth->authentication_key);
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		for (i = 0; i < (int)resp_auth->authentication_key_length; i++) {
			g_variant_builder_add (&builder, "y", resp_auth->authentication_key[i]);
		}
		ak = g_variant_builder_end(&builder);
		ak_gv = g_variant_new("v", ak);

		tcore_util_hex_dump("[CIPHER_DATA] ", resp_auth->cipher_length, resp_auth->cipher_data);
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		for (i = 0; i < (int)resp_auth->cipher_length; i++) {
			g_variant_builder_add (&builder, "y", resp_auth->cipher_data[i]);
		}
		cp = g_variant_builder_end(&builder);
		cp_gv = g_variant_new("v", cp);

		tcore_util_hex_dump("[INTEGRITY_DATA] ", resp_auth->integrity_length, resp_auth->integrity_data);
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		for (i = 0; i < (int)resp_auth->integrity_length; i++) {
			g_variant_builder_add (&builder, "y", resp_auth->integrity_data[i]);
		}
		it = g_variant_builder_end(&builder);
		it_gv = g_variant_new("v", it);

		tcore_util_hex_dump("[RESP_DATA] ", resp_auth->resp_length, resp_auth->resp_data);
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		for (i = 0; i < (int)resp_auth->resp_length; i++) {
			g_variant_builder_add (&builder, "y", resp_auth->resp_data[i]);
		}
		resp = g_variant_builder_end(&builder);
		resp_gv = g_variant_new("v", resp);

		telephony_sim_complete_authentication (dbus_info->interface_object, dbus_info->invocation,
				resp_auth->result,
				resp_auth->auth_type,
				resp_auth->auth_result,
				ak_gv,
				cp_gv,
				it_gv,
				resp_gv);
	}
	break;

	case TRESP_SIM_VERIFY_PINS: {
		const struct tresp_sim_verify_pins *resp_verify_pins = data;

		dbg("TRESP_SIM_VERIFY_PINS - Result: [%s] PIN Type: [%d] Re-try count: [%d]",
			(resp_verify_pins->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_verify_pins->pin_type, resp_verify_pins->retry_count);

		telephony_sim_complete_verify_sec(dbus_info->interface_object, dbus_info->invocation,
				resp_verify_pins->result,
				resp_verify_pins->pin_type,
				resp_verify_pins->retry_count);
	}
	break;

	case TRESP_SIM_VERIFY_PUKS: {
		const struct tresp_sim_verify_puks *resp_verify_puks = data;

		dbg("TRESP_SIM_VERIFY_PUKS - Result: [%s] PIN Type: [%d] Re-try count: [%d]",
			(resp_verify_puks->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_verify_puks->pin_type, resp_verify_puks->retry_count);

		telephony_sim_complete_verify_puk (dbus_info->interface_object, dbus_info->invocation,
				resp_verify_puks->result,
				resp_verify_puks->pin_type,
				resp_verify_puks->retry_count);
	}
	break;

	case TRESP_SIM_CHANGE_PINS: {
		const struct tresp_sim_change_pins *resp_change_pins = data;

		dbg("TRESP_SIM_CHANGE_PINS - Result: [%s] PIN Type: [%d] Re-try count: [%d]",
			(resp_change_pins->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_change_pins->pin_type, resp_change_pins->retry_count);

		telephony_sim_complete_change_pin(dbus_info->interface_object, dbus_info->invocation,
				resp_change_pins->result,
				resp_change_pins->pin_type,
				resp_change_pins->retry_count);
	}
	break;

	case TRESP_SIM_DISABLE_FACILITY: {
		const struct tresp_sim_disable_facility *resp_dis_facility = data;
		gint f_type =0;

		dbg("TRESP_SIM_DISABLE_FACILITY - Result: [%s] Type: [%d] Re-try count: [%d]",
			(resp_dis_facility->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_dis_facility->type, resp_dis_facility->retry_count);

		switch (resp_dis_facility->type) {
		case SIM_FACILITY_PS:
			f_type = 1;
		break;
		case SIM_FACILITY_SC:
			f_type = 3;
		break;
		case SIM_FACILITY_FD:
			f_type = 4;
		break;
		case SIM_FACILITY_PN:
			f_type = 5;
		break;
		case SIM_FACILITY_PU:
			f_type = 6;
		break;
		case SIM_FACILITY_PP:
			f_type = 7;
		break;
		case SIM_FACILITY_PC:
			f_type = 8;
		break;
		default:
			err("Unhandled/Unknown type[0x%x]", resp_dis_facility->type);
		break;
		}

		telephony_sim_complete_disable_facility(dbus_info->interface_object, dbus_info->invocation,
				resp_dis_facility->result,
				f_type,
				resp_dis_facility->retry_count);
	}
	break;

	case TRESP_SIM_ENABLE_FACILITY: {
		const struct tresp_sim_enable_facility *resp_en_facility = data;
		gint f_type =0;

		dbg("TRESP_SIM_ENABLE_FACILITY - Result: [%s] Type: [%d] Re-try count: [%d]",
			(resp_en_facility->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_en_facility->type, resp_en_facility->retry_count);

		switch (resp_en_facility->type) {
		case SIM_FACILITY_PS:
			f_type = 1;
		break;
		case SIM_FACILITY_SC:
			f_type = 3;
		break;
		case SIM_FACILITY_FD:
			f_type = 4;
		break;
		case SIM_FACILITY_PN:
			f_type = 5;
		break;
		case SIM_FACILITY_PU:
			f_type = 6;
		break;
		case SIM_FACILITY_PP:
			f_type = 7;
		break;
		case SIM_FACILITY_PC:
			f_type = 8;
		break;
		default:
			err("Unhandled/Unknown type[0x%x]", resp_en_facility->type);
		break;
		}

		telephony_sim_complete_enable_facility(dbus_info->interface_object, dbus_info->invocation,
				resp_en_facility->result,
				f_type,
				resp_en_facility->retry_count);
	}
	break;

	case TRESP_SIM_GET_FACILITY_STATUS: {
		const struct tresp_sim_get_facility_status *resp_get_facility = data;
		gint f_type =0;

		dbg("TRESP_SIM_GET_FACILITY_STATUS - Result: [%s] Type: [%d] Enable: [%s]",
			(resp_get_facility->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_get_facility->type,
			(resp_get_facility->b_enable ? "Yes" : "No"));

		switch (resp_get_facility->type) {
		case SIM_FACILITY_PS:
			f_type = 1;
		break;
		case SIM_FACILITY_SC:
			f_type = 3;
		break;
		case SIM_FACILITY_FD:
			f_type = 4;
		break;
		case SIM_FACILITY_PN:
			f_type = 5;
		break;
		case SIM_FACILITY_PU:
			f_type = 6;
		break;
		case SIM_FACILITY_PP:
			f_type = 7;
		break;
		case SIM_FACILITY_PC:
			f_type = 8;
		break;
		default:
			err("Unhandled/Unknown type[0x%x]", resp_get_facility->type);
		break;
		}

		telephony_sim_complete_get_facility(dbus_info->interface_object, dbus_info->invocation,
				resp_get_facility->result,
				f_type,
				resp_get_facility->b_enable);
	}
	break;

	case TRESP_SIM_GET_LOCK_INFO: {
		const struct tresp_sim_get_lock_info *resp_lock = data;
		gint f_type =0;

		dbg("TRESP_SIM_GET_LOCK_INFO - Result: [%s] Type: [%d] Re-try count: [%d]",
			(resp_lock->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_lock->type, resp_lock->retry_count);

		switch (resp_lock->type) {
		case SIM_FACILITY_PS:
			f_type = 1;
		break;
		case SIM_FACILITY_SC:
			f_type = 3;
		break;
		case SIM_FACILITY_FD:
			f_type = 4;
		break;
		case SIM_FACILITY_PN:
			f_type = 5;
		break;
		case SIM_FACILITY_PU:
			f_type = 6;
		break;
		case SIM_FACILITY_PP:
			f_type = 7;
		break;
		case SIM_FACILITY_PC:
			f_type = 8;
		break;
		default:
			err("Unhandled/Unknown type[0x%x]", resp_lock->type);
		break;
		}

		telephony_sim_complete_get_lock_info(dbus_info->interface_object, dbus_info->invocation,
				resp_lock->result,
				f_type,
				resp_lock->lock_status,
				resp_lock->retry_count);
	}
	break;

	case TRESP_SIM_TRANSMIT_APDU: {
		const struct tresp_sim_transmit_apdu *resp_apdu = data;
		GVariantBuilder builder;
		GVariant * apdu_gv = NULL;
		GVariant *inner_gv = NULL;
		int i =0;

		dbg("TRESP_SIM_TRANSMIT_APDU - Result: [%s]",
			(resp_apdu->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));
		tcore_util_hex_dump("[APDU_RESP] ",
			resp_apdu->apdu_resp_length, resp_apdu->apdu_resp);

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		for (i = 0; i < (int)resp_apdu->apdu_resp_length; i++) {
			g_variant_builder_add (&builder, "y", resp_apdu->apdu_resp[i]);
		}
		inner_gv = g_variant_builder_end(&builder);
		apdu_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_transfer_apdu(dbus_info->interface_object, dbus_info->invocation,
				resp_apdu->result,
				apdu_gv);
	}
	break;

	case TRESP_SIM_GET_ATR:{
		const struct tresp_sim_get_atr *resp_get_atr = data;
		GVariantBuilder builder;
		GVariant * atr_gv = NULL;
		GVariant *inner_gv = NULL;
		int i =0;

		dbg("TRESP_SIM_GET_ATR - Result: [%s]",
			(resp_get_atr->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));
		tcore_util_hex_dump("[ATR_RESP] ",
			resp_get_atr->atr_length, resp_get_atr->atr);

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		for (i = 0; i < (int)resp_get_atr->atr_length; i++) {
			g_variant_builder_add (&builder, "y", resp_get_atr->atr[i]);
		}
		inner_gv = g_variant_builder_end(&builder);
		atr_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_get_atr(dbus_info->interface_object, dbus_info->invocation,
				resp_get_atr->result,
				atr_gv);
	}
	break;

	case TRESP_SIM_SET_POWERSTATE: {
		const struct tresp_sim_set_powerstate *resp_power = data;

		dbg("TRESP_SIM_SET_POWERSTATE - Result: [%s]",
			(resp_power->result == SIM_POWER_SET_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_powerstate(dbus_info->interface_object, dbus_info->invocation,
				resp_power->result);
	}
	break;

	default:
		err("Unhandled/Unknown Response!!!");
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_sim_notification(struct custom_data *ctx, CoreObject *source,
	TelephonyObjectSkeleton *object, enum tcore_notification_command command,
	unsigned int data_len, const void *data)
{
	TelephonySim *sim;
	const char *cp_name;

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	sim = telephony_object_peek_sim(TELEPHONY_OBJECT(object));
	dbg("sim: [%p]", sim);

	switch (command) {
	case TNOTI_SIM_STATUS: {
		const struct tnoti_sim_status *n_sim_status = data;

		info("[DBUSINFO][%s] SIM_STATUS : [%d]", cp_name, n_sim_status->sim_status);

#ifdef ENABLE_KPI_LOGS
		if (n_sim_status->sim_status == SIM_STATUS_INIT_COMPLETED)
			TIME_CHECK("[%s] SIM Initialized", cp_name);
#endif

		telephony_sim_emit_status(sim, n_sim_status->sim_status);
	}
	break;

	case TNOTI_SIM_REFRESHED: {
		const struct tnoti_sim_refreshed *n_sim_refreshed = data;
		info("[DBUSINFO][%s] SIM_REFRESHED : b_full_file_changed: [%s] changed_file_count: [%d]",
			cp_name, (n_sim_refreshed->b_full_file_changed ? "Yes" : "No"),	n_sim_refreshed->file_list.file_count);

		telephony_sim_emit_refreshed(sim, n_sim_refreshed->cmd_type);
	}
	break;

	case TNOTI_SIM_CALL_FORWARD_STATE: {
		const struct tnoti_sim_call_forward_state *info = data;
		info("[DBUSINFO][%s] SIM_CALL_FORWARD_STATE : [%s]",
			cp_name, info->b_forward ? "ON" : "OFF");

		telephony_sim_set_cf_state(sim, info->b_forward);
	}
	break;

	default:
		err("Unhandled/Unknown Notification!!!");
	break;
	}

	return TRUE;
}

