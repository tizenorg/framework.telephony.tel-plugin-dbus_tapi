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
#include <user_request.h>
#include <co_sim.h>

#include "generated-code.h"
#include "dtapi_common.h"

/*
 * Error message to application (DBUS)
 */
#define DBUS_SIM_STATUS_ERROR				"SIM STATUS ERROR"
#define DBUS_SIM_NOT_FOUND				"SIM NOT FOUND"
#define DBUS_SIM_PERM_BLOCKED				"SIM PERM BLOCKED"
#define DBUS_SIM_CARD_ERROR				"SIM CARD ERROR"
#define DBUS_SIM_NOT_INITIALIZED			"SIM NOT INITIALIZED"
#define DBUS_SIM_INIT_COMPLETED			"SIM INIT COMPLETED"
#define DBUS_SIM_LOCKED				"SIM LOCKED"
#define DBUS_SIM_NOT_READY				"SIM NOT READY"
#define DBUS_SIM_RESPONSE_DATA_ERROR		"SIM RESPONSE DATA ERROR"
#define DBUS_SIM_SERVICE_IS_DISABLED			"SIM SERVICE IS DISABLED"
#define DBUS_SIM_SERVICE_NOT_SUPPORTED_FOR_NVSIM	"SERVICE NOT SUPPORTED FOR NVSIM"

#define DBUS_SIM_GET_COSIM(invocation, co_sim, server) do { \
	co_sim = __get_sim_co_by_cp_name(server, GET_CP_NAME(invocation)); \
	if (!co_sim) { \
		err("[%s] SIM Core object is NULL", GET_CP_NAME(invocation)); \
		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED); \
		return TRUE; \
	} \
} while (0)

#define DBUS_SIM_CHECK_SIM_STATUS(invocation, op_type, co_sim) do { \
	if (__check_sim_state(op_type, tcore_sim_get_status(co_sim)) == FALSE) { \
		err("[%s] Invalid SIM status", GET_CP_NAME(invocation)); \
		__return_fail_response(invocation, tcore_sim_get_status(co_sim)); \
		return TRUE; \
	} \
} while (0)

#define DBUS_SIM_CHECK_SIM_TYPE(co_sim, request) do { \
	if (tcore_sim_get_type(co_sim) == SIM_TYPE_NVSIM) { \
		err("[%s] is not supported for NVSIM", request); \
		FAIL_RESPONSE(invocation, DBUS_SIM_SERVICE_NOT_SUPPORTED_FOR_NVSIM); \
		return TRUE; \
	} \
} while (0)

#define DBUS_SIM_CHECK_SIM_SERVICE_TABLE(invocation, op_type, co_sim) do { \
	gboolean b_cphs = FALSE; \
	b_cphs = tcore_sim_get_cphs_status(co_sim); \
	if (b_cphs && op_type != GET_MSISDN) { \
		dbg("[%s] CPHS SIM... Do not check SST", GET_CP_NAME(invocation)); \
	} else { \
		struct tel_sim_service_table* svct = tcore_sim_get_service_table(co_sim); \
		if (svct != NULL) { \
			if (__check_sim_service_table(op_type, svct) == FALSE) { \
				err("[%s] 'Service' is disabled in SST", GET_CP_NAME(invocation)); \
				FAIL_RESPONSE(invocation, DBUS_SIM_SERVICE_IS_DISABLED); \
				free(svct); \
				return TRUE; \
			} else { \
				dbg("[%s] Request to modem", GET_CP_NAME(invocation)); \
				free(svct); \
			} \
		} \
	} \
} while (0)

#define DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation) do { \
	if (ret != TCORE_RETURN_SUCCESS) { \
		if (ret == TCORE_RETURN_SIM_DISABLED_IN_SST) { \
			err("[%s] 'Service' is disabled in SST", GET_CP_NAME(invocation)); \
			FAIL_RESPONSE(invocation, DBUS_SIM_SERVICE_IS_DISABLED); \
		} else { \
			err("[%s] Dispatch request failed: [0x%x]", GET_CP_NAME(invocation), ret); \
			FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED); \
		} \
	} \
} while (0)

enum dbus_tapi_sim_gdbus_method_name {
	/* EF Get */
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

	/* Misc */
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
	GET_FIELDS = 30, /* for get various data at once */
	GET_GID,
	SET_POWERSTATE,
	GET_IMPI,
	GET_IMPU,
	GET_DOMAIN = 35,
	GET_PCSCF,
	GET_APP_LIST,
	GET_ISIM_SERVICE_TABLE,

	/* Notification */
	STATUS = 100,
	REFRESHED,
};

static gboolean __is_sim_status_valid(enum tel_sim_status sim_status)
{
	switch (sim_status) {
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

static CoreObject *__get_sim_co_by_cp_name(Server *server, char *cp_name)
{
	TcorePlugin *plugin;

	if (!server) {
		err("server is NULL");
		return NULL;
	}

	plugin = tcore_server_find_plugin(server, cp_name);
	return tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SIM);
}

static CoreObject* __get_sim_co_from_ur(Server *server, UserRequest *ur)
{
	CoreObject *co_sim;
	char *modem_name;

	modem_name = tcore_user_request_get_modem_name(ur);
	if (!modem_name) {
		err("Modem name is NULL");
		return NULL;
	}

	co_sim = __get_sim_co_by_cp_name(server, modem_name);
	free(modem_name);

	return co_sim;
}

static gboolean __check_sim_state(enum dbus_tapi_sim_gdbus_method_name method,
	enum tel_sim_status sim_status)
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
	/* Regarding Lock facilities */
	case CHANGE_PIN:
	case ENABLE_FACILITY:
	case DISABLE_FACILITY:
	case GET_FACILITY:
	case GET_LOCK_INFO:
	case VERIFY_SEC:
	case VERIFY_PUK:
		switch (sim_status) {
		case SIM_STATUS_CARD_ERROR: /* FALLTHROUGH */
		case SIM_STATUS_CARD_BLOCKED: /* FALLTHROUGH */
		case SIM_STATUS_CARD_NOT_PRESENT: /* FALLTHROUGH */
		case SIM_STATUS_CARD_REMOVED: /* FALLTHROUGH */
		case SIM_STATUS_UNKNOWN: /* FALLTHROUGH */
		case SIM_STATUS_CARD_POWEROFF:
			ret = FALSE;
		break;

		default:
		break;
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
	case GET_IMPI:
	case GET_IMPU:
	case GET_GID:
	case GET_DOMAIN:
	case GET_PCSCF:
	case GET_APP_LIST:
	case GET_ISIM_SERVICE_TABLE:
		if (sim_status != SIM_STATUS_INIT_COMPLETED)
			ret = FALSE;
	break;

	case SET_POWERSTATE:
		switch (sim_status) {
		case SIM_STATUS_INIT_COMPLETED: /* FALLTHROUGH */
		case SIM_STATUS_INITIALIZING: /* FALLTHROUGH */
		case SIM_STATUS_PIN_REQUIRED: /* FALLTHROUGH */
		case SIM_STATUS_CARD_BLOCKED: /* FALLTHROUGH */
		case SIM_STATUS_CARD_POWEROFF:
		break;

		default:
			ret = FALSE;
		break;
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

static gboolean __check_sim_service_table(enum dbus_tapi_sim_gdbus_method_name method,
	struct tel_sim_service_table *svct)
{
	enum tel_sim_type sim_type = svct->sim_type;

	gboolean ret = TRUE;

	switch (method) {
	case GET_MSISDN:
		if (!(sim_type == SIM_TYPE_GSM && svct->table.sst.service[SIM_SST_MSISDN])
				&& !(sim_type == SIM_TYPE_USIM && svct->table.ust.service[SIM_UST_MSISDN]))
			ret = FALSE;
	break;

	case GET_CALL_FORWARDING:
	case SET_CALL_FORWARDING:
		if (!(sim_type == SIM_TYPE_GSM && svct->table.sst.service[SIM_SST_CFIS])
				&& !(sim_type == SIM_TYPE_USIM && svct->table.ust.service[SIM_UST_CFIS]))
			ret = FALSE;
	break;

	case GET_MESSAGE_WAITING:
	case SET_MESSAGE_WAITING:
		if (!(sim_type == SIM_TYPE_GSM && svct->table.sst.service[SIM_SST_MWIS])
				&& !(sim_type == SIM_TYPE_USIM && svct->table.ust.service[SIM_UST_MWIS]))
			ret = FALSE;
	break;

	case GET_MAILBOX:
	case SET_MAILBOX:
		if (!(sim_type == SIM_TYPE_GSM && svct->table.sst.service[SIM_SST_MBDN]) &&
				!(sim_type == SIM_TYPE_USIM && svct->table.ust.service[SIM_UST_MBDN]))
			ret = FALSE;
	break;

	default:
		err("Unhandled/Unknown operation: [%d]", method);
	break;
	}

	return ret;
}

static void __return_fail_response(GDBusMethodInvocation *invocation,
	enum tel_sim_status sim_status)
{
	dbg("[%s] SIM Status: [%d]", GET_CP_NAME(invocation), sim_status);

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

static gboolean on_sim_get_init_status(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	enum tel_sim_status sim_status = SIM_STATUS_UNKNOWN;
	gboolean sim_changed = FALSE;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);

	sim_status = tcore_sim_get_status(co_sim);
	sim_changed = tcore_sim_get_identification(co_sim);
	dbg("[%s] SIM - Status: [%d] Changed: [%s]",
		GET_CP_NAME(invocation),
		sim_status, (sim_changed ? "YES" : "NO"));

	telephony_sim_complete_get_init_status(sim,
		invocation, sim_status, sim_changed);

	return TRUE;
}

static gboolean on_sim_get_card_type(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	enum tel_sim_type sim_type = SIM_TYPE_UNKNOWN;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_CARD_TYPE, co_sim);

	sim_type = tcore_sim_get_type(co_sim);
	dbg("[%s] SIM Card type: [%s]",  GET_CP_NAME(invocation),
		(sim_type == SIM_TYPE_GSM ? "GSM" :
		(sim_type == SIM_TYPE_USIM ? "USIM" :
		(sim_type == SIM_TYPE_RUIM ? "RUIM" :
		(sim_type == SIM_TYPE_NVSIM ? "NVSIM" :
		(sim_type == SIM_TYPE_ISIM ? "ISIM" :
		"UNKNOWN"))))));

	telephony_sim_complete_get_card_type(sim,
		invocation, sim_type);

	return TRUE;
}

static gboolean on_sim_get_imsi(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct tel_sim_imsi *imsi;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_IMSI, co_sim);

	imsi = tcore_sim_get_imsi(co_sim);
	if (!imsi) {
		FAIL_RESPONSE(invocation, DBUS_SIM_RESPONSE_DATA_ERROR);
	} else {
		dbg("[%s] IMSI - PLMN: [%s] MSIN: [%s]", GET_CP_NAME(invocation),
			imsi->plmn, imsi->msin);

		telephony_sim_complete_get_imsi(sim,
			invocation, imsi->plmn, imsi->msin);

		g_free(imsi);
	}

	return TRUE;
}

static gboolean on_sim_get_ecc(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct tel_sim_ecc_list *ecc_list = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_ECC, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get ECC");

	ecc_list = tcore_sim_get_ecc_list(co_sim);
	if (!ecc_list) {
		struct custom_data *ctx = user_data;

		dbg("[%s] ECC list is NULL - Request to Modem.", GET_CP_NAME(invocation));

		/* Dispatch request */
		dtapi_dispatch_request(ctx, sim, invocation,
			TREQ_SIM_GET_ECC,
			NULL, 0);
	} else {
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i;

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < ecc_list->ecc_count; i++) {
			dbg("[%s] ECC[%d] - Category: [0x%x] Number: [%s] String: [%s]",
				GET_CP_NAME(invocation), i,
				ecc_list->ecc[i].ecc_category,
				ecc_list->ecc[i].ecc_num,
				ecc_list->ecc[i].ecc_string);
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "category",
				g_variant_new_int32(ecc_list->ecc[i].ecc_category));
			g_variant_builder_add(&b, "{sv}", "number",
				g_variant_new_string(ecc_list->ecc[i].ecc_num));
			g_variant_builder_add(&b, "{sv}", "name",
				g_variant_new_string(ecc_list->ecc[i].ecc_string));
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);
		if (!gv)
			err("ecc gv is NULL");

		telephony_sim_complete_get_ecc(sim,
			invocation, gv);

		g_free(ecc_list);
	}

	return TRUE;
}

static gboolean on_sim_get_iccid(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct tel_sim_iccid* iccid = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_ICCID, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get ICCID");

	iccid = tcore_sim_get_iccid(co_sim);
	if (!iccid) {
		/* Dispatch request */
		dtapi_dispatch_request(ctx, sim, invocation,
			TREQ_SIM_GET_ICCID,
			NULL, 0);
	} else {
		dbg("[%s] ICCID: [%s]", GET_CP_NAME(invocation),
			iccid->iccid);

		telephony_sim_complete_get_iccid(sim,
			invocation, SIM_ACCESS_SUCCESS, iccid->iccid);

		g_free(iccid);
	}

	return TRUE;
}

static gboolean on_sim_get_language(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_LANGUAGE, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get Language");

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_LANGUAGE,
		NULL, 0);

	return TRUE;
}

static gboolean on_sim_set_language(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gint language, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_language req;

	if (!check_access_control(invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, SET_LANGUAGE, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Set Language");

	memset(&req, 0x0, sizeof(struct treq_sim_set_language));

	req.language = language;

	dbg("[%s] Language: [0x%02x]", GET_CP_NAME(invocation),
		req.language);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_SET_LANGUAGE,
		&req, sizeof(struct treq_sim_set_language));

	return TRUE;
}

static gboolean on_sim_get_call_forwarding(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	TReturn ret;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_CALL_FORWARDING, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get Call Forwarding");
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(invocation, GET_CALL_FORWARDING, co_sim);

	/* Dispatch request */
	ret = dtapi_dispatch_request_ex(ctx, sim, invocation,
		TREQ_SIM_GET_CALLFORWARDING,
		NULL, 0);
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation);

	return TRUE;
}

static gboolean on_sim_set_call_forwarding(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	gboolean  cphs,
	gint rec_index,
	gint msp_num,
	guchar cfu_status,
	gint ton, gint npi, const gchar *number,
	gint cc2_id, gint ext7_id,
	gboolean cphs_line1, gboolean cphs_line2,
	gboolean cphs_fax, gboolean cphs_data, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_callforwarding req;
	TReturn ret;

	if (!check_access_control(invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, SET_CALL_FORWARDING, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Set Call Forwarding");
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(invocation, SET_CALL_FORWARDING, co_sim);

	memset(&req, 0x0, sizeof(struct treq_sim_set_callforwarding));

	req.b_cphs = cphs;
	if (req.b_cphs) {
		req.cphs_cf.b_line1 = cphs_line1;
		req.cphs_cf.b_line2 = cphs_line2;
		req.cphs_cf.b_fax = cphs_fax;
		req.cphs_cf.b_data = cphs_data;

		dbg("[%s] b_line1: [%d] b_line2: [%d] b_fax: [%d] b_data: [%d]",
			GET_CP_NAME(invocation),
			req.cphs_cf.b_line1, req.cphs_cf.b_line2,
			req.cphs_cf.b_fax, req.cphs_cf.b_data);
	} else {
		req.cf.rec_index = rec_index;
		req.cf.msp_num = msp_num;
		req.cf.cfu_status = cfu_status;
		req.cf.ton = ton;
		req.cf.npi = npi;
		memcpy(&req.cf.cfu_num, number, strlen(number));
		req.cf.cc2_id = cc2_id;
		req.cf.ext7_id = ext7_id;

		dbg("[%s] rec_index: [%d] msp_num: [%d] cfu_status: [0x%x] " \
			"ton: [%d] npi: [%d] cfu_num: [%s] cc2_id: [%d] ext7_id: [%d]",
			GET_CP_NAME(invocation), req.cf.rec_index,
			req.cf.msp_num, req.cf.cfu_status, req.cf.ton,
			req.cf.npi, req.cf.cfu_num, req.cf.cc2_id, req.cf.ext7_id);
	}

	/* Dispatch request */
	ret = dtapi_dispatch_request_ex(ctx, sim, invocation,
		TREQ_SIM_SET_CALLFORWARDING,
		&req, sizeof(struct treq_sim_set_callforwarding));
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation);

	return TRUE;
}

static gboolean on_sim_get_message_waiting(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	TReturn ret;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_MESSAGE_WAITING, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get Message Waiting");
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(invocation, GET_MESSAGE_WAITING, co_sim);

	/* Dispatch request */
	ret = dtapi_dispatch_request_ex(ctx, sim, invocation,
		TREQ_SIM_GET_MESSAGEWAITING,
		NULL, 0);
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation);

	return TRUE;
}

static gboolean on_sim_set_message_waiting(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	gboolean  cphs,
	gint rec_index,
	guchar indicator_status,
	gint voice_cnt, gint fax_cnt,
	gint email_cnt, gint other_cnt,
	gint video_cnt,
	gboolean cphs_voice1, gboolean cphs_voice2,
	gboolean cphs_fax, gboolean cphs_data, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_messagewaiting req;

	if (!check_access_control(invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, SET_MESSAGE_WAITING, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Set Message Waiting");
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(invocation, SET_MESSAGE_WAITING, co_sim);

	memset(&req, 0x0, sizeof(struct treq_sim_set_messagewaiting));

	req.b_cphs = cphs;

	if (req.b_cphs) {
		req.cphs_mw.b_voice1 = cphs_voice1;
		req.cphs_mw.b_voice2 = cphs_voice2;
		req.cphs_mw.b_fax = cphs_fax;
		req.cphs_mw.b_data = cphs_data;

		dbg("[%s] b_voice1: [%d] b_voice2: [%d] b_fax: [%d] b_data:[%d]",
			GET_CP_NAME(invocation),
			req.cphs_mw.b_voice1, req.cphs_mw.b_voice2,
			req.cphs_mw.b_fax, req.cphs_mw.b_data);
	} else {
		req.mw.rec_index = rec_index;
		req.mw.indicator_status = indicator_status;
		req.mw.voice_count = voice_cnt;
		req.mw.fax_count = fax_cnt;
		req.mw.email_count = email_cnt;
		req.mw.other_count = other_cnt;
		req.mw.video_count = video_cnt;

		dbg("[%s] rec_index: [%d] indicator_status: [0x%x] voice_count: [%d] " \
			"fax_count: [%d] email_count: [%d] other_count: [%d] video_count: [%d]",
			GET_CP_NAME(invocation),
			req.mw.rec_index, req.mw.indicator_status,
			req.mw.voice_count, req.mw.fax_count,
			req.mw.email_count, req.mw.other_count,
			req.mw.video_count);
	}

	/* Dispatch request */
	ret = dtapi_dispatch_request_ex(ctx, sim, invocation,
		TREQ_SIM_SET_MESSAGEWAITING,
		&req, sizeof(struct treq_sim_set_messagewaiting));
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation);

	return TRUE;
}

static gboolean on_sim_get_mailbox(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	TReturn ret;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_MAILBOX, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get Mailbox");
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(invocation, GET_MAILBOX, co_sim);

	/* Dispatch request */
	ret = dtapi_dispatch_request_ex(ctx, sim, invocation,
		TREQ_SIM_GET_MAILBOX,
		NULL, 0);
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation);

	return TRUE;
}

static gboolean on_sim_set_mailbox(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	gboolean cphs,
	gint mb_type, gint rec_index,
	gint profile_number,
	gint alpha_id_max_len, const gchar *alpha_id,
	gint ton, gint npi, const gchar *number,
	gint cc_id, gint ext1_id, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_mailbox req;

	if (!check_access_control(invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, SET_MAILBOX, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Set Mailbox");
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(invocation, SET_MAILBOX, co_sim);

	memset(&req, 0x0, sizeof(struct treq_sim_set_mailbox));

	req.b_cphs = cphs;

	req.mb_info.mb_type = mb_type;
	req.mb_info.rec_index = rec_index;
	req.mb_info.profile_number = profile_number;
	req.mb_info.number_info.alpha_id_max_len = alpha_id_max_len;
	if (strlen(alpha_id))
		memcpy(&req.mb_info.number_info.alpha_id, alpha_id, strlen(alpha_id));
	req.mb_info.number_info.ton = ton;
	req.mb_info.number_info.npi = npi;
	if (strlen(number))
		memcpy(&req.mb_info.number_info.num, number, strlen(number));
	req.mb_info.number_info.cc_id = cc_id;
	req.mb_info.number_info.ext1_id = ext1_id;

	dbg("[%s] b_cphs: [%d] mb_type: [%d] rec_index: [%d] " \
		"profile_number: [%d] alpha_id_max_len: [%d] alpha_id: [%s] " \
		"ton: [%d] npi: [%d] num: [%s] cc_id: [%d] ext1_id: [%d]",
		GET_CP_NAME(invocation),
		req.b_cphs,
		req.mb_info.mb_type, req.mb_info.rec_index,
		req.mb_info.profile_number,
		req.mb_info.number_info.alpha_id_max_len,
		req.mb_info.number_info.alpha_id,
		req.mb_info.number_info.ton, req.mb_info.number_info.npi,
		req.mb_info.number_info.num,
		req.mb_info.number_info.cc_id, req.mb_info.number_info.ext1_id);

	/* Dispatch request */
	ret = dtapi_dispatch_request_ex(ctx, sim, invocation,
		TREQ_SIM_SET_MAILBOX,
		&req, sizeof(struct treq_sim_set_mailbox));
	DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation);

	return TRUE;
}

static gboolean on_sim_get_cphsinfo(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_CPHS_INFO, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get CPHS Info");

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_CPHS_INFO,
		NULL, 0);

	return TRUE;
}

static gboolean on_sim_get_service_table(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct tel_sim_service_table *svct = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_SVCT, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get SVCT");

	svct = tcore_sim_get_service_table(co_sim);
	if (!svct) {
		struct custom_data *ctx = user_data;

		dbg("[%s] NOT cached - Request to modem",
			GET_CP_NAME(invocation));

		/* Dispatch request */
		dtapi_dispatch_request(ctx, sim, invocation,
			TREQ_SIM_GET_SERVICE_TABLE,
			NULL, 0);
	} else {
		GVariantBuilder builder;
		GVariant * inner_gv = NULL;
		GVariant *svct_gv = NULL;
		int i = 0;

		dbg("[%s] GET_SERVICE_TABLE", GET_CP_NAME(invocation));

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		if (svct->sim_type == SIM_TYPE_GSM) {
			for (i = 0; i < SIM_SST_SERVICE_CNT_MAX; i++)
				g_variant_builder_add(&builder, "y",
					svct->table.sst.service[i]);
		} else if (svct->sim_type == SIM_TYPE_USIM) {
			for (i = 0; i < SIM_UST_SERVICE_CNT_MAX; i++)
				g_variant_builder_add(&builder, "y",
					svct->table.ust.service[i]);
		} else if (svct->sim_type == SIM_TYPE_RUIM) {
			if (SIM_CDMA_SVC_TABLE == svct->table.cst.cdma_svc_table) {
				for (i = 0; i < SIM_CDMA_ST_SERVICE_CNT_MAX; i++)
					g_variant_builder_add(&builder, "iy",
						svct->table.cst.cdma_svc_table,
						svct->table.cst.service.cdma_service[i]);
			} else if (SIM_CSIM_SVC_TABLE == svct->table.cst.cdma_svc_table) {
				for (i = 0; i < SIM_CSIM_ST_SERVICE_CNT_MAX; i++)
					g_variant_builder_add(&builder, "iy",
						svct->table.cst.cdma_svc_table,
						svct->table.cst.service.csim_service[i]);
			} else {
				err("Invalid cdma_svc_table: [%d]", svct->table.cst.cdma_svc_table);
			}
		} else {
			err("[%s] Unknown SIM type: [%d]", GET_CP_NAME(invocation), svct->sim_type);
		}
		inner_gv = g_variant_builder_end(&builder);
		svct_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_get_service_table(sim,
			invocation, SIM_ACCESS_SUCCESS, svct->sim_type, svct_gv);

		free(svct);
	}

	return TRUE;
}

static gboolean on_sim_get_msisdn(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct tel_sim_msisdn_list *msisdn_list = NULL;
	gboolean read_from_modem = FALSE;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_MSISDN, co_sim);
	DBUS_SIM_CHECK_SIM_SERVICE_TABLE(invocation, GET_MSISDN, co_sim);

	if (SIM_TYPE_NVSIM == tcore_sim_get_type(co_sim)) {
		dbg("NV SIM, don't use cached MSISDN");
		read_from_modem = TRUE;
	} else {
		msisdn_list = tcore_sim_get_msisdn_list(co_sim);
		if (msisdn_list)
			read_from_modem = FALSE;
		else
			read_from_modem = TRUE;
	}

	if (read_from_modem) {
		TReturn ret;

		dbg("[%s] NOT cached - Request to modem", GET_CP_NAME(invocation));

		/* Dispatch request */
		ret = dtapi_dispatch_request_ex(ctx, sim, invocation,
			TREQ_SIM_GET_MSISDN,
			NULL, 0);
		DBUS_SIM_CHECK_DISPATCH_RET(ret, invocation);
	} else {
		GVariant *gv = NULL;
		int i;
		GVariantBuilder b;

		dbg("[%s] MSISDN count: [%d]",
			GET_CP_NAME(invocation), msisdn_list->count);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < msisdn_list->count; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "name",
				g_variant_new_string((const gchar *)msisdn_list->msisdn[i].name));
			if (msisdn_list->msisdn[i].ton == SIM_TON_INTERNATIONAL) {
				unsigned char *tmp = (unsigned char *)calloc(SIM_MSISDN_NUMBER_LEN_MAX + 1, 1);
				if (tmp != NULL) {
					tmp[0] = '+';

					strncpy((char *)tmp+1,
						(const char*)msisdn_list->msisdn[i].num,
						SIM_MSISDN_NUMBER_LEN_MAX - 1);
					tmp[SIM_MSISDN_NUMBER_LEN_MAX] = '\0';

					g_variant_builder_add(&b, "{sv}", "number",
						g_variant_new_string((const gchar *)tmp));

					free(tmp);
				} else {
					warn("Memory allocation failed");
					g_variant_builder_add(&b, "{sv}", "number",
						g_variant_new_string((const gchar *)msisdn_list->msisdn[i].num));
				}
			} else {
				g_variant_builder_add(&b, "{sv}", "number",
					g_variant_new_string((const gchar *)msisdn_list->msisdn[i].num));
			}
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_msisdn(sim,
			invocation, SIM_ACCESS_SUCCESS, gv);

		g_free(msisdn_list);
	}

	return TRUE;
}

static gboolean on_sim_get_oplmnwact(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_OPLMWACT, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get OPLMNWACT");

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_OPLMNWACT,
		NULL, 0);

	return TRUE;
}

static gboolean on_sim_get_spn(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct tel_sim_spn* spn = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_SPN, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get SPN");

	spn = tcore_sim_get_spn(co_sim);
	if (!spn) {
		dbg("[%s] NOT cached - Request to modem", GET_CP_NAME(invocation));

		/* Dispatch request */
		dtapi_dispatch_request(ctx, sim, invocation,
			TREQ_SIM_GET_SPN,
			NULL, 0);
	} else {
		dbg("[%s] Display condition: [%d] SPN: [%s]",
			GET_CP_NAME(invocation),
			spn->display_condition, (const gchar *)spn->spn);

		telephony_sim_complete_get_spn(sim, invocation, SIM_ACCESS_SUCCESS,
			spn->display_condition, (const gchar *)spn->spn);

		g_free(spn);
	}
	return TRUE;
}

static gboolean on_sim_get_cphs_netname(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct tel_sim_cphs_netname *cphs_netname = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_CPHS_NET_NAME, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get CPHS Net Name");

	cphs_netname = tcore_sim_get_cphs_netname(co_sim);
	if (!cphs_netname) {
		dbg("[%s] NOT cached - Request to modem", GET_CP_NAME(invocation));

		/* Dispatch request */
		dtapi_dispatch_request(ctx, sim, invocation,
			TREQ_SIM_GET_CPHS_NETNAME,
			NULL, 0);
	} else {
		dbg("[%s] Full name: [%s] Short name: [%s]",
			GET_CP_NAME(invocation),
			(const gchar *)cphs_netname->full_name,
			(const gchar *)cphs_netname->short_name);

		telephony_sim_complete_get_cphs_net_name(sim,
			invocation, SIM_ACCESS_SUCCESS,
			(const gchar *)cphs_netname->full_name,
			(const gchar *)cphs_netname->short_name);

		g_free(cphs_netname);
	}

	return TRUE;
}

static gboolean on_sim_get_gid(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_GID, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get GID");

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_GID,
		NULL, 0);

	return TRUE;
}

static gboolean on_sim_authentication(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gint auth_type,
	GVariant *rand, GVariant *autn, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	GVariantIter *iter = NULL;
	GVariant *rand_gv = NULL;
	GVariant *autn_gv = NULL;
	guchar rt_i;
	int i = 0;
	TReturn ret;
	CoreObject *co_sim = NULL;
	struct treq_sim_req_authentication req;

	if (!check_access_control(invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, AUTHENTICATION, co_sim);

	memset(&req, 0x0, sizeof(struct treq_sim_req_authentication));

	req.auth_type = auth_type;

	rand_gv = g_variant_get_variant(rand);
	g_variant_get(rand_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &rt_i)) {
		req.rand_data[i] = rt_i;
		i++;
	}
	g_variant_iter_free(iter);
	g_variant_unref(rand_gv);

	req.rand_length = (unsigned int)i;

	i = 0;
	autn_gv = g_variant_get_variant(autn);
	g_variant_get(autn_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &rt_i)) {
		req.autn_data[i] = rt_i;
		i++;
	}
	g_variant_iter_free(iter);
	g_variant_unref(autn_gv);

	req.autn_length = (unsigned int)i;

	dbg("[%s] Authentication - type: [0x%02x] RAND len: [%d] AUTN len: [%d]",
		GET_CP_NAME(invocation),
		req.auth_type, req.rand_length, req.autn_length);

	/* Dispatch request */
	ret = dtapi_dispatch_request_ex(ctx, sim, invocation,
		TREQ_SIM_REQ_AUTHENTICATION,
		&req, sizeof(struct treq_sim_req_authentication));
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

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		ak = g_variant_builder_end(&builder);
		ak_gv = g_variant_new("v", ak);

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		cp = g_variant_builder_end(&builder);
		cp_gv = g_variant_new("v", cp);

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		it = g_variant_builder_end(&builder);
		it_gv = g_variant_new("v", it);

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		resp = g_variant_builder_end(&builder);
		resp_gv = g_variant_new("v", resp);

		telephony_sim_complete_authentication(sim,
			invocation, SIM_ACCESS_FAILED,
			0, 0, ak_gv, cp_gv, it_gv, resp_gv);
	}

	return TRUE;
}

static gboolean on_sim_verify_sec(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	gint pin_type, const gchar *pin, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct treq_sim_verify_pins req;

	if (!check_access_control(invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, VERIFY_SEC, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Verify Sec");

	memset(&req, 0x0, sizeof(struct treq_sim_verify_pins));

	req.pin_type = pin_type;
	req.pin_length = strlen(pin);
	memcpy(req.pin, pin, req.pin_length);

	dbg("[%s] PIN - type: [0x%02x] len: [%d]",
		GET_CP_NAME(invocation),
		req.pin_type, req.pin_length);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_VERIFY_PINS,
		&req, sizeof(struct treq_sim_verify_pins));

	return TRUE;
}

static gboolean on_sim_verify_puk(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	gint puk_type, const gchar *puk,
	const gchar *new_pin, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct treq_sim_verify_puks req;

	if (!check_access_control(invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, VERIFY_PUK, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Verify PUK");

	memset(&req, 0x0, sizeof(struct treq_sim_verify_puks));

	req.puk_type = puk_type;
	req.puk_length = strlen(puk);
	memcpy(req.puk, puk, req.puk_length);
	req.pin_length = strlen(new_pin);
	memcpy(req.pin, new_pin, req.pin_length);

	dbg("[%s] PUK - type: [0x%02x] len: [%d] PIN len: [%d]",
		GET_CP_NAME(invocation), req.puk_type,
		req.puk_length, req.pin_length);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_VERIFY_PUKS,
		&req, sizeof(struct treq_sim_verify_puks));

	return TRUE;
}

static gboolean on_sim_change_pin(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	gint pin_type, const gchar *old_pin, const gchar *new_pin,
	gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct treq_sim_change_pins req;

	if (!check_access_control(invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, CHANGE_PIN, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Change PIN");

	memset(&req, 0x0, sizeof(struct treq_sim_change_pins));

	req.type = pin_type;
	req.old_pin_length = strlen(old_pin);
	memcpy(req.old_pin, old_pin, req.old_pin_length);
	req.new_pin_length = strlen(new_pin);
	memcpy(req.new_pin, new_pin, req.new_pin_length);

	dbg("[%s] PIN - type: [0x%02x] Old PIN len: [%d] New PIN len: [%d]",
		GET_CP_NAME(invocation), req.type,
		req.old_pin_length, req.new_pin_length);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_CHANGE_PINS,
		&req, sizeof(struct treq_sim_change_pins));

	return TRUE;
}

static gboolean on_sim_disable_facility(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	gint facility_type, const gchar *password, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_sim_disable_facility req;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, DISABLE_FACILITY, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Diable Facility");

	memset(&req, 0x0, sizeof(struct treq_sim_disable_facility));

	dbg("[%s] facility_type: [%d]", GET_CP_NAME(invocation), facility_type);
	switch (facility_type) {
	case 1:
		req.type = SIM_FACILITY_PS;
	break;

	case 3:
		req.type = SIM_FACILITY_SC;
	break;

	case 4:
		req.type = SIM_FACILITY_FD;
	break;

	case 5:
		req.type = SIM_FACILITY_PN;
	break;

	case 6:
		req.type = SIM_FACILITY_PU;
	break;

	case 7:
		req.type = SIM_FACILITY_PP;
	break;

	case 8:
		req.type = SIM_FACILITY_PC;
	break;

	default:
		err("Unhandled/Unknown Facility type: [0x%x]", facility_type);

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	}

	req.password_length = strlen(password);
	memcpy(req.password, password, req.password_length);

	dbg("[%s] Facility - type: [0x%02x] Passowrd len: [%d]",
		GET_CP_NAME(invocation),
		req.type, req.password_length);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_DISABLE_FACILITY,
		&req, sizeof(struct treq_sim_disable_facility));

	return TRUE;
}

static gboolean on_sim_enable_facility(TelephonySim *sim, GDBusMethodInvocation *invocation,
	    gint facility_type,
	    const gchar *password,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_sim_enable_facility req;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, ENABLE_FACILITY, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Enable Facility");

	memset(&req, 0x0, sizeof(struct treq_sim_enable_facility));

	dbg("[%s] facility_type: [%d]", GET_CP_NAME(invocation), facility_type);
	switch (facility_type) {
	case 1:
		req.type = SIM_FACILITY_PS;
	break;

	case 3:
		req.type = SIM_FACILITY_SC;
	break;

	case 4:
		req.type = SIM_FACILITY_FD;
	break;

	case 5:
		req.type = SIM_FACILITY_PN;
	break;

	case 6:
		req.type = SIM_FACILITY_PU;
	break;

	case 7:
		req.type = SIM_FACILITY_PP;
	break;

	case 8:
		req.type = SIM_FACILITY_PC;
	break;

	default:
		err("Unhandled/Unknown Facility type: [0x%x]", facility_type);

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	}

	req.password_length = strlen(password);
	memcpy(req.password, password, req.password_length);

	dbg("[%s] Facility - type: [0x%02x] Passowrd len: [%d]",
		GET_CP_NAME(invocation),
		req.type, req.password_length);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_ENABLE_FACILITY,
		&req, sizeof(struct treq_sim_enable_facility));

	return TRUE;
}

static gboolean on_sim_get_facility(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	gint facility_type, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_sim_get_facility_status req;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_FACILITY, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get Facility");

	memset(&req, 0x0, sizeof(struct treq_sim_get_facility_status));

	dbg("[%s] facility_type: [%d]", GET_CP_NAME(invocation), facility_type);

	switch (facility_type) {
	case 1:
		req.type = SIM_FACILITY_PS;
	break;

	case 3:
		req.type = SIM_FACILITY_SC;
	break;

	case 4:
		req.type = SIM_FACILITY_FD;
	break;

	case 5:
		req.type = SIM_FACILITY_PN;
	break;

	case 6:
		req.type = SIM_FACILITY_PU;
	break;

	case 7:
		req.type = SIM_FACILITY_PP;
	break;

	case 8:
		req.type = SIM_FACILITY_PC;
	break;

	default:
		err("Unhandled/Unknown Facility type: [0x%x]", facility_type);

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	}

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_FACILITY_STATUS,
		&req, sizeof(struct treq_sim_get_facility_status));

	return TRUE;
}

static gboolean on_sim_get_lock_info(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	gint facility_type, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct treq_sim_get_lock_info req;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_LOCK_INFO, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get Lock Info");

	memset(&req, 0x0, sizeof(struct treq_sim_get_lock_info));

	dbg("[%s] facility_type: [%d]", GET_CP_NAME(invocation), facility_type);
	switch (facility_type) {
	case 1:
		req.type = SIM_FACILITY_PS;
	break;

	case 3:
		req.type = SIM_FACILITY_SC;
	break;

	case 4:
		req.type = SIM_FACILITY_FD;
	break;

	case 5:
		req.type = SIM_FACILITY_PN;
	break;

	case 6:
		req.type = SIM_FACILITY_PU;
	break;

	case 7:
		req.type = SIM_FACILITY_PP;
	break;

	case 8:
		req.type = SIM_FACILITY_PC;
	break;

	default:
		err("Unhandled/Unknown Facility type: [0x%x]", facility_type);

		FAIL_RESPONSE(invocation, DEFAULT_MSG_REQ_FAILED);

		return TRUE;
	}

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_LOCK_INFO,
		&req, sizeof(struct treq_sim_get_lock_info));

	return TRUE;
}

static gboolean on_sim_transfer_apdu(TelephonySim *sim,
	GDBusMethodInvocation *invocation,
	GVariant *apdu, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_sim_transmit_apdu req;
	GVariantIter *iter = NULL;
	GVariant *inner_gv = NULL;
	guchar rt_i;
	CoreObject *co_sim = NULL;
	int i = 0;

	if (!check_access_control(invocation, AC_SIM, "x"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, TRANSFER_APDU, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Transfer APDU");

	memset(&req, 0x0, sizeof(struct treq_sim_transmit_apdu));

	inner_gv = g_variant_get_variant(apdu);

	g_variant_get(inner_gv, "ay", &iter);
	while (g_variant_iter_loop(iter, "y", &rt_i)) {
		req.apdu[i] = rt_i;
		i++;
	}
	req.apdu_length = (unsigned int)i;
	g_variant_iter_free(iter);
	g_variant_unref(inner_gv);
	g_variant_unref(apdu);

	tcore_util_hex_dump("[APDU_REQ] ", req.apdu_length, req.apdu);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_TRANSMIT_APDU,
		&req, sizeof(struct treq_sim_transmit_apdu));

	return TRUE;
}

static gboolean on_sim_get_atr(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_ATR, co_sim);
	DBUS_SIM_CHECK_SIM_TYPE(co_sim, "Get ATR");

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_ATR,
		NULL, 0);

	return TRUE;
}

static gboolean on_sim_get_fields(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct tel_sim_imsi *n_imsi = NULL;
	CoreObject *co_sim = NULL;
	GVariantBuilder b;
	GVariant *gv_fields = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);

	g_variant_builder_init(&b, G_VARIANT_TYPE("a{svv}}"));

	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_IMSI, co_sim);

	n_imsi = tcore_sim_get_imsi(co_sim);
	if (n_imsi != NULL) {
		g_variant_builder_add(&b, "{svv}", "imsi",
			g_variant_new_string("plmn"),
			g_variant_new_string(n_imsi->plmn));
		g_variant_builder_add(&b, "{svv}", "imsi",
			g_variant_new_string("msin"),
			g_variant_new_string(n_imsi->msin));
		free(n_imsi);
	}

	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_ICCID, co_sim);
	g_variant_builder_add(&b, "{svv}", "iccid",
		g_variant_new_string(""), g_variant_new_string(""));

	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_MSISDN, co_sim);
	g_variant_builder_add(&b, "{svv}", "msisdn",
		g_variant_new_string("name"), g_variant_new_string("number"));

	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_SPN, co_sim);
	g_variant_builder_add(&b, "{svv}", "spn",
		g_variant_new_uint16(255), g_variant_new_string("network name"));

	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_INIT_STATUS, co_sim);
	g_variant_builder_add(&b, "{svv}", "init_status",
		g_variant_new_uint16(0), g_variant_new_boolean(TRUE));

	gv_fields = g_variant_builder_end(&b);

	telephony_sim_complete_get_fields(sim,
		invocation, 0, gv_fields);

	return TRUE;
}

static gboolean on_sim_set_power_state(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gint state, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	struct treq_sim_set_powerstate req;

	if (!check_access_control(invocation, AC_SIM, "w"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, SET_POWERSTATE, co_sim);

	memset(&req, 0x0, sizeof(struct treq_sim_set_powerstate));

	req.state = state;

	dbg("[%s] SIM Power state: [%d]",
		GET_CP_NAME(invocation), req.state);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_SET_POWERSTATE,
		&req, sizeof(struct treq_sim_set_powerstate));

	return TRUE;
}

static gboolean on_sim_get_impi(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_IMPI, co_sim);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_IMPI,
		NULL, 0);

	return TRUE;
}

static gboolean on_sim_get_impu(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_IMPU, co_sim);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_IMPU,
		NULL, 0);

	return TRUE;
}

static gboolean on_sim_get_domain(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_DOMAIN, co_sim);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_DOMAIN,
		NULL, 0);

	return TRUE;
}

static gboolean on_sim_get_pcscf(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_PCSCF, co_sim);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, sim, invocation,
		TREQ_SIM_GET_PCSCF,
		NULL, 0);

	return TRUE;
}

static gboolean on_sim_get_app_list(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	CoreObject *co_sim = NULL;
	unsigned char app_list = 0;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_APP_LIST, co_sim);

	app_list = tcore_sim_get_app_list(co_sim);

	telephony_sim_complete_get_app_list(sim,
		invocation, app_list);

	return TRUE;
}

static gboolean on_sim_get_isim_service_table(TelephonySim *sim,
	GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct tel_sim_ist *ist = NULL;
	CoreObject *co_sim = NULL;

	if (!check_access_control(invocation, AC_SIM, "r"))
		return TRUE;

	DBUS_SIM_GET_COSIM(invocation, co_sim, ctx->server);
	DBUS_SIM_CHECK_SIM_STATUS(invocation, GET_ISIM_SERVICE_TABLE, co_sim);

	ist = tcore_sim_get_isim_service_table(co_sim);
	if (ist) {
		GVariantBuilder builder;
		GVariant *ist_gv = NULL;
		GVariant *inner_gv = NULL;
		int i;

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < SIM_IST_SERVICE_CNT_MAX; i++)
			g_variant_builder_add(&builder, "y", ist->service[i]);
		inner_gv = g_variant_builder_end(&builder);
		ist_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_get_isim_service_table(sim, invocation,
			SIM_ACCESS_SUCCESS, ist_gv);

		g_free(ist);
	} else {
		/* Dispatch request */
		dtapi_dispatch_request(ctx, sim, invocation,
			TREQ_SIM_GET_ISIM_SERVICE_TABLE,
			NULL, 0);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_sim_interface(TelephonyObjectSkeleton *object,
	struct custom_data *ctx)
{
	TelephonySim *sim;

	sim = telephony_sim_skeleton_new();
	telephony_object_skeleton_set_sim(object, sim);
	g_object_unref(sim);

	dbg("sim = %p", sim);

	/*
	 * Register signal handlers for SIM interface
	 */
	g_signal_connect(sim,
		"handle-get-init-status",
		G_CALLBACK(on_sim_get_init_status), ctx);

	g_signal_connect(sim,
		"handle-get-card-type",
		G_CALLBACK(on_sim_get_card_type), ctx);

	g_signal_connect(sim,
		"handle-get-imsi",
		G_CALLBACK(on_sim_get_imsi), ctx);

	g_signal_connect(sim,
		"handle-get-ecc",
		G_CALLBACK(on_sim_get_ecc), ctx);

	g_signal_connect(sim,
		"handle-get-iccid",
		G_CALLBACK(on_sim_get_iccid), ctx);

	g_signal_connect(sim,
		"handle-get-language",
		G_CALLBACK(on_sim_get_language), ctx);

	g_signal_connect(sim,
		"handle-set-language",
		G_CALLBACK(on_sim_set_language), ctx);

	g_signal_connect(sim,
		"handle-get-call-forwarding",
		G_CALLBACK(on_sim_get_call_forwarding), ctx);

	g_signal_connect(sim,
		"handle-set-call-forwarding",
		G_CALLBACK(on_sim_set_call_forwarding), ctx);

	g_signal_connect(sim,
		"handle-get-message-waiting",
		G_CALLBACK(on_sim_get_message_waiting), ctx);

	g_signal_connect(sim,
		"handle-set-message-waiting",
		G_CALLBACK(on_sim_set_message_waiting), ctx);

	g_signal_connect(sim,
		"handle-get-mailbox",
		G_CALLBACK(on_sim_get_mailbox), ctx);

	g_signal_connect(sim,
		"handle-set-mailbox",
		G_CALLBACK(on_sim_set_mailbox), ctx);

	g_signal_connect(sim,
		"handle-get-cphsinfo",
		G_CALLBACK(on_sim_get_cphsinfo), ctx);

	g_signal_connect(sim,
		"handle-get-service-table",
		G_CALLBACK(on_sim_get_service_table), ctx);

	g_signal_connect(sim,
		"handle-get-msisdn",
		G_CALLBACK(on_sim_get_msisdn), ctx);

	g_signal_connect(sim,
		"handle-get-oplmnwact",
		G_CALLBACK(on_sim_get_oplmnwact), ctx);

	g_signal_connect(sim,
		"handle-get-spn",
		G_CALLBACK(on_sim_get_spn), ctx);

	g_signal_connect(sim,
		"handle-get-cphs-net-name",
		G_CALLBACK(on_sim_get_cphs_netname), ctx);

	g_signal_connect(sim,
		"handle-get-gid",
		G_CALLBACK(on_sim_get_gid), ctx);

	g_signal_connect(sim,
		"handle-authentication",
		G_CALLBACK(on_sim_authentication), ctx);

	g_signal_connect(sim,
		"handle-verify-sec",
		G_CALLBACK(on_sim_verify_sec), ctx);

	g_signal_connect(sim,
		"handle-verify-puk",
		G_CALLBACK(on_sim_verify_puk), ctx);

	g_signal_connect(sim,
		"handle-change-pin",
		G_CALLBACK(on_sim_change_pin), ctx);

	g_signal_connect(sim,
		"handle-disable-facility",
		G_CALLBACK(on_sim_disable_facility), ctx);

	g_signal_connect(sim,
		"handle-enable-facility",
		G_CALLBACK(on_sim_enable_facility), ctx);

	g_signal_connect(sim,
		"handle-get-facility",
		G_CALLBACK(on_sim_get_facility), ctx);

	g_signal_connect(sim,
		"handle-get-lock-info",
		G_CALLBACK(on_sim_get_lock_info), ctx);

	g_signal_connect(sim,
		"handle-transfer-apdu",
		G_CALLBACK(on_sim_transfer_apdu), ctx);

	g_signal_connect(sim,
		"handle-get-atr",
		G_CALLBACK(on_sim_get_atr), ctx);

	g_signal_connect(sim,
		"handle-get-fields",
		G_CALLBACK(on_sim_get_fields), ctx);

	g_signal_connect(sim,
		"handle-set-powerstate",
		G_CALLBACK(on_sim_set_power_state), ctx);

	g_signal_connect(sim,
		"handle-get-impi",
		G_CALLBACK(on_sim_get_impi), ctx);

	g_signal_connect(sim,
		"handle-get-impu",
		G_CALLBACK(on_sim_get_impu), ctx);

	g_signal_connect(sim,
		"handle-get-domain",
		G_CALLBACK(on_sim_get_domain), ctx);

	g_signal_connect(sim,
		"handle-get-pcscf",
		G_CALLBACK(on_sim_get_pcscf), ctx);

	g_signal_connect(sim,
		"handle-get-app-list",
		G_CALLBACK(on_sim_get_app_list), ctx);

	g_signal_connect(sim,
		"handle-get-isim-service-table",
		G_CALLBACK(on_sim_get_isim_service_table), ctx);

	/*
	 * Initialize DBUS property
	 */
	telephony_sim_set_cf_state(sim, FALSE);

	return TRUE;
}

gboolean dbus_plugin_sim_response(struct custom_data *ctx,
	UserRequest *ur, struct dbus_request_info *dbus_info,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	char *cpname = dbus_info ? GET_CP_NAME(dbus_info->invocation) : "";

	switch (command) {
	case TRESP_SIM_GET_ECC: {
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i = 0;

		dbg("[%s] SIM_GET_ECC - Result: [%s])", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS)
			tcore_sim_set_ecc_list(co_sim, &resp_read->data.ecc);
		else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND)
			tcore_sim_set_ecc_list(co_sim, NULL);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_read->data.ecc.ecc_count; i++) {
			dbg("[%s] ecc[%d] : ecc_category=[0x%x], ecc_num=[%s], " \
				"ecc_string=[%s]", cpname, i,
				resp_read->data.ecc.ecc[i].ecc_category,
				resp_read->data.ecc.ecc[i].ecc_num,
				resp_read->data.ecc.ecc[i].ecc_string);

			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "category",
				g_variant_new_int32(resp_read->data.ecc.ecc[i].ecc_category));
			g_variant_builder_add(&b, "{sv}", "number",
				g_variant_new_string(resp_read->data.ecc.ecc[i].ecc_num));
			g_variant_builder_add(&b, "{sv}", "name",
				g_variant_new_string(resp_read->data.ecc.ecc[i].ecc_string));
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_ecc(dbus_info->interface_object,
			dbus_info->invocation, gv);
	}
	break;

	case TRESP_SIM_GET_ICCID: {
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;

		dbg("[%s] SIM_GET_ICCID - Result: [%s] ICCID: [%s])", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			 resp_read->data.iccid.iccid);

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS)
			tcore_sim_set_iccid(co_sim, &resp_read->data.iccid);
		else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND)
			tcore_sim_set_iccid(co_sim, NULL);

		telephony_sim_complete_get_iccid(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			resp_read->data.iccid.iccid);
	}
	break;

	case TRESP_SIM_GET_LANGUAGE: {
		const struct tresp_sim_read *resp_read = data;

		dbg("[%s] SIM_GET_LANGUAGE - Result: [%s] Language: [0x%2x]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			resp_read->data.language.language[0]);

		telephony_sim_complete_get_language(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			resp_read->data.language.language[0]);
	}
	break;

	case TRESP_SIM_SET_LANGUAGE: {
		const struct tresp_sim_set_data *resp_set_data = data;

		dbg("[%s] SIM_SET_LANGUAGE - Result: [%s]", cpname,
			(resp_set_data->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_language(dbus_info->interface_object,
			dbus_info->invocation, resp_set_data->result);
	}
	break;

	case TRESP_SIM_GET_CALLFORWARDING: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv_cf = NULL;
		GVariant *gv_cphs_cf = NULL;
		GVariantBuilder b;

		dbg("[%s] SIM_GET_CALLFORWARDING - Result: [%s] CPHS: [%s]",
			cpname, (resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			(resp_read->data.cf.b_cphs ? "Yes" : "No"));

		if (resp_read->data.cf.b_cphs) {
			dbg("[%s] b_line1[%d], b_line2[%d], b_fax[%d], b_data[%d]",
				cpname, resp_read->data.cf.cphs_cf.b_line1,
				resp_read->data.cf.cphs_cf.b_line2,
				resp_read->data.cf.cphs_cf.b_fax,
				resp_read->data.cf.cphs_cf.b_data);

			g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "b_line1",
				g_variant_new_boolean(resp_read->data.cf.cphs_cf.b_line1));
			g_variant_builder_add(&b, "{sv}", "b_line2",
				g_variant_new_boolean(resp_read->data.cf.cphs_cf.b_line2));
			g_variant_builder_add(&b, "{sv}", "b_fax",
				g_variant_new_boolean(resp_read->data.cf.cphs_cf.b_fax));
			g_variant_builder_add(&b, "{sv}", "b_data",
				g_variant_new_boolean(resp_read->data.cf.cphs_cf.b_data));
			gv_cphs_cf = g_variant_builder_end(&b);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
			gv_cf = g_variant_builder_end(&b);

		} else {
			int i = 0;

			dbg("[%s] Profile count: [%d]", cpname, resp_read->data.cf.cf_list.profile_count);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
			for (i = 0; i < resp_read->data.cf.cf_list.profile_count; i++) {
				dbg("[%s] [%d] : rec_index[0x%x], msp_num[0x%x], " \
					"cfu_status[0x%x], cfu_num[%s], ton[0x%x], " \
					"npi[0x%x], cc2_id[0x%x], ext7_id[0x%x]", cpname, i,
					resp_read->data.cf.cf_list.cf[i].rec_index,
					resp_read->data.cf.cf_list.cf[i].msp_num,
					resp_read->data.cf.cf_list.cf[i].cfu_status,
					resp_read->data.cf.cf_list.cf[i].cfu_num,
					resp_read->data.cf.cf_list.cf[i].ton,
					resp_read->data.cf.cf_list.cf[i].npi,
					resp_read->data.cf.cf_list.cf[i].cc2_id,
					resp_read->data.cf.cf_list.cf[i].ext7_id);

				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "rec_index",
					g_variant_new_int32(resp_read->data.cf.cf_list.cf[i].rec_index));
				g_variant_builder_add(&b, "{sv}", "msp_num",
					g_variant_new_byte(resp_read->data.cf.cf_list.cf[i].msp_num));
				g_variant_builder_add(&b, "{sv}", "cfu_status",
					g_variant_new_byte(resp_read->data.cf.cf_list.cf[i].cfu_status));
				g_variant_builder_add(&b, "{sv}", "cfu_num",
					g_variant_new_string(resp_read->data.cf.cf_list.cf[i].cfu_num));
				g_variant_builder_add(&b, "{sv}", "ton",
					g_variant_new_int32(resp_read->data.cf.cf_list.cf[i].ton));
				g_variant_builder_add(&b, "{sv}", "npi",
					g_variant_new_int32(resp_read->data.cf.cf_list.cf[i].npi));
				g_variant_builder_add(&b, "{sv}", "cc2_id",
					g_variant_new_byte(resp_read->data.cf.cf_list.cf[i].cc2_id));
				g_variant_builder_add(&b, "{sv}", "ext7_id",
					g_variant_new_byte(resp_read->data.cf.cf_list.cf[i].ext7_id));
				g_variant_builder_close(&b);
			}
			gv_cf = g_variant_builder_end(&b);

			g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
			gv_cphs_cf = g_variant_builder_end(&b);
		}

		telephony_sim_complete_get_call_forwarding(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			resp_read->data.cf.b_cphs, gv_cf, gv_cphs_cf);
	}
	break;

	case TRESP_SIM_SET_CALLFORWARDING: {
		const struct tresp_sim_set_data *resp_set_data = data;

		dbg("[%s] SIM_SET_CALLFORWARDING - Result: [%s]", cpname,
			(resp_set_data->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_call_forwarding(dbus_info->interface_object,
			dbus_info->invocation, resp_set_data->result);
	}
	break;

	case TRESP_SIM_GET_MESSAGEWAITING: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv_mw = NULL;
		GVariant *gv_cphs_mw = NULL;
		GVariantBuilder b;

		dbg("[%s] SIM_GET_MESSAGEWAITING - Result: [%s] CPHS: [%s]",
			cpname, (resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			(resp_read->data.mw.b_cphs ? "Yes" : "No"));

		if (resp_read->data.mw.b_cphs) {
			dbg("[%s] b_voice1[%d], b_voice2[%d], b_fax[%d], b_data[%d]",
				cpname, resp_read->data.mw.cphs_mw.b_voice1,
				resp_read->data.mw.cphs_mw.b_voice2,
				resp_read->data.mw.cphs_mw.b_fax,
				resp_read->data.mw.cphs_mw.b_data);

			g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "b_voice1",
				g_variant_new_boolean(resp_read->data.mw.cphs_mw.b_voice1));
			g_variant_builder_add(&b, "{sv}", "b_voice2",
				g_variant_new_boolean(resp_read->data.mw.cphs_mw.b_voice2));
			g_variant_builder_add(&b, "{sv}", "b_fax",
				g_variant_new_boolean(resp_read->data.mw.cphs_mw.b_fax));
			g_variant_builder_add(&b, "{sv}", "b_data",
				g_variant_new_boolean(resp_read->data.mw.cphs_mw.b_data));
			gv_cphs_mw = g_variant_builder_end(&b);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
			gv_mw = g_variant_builder_end(&b);

		} else {
			int i = 0;

			dbg("[%s] Profile count: [%d]", cpname,
				resp_read->data.mw.mw_list.profile_count);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
			for (i = 0; i < resp_read->data.mw.mw_list.profile_count; i++) {
				dbg("[%s] mw[%d] : rec_index[0x%x], indicator_status[0x%x], " \
					"voice_count[0x%x], fax_count[0x%x] email_count[0x%x], " \
					"other_count[0x%x], video_count[0x%x]", cpname, i,
					resp_read->data.mw.mw_list.mw[i].rec_index,
					resp_read->data.mw.mw_list.mw[i].indicator_status,
					resp_read->data.mw.mw_list.mw[i].voice_count,
					resp_read->data.mw.mw_list.mw[i].fax_count,
					resp_read->data.mw.mw_list.mw[i].email_count,
					resp_read->data.mw.mw_list.mw[i].other_count,
					resp_read->data.mw.mw_list.mw[i].video_count);

				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "rec_index",
					g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].rec_index));
				g_variant_builder_add(&b, "{sv}", "indicator_status",
					g_variant_new_byte(resp_read->data.mw.mw_list.mw[i].indicator_status));
				g_variant_builder_add(&b, "{sv}", "voice_count",
					g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].voice_count));
				g_variant_builder_add(&b, "{sv}", "fax_count",
					g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].fax_count));
				g_variant_builder_add(&b, "{sv}", "email_count",
					g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].email_count));
				g_variant_builder_add(&b, "{sv}", "other_count",
					g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].other_count));
				g_variant_builder_add(&b, "{sv}", "video_count",
					g_variant_new_int32(resp_read->data.mw.mw_list.mw[i].video_count));
				g_variant_builder_close(&b);
			}
			gv_mw = g_variant_builder_end(&b);
			g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
			gv_cphs_mw = g_variant_builder_end(&b);
		}

		telephony_sim_complete_get_message_waiting(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			resp_read->data.mw.b_cphs, gv_mw, gv_cphs_mw);
	}
	break;

	case TRESP_SIM_SET_MESSAGEWAITING: {
		const struct tresp_sim_set_data *resp_set_data = data;

		dbg("[%s] SIM_SET_MESSAGEWAITING - Result: [%s]",
			cpname, (resp_set_data->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_message_waiting(dbus_info->interface_object,
			dbus_info->invocation, resp_set_data->result);
	}
	break;

	case TRESP_SIM_GET_MAILBOX: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i = 0;

		dbg("[%s] SIM_GET_MAILBOX - Result: [%s] CPHS: [%s] Count: [%d])",
			cpname, (resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			(resp_read->data.mb.b_cphs ? "Yes" : "No"),
			resp_read->data.mb.count);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_read->data.mb.count; i++) {
			dbg("[%s] mb[%d] : rec_index[%d], profile_number[%d], mb_type[%d], " \
				"alpha_id_max_len[%d]alpha_id[%s], ton[%d], npi[%d], num[%s], " \
				"cc_id[%d], ext1_id[%d]", cpname, i,
				resp_read->data.mb.mb[i].rec_index, resp_read->data.mb.mb[i].profile_number,
				resp_read->data.mb.mb[i].mb_type, resp_read->data.mb.mb[i].number_info.alpha_id_max_len,
				resp_read->data.mb.mb[i].number_info.alpha_id, resp_read->data.mb.mb[i].number_info.ton,
				resp_read->data.mb.mb[i].number_info.npi, resp_read->data.mb.mb[i].number_info.num,
				resp_read->data.mb.mb[i].number_info.cc_id, resp_read->data.mb.mb[i].number_info.ext1_id);

			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "rec_index",
			g_variant_new_int32(resp_read->data.mb.mb[i].rec_index));
			g_variant_builder_add(&b, "{sv}", "profile_num",
			g_variant_new_int32(resp_read->data.mb.mb[i].profile_number));
			g_variant_builder_add(&b, "{sv}", "mb_type",
			g_variant_new_int32(resp_read->data.mb.mb[i].mb_type));
			g_variant_builder_add(&b, "{sv}", "alpha_id_max_len",
			g_variant_new_int32(resp_read->data.mb.mb[i].number_info.alpha_id_max_len));
			g_variant_builder_add(&b, "{sv}", "alpha_id",
			g_variant_new_string(resp_read->data.mb.mb[i].number_info.alpha_id));
			g_variant_builder_add(&b, "{sv}", "ton",
			g_variant_new_int32(resp_read->data.mb.mb[i].number_info.ton));
			g_variant_builder_add(&b, "{sv}", "npi",
			g_variant_new_int32(resp_read->data.mb.mb[i].number_info.npi));
			g_variant_builder_add(&b, "{sv}", "num",
			g_variant_new_string(resp_read->data.mb.mb[i].number_info.num));
			g_variant_builder_add(&b, "{sv}", "cc_id",
			g_variant_new_byte(resp_read->data.mb.mb[i].number_info.cc_id));
			g_variant_builder_add(&b, "{sv}", "ext1_id",
			g_variant_new_byte(resp_read->data.mb.mb[i].number_info.ext1_id));
			g_variant_builder_close(&b);
		}

		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_mailbox(dbus_info->interface_object, dbus_info->invocation,
			resp_read->result, resp_read->data.mb.b_cphs, gv);
	}
	break;

	case TRESP_SIM_SET_MAILBOX: {
		const struct tresp_sim_set_data *resp_set_data = data;

		dbg("[%s] SIM_SET_MAILBOX - Result: [%s]", cpname,
			(resp_set_data->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_mailbox(dbus_info->interface_object,
			dbus_info->invocation, resp_set_data->result);
	}
	break;

	case TRESP_SIM_GET_CPHS_INFO: {
		const struct tresp_sim_read *resp_read = data;

		dbg("[%s] SIM_GET_CPHS_INFO - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_get_cphsinfo(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
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
		int i = 0;

		dbg("[%s] SIM_GET_SERVICE_TABLE - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS)
			tcore_sim_set_service_table(co_sim, &resp_read->data.svct);
		else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND)
			tcore_sim_set_service_table(co_sim, NULL);

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		if (resp_read->data.svct.sim_type == SIM_TYPE_GSM) {
			for (i = 0; i < SIM_SST_SERVICE_CNT_MAX; i++)
				g_variant_builder_add(&builder, "y",
					resp_read->data.svct.table.sst.service[i]);
		} else if (resp_read->data.svct.sim_type == SIM_TYPE_USIM) {
			for (i = 0; i < SIM_UST_SERVICE_CNT_MAX; i++)
				g_variant_builder_add(&builder, "y",
					resp_read->data.svct.table.ust.service[i]);
		} else if (resp_read->data.svct.sim_type == SIM_TYPE_RUIM) {
			if (SIM_CDMA_SVC_TABLE == resp_read->data.svct.table.cst.cdma_svc_table) {
				for (i = 0; i < SIM_CDMA_ST_SERVICE_CNT_MAX; i++) {
					g_variant_builder_add(&builder, "iy",
						resp_read->data.svct.table.cst.cdma_svc_table,
						resp_read->data.svct.table.cst.service.cdma_service[i]);
				}
			} else if (SIM_CSIM_SVC_TABLE == resp_read->data.svct.table.cst.cdma_svc_table) {
				for (i = 0; i < SIM_CSIM_ST_SERVICE_CNT_MAX; i++) {
					g_variant_builder_add(&builder, "iy",
						resp_read->data.svct.table.cst.cdma_svc_table,
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

		telephony_sim_complete_get_service_table(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			resp_read->data.svct.sim_type, svct_gv);
	}
	break;

	case TRESP_SIM_GET_SPN: {
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;

		dbg("[%s] SIM_GET_SPN - Result: [%s] Display condition: [%d] SPN: [%s]",
			cpname, (resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"),
			resp_read->data.spn.display_condition, (const gchar *)resp_read->data.spn.spn);

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS)
			tcore_sim_set_spn(co_sim, &resp_read->data.spn);
		else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND)
			tcore_sim_set_spn(co_sim, NULL);

		telephony_sim_complete_get_spn(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			resp_read->data.spn.display_condition,
			(const gchar *)resp_read->data.spn.spn);
	}
	break;

	case TRESP_SIM_GET_CPHS_NETNAME: {
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;

		dbg("[%s] SIM_GET_CPHS_NETNAME - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		if (resp_read->result == SIM_ACCESS_SUCCESS)
			tcore_sim_set_cphs_netname(co_sim, &resp_read->data.cphs_net);
		else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND)
			tcore_sim_set_cphs_netname(co_sim, NULL);

		telephony_sim_complete_get_cphs_net_name(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			(const gchar *)resp_read->data.cphs_net.full_name,
			(const gchar *)resp_read->data.cphs_net.short_name);
	}
	break;

	case TRESP_SIM_GET_GID: {
		const struct tresp_sim_read *resp_read = data;
		GVariantBuilder builder;
		GVariant *inner_gv = NULL;
		GVariant *gid_gv = NULL;
		int i = 0;

		dbg("[%s] SIM_GET_GID - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < resp_read->data.gid.GroupIdentifierLen; i++)
			g_variant_builder_add(&builder, "y", resp_read->data.gid.szGroupIdentifier[i]);
		inner_gv = g_variant_builder_end(&builder);
		gid_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_get_gid(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			resp_read->data.gid.GroupIdentifierLen, gid_gv);
	}
	break;

	case TRESP_SIM_GET_MSISDN:{
		const struct tresp_sim_read *resp_read = data;
		CoreObject *co_sim = NULL;
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i = 0;

		dbg("[%s] SIM_GET_MSISDN - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		co_sim = __get_sim_co_from_ur(ctx->server, ur);
		if (!co_sim) {
			err("SIM Core object is NULL");
			return FALSE;
		}

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		if (resp_read->result == SIM_ACCESS_SUCCESS)
			tcore_sim_set_msisdn_list(co_sim, &resp_read->data.msisdn_list);
		else if (resp_read->result == SIM_ACCESS_FILE_NOT_FOUND)
			tcore_sim_set_msisdn_list(co_sim, NULL);

		for (i = 0; i < resp_read->data.msisdn_list.count; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "name",
				g_variant_new_string((const gchar *)resp_read->data.msisdn_list.msisdn[i].name));
			if (resp_read->data.msisdn_list.msisdn[i].ton == SIM_TON_INTERNATIONAL) {
				unsigned char *tmp = (unsigned char *)calloc(SIM_MSISDN_NUMBER_LEN_MAX + 1, 1);
				if (tmp != NULL) {
					tmp[0] = '+';

					strncpy((char *)tmp + 1,
						(const char*)resp_read->data.msisdn_list.msisdn[i].num,
						SIM_MSISDN_NUMBER_LEN_MAX - 1);
					tmp[SIM_MSISDN_NUMBER_LEN_MAX] = '\0';

					g_variant_builder_add(&b, "{sv}", "number",
						g_variant_new_string((const gchar *)tmp));
					free(tmp);
				} else {
					dbg("Memory allocation failed");

					g_variant_builder_add(&b, "{sv}", "number",
						g_variant_new_string((const gchar *)resp_read->data.msisdn_list.msisdn[i].num));
				}
			} else {
				g_variant_builder_add(&b, "{sv}", "number",
					g_variant_new_string((const gchar *)resp_read->data.msisdn_list.msisdn[i].num));
			}
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_msisdn(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result, gv);
	}
	break;

	case TRESP_SIM_GET_OPLMNWACT: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv = NULL;
		GVariantBuilder b;
		int i = 0;

		dbg("[%s] SIM_GET_OPLMNWACT - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_read->data.opwa.opwa_count; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "plmn",
				g_variant_new_string((const gchar *)resp_read->data.opwa.opwa[i].plmn));
			g_variant_builder_add(&b, "{sv}", "b_umts",
				g_variant_new_boolean(resp_read->data.opwa.opwa[i].b_umts));
			g_variant_builder_add(&b, "{sv}", "b_gsm",
				g_variant_new_boolean(resp_read->data.opwa.opwa[i].b_gsm));
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_oplmnwact(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result, gv);
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
		int i = 0;

		dbg("[%s] SIM_REQ_AUTHENTICATION - Result: [%s]", cpname,
			(resp_auth->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		tcore_util_hex_dump("[AUTH_KEY] ",
			resp_auth->authentication_key_length, resp_auth->authentication_key);
		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < (int)resp_auth->authentication_key_length; i++)
			g_variant_builder_add(&builder, "y", resp_auth->authentication_key[i]);
		ak = g_variant_builder_end(&builder);
		ak_gv = g_variant_new("v", ak);

		tcore_util_hex_dump("[CIPHER_DATA] ",
			resp_auth->cipher_length, resp_auth->cipher_data);
		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < (int)resp_auth->cipher_length; i++)
			g_variant_builder_add(&builder, "y", resp_auth->cipher_data[i]);
		cp = g_variant_builder_end(&builder);
		cp_gv = g_variant_new("v", cp);

		tcore_util_hex_dump("[INTEGRITY_DATA] ",
			resp_auth->integrity_length, resp_auth->integrity_data);
		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < (int)resp_auth->integrity_length; i++)
			g_variant_builder_add(&builder, "y", resp_auth->integrity_data[i]);
		it = g_variant_builder_end(&builder);
		it_gv = g_variant_new("v", it);

		tcore_util_hex_dump("[RESP_DATA] ",
			resp_auth->resp_length, resp_auth->resp_data);
		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < (int)resp_auth->resp_length; i++)
			g_variant_builder_add(&builder, "y", resp_auth->resp_data[i]);
		resp = g_variant_builder_end(&builder);
		resp_gv = g_variant_new("v", resp);

		telephony_sim_complete_authentication(dbus_info->interface_object,
			dbus_info->invocation, resp_auth->result,
			resp_auth->auth_type, resp_auth->auth_result,
			ak_gv, cp_gv, it_gv, resp_gv);
	}
	break;

	case TRESP_SIM_VERIFY_PINS: {
		const struct tresp_sim_verify_pins *resp_verify_pins = data;

		dbg("[%s] SIM_VERIFY_PINS - Result: [%s] PIN Type: [%d] Re-try count: [%d]",
			cpname, (resp_verify_pins->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_verify_pins->pin_type, resp_verify_pins->retry_count);

		telephony_sim_complete_verify_sec(dbus_info->interface_object,
			dbus_info->invocation, resp_verify_pins->result,
			resp_verify_pins->pin_type, resp_verify_pins->retry_count);
	}
	break;

	case TRESP_SIM_VERIFY_PUKS: {
		const struct tresp_sim_verify_puks *resp_verify_puks = data;

		dbg("[%s] SIM_VERIFY_PUKS - Result: [%s] PIN Type: [%d] Re-try count: [%d]",
			cpname, (resp_verify_puks->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_verify_puks->pin_type, resp_verify_puks->retry_count);

		telephony_sim_complete_verify_puk(dbus_info->interface_object,
			dbus_info->invocation, resp_verify_puks->result,
			resp_verify_puks->pin_type, resp_verify_puks->retry_count);
	}
	break;

	case TRESP_SIM_CHANGE_PINS: {
		const struct tresp_sim_change_pins *resp_change_pins = data;

		dbg("[%s] SIM_CHANGE_PINS - Result: [%s] PIN Type: [%d] Re-try count: [%d]",
			cpname, (resp_change_pins->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
			resp_change_pins->pin_type, resp_change_pins->retry_count);

		telephony_sim_complete_change_pin(dbus_info->interface_object,
			dbus_info->invocation, resp_change_pins->result,
			resp_change_pins->pin_type, resp_change_pins->retry_count);
	}
	break;

	case TRESP_SIM_DISABLE_FACILITY: {
		const struct tresp_sim_disable_facility *resp_dis_facility = data;
		gint f_type = 0;

		dbg("[%s] SIM_DISABLE_FACILITY - Result: [%s] Type: [%d] Re-try count: [%d]",
			cpname, (resp_dis_facility->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
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
			err("Unhandled/Unknown Facility type: [0x%x]", resp_dis_facility->type);
		break;
		}

		telephony_sim_complete_disable_facility(dbus_info->interface_object,
			dbus_info->invocation, resp_dis_facility->result,
			f_type, resp_dis_facility->retry_count);
	}
	break;

	case TRESP_SIM_ENABLE_FACILITY: {
		const struct tresp_sim_enable_facility *resp_en_facility = data;
		gint f_type = 0;

		dbg("[%s] SIM_ENABLE_FACILITY - Result: [%s] Type: [%d] Re-try count: [%d]",
			cpname, (resp_en_facility->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
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
			err("Unhandled/Unknown Facility type: [0x%x]", resp_en_facility->type);
		break;
		}

		telephony_sim_complete_enable_facility(dbus_info->interface_object,
			dbus_info->invocation, resp_en_facility->result,
			f_type, resp_en_facility->retry_count);
	}
	break;

	case TRESP_SIM_GET_FACILITY_STATUS: {
		const struct tresp_sim_get_facility_status *resp_get_facility = data;
		gint f_type = 0;

		dbg("[%s] SIM_GET_FACILITY_STATUS - Result: [%s] Type: [%d] Enable: [%s]",
			cpname, (resp_get_facility->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
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
			err("Unhandled/Unknown Facility type: [0x%x]", resp_get_facility->type);
		break;
		}

		telephony_sim_complete_get_facility(dbus_info->interface_object,
			dbus_info->invocation, resp_get_facility->result,
			f_type, resp_get_facility->b_enable);
	}
	break;

	case TRESP_SIM_GET_LOCK_INFO: {
		const struct tresp_sim_get_lock_info *resp_lock = data;
		gint f_type = 0;

		dbg("[%s] SIM_GET_LOCK_INFO - Result: [%s] Type: [%d] Re-try count: [%d]",
			cpname, (resp_lock->result == SIM_PIN_OPERATION_SUCCESS ? "Success" : "Fail"),
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
			err("Unhandled/Unknown Lock type: [0x%x]", resp_lock->type);
		break;
		}

		telephony_sim_complete_get_lock_info(dbus_info->interface_object,
			dbus_info->invocation, resp_lock->result,
			f_type, resp_lock->lock_status, resp_lock->retry_count);
	}
	break;

	case TRESP_SIM_TRANSMIT_APDU: {
		const struct tresp_sim_transmit_apdu *resp_apdu = data;
		GVariantBuilder builder;
		GVariant * apdu_gv = NULL;
		GVariant *inner_gv = NULL;
		int i = 0;

		dbg("[%s] SIM_TRANSMIT_APDU - Result: [%s]", cpname,
			(resp_apdu->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		tcore_util_hex_dump("[APDU_RESP] ",
			resp_apdu->apdu_resp_length, resp_apdu->apdu_resp);

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < (int)resp_apdu->apdu_resp_length; i++)
			g_variant_builder_add(&builder, "y", resp_apdu->apdu_resp[i]);
		inner_gv = g_variant_builder_end(&builder);
		apdu_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_transfer_apdu(dbus_info->interface_object,
			dbus_info->invocation, resp_apdu->result, apdu_gv);
	}
	break;

	case TRESP_SIM_GET_ATR:{
		const struct tresp_sim_get_atr *resp_get_atr = data;
		GVariantBuilder builder;
		GVariant * atr_gv = NULL;
		GVariant *inner_gv = NULL;
		int i = 0;

		dbg("[%s] SIM_GET_ATR - Result: [%s]", cpname,
			(resp_get_atr->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		tcore_util_hex_dump("[ATR_RESP] ",
			resp_get_atr->atr_length, resp_get_atr->atr);

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < (int)resp_get_atr->atr_length; i++)
			g_variant_builder_add(&builder, "y", resp_get_atr->atr[i]);
		inner_gv = g_variant_builder_end(&builder);
		atr_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_get_atr(dbus_info->interface_object,
			dbus_info->invocation, resp_get_atr->result, atr_gv);
	}
	break;

	case TRESP_SIM_SET_POWERSTATE: {
		const struct tresp_sim_set_powerstate *resp_power = data;

		info("[%s] SIM_SET_POWERSTATE - Result: [%s]", cpname,
			(resp_power->result == SIM_POWER_SET_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_set_powerstate(dbus_info->interface_object,
			dbus_info->invocation, resp_power->result);
	}
	break;

	case TRESP_SIM_GET_IMPI: {
		const struct tresp_sim_read *resp_read = data;

		dbg("[%s] SIM_GET_IMPI - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_get_impi(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			resp_read->data.impi.impi);
	}
	break;

	case TRESP_SIM_GET_IMPU: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv = NULL;
		GVariantBuilder b;
		unsigned int i;

		dbg("[%s] SIM_GET_IMPU - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_read->data.impu_list.count; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "impu",
				g_variant_new_string(resp_read->data.impu_list.impu[i].impu));
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_impu(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result, gv);
	}
	break;

	case TRESP_SIM_GET_DOMAIN: {
		const struct tresp_sim_read *resp_read = data;

		dbg("[%s] SIM_GET_DOMAIN - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		telephony_sim_complete_get_domain(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result,
			resp_read->data.domain.domain);
	}
	break;

	case TRESP_SIM_GET_PCSCF: {
		const struct tresp_sim_read *resp_read = data;
		GVariant *gv = NULL;
		GVariantBuilder b;
		unsigned int i;

		dbg("[%s] SIM_GET_PCSCF - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp_read->data.pcscf_list.count; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "type",
				g_variant_new_int32(resp_read->data.pcscf_list.pcscf[i].type));
			g_variant_builder_add(&b, "{sv}", "pcscf",
				g_variant_new_string(resp_read->data.pcscf_list.pcscf[i].pcscf));
			g_variant_builder_close(&b);
		}
		gv = g_variant_builder_end(&b);

		telephony_sim_complete_get_pcscf(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result, gv);
	}
	break;

	case TRESP_SIM_GET_ISIM_SERVICE_TABLE: {
		const struct tresp_sim_read *resp_read = data;
		GVariantBuilder builder;
		GVariant *ist_gv = NULL;
		GVariant *inner_gv = NULL;
		int i;

		dbg("[%s] SIM_GET_ISIM_SERVICE_TABLE - Result: [%s]", cpname,
			(resp_read->result == SIM_ACCESS_SUCCESS ? "Success" : "Fail"));

		g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
		for (i = 0; i < SIM_IST_SERVICE_CNT_MAX; i++)
			g_variant_builder_add(&builder, "y", resp_read->data.ist.service[i]);
		inner_gv = g_variant_builder_end(&builder);
		ist_gv = g_variant_new("v", inner_gv);

		telephony_sim_complete_get_isim_service_table(dbus_info->interface_object,
			dbus_info->invocation, resp_read->result, ist_gv);
	}
	break;

	default:
		err("Unhandled/Unknown Response: [0x%x]", command);
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_sim_notification(struct custom_data *ctx,
	CoreObject *source, TelephonyObjectSkeleton *object,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonySim *sim;
	const char *cp_name;
	enum dbus_tapi_sim_slot_id slot_id = SIM_SLOT_PRIMARY;

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	sim = telephony_object_peek_sim(TELEPHONY_OBJECT(object));
	if (sim == NULL) {
		err("sim object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_SIM_STATUS: {
		const struct tnoti_sim_status *n_sim_status = data;
		int count = 0;

		info("[%s] SIM_STATUS - [%d]", cp_name,
			n_sim_status->sim_status);

#ifdef ENABLE_KPI_LOGS
		if (n_sim_status->sim_status == SIM_STATUS_INIT_COMPLETED)
			TIME_CHECK("[%s] SIM Initialized", cp_name);
#endif

		telephony_sim_emit_status(sim, n_sim_status->sim_status);

		slot_id = get_sim_slot_id_by_cp_name(cp_name);
		if (slot_id == SIM_SLOT_PRIMARY)
			ctx->sim1_status = n_sim_status->sim_status;
		else if (slot_id == SIM_SLOT_SECONDARY)
			ctx->sim2_status = n_sim_status->sim_status;
		else
			warn("NOT handled Slot ID: [%d]", slot_id);

		if (__is_sim_status_valid(ctx->sim1_status))
			count++;

		if (__is_sim_status_valid(ctx->sim2_status))
			count++;

		if (ctx->valid_sim_count != count) {
			ctx->valid_sim_count = count;

			telephony_manager_emit_sim_inserted(ctx->mgr, count);
		}
	}
	break;

	case TNOTI_SIM_REFRESHED: {
		const struct tnoti_sim_refreshed *n_sim_refreshed = data;

		info("[%s] SIM_REFRESHED - b_full_file_changed: [%s] changed_file_count: [%d]",
			cp_name, (n_sim_refreshed->b_full_file_changed ? "YES" : "NO"),
			n_sim_refreshed->file_list.file_count);

		telephony_sim_emit_refreshed(sim, n_sim_refreshed->cmd_type);
	}
	break;

	case TNOTI_SIM_CALL_FORWARD_STATE: {
		const struct tnoti_sim_call_forward_state *info = data;

		info("[%s] SIM_CALL_FORWARD_STATE - Call Forwarding: [%s]",
			cp_name, info->b_forward ? "ON" : "OFF");

		telephony_sim_set_cf_state(sim, info->b_forward);
	}
	break;

	default:
		err("Unhandled/Unknown Notification: [0x%x]", command);
	break;
	}

	return TRUE;
}

