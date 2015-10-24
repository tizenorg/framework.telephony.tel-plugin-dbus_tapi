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

#include <appsvc.h>
#include <bundle_internal.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <co_ss.h>

#include "generated-code.h"
#include "dtapi_common.h"

/*
 * CISS application package name
 */
#define CISS_APP "org.tizen.ciss"

typedef struct {
	int status;
	int dcs;
	int length;
	char data[MAX_SS_USSD_LEN];
} CissDataType;

typedef struct {
	int err;
	int ss_type;
} CissInformation;

static void __launch_ciss_information(const struct tnoti_ss_information *ss_info, enum dbus_tapi_sim_slot_id slot_id)
{
	gchar *encoded_data;
	CissInformation ciss_inform;
	char slot_info[2] = {0,};

	bundle *kb = NULL;

	memset(&ciss_inform, 0x0, sizeof(CissInformation));
	ciss_inform.err = ss_info->err;
	ciss_inform.ss_type = ss_info->ss_type;

	snprintf(slot_info, 2, "%d", slot_id);
	dbg("slot_id : [%s]", slot_info);

	dbg("Explicit launch CISS application by appsvc");

	kb = bundle_create();
	if (!kb) {
		warn("bundle_create() failed");
		return;
	}

	appsvc_set_pkgname(kb, CISS_APP);

	encoded_data = g_base64_encode((guchar *)&ciss_inform, sizeof(CissInformation));

	appsvc_add_data(kb, "CISS_LAUNCHING_MODE", "RESP");
	appsvc_add_data(kb, "KEY_EVENT_TYPE", "200");
	appsvc_add_data(kb, "KEY_ENCODED_DATA", encoded_data);
	appsvc_add_data(kb, "KEY_SLOT_ID", slot_info);

	dbg("CISS appsvc run!");
	appsvc_run_service(kb, 0, NULL, NULL);

	bundle_free(kb);
	g_free(encoded_data);
}

static void __launch_ciss(const struct tnoti_ss_ussd *ussd, enum dbus_tapi_sim_slot_id slot_id)
{
	gchar *encoded_data;
	CissDataType ciss_data;
	char slot_info[2] = {0,};

	bundle *kb = NULL;

	memset(&ciss_data, 0x0, sizeof(CissDataType));
	ciss_data.status = ussd->dcs;
	ciss_data.status = ussd->status;
	ciss_data.length = ussd->len;
	memcpy(ciss_data.data, ussd->str, ciss_data.length);

	snprintf(slot_info, 2, "%d", slot_id);
	dbg("slot_id : [%s]", slot_info);

	dbg("Explicit launch CISS application by appsvc");

	kb = bundle_create();
	if (!kb) {
		warn("bundle_create() failed");
		return;
	}

	appsvc_set_pkgname(kb, CISS_APP);

	encoded_data = g_base64_encode((guchar *)&ciss_data, sizeof(CissDataType));

	appsvc_add_data(kb, "CISS_LAUNCHING_MODE", "RESP");
	appsvc_add_data(kb, "KEY_EVENT_TYPE", "100");
	appsvc_add_data(kb, "KEY_ENCODED_DATA", encoded_data);
	appsvc_add_data(kb, "KEY_SLOT_ID", slot_info);

	dbg("CISS appsvc run!");
	appsvc_run_service(kb, 0, NULL, NULL);

	bundle_free(kb);
	g_free(encoded_data);
}

static gboolean on_ss_activate_barring(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class,
	gint barring_mode, const gchar *barring_password,
	gpointer user_data)
{
	struct treq_ss_barring req;
	struct custom_data *ctx = user_data;
	char buf[MAX_SS_BARRING_PASSWORD_LEN + 1];

	if (!check_access_control(invocation, AC_SS, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_barring));

	req.class = ss_class;
	req.mode = barring_mode;

	memcpy(req.password, barring_password, MAX_SS_BARRING_PASSWORD_LEN);

	memcpy(buf, barring_password, MAX_SS_BARRING_PASSWORD_LEN);
	buf[MAX_SS_BARRING_PASSWORD_LEN] = '\0';
	dbg("Class: [%d] Barring - mode: [%d] password: [%s]",
		req.class, req.mode, buf);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_BARRING_ACTIVATE,
		&req, sizeof(struct treq_ss_barring));

	return TRUE;
}

static gboolean on_ss_deactivate_barring(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class,
	gint barring_mode, const gchar *barring_password,
	gpointer user_data)
{
	struct treq_ss_barring req;
	struct custom_data *ctx = user_data;
	char buf[MAX_SS_BARRING_PASSWORD_LEN + 1];

	if (!check_access_control(invocation, AC_SS, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_barring));

	req.class = ss_class;
	req.mode = barring_mode;

	memcpy(req.password, barring_password, MAX_SS_BARRING_PASSWORD_LEN);

	memcpy(buf, barring_password, MAX_SS_BARRING_PASSWORD_LEN);
	buf[MAX_SS_BARRING_PASSWORD_LEN] = '\0';
	dbg("Class: [%d] Barring - mode: [%d] password: [%s]",
		req.class, req.mode, buf);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_BARRING_DEACTIVATE,
		&req, sizeof(struct treq_ss_barring));

	return TRUE;
}

static gboolean on_ss_change_barring_password(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	const gchar *barring_password,
	const gchar *barring_password_new,
	const gchar *barring_password_confirm,
	gpointer user_data)
{
	struct treq_ss_barring_change_password req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_barring_change_password));

	memcpy(req.password_old, barring_password, MAX_SS_BARRING_PASSWORD_LEN);
	memcpy(req.password_new, barring_password_new, MAX_SS_BARRING_PASSWORD_LEN);
	memcpy(req.password_confirm, barring_password_confirm, MAX_SS_BARRING_PASSWORD_LEN);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_BARRING_CHANGE_PASSWORD,
		&req, sizeof(struct treq_ss_barring_change_password));

	return TRUE;
}

static gboolean on_ss_get_barring_status(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class, gint barring_mode,
	gpointer user_data)
{
	struct treq_ss_barring req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "r"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_barring));

	req.class = ss_class;
	req.mode = barring_mode;

	dbg("Class: [%d] Barring mode: [%d]", req.class, req.mode);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_BARRING_GET_STATUS,
		&req, sizeof(struct treq_ss_barring));

	return TRUE;
}

static gboolean on_ss_register_forwarding(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class,
	gint forward_mode,
	gint forward_no_reply_time,
	gint forward_ton, gint forward_npi, const gchar *forward_number,
	gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;
	req.time = forward_no_reply_time;
	req.ton  = forward_ton;
	req.npi  = forward_npi;
	snprintf(req.number, MAX_SS_FORWARDING_NUMBER_LEN, "%s", forward_number);

	dbg("Class: [%d] Forwarding - mode: [%d] time: [%d] number: [%s]",
		req.class, req.mode, req.time, req.number);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_FORWARDING_REGISTER,
		&req, sizeof(struct treq_ss_forwarding));

	return TRUE;
}

static gboolean on_ss_deregister_forwarding(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class,
	gint forward_mode,
	gint forward_no_reply_time,
	gint forward_ton, gint forward_npi, const gchar *forward_number,
	gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;
	req.time = forward_no_reply_time;
	req.ton = forward_ton;
	req.npi = forward_npi;
	snprintf(req.number, MAX_SS_FORWARDING_NUMBER_LEN, "%s", forward_number);

	dbg("Class: [%d] Forwarding - mode: [%d] time: [%d] number: [%s]",
		req.class, req.mode, req.time, req.number);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_FORWARDING_DEREGISTER,
		&req, sizeof(struct treq_ss_forwarding));

	return TRUE;
}

static gboolean on_ss_activate_forwarding(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class,
	gint forward_mode,
	gint forward_no_reply_time,
	gint forward_ton, gint forward_npi, const gchar *forward_number,
	gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;
	req.time = forward_no_reply_time;
	req.ton = forward_ton;
	req.npi = forward_npi;
	snprintf(req.number, MAX_SS_FORWARDING_NUMBER_LEN, "%s", forward_number);

	dbg("Class: [%d] Forwarding - mode: [%d] time: [%d] number: [%s]",
		req.class, req.mode, req.time, req.number);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_FORWARDING_ACTIVATE,
		&req, sizeof(struct treq_ss_forwarding));

	return TRUE;
}

static gboolean on_ss_deactivate_forwarding(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class,
	gint forward_mode,
	gint forward_no_reply_time,
	gint forward_ton, gint forward_npi, const gchar *forward_number,
	gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;
	req.time = forward_no_reply_time;
	req.ton = forward_ton;
	req.npi = forward_npi;
	snprintf(req.number, MAX_SS_FORWARDING_NUMBER_LEN, "%s", forward_number);

	dbg("Class: [%d] Forwarding - mode: [%d] time: [%d] number: [%s]",
		req.class, req.mode, req.time, req.number);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_FORWARDING_DEACTIVATE,
		&req, sizeof(struct treq_ss_forwarding));

	return TRUE;
}

static gboolean on_ss_get_forwarding_status(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class,
	gint forward_mode,
	gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "r"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;

	dbg("Class: [%d] Forwarding mode: [%d]", req.class, req.mode);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_FORWARDING_GET_STATUS,
		&req, sizeof(struct treq_ss_forwarding));

	return TRUE;
}

static gboolean on_ss_activate_waiting(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class, gpointer user_data)
{
	struct treq_ss_waiting req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_waiting));

	req.class = ss_class;

	dbg("Class: [%d]", req.class);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_WAITING_ACTIVATE,
		&req, sizeof(struct treq_ss_waiting));

	return TRUE;
}

static gboolean on_ss_deactivate_waiting(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class, gpointer user_data)
{
	struct treq_ss_waiting req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_waiting));

	req.class = ss_class;

	dbg("Class: [%d]", req.class);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_WAITING_DEACTIVATE,
		&req, sizeof(struct treq_ss_waiting));

	return TRUE;
}

static gboolean on_ss_get_waiting_status(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ss_class, gpointer user_data)
{
	struct treq_ss_waiting req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "r"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_waiting));

	req.class = ss_class;

	dbg("Class: [%d]", req.class);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_WAITING_GET_STATUS,
		&req, sizeof(struct treq_ss_waiting));

	return TRUE;
}

static gboolean on_ss_set_cli_status(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint cli_type, gint cli_status, gpointer user_data)
{
	struct treq_ss_set_cli req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "w"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_set_cli));

	req.type = cli_type;
	req.status = cli_status;

	dbg("CLI - type: [%d] status: [%d]", req.type, req.status);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_CLI_SET_STATUS,
		&req, sizeof(struct treq_ss_set_cli));

	return TRUE;
}


static gboolean on_ss_get_cli_status(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint cli_type, gpointer user_data)
{
	struct treq_ss_cli req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "r"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_cli));

	req.type = cli_type;

	dbg("CLI type: [%d]", req.type);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_CLI_GET_STATUS,
		&req, sizeof(struct treq_ss_cli));

	return TRUE;
}

static gboolean on_ss_send_ussd(TelephonySs *ss,
	GDBusMethodInvocation *invocation,
	gint ussd_type, gint ussd_dcs,
	gint ussd_len, const gchar *ussd_string,
	gpointer user_data)
{
	struct treq_ss_ussd req;
	struct custom_data *ctx = user_data;

	if (!check_access_control(invocation, AC_SS, "x"))
		return TRUE;

	memset(&req, 0x0, sizeof(struct treq_ss_ussd));

	req.type = ussd_type;
	req.dcs = (unsigned char)ussd_dcs;
	req.len = (unsigned short)ussd_len;

	snprintf((char *)req.str, MAX_SS_USSD_LEN, "%s", ussd_string);

	dbg("USSD - type: [%d] dcs: [%d] len: [%d] string: [%s]",
		req.type, req.dcs, req.len, req.str);

	/* Dispatch request */
	dtapi_dispatch_request(ctx, ss, invocation,
		TREQ_SS_SEND_USSD,
		&req, sizeof(struct treq_ss_ussd));

	return TRUE;
}

gboolean dbus_plugin_setup_ss_interface(TelephonyObjectSkeleton *object,
	struct custom_data *ctx)
{
	TelephonySs *ss;

	ss = telephony_ss_skeleton_new();
	telephony_object_skeleton_set_ss(object, ss);
	g_object_unref(ss);

	dbg("ss = %p", ss);

	/*
	 * Register signal handlers for SS interface
	 */
	g_signal_connect(ss,
		"handle-activate-barring",
		G_CALLBACK(on_ss_activate_barring), ctx);

	g_signal_connect(ss,
		"handle-deactivate-barring",
		G_CALLBACK(on_ss_deactivate_barring), ctx);

	g_signal_connect(ss,
		"handle-change-barring-password",
		G_CALLBACK(on_ss_change_barring_password), ctx);

	g_signal_connect(ss,
		"handle-get-barring-status",
		G_CALLBACK(on_ss_get_barring_status), ctx);

	g_signal_connect(ss,
		"handle-register-forwarding",
		G_CALLBACK(on_ss_register_forwarding), ctx);

	g_signal_connect(ss,
		"handle-deregister-forwarding",
		G_CALLBACK(on_ss_deregister_forwarding), ctx);

	g_signal_connect(ss,
		"handle-activate-forwarding",
		G_CALLBACK(on_ss_activate_forwarding), ctx);

	g_signal_connect(ss,
		"handle-deactivate-forwarding",
		G_CALLBACK(on_ss_deactivate_forwarding), ctx);

	g_signal_connect(ss,
		"handle-get-forwarding-status",
		G_CALLBACK(on_ss_get_forwarding_status), ctx);

	g_signal_connect(ss,
		"handle-activate-waiting",
		G_CALLBACK(on_ss_activate_waiting), ctx);

	g_signal_connect(ss,
		"handle-deactivate-waiting",
		G_CALLBACK(on_ss_deactivate_waiting), ctx);

	g_signal_connect(ss,
		"handle-get-waiting-status",
		G_CALLBACK(on_ss_get_waiting_status), ctx);

	g_signal_connect(ss,
		"handle-set-clistatus",
		G_CALLBACK(on_ss_set_cli_status), ctx);

	g_signal_connect(ss,
		"handle-get-clistatus",
		G_CALLBACK(on_ss_get_cli_status), ctx);

	g_signal_connect(ss,
		"handle-send-ussd",
		G_CALLBACK(on_ss_send_ussd), ctx);

	return TRUE;
}

gboolean dbus_plugin_ss_response(struct custom_data *ctx,
	UserRequest *ur, struct dbus_request_info *dbus_info,
	enum tcore_response_command command, unsigned int data_len, const void *data)
{
	GVariant *result = 0;
	GVariantBuilder b;
	int i = 0;

	if (!data) {
		err("response data : 0");
		return FALSE;
	}

	switch (command) {
	case TRESP_SS_BARRING_ACTIVATE: {
		const struct tresp_ss_barring *resp = data;

		dbg("receive TRESP_SS_BARRING_ACTIVATE (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_add(&b, "{sv}", "barring_mode",
				g_variant_new_int32(resp->record[i].mode));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_activate_barring(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_BARRING_DEACTIVATE: {
		const struct tresp_ss_barring *resp = data;

		dbg("receive TRESP_SS_BARRING_DEACTIVATE (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_add(&b, "{sv}", "barring_mode",
				g_variant_new_int32(resp->record[i].mode));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_deactivate_barring(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_BARRING_CHANGE_PASSWORD: {
		const struct tresp_ss_general *resp = data;

		dbg("receive TRESP_SS_BARRING_CHANGE_PASSWORD (err[%d])", resp->err);

		telephony_ss_complete_change_barring_password(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_SS_BARRING_GET_STATUS: {
		const struct tresp_ss_barring *resp = data;

		dbg("receive TRESP_SS_BARRING_GET_STATUS (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_add(&b, "{sv}", "barring_mode",
				g_variant_new_int32(resp->record[i].mode));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_get_barring_status(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_FORWARDING_ACTIVATE: {
		const struct tresp_ss_forwarding *resp = data;

		dbg("receive TRESP_SS_FORWARDING_ACTIVATE (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_add(&b, "{sv}", "forwarding_mode",
				g_variant_new_int32(resp->record[i].mode));
			g_variant_builder_add(&b, "{sv}", "number_present",
				g_variant_new_int32(resp->record[i].number_present));
			g_variant_builder_add(&b, "{sv}", "no_reply_time",
				g_variant_new_int32(resp->record[i].time));
			g_variant_builder_add(&b, "{sv}", "type_of_number",
				g_variant_new_int32(resp->record[i].ton));
			g_variant_builder_add(&b, "{sv}", "numbering_plan_identity",
				g_variant_new_int32(resp->record[i].npi));
			g_variant_builder_add(&b, "{sv}", "forwarding_number",
				g_variant_new_string(resp->record[i].number));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_activate_forwarding(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_FORWARDING_DEACTIVATE: {
		const struct tresp_ss_forwarding *resp = data;

		dbg("receive TRESP_SS_FORWARDING_DEACTIVATE (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_add(&b, "{sv}", "forwarding_mode",
				g_variant_new_int32(resp->record[i].mode));
			g_variant_builder_add(&b, "{sv}", "number_present",
				g_variant_new_int32(resp->record[i].number_present));
			g_variant_builder_add(&b, "{sv}", "no_reply_time",
				g_variant_new_int32(resp->record[i].time));
			g_variant_builder_add(&b, "{sv}", "type_of_number",
				g_variant_new_int32(resp->record[i].ton));
			g_variant_builder_add(&b, "{sv}", "numbering_plan_identity",
				g_variant_new_int32(resp->record[i].npi));
			g_variant_builder_add(&b, "{sv}", "forwarding_number",
				g_variant_new_string(resp->record[i].number));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_deactivate_forwarding(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_FORWARDING_REGISTER: {
		const struct tresp_ss_forwarding *resp = data;

		dbg("receive TRESP_SS_FORWARDING_REGISTER (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_add(&b, "{sv}", "forwarding_mode",
				g_variant_new_int32(resp->record[i].mode));
			g_variant_builder_add(&b, "{sv}", "number_present",
				g_variant_new_int32(resp->record[i].number_present));
			g_variant_builder_add(&b, "{sv}", "no_reply_time",
				g_variant_new_int32(resp->record[i].time));
			g_variant_builder_add(&b, "{sv}", "type_of_number",
				g_variant_new_int32(resp->record[i].ton));
			g_variant_builder_add(&b, "{sv}", "numbering_plan_identity",
				g_variant_new_int32(resp->record[i].npi));
			g_variant_builder_add(&b, "{sv}", "forwarding_number",
				g_variant_new_string(resp->record[i].number));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_register_forwarding(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_FORWARDING_DEREGISTER: {
		const struct tresp_ss_forwarding *resp = data;

		dbg("receive TRESP_SS_FORWARDING_DEREGISTER (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_add(&b, "{sv}", "forwarding_mode",
				g_variant_new_int32(resp->record[i].mode));
			g_variant_builder_add(&b, "{sv}", "number_present",
				g_variant_new_int32(resp->record[i].number_present));
			g_variant_builder_add(&b, "{sv}", "no_reply_time",
				g_variant_new_int32(resp->record[i].time));
			g_variant_builder_add(&b, "{sv}", "type_of_number",
				g_variant_new_int32(resp->record[i].ton));
			g_variant_builder_add(&b, "{sv}", "numbering_plan_identity",
				g_variant_new_int32(resp->record[i].npi));
			g_variant_builder_add(&b, "{sv}", "forwarding_number",
				g_variant_new_string(resp->record[i].number));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_deregister_forwarding(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_FORWARDING_GET_STATUS: {
		const struct tresp_ss_forwarding *resp = data;

		dbg("receive TRESP_SS_FORWARDING_GET_STATUS (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_add(&b, "{sv}", "forwarding_mode",
				g_variant_new_int32(resp->record[i].mode));
			g_variant_builder_add(&b, "{sv}", "number_present",
				g_variant_new_int32(resp->record[i].number_present));
			g_variant_builder_add(&b, "{sv}", "no_reply_time",
				g_variant_new_int32(resp->record[i].time));
			g_variant_builder_add(&b, "{sv}", "type_of_number",
				g_variant_new_int32(resp->record[i].ton));
			g_variant_builder_add(&b, "{sv}", "numbering_plan_identity",
				g_variant_new_int32(resp->record[i].npi));
			g_variant_builder_add(&b, "{sv}", "forwarding_number",
				g_variant_new_string(resp->record[i].number));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_get_forwarding_status(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_WAITING_ACTIVATE: {
		const struct tresp_ss_waiting *resp = data;

		dbg("receive TRESP_SS_WAITING_ACTIVATE (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_activate_waiting(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_WAITING_DEACTIVATE: {
		const struct tresp_ss_waiting *resp = data;

		dbg("receive TRESP_SS_WAITING_DEACTIVATE (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_deactivate_waiting(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_WAITING_GET_STATUS: {
		const struct tresp_ss_waiting *resp = data;

		dbg("receive TRESP_SS_WAITING_GET_STATUS (err[%d])", resp->err);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < resp->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(resp->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(resp->record[i].status));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_complete_get_waiting_status(dbus_info->interface_object,
			dbus_info->invocation, result, resp->err);
	}
	break;

	case TRESP_SS_CLI_SET_STATUS: {
		const struct tresp_ss_set_cli *resp = data;

		dbg("receive TRESP_SS_CLI_SET_STATUS (err[%d])", resp->err);

		telephony_ss_complete_set_clistatus(dbus_info->interface_object,
			dbus_info->invocation, resp->err);
	}
	break;

	case TRESP_SS_CLI_GET_STATUS: {
		const struct tresp_ss_cli *resp = data;

		dbg("receive TRESP_SS_CLI_GET_STATUS (err[%d])", resp->err);

		telephony_ss_complete_get_clistatus(dbus_info->interface_object,
			dbus_info->invocation, resp->err, resp->type, resp->status);
	}
	break;

	case TRESP_SS_SEND_USSD: {
		const struct tresp_ss_ussd *resp = data;

		dbg("receive TRESP_SS_SEND_USSD (err[%d])", resp->err);
		dbg("USSD - type: [0x%x] status: [0x%x] dcs: [0x%x] len: [%d] string: [%s])",
			resp->type, resp->status, resp->dcs, resp->len, resp->str);

		telephony_ss_complete_send_ussd(dbus_info->interface_object,
			dbus_info->invocation, resp->err,
			resp->type, resp->status, resp->dcs,
			resp->len, (char *)resp->str);
	}
	break;

	default:
		err("Unhandled/Unknown Response: [0x%x]", command);
	break;
	}

	return TRUE;
}

gboolean dbus_plugin_ss_notification(struct custom_data *ctx,
	CoreObject *source, TelephonyObjectSkeleton *object,
	enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonySs *ss = 0;
	GVariant *result = 0;
	GVariantBuilder b;
	int i = 0;
	char *cp_name = NULL;

	if (!object) {
		err("object is NULL");
		return FALSE;
	}

	if (!data) {
		err("data is NULL");
		return FALSE;
	}

	cp_name =  (char *)tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
	ss = telephony_object_peek_ss(TELEPHONY_OBJECT(object));
	if (ss == NULL) {
		err("ss object is NULL!!!");
		return FALSE;
	}

	switch (command) {
	case TNOTI_SS_USSD: {
		const struct tnoti_ss_ussd *ussd = data;
		enum dbus_tapi_sim_slot_id slot_id;

		dbg("[%s] SS_USSD - status: [0x%x] dcs: [0x%x] len: [%d] string: [%s])",
			cp_name, ussd->status, ussd->dcs, ussd->len, ussd->str);

		telephony_ss_emit_notify_ussd(ss,
				ussd->status,
				ussd->dcs,
				ussd->len,
				(char *)ussd->str);

		/*
		 * Launch CISS application for specific slot ID.
		 */
		slot_id = get_sim_slot_id_by_cp_name(cp_name);
		__launch_ciss(ussd, slot_id);
	}
	break;

	case TNOTI_SS_FORWARDING_STATUS: {
		const struct tnoti_ss_forwarding_status *fwrd = data;

		dbg("[%s] SS_FORWARDING_STATUS", cp_name);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < fwrd->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(fwrd->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(fwrd->record[i].status));
			g_variant_builder_add(&b, "{sv}", "forwarding_mode",
				g_variant_new_int32(fwrd->record[i].mode));
			g_variant_builder_add(&b, "{sv}", "number_present",
				g_variant_new_int32(fwrd->record[i].number_present));
			g_variant_builder_add(&b, "{sv}", "no_reply_time",
				g_variant_new_int32(fwrd->record[i].time));
			g_variant_builder_add(&b, "{sv}", "type_of_number",
				g_variant_new_int32(fwrd->record[i].ton));
			g_variant_builder_add(&b, "{sv}", "numbering_plan_identity",
				g_variant_new_int32(fwrd->record[i].npi));
			g_variant_builder_add(&b, "{sv}", "forwarding_number",
				g_variant_new_string(fwrd->record[i].number));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_emit_notify_forwarding(ss, result);
	}
	break;

	case TNOTI_SS_BARRING_STATUS: {
		const struct tnoti_ss_barring_status *barr = data;

		dbg("[%s] SS_BARRING_STATUS", cp_name);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < barr->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(barr->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(barr->record[i].status));
			g_variant_builder_add(&b, "{sv}", "barring_mode",
				g_variant_new_int32(barr->record[i].mode));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_emit_notify_barring(ss, result);
	}
	break;

	case TNOTI_SS_WAITING_STATUS: {
		const struct tnoti_ss_waiting_status *wait = data;

		dbg("[%s] SS_WAITING_STATUS", cp_name);

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		for (i = 0; i < wait->record_num; i++) {
			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&b, "{sv}", "ss_class",
				g_variant_new_int32(wait->record[i].class));
			g_variant_builder_add(&b, "{sv}", "ss_status",
				g_variant_new_int32(wait->record[i].status));
			g_variant_builder_close(&b);
		}
		result = g_variant_builder_end(&b);

		telephony_ss_emit_notify_waiting(ss, result);
	}
	break;

	case TNOTI_SS_RELEASE_COMPLETE: {
		int i = 0;
		GVariantBuilder builder;
		GVariant *msg_data = 0, *packet = NULL;
		const struct tnoti_ss_release_complete *msg = data;

		dbg("[%s] SS_RELEASE_COMPLETE", cp_name);

		if (msg) {
			g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
			for (i = 0; i < msg->data_len; i++)
				g_variant_builder_add(&builder, "y", msg->data[i]);
			msg_data = g_variant_builder_end(&builder);

			packet = g_variant_new("v", msg_data);
			dbg("type_format(%s)", g_variant_get_type_string(packet));

			telephony_ss_emit_release_complete(ss,
				msg->data_len, packet);
		} else {
			dbg("No data is passed in USSD release notification");

			g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
			g_variant_builder_add(&builder, "y", '\0');
			msg_data = g_variant_builder_end(&builder);

			packet = g_variant_new("v", msg_data);
			dbg("type_format(%s)", g_variant_get_type_string(packet));

			telephony_ss_emit_release_complete(ss,
				1, packet);
		}
	}
	break;

	case TNOTI_SS_INFO: {
		const struct tnoti_ss_information *ss_info = data;
		enum dbus_tapi_sim_slot_id slot_id;

		dbg("[%s] SS_INFO", cp_name);

		telephony_ss_emit_notify_ss_info(ss,
				ss_info->err,
				ss_info->ss_type);

		/*
		 * Launch CISS information.
		 */
		slot_id = get_sim_slot_id_by_cp_name(cp_name);
		__launch_ciss_information(ss_info, slot_id);
#if 0
		/* Launch CISS application */
		__launch_ciss(ss_info);
#endif
	}
	break;

	default:
		err("Unhandled/Unknown Notification: [0x%x]", command);
	break;
	}

	return TRUE;
}

