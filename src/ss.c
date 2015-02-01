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

#include <appsvc.h>
#include <bundle.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <hal.h>
#include <communicator.h>
#include <storage.h>
#include <queue.h>
#include <user_request.h>
#include <co_ss.h>
#include <co_sim.h>
#include <co_ps.h>

#include "generated-code.h"
#include "common.h"

struct ciss_data_type {
	int status;
	int dcs;
	int length;
	char data[MAX_SS_USSD_LEN];
};

struct ciss_information {
	int err;
	int ss_type;
};

static void _launch_ciss_information(const struct tnoti_ss_information *info)
{
	gchar *encoded_data;
	struct ciss_information ciss_inform;

	bundle *kb = NULL;

	memset(&ciss_inform, 0, sizeof(struct ciss_information));
	ciss_inform.err = info->err;
	ciss_inform.ss_type = info->ss_type;

	dbg("Explicit launch ciss application by appsvc");

	kb = bundle_create();
	if (!kb) {
		warn("bundle_create() failed");
		return;
	}

	appsvc_set_pkgname(kb, "org.tizen.ciss");

	encoded_data = g_base64_encode((guchar *)&ciss_inform, sizeof(struct ciss_information));

	appsvc_add_data(kb, "CISS_LAUNCHING_MODE", "RESP");
	appsvc_add_data(kb, "KEY_EVENT_TYPE", "200");
	appsvc_add_data(kb, "KEY_ENCODED_DATA", encoded_data);

	dbg("ciss appsvc run");
	appsvc_run_service(kb, 0, NULL, NULL);

	bundle_free(kb);
	g_free(encoded_data);

	return;
}


static void _launch_ciss(const struct tnoti_ss_ussd *ussd, enum dbus_tapi_sim_slot_id slot_id)
{
	gchar *encoded_data;
	struct ciss_data_type ciss_data;
	char slot_info[2] = {0,};

	bundle *kb = NULL;

	memset(&ciss_data, 0, sizeof(struct ciss_data_type));
	ciss_data.status = ussd->dcs;
	ciss_data.status = ussd->status;
	ciss_data.length = ussd->len;
	memcpy(ciss_data.data, ussd->str, ciss_data.length);

	snprintf(slot_info, 2, "%d", slot_id);
	dbg("slot_id : [%s]", slot_info);

	dbg("Explicit launch ciss application by appsvc");

	kb = bundle_create();
	if (!kb) {
		warn("bundle_create() failed");
		return;
	}


	appsvc_set_pkgname(kb, "org.tizen.ciss");

	encoded_data = g_base64_encode((guchar *)&ciss_data, sizeof(struct ciss_data_type));

	appsvc_add_data(kb, "CISS_LAUNCHING_MODE", "RESP");
	appsvc_add_data(kb, "KEY_EVENT_TYPE", "100");
	appsvc_add_data(kb, "KEY_ENCODED_DATA", encoded_data);
	appsvc_add_data(kb, "KEY_SLOT_ID", slot_info);

	dbg("ciss appsvc run");
	appsvc_run_service(kb, 0, NULL, NULL);

	bundle_free(kb);
	g_free(encoded_data);

	return;
}

static gboolean
on_ss_activate_barring (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gint barring_mode,
		const gchar *barring_password,
		gpointer user_data)
{
	char buf[5];
	struct treq_ss_barring req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_barring));

	req.class = ss_class;
	req.mode = barring_mode;

	memcpy(req.password, barring_password, MAX_SS_BARRING_PASSWORD_LEN);
	memcpy(buf, barring_password, MAX_SS_BARRING_PASSWORD_LEN);

	buf[4] = 0;
	dbg("req.password = [%s]", buf);

	dbg("class = %d, mode = %d", req.class, req.mode);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_barring), &req);
	tcore_user_request_set_command(ur, TREQ_SS_BARRING_ACTIVATE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_deactivate_barring (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gint barring_mode,
		const gchar *barring_password,
		gpointer user_data)
{
	char buf[5];
	struct treq_ss_barring req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_barring));

	req.class = ss_class;
	req.mode = barring_mode;

	memcpy(req.password, barring_password, MAX_SS_BARRING_PASSWORD_LEN);
	memcpy(buf, barring_password, MAX_SS_BARRING_PASSWORD_LEN);

	buf[4] = 0;
	dbg("req.password = [%s]", buf);
	dbg("class = %d, mode = %d", req.class, req.mode);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_barring), &req);
	tcore_user_request_set_command(ur, TREQ_SS_BARRING_DEACTIVATE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_change_barring_password (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		const gchar *barring_password,
		const gchar *barring_password_new,
		const gchar *barring_password_confirm,
		gpointer user_data)
{
	char buf[5];
	struct treq_ss_barring_change_password req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_barring_change_password));

	memcpy(req.password_old, barring_password, MAX_SS_BARRING_PASSWORD_LEN);
	memcpy(req.password_new, barring_password_new, MAX_SS_BARRING_PASSWORD_LEN);
	memcpy(req.password_confirm, barring_password_confirm, MAX_SS_BARRING_PASSWORD_LEN);

	memcpy(buf, barring_password, MAX_SS_BARRING_PASSWORD_LEN);
	buf[4] = 0;

	memcpy(buf, barring_password_new, MAX_SS_BARRING_PASSWORD_LEN);

	memcpy(buf, barring_password_confirm, MAX_SS_BARRING_PASSWORD_LEN);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_barring_change_password), &req);
	tcore_user_request_set_command(ur, TREQ_SS_BARRING_CHANGE_PASSWORD);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_get_barring_status (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gint barring_mode,
		gpointer user_data)
{
	struct treq_ss_barring req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_barring));

	req.class = ss_class;
	req.mode = barring_mode;

	dbg("class = %d, mode = %d", req.class, req.mode);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_barring), &req);
	tcore_user_request_set_command(ur, TREQ_SS_BARRING_GET_STATUS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_register_forwarding (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gint forward_mode,
		gint forward_no_reply_time,
		gint forward_ton,
		gint forward_npi,
		const gchar *forward_number,
		gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	if (!check_access_control (invocation, AC_SS, "w")) {
		GVariant *result = 0;
		GVariantBuilder b;

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		result = g_variant_builder_end(&b);

		telephony_ss_complete_register_forwarding(ss, invocation, result, ret);

		return TRUE;
	}

	memset(&req, 0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;
	req.time = forward_no_reply_time;
	req.ton  = forward_ton;
	req.npi  = forward_npi;
	snprintf(req.number, MAX_SS_FORWARDING_NUMBER_LEN, "%s", forward_number);

	dbg("class = %d, mode = %d, time = %d, number = %s",
			req.class, req.mode, req.time, req.number);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_forwarding), &req);
	tcore_user_request_set_command(ur, TREQ_SS_FORWARDING_REGISTER);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_deregister_forwarding (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gint forward_mode,
		gint forward_no_reply_time,
		gint forward_ton,
		gint forward_npi,
		const gchar *forward_number,
		gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	if (!check_access_control (invocation, AC_SS, "w")) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	memset(&req, 0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;
	req.time = forward_no_reply_time;
	req.ton = forward_ton;
	req.npi = forward_npi;
	snprintf(req.number, MAX_SS_FORWARDING_NUMBER_LEN, "%s", forward_number);

	dbg("class = %d, mode = %d, time = %d, number = %s",
			req.class, req.mode, req.time, req.number);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_forwarding), &req);
	tcore_user_request_set_command(ur, TREQ_SS_FORWARDING_DEREGISTER);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_activate_forwarding (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gint forward_mode,
		gint forward_no_reply_time,
		gint forward_ton,
		gint forward_npi,
		const gchar *forward_number,
		gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	if (!check_access_control (invocation, AC_SS, "w")) {
		GVariant *result = 0;
		GVariantBuilder b;

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		result = g_variant_builder_end(&b);

		telephony_ss_complete_activate_forwarding(ss, invocation, result, ret);

		return TRUE;
	}

	memset(&req, 0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;
	req.time = forward_no_reply_time;
	req.ton = forward_ton;
	req.npi = forward_npi;
	snprintf(req.number, MAX_SS_FORWARDING_NUMBER_LEN, "%s", forward_number);

	dbg("class = %d, mode = %d, time = %d, number = %s",
			req.class, req.mode, req.time, req.number);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_forwarding), &req);
	tcore_user_request_set_command(ur, TREQ_SS_FORWARDING_ACTIVATE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_deactivate_forwarding (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gint forward_mode,
		gint forward_no_reply_time,
		gint forward_ton,
		gint forward_npi,
		const gchar *forward_number,
		gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	if (!check_access_control (invocation, AC_SS, "w")) {
		GVariant *result = 0;
		GVariantBuilder b;

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		result = g_variant_builder_end(&b);

		telephony_ss_complete_deactivate_forwarding(ss, invocation, result, ret);

		return TRUE;
	}

	memset(&req, 0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;
	req.time = forward_no_reply_time;
	req.ton = forward_ton;
	req.npi = forward_npi;
	snprintf(req.number, MAX_SS_FORWARDING_NUMBER_LEN, "%s", forward_number);

	dbg("class = %d, mode = %d, time = %d, number = %s",
			req.class, req.mode, req.time, req.number);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_forwarding), &req);
	tcore_user_request_set_command(ur, TREQ_SS_FORWARDING_DEACTIVATE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_get_forwarding_status (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gint forward_mode,
		gpointer user_data)
{
	struct treq_ss_forwarding req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	if (!check_access_control (invocation, AC_SS, "r")) {
		GVariant *result = 0;
		GVariantBuilder b;

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		result = g_variant_builder_end(&b);

		telephony_ss_complete_get_forwarding_status(ss, invocation, result, ret);

		return TRUE;
	}

	memset(&req, 0, sizeof(struct treq_ss_forwarding));

	req.class = ss_class;
	req.mode = forward_mode;

	dbg("class = %d, mode = %d, time = %d, number = %s",
			req.class, req.mode, req.time, req.number);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_forwarding), &req);
	tcore_user_request_set_command(ur, TREQ_SS_FORWARDING_GET_STATUS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_activate_waiting (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gpointer user_data)
{
	struct treq_ss_waiting req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_waiting));

	req.class = ss_class;

	dbg("class = %d", req.class);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_waiting), &req);
	tcore_user_request_set_command(ur, TREQ_SS_WAITING_ACTIVATE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_deactivate_waiting (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gpointer user_data)
{
	struct treq_ss_waiting req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_waiting));

	req.class = ss_class;

	dbg("class = %d", req.class);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_waiting), &req);
	tcore_user_request_set_command(ur, TREQ_SS_WAITING_DEACTIVATE);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_get_waiting_status (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ss_class,
		gpointer user_data)
{
	struct treq_ss_waiting req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_waiting));

	req.class = ss_class;

	dbg("class = %d", req.class);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_waiting), &req);
	tcore_user_request_set_command(ur, TREQ_SS_WAITING_GET_STATUS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_set_cli_status (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint cli_type,
		gint cli_status,
		gpointer user_data)
{
	struct treq_ss_set_cli req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_set_cli));

	req.type = cli_type;
	req.status = cli_status;

	dbg("type = %d, status = %d", req.type, req.status);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_set_cli), &req);
	tcore_user_request_set_command(ur, TREQ_SS_CLI_SET_STATUS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}


static gboolean
on_ss_get_cli_status (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint cli_type,
		gpointer user_data)
{
	struct treq_ss_cli req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_cli));

	req.type = cli_type;

	dbg("type = %d", req.type);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_cli), &req);
	tcore_user_request_set_command(ur, TREQ_SS_CLI_GET_STATUS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_ss_send_ussd (TelephonySs *ss,
		GDBusMethodInvocation *invocation,
		gint ussd_type,
		gint ussd_dcs,
		gint ussd_len,
		const gchar *ussd_string,
		gpointer user_data)
{
	struct treq_ss_ussd req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	int ret = 0;

	memset(&req, 0, sizeof(struct treq_ss_ussd));

	req.type = ussd_type;
	req.dcs = (unsigned char)ussd_dcs;
	req.len = (unsigned short)ussd_len;

	snprintf((char*)req.str, MAX_SS_USSD_LEN, "%s", ussd_string);

	dbg("[ check ] type = %d, dcs = %d, len = %d, string = %s", req.type, req.dcs, req.len, req.str);

	ur = MAKE_UR(ctx, ss, invocation);

	tcore_user_request_set_data(ur, sizeof(struct treq_ss_ussd), &req);
	tcore_user_request_set_command(ur, TREQ_SS_SEND_USSD);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_ss_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonySs *ss;

	ss = telephony_ss_skeleton_new();
	telephony_object_skeleton_set_ss(object, ss);
	g_object_unref(ss);

	g_signal_connect (ss,
			"handle-activate-barring",
			G_CALLBACK (on_ss_activate_barring),
			ctx);

	g_signal_connect (ss,
			"handle-deactivate-barring",
			G_CALLBACK (on_ss_deactivate_barring),
			ctx);

	g_signal_connect (ss,
			"handle-change-barring-password",
			G_CALLBACK (on_ss_change_barring_password),
			ctx);

	g_signal_connect (ss,
			"handle-get-barring-status",
			G_CALLBACK (on_ss_get_barring_status),
			ctx);

	g_signal_connect (ss,
			"handle-register-forwarding",
			G_CALLBACK (on_ss_register_forwarding),
			ctx);

	g_signal_connect (ss,
			"handle-deregister-forwarding",
			G_CALLBACK (on_ss_deregister_forwarding),
			ctx);

	g_signal_connect (ss,
			"handle-activate-forwarding",
			G_CALLBACK (on_ss_activate_forwarding),
			ctx);

	g_signal_connect (ss,
			"handle-deactivate-forwarding",
			G_CALLBACK (on_ss_deactivate_forwarding),
			ctx);

	g_signal_connect (ss,
			"handle-get-forwarding-status",
			G_CALLBACK (on_ss_get_forwarding_status),
			ctx);

	g_signal_connect (ss,
			"handle-activate-waiting",
			G_CALLBACK (on_ss_activate_waiting),
			ctx);

	g_signal_connect (ss,
			"handle-deactivate-waiting",
			G_CALLBACK (on_ss_deactivate_waiting),
			ctx);

	g_signal_connect (ss,
			"handle-get-waiting-status",
			G_CALLBACK (on_ss_get_waiting_status),
			ctx);

	g_signal_connect (ss,
			"handle-set-clistatus",
			G_CALLBACK (on_ss_set_cli_status),
			ctx);

	g_signal_connect (ss,
			"handle-get-clistatus",
			G_CALLBACK (on_ss_get_cli_status),
			ctx);

	g_signal_connect (ss,
			"handle-send-ussd",
			G_CALLBACK (on_ss_send_ussd),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_ss_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	GVariant *result = 0;
	GVariantBuilder b;
	int i = 0;

	if ( !data ) {
		err("response data : 0");
		return FALSE;
	}

	switch (command) {
		case TRESP_SS_BARRING_ACTIVATE: {

			const struct tresp_ss_barring *resp = data;

			dbg("receive TRESP_SS_BARRING_ACTIVATE (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "barring_mode", g_variant_new_int32( resp->record[i].mode ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_activate_barring(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_BARRING_DEACTIVATE: {

			const struct tresp_ss_barring *resp = data;

			dbg("receive TRESP_SS_BARRING_DEACTIVATE (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "barring_mode", g_variant_new_int32( resp->record[i].mode ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_deactivate_barring(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_BARRING_CHANGE_PASSWORD: {

			const struct tresp_ss_general *resp = data;

			dbg("receive TRESP_SS_BARRING_CHANGE_PASSWORD (err[%d])", resp->err);

			telephony_ss_complete_change_barring_password(dbus_info->interface_object, dbus_info->invocation, resp->err);

		} break;

		case TRESP_SS_BARRING_GET_STATUS: {

			const struct tresp_ss_barring *resp = data;

			dbg("receive TRESP_SS_BARRING_GET_STATUS (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "barring_mode", g_variant_new_int32( resp->record[i].mode ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_get_barring_status(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_FORWARDING_ACTIVATE: {
			const struct tresp_ss_forwarding *resp = data;

			dbg("receive TRESP_SS_FORWARDING_ACTIVATE (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "forwarding_mode", g_variant_new_int32( resp->record[i].mode ));
				g_variant_builder_add(&b, "{sv}", "number_present", g_variant_new_int32( resp->record[i].number_present ));
				g_variant_builder_add(&b, "{sv}", "no_reply_time", g_variant_new_int32( resp->record[i].time ));
				g_variant_builder_add(&b, "{sv}", "type_of_number", g_variant_new_int32( resp->record[i].ton ));
				g_variant_builder_add(&b, "{sv}", "numbering_plan_identity", g_variant_new_int32( resp->record[i].npi ));
				g_variant_builder_add(&b, "{sv}", "forwarding_number", g_variant_new_string( resp->record[i].number ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_activate_forwarding(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_FORWARDING_DEACTIVATE: {

			const struct tresp_ss_forwarding *resp = data;

			dbg("receive TRESP_SS_FORWARDING_DEACTIVATE (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "forwarding_mode", g_variant_new_int32( resp->record[i].mode ));
				g_variant_builder_add(&b, "{sv}", "number_present", g_variant_new_int32( resp->record[i].number_present ));
				g_variant_builder_add(&b, "{sv}", "no_reply_time", g_variant_new_int32( resp->record[i].time ));
				g_variant_builder_add(&b, "{sv}", "type_of_number", g_variant_new_int32( resp->record[i].ton ));
				g_variant_builder_add(&b, "{sv}", "numbering_plan_identity", g_variant_new_int32( resp->record[i].npi ));
				g_variant_builder_add(&b, "{sv}", "forwarding_number", g_variant_new_string( resp->record[i].number ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_deactivate_forwarding(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_FORWARDING_REGISTER: {

			const struct tresp_ss_forwarding *resp = data;

			dbg("receive TRESP_SS_FORWARDING_REGISTER (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "forwarding_mode", g_variant_new_int32( resp->record[i].mode ));
				g_variant_builder_add(&b, "{sv}", "number_present", g_variant_new_int32( resp->record[i].number_present ));
				g_variant_builder_add(&b, "{sv}", "no_reply_time", g_variant_new_int32( resp->record[i].time ));
				g_variant_builder_add(&b, "{sv}", "type_of_number", g_variant_new_int32( resp->record[i].ton ));
				g_variant_builder_add(&b, "{sv}", "numbering_plan_identity", g_variant_new_int32( resp->record[i].npi ));
				g_variant_builder_add(&b, "{sv}", "forwarding_number", g_variant_new_string( resp->record[i].number ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_register_forwarding(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

	    } break;

		case TRESP_SS_FORWARDING_DEREGISTER: {

			const struct tresp_ss_forwarding *resp = data;

			dbg("receive TRESP_SS_FORWARDING_DEREGISTER (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "forwarding_mode", g_variant_new_int32( resp->record[i].mode ));
				g_variant_builder_add(&b, "{sv}", "number_present", g_variant_new_int32( resp->record[i].number_present ));
				g_variant_builder_add(&b, "{sv}", "no_reply_time", g_variant_new_int32( resp->record[i].time ));
				g_variant_builder_add(&b, "{sv}", "type_of_number", g_variant_new_int32( resp->record[i].ton ));
				g_variant_builder_add(&b, "{sv}", "numbering_plan_identity", g_variant_new_int32( resp->record[i].npi ));
				g_variant_builder_add(&b, "{sv}", "forwarding_number", g_variant_new_string( resp->record[i].number ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_deregister_forwarding(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_FORWARDING_GET_STATUS: {

			const struct tresp_ss_forwarding *resp = data;

			dbg("receive TRESP_SS_FORWARDING_GET_STATUS (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "forwarding_mode", g_variant_new_int32( resp->record[i].mode ));
				g_variant_builder_add(&b, "{sv}", "number_present", g_variant_new_int32( resp->record[i].number_present ));
				g_variant_builder_add(&b, "{sv}", "no_reply_time", g_variant_new_int32( resp->record[i].time ));
				g_variant_builder_add(&b, "{sv}", "type_of_number", g_variant_new_int32( resp->record[i].ton ));
				g_variant_builder_add(&b, "{sv}", "numbering_plan_identity", g_variant_new_int32( resp->record[i].npi ));
				g_variant_builder_add(&b, "{sv}", "forwarding_number", g_variant_new_string( resp->record[i].number ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_get_forwarding_status(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_WAITING_ACTIVATE: {

			const struct tresp_ss_waiting *resp = data;

			dbg("receive TRESP_SS_WAITING_ACTIVATE (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_activate_waiting(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_WAITING_DEACTIVATE: {

			const struct tresp_ss_waiting *resp = data;

			dbg("receive TRESP_SS_WAITING_DEACTIVATE (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_deactivate_waiting(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_WAITING_GET_STATUS: {

			const struct tresp_ss_waiting *resp = data;

			dbg("receive TRESP_SS_WAITING_GET_STATUS (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<resp->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( resp->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( resp->record[i].status ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);

			telephony_ss_complete_get_waiting_status(dbus_info->interface_object, dbus_info->invocation, result, resp->err);

		} break;

		case TRESP_SS_CLI_SET_STATUS: {

			const struct tresp_ss_set_cli *resp = data;

			dbg("receive TRESP_SS_CLI_SET_STATUS (err[%d])", resp->err);

			telephony_ss_complete_set_clistatus(dbus_info->interface_object, dbus_info->invocation, resp->err);

		} break;

		case TRESP_SS_CLI_GET_STATUS: {

			const struct tresp_ss_cli *resp = data;

			dbg("receive TRESP_SS_CLI_GET_STATUS (err[%d])", resp->err);

			telephony_ss_complete_get_clistatus(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->type, resp->status);

		} break;

		case TRESP_SS_SEND_USSD: {

			const struct tresp_ss_ussd *resp = data;

			dbg("receive TRESP_SS_SEND_USSD (err[%d])", resp->err);
			dbg("USSD : %s (len : %d, type : 0x%x, status : 0x%x, dcs : 0x%x)", resp->str, resp->len, resp->type, resp->status, resp->dcs);
			telephony_ss_complete_send_ussd(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->type, resp->status, resp->dcs, resp->len, (char*)resp->str);

		} break;

		default:
			dbg("not handled command[%d]", command);
		break;
	}

	return TRUE;
}

gboolean dbus_plugin_ss_notification(struct custom_data *ctx, CoreObject *source, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonySs *ss = 0;
	GVariant *result = 0;
	GVariantBuilder b;
	int i = 0;
	char *cp_name= NULL;

	if (!object) {
		dbg("object is NULL");
		return FALSE;
	}
	cp_name =  (char*)tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));

	ss = telephony_object_peek_ss(TELEPHONY_OBJECT(object));

	switch (command) {
		case TNOTI_SS_USSD: {
			const struct tnoti_ss_ussd *ussd = data;
			enum dbus_tapi_sim_slot_id slot_id;

			slot_id = get_sim_slot_id_by_cp_name(cp_name);
			dbg("slot_id: [%d]", slot_id);

			telephony_ss_emit_notify_ussd(ss,
					ussd->status,
					ussd->dcs,
					ussd->len,
					(char*)ussd->str);
			_launch_ciss(ussd, slot_id);
		} break;

		case TNOTI_SS_FORWARDING_STATUS: {
			const struct tnoti_ss_forwarding_status *fwrd = data;

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<fwrd->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( fwrd->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( fwrd->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "forwarding_mode", g_variant_new_int32( fwrd->record[i].mode ));
				g_variant_builder_add(&b, "{sv}", "number_present", g_variant_new_int32( fwrd->record[i].number_present ));
				g_variant_builder_add(&b, "{sv}", "no_reply_time", g_variant_new_int32( fwrd->record[i].time ));
				g_variant_builder_add(&b, "{sv}", "type_of_number", g_variant_new_int32( fwrd->record[i].ton ));
				g_variant_builder_add(&b, "{sv}", "numbering_plan_identity", g_variant_new_int32( fwrd->record[i].npi ));
				g_variant_builder_add(&b, "{sv}", "forwarding_number", g_variant_new_string( fwrd->record[i].number ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);
			telephony_ss_emit_notify_forwarding(ss, result);

		} break;

		case TNOTI_SS_BARRING_STATUS: {

			const struct tnoti_ss_barring_status *barr = data;

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<barr->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( barr->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( barr->record[i].status ));
				g_variant_builder_add(&b, "{sv}", "barring_mode", g_variant_new_int32( barr->record[i].mode ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);
			telephony_ss_emit_notify_barring(ss, result);

		} break;

		case TNOTI_SS_WAITING_STATUS: {
			const struct tnoti_ss_waiting_status *wait = data;

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			for (i=0; i<wait->record_num; i++) {
				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "ss_class", g_variant_new_int32( wait->record[i].class ));
				g_variant_builder_add(&b, "{sv}", "ss_status", g_variant_new_int32( wait->record[i].status ));
				g_variant_builder_close(&b);
			}

			result = g_variant_builder_end(&b);
			telephony_ss_emit_notify_waiting(ss, result);

		} break;

		case TNOTI_SS_RELEASE_COMPLETE: {
			int i = 0;
			GVariantBuilder builder;
			GVariant *msg_data = 0, *packet = NULL;
			const struct tnoti_ss_release_complete *msg = data;
			if (msg) {
				g_variant_builder_init(&builder, G_VARIANT_TYPE ("ay"));
				for (i = 0; i < msg->data_len; i++) {
					g_variant_builder_add(&builder, "y", msg->data[i]);
				}
				msg_data = g_variant_builder_end(&builder);
				packet = g_variant_new("v", msg_data);

				dbg("type_format(%s)", g_variant_get_type_string(packet));
				telephony_ss_emit_release_complete(ss, msg->data_len, packet );
			} else {
				dbg("No data is passed in USSD release notification");
				g_variant_builder_init(&builder, G_VARIANT_TYPE ("ay"));
				g_variant_builder_add(&builder, "y", '\0');
				msg_data = g_variant_builder_end(&builder);
				packet = g_variant_new("v", msg_data);
				dbg("type_format(%s)", g_variant_get_type_string(packet));
				telephony_ss_emit_release_complete(ss, 1, packet);
			}
		} break;
		case TNOTI_SS_INFO: {
			const struct tnoti_ss_information *ss_info = data;
			telephony_ss_emit_notify_ss_info(ss,
					ss_info->err,
					ss_info->ss_type);
			_launch_ciss_information(ss_info);
			/* Launch CISS application
			_launch_ciss(ss_info);
			*/
		} break;
		default:
			dbg("not handled command[%d]", command);
		break;
	}

	return TRUE;
}

