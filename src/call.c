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

#include <aul.h>
#include <appsvc.h>
#include <bundle.h>
#include <tcore.h>
#include <plugin.h>
#include <server.h>
#include <storage.h>
#include <user_request.h>
#include <core_object.h>
#include <co_call.h>
#include <communicator.h>

#include "generated-code.h"
#include "common.h"


static void _launch_voice_call( struct tnoti_call_status_incoming* incoming, enum dbus_tapi_sim_slot_id slot_id )
{
	char id[2] = {0, };
	char cli[2] = {0, };
	char clicause[3] = {0, };
	char forward[2] = {0, };
	char active_line[2] = {0, };
	char cna[2] = {0, };
	char number[83] = {0, };
	char name[83] = {0, };
	char slot_info[2] = {0,};

	bundle *kb  = 0;

	snprintf( id, 2, "%d", incoming->id );
	dbg("id : [%s]", id );
	snprintf( cli, 2, "%d", incoming->cli.mode );
	dbg("cli : [%s]", cli );
	snprintf( clicause, 3, "%d", incoming->cli.no_cli_cause );
	dbg("clicause : [%s]", clicause );
	snprintf( number, 83, "%s", incoming->cli.number );
	dbg("number : [%s]", number );
	snprintf( forward, 2, "%d", incoming->forward );
	dbg("forward : [%s]", forward );
	snprintf( active_line, 2, "%d", incoming->active_line );
	dbg("active_line : [%s]", active_line );

	if ( incoming->cna.mode == CALL_CNA_MODE_PRESENT )
		snprintf( cna, 2, "%d", 0 );
	else
		snprintf( cna, 2, "%d", 1 );

	dbg("cna : [%s]", cna );
	snprintf( name, 83, "%s", incoming->cna.name );
	dbg("name : [%s]", name );

	snprintf(slot_info, 2, "%d", slot_id);
	dbg("slot_id : [%s]", slot_info);


	kb = bundle_create();

	/* AppSvc */
	appsvc_set_operation(kb, APPSVC_OPERATION_CALL);
	appsvc_set_uri(kb,"tel:MT");

	appsvc_add_data(kb, "launch-type", "MT");
	appsvc_add_data(kb, "handle", id);
	appsvc_add_data(kb, "number", number);
	appsvc_add_data(kb, "name_mode", cna);
	appsvc_add_data(kb, "name", name);
	appsvc_add_data(kb, "cli", cli);
	appsvc_add_data(kb, "clicause", clicause);
	appsvc_add_data(kb, "fwded", forward);
	appsvc_add_data(kb, "activeline", active_line);
	appsvc_add_data(kb, "slot_id", slot_info);

	appsvc_run_service(kb, 0, NULL, NULL);
	bundle_free(kb);
}

static void _launch_video_call( struct tnoti_call_status_incoming* incoming, enum dbus_tapi_sim_slot_id slot_id)
{
	char id[2] = {0, };
	char cli[2] = {0, };
	char forward[2] = {0, };
	char number[83] = {0, };
	char slot_info[2] = {0,};
	int ret = 0;

	bundle *kb  = 0;

	dbg("Func Entrance");

	snprintf( id, 2, "%d", incoming->id );
	dbg("id : [%s]", id );
	snprintf( number, 83, "%s", incoming->cli.number );
	dbg("number : [%s]", number );
	snprintf( cli, 2, "%d", incoming->cli.mode );
	dbg("cli : [%s]", id );
	snprintf( forward, 2, "%d", incoming->forward );
	dbg("forward : [%s]", forward );

	snprintf(slot_info, 2, "%d", slot_id);
	dbg("slot_id : [%s]", slot_info);

	kb = bundle_create();
	bundle_add(kb, "KEY_CALL_TYPE", "mt");
	bundle_add(kb, "KEY_CALL_HANDLE", id);
	bundle_add(kb, "KEY_CALLING_PARTY_NUMBER", number);
	bundle_add(kb, "KEY_CLI_CAUSE", cli);
	bundle_add(kb, "KEY_FORWARDED", forward);
	bundle_add(kb, "KEY_SLOT_ID", slot_info);


	ret = aul_launch_app("org.tizen.vtmain", kb);
	bundle_free(kb);

	dbg("VT AUL return %d",ret);
}

static gboolean on_call_dial(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_type, gint call_ecc, gchar* call_number, gpointer user_data)
{
	struct treq_call_dial req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	memset(&req, 0x0,sizeof(req));

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.type = call_type;
	req.ecc = call_ecc;

	if ( call_number ){
		g_strlcpy( req.number, call_number, MAX_CALL_DIAL_NUM_LEN);
	}

	dbg("dial len : %d, dial str : %s", strlen(req.number), req.number);

	tcore_user_request_set_data( ur, sizeof( struct treq_call_dial ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_DIAL );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_answer(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gint answer_type, gpointer user_data)
{
	struct treq_call_answer req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.id = call_id;
	req.type = answer_type;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_answer ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_ANSWER );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_end(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gint end_type, gpointer user_data)
{
	struct treq_call_end req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.id = call_id;
	req.type = end_type;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_end ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_END );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_start_cont_dtmf(TelephonyCall *call, GDBusMethodInvocation *invocation, guchar dtmf_digit, gpointer user_data)
{
	struct treq_call_start_cont_dtmf  req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);
	memset(&req, 0x0,sizeof(req));

	req.dtmf_digit = dtmf_digit;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_start_cont_dtmf ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_START_CONT_DTMF );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_stop_cont_dtmf(TelephonyCall *call, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	tcore_user_request_set_command( ur, TREQ_CALL_STOP_CONT_DTMF );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_send_burst_dtmf(TelephonyCall *call, GDBusMethodInvocation *invocation, gchar *dtmf_string, gint pulse_width, gint inter_digit_interval, gpointer user_data)
{
	struct treq_call_send_burst_dtmf req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);
	memset(&req, 0x0,sizeof(req));
	if ( dtmf_string ) {
		g_strlcpy( req.dtmf_string, dtmf_string, MAX_CALL_BURST_DTMF_STRING_LEN +1 );
	}
	else {
		FAIL_RESPONSE (invocation, "Invalid Input");
		err("Invalid DTMF string" );
		tcore_user_request_unref(ur);
		return TRUE;
	}


	req.pulse_width = pulse_width;
	req.inter_digit_interval = inter_digit_interval;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_send_burst_dtmf ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SEND_BURST_DTMF );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		err("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_active(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_active req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_active ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_ACTIVE );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_hold(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_hold req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_hold ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_HOLD );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_swap(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_swap req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_swap ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SWAP );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_join(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_join req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_join ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_JOIN );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_split(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_split req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_split ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SPLIT );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_transfer(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_transfer req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_transfer ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_TRANSFER );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_deflect(TelephonyCall *call, GDBusMethodInvocation *invocation, gchar *call_number, gpointer user_data)
{
	struct treq_call_deflect req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "x"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	if ( call_number ){
		g_strlcpy( req.number, call_number, MAX_CALL_DIAL_NUM_LEN);
	}

	tcore_user_request_set_data( ur, sizeof( struct treq_call_deflect ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_DEFLECT );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_get_privacy_mode(TelephonyCall *call, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);
	tcore_user_request_set_command( ur, TREQ_CALL_GET_PRIVACY_MODE );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_set_privacy_mode(TelephonyCall *call, GDBusMethodInvocation *invocation, gint privacy_mode, gpointer user_data)
{
	struct treq_call_set_voice_privacy_mode req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.privacy_mode = privacy_mode;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_set_voice_privacy_mode ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_PRIVACY_MODE );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_get_status(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data )
{
	struct custom_data *ctx = user_data;
	TcorePlugin *plugin = 0;
	GSList *o_list = 0;
	CoreObject *o = 0;
	CallObject *co = 0;

	gchar call_number[MAX_CALL_NUMBER_LEN];
	gint call_type;
	gboolean call_direction;
	gint call_status;
	gboolean call_multiparty_state;

	/* NOTE: Ignore access control */

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));

	o_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_CALL);
	if ( !o_list ) {
		dbg("[ error ] co_list : 0");
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}

	o = (CoreObject *)o_list->data;
	g_slist_free(o_list);

	co = tcore_call_object_find_by_id( o, call_id );
	if ( !co ) {
		dbg("[ error ] co : 0");
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}

	memset( call_number, 0, MAX_CALL_NUMBER_LEN );
	tcore_call_object_get_number( co, call_number );

	call_type = tcore_call_object_get_type( co );
	call_direction = tcore_call_object_get_direction( co );

	if ( call_direction == TCORE_CALL_DIRECTION_OUTGOING ) {
		call_direction = TRUE;
	} else {
		call_direction = FALSE;
	}

	call_status = tcore_call_object_get_status( co );
	call_multiparty_state = tcore_call_object_get_multiparty_state( co );


	telephony_call_complete_get_status(call, invocation,
			call_id, call_number, call_type, call_direction, call_status, call_multiparty_state );

	return TRUE;
}

static gboolean on_call_get_status_all(TelephonyCall *call, GDBusMethodInvocation *invocation, gpointer user_data )
{
	struct custom_data *ctx = user_data;
	TcorePlugin *plugin = 0;
	GSList *list = 0;
	CoreObject *o = 0;
	CallObject *co = 0;

	GVariant *gv = 0;
	GVariantBuilder b;

	gint call_id;
	gchar call_number[MAX_CALL_NUMBER_LEN];
	gint call_type;
	gboolean call_direction;
	gint call_status;
	gboolean call_multiparty_state;

	int len, i;

	if (!check_access_control (invocation, AC_CALL, "r"))
		return TRUE;

	plugin = tcore_server_find_plugin(ctx->server, GET_CP_NAME(invocation));

	list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_CALL);
	if ( !list ) {
		dbg("[ error ] co_list : 0");
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		return TRUE;
	}

	o = (CoreObject *)list->data;
	g_slist_free(list);

	g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

#define MAX_CALL_STATUS_NUM 7
	for ( i=0; i<MAX_CALL_STATUS_NUM; i++ ) {
		list = tcore_call_object_find_by_status( o, i );

		if ( list ) {

			GSList *tmp = 0;
			tmp = list;

			dbg("[ check ] there is  a call on state %s", i== TCORE_CALL_STATUS_IDLE?"(IDLE)":
								(i== TCORE_CALL_STATUS_ACTIVE?"(ACTIVE)":
								(i== TCORE_CALL_STATUS_HELD?"(HELD)":
								(i== TCORE_CALL_STATUS_DIALING?"(DIALING)":
								(i== TCORE_CALL_STATUS_ALERT?"(ALERT)":
								(i== TCORE_CALL_STATUS_INCOMING?"(INCOMING)":
								(i== TCORE_CALL_STATUS_WAITING?"(WAITING)":"(UNKNOWN)")))))));

			while ( tmp ) {

				co = (CallObject*)tmp->data;
				if ( !co ) {
					dbg("[ error ] call object : 0");
					tmp = tmp->next;
					continue;
				}

				call_id = tcore_call_object_get_id( co );

				memset( call_number, 0, MAX_CALL_NUMBER_LEN );
				len = tcore_call_object_get_number( co, call_number );

				call_type = tcore_call_object_get_type( co );
				call_direction = tcore_call_object_get_direction( co );

				if ( call_direction == TCORE_CALL_DIRECTION_OUTGOING ) {
					call_direction = TRUE;
				} else {
					call_direction = FALSE;
				}

				call_status = tcore_call_object_get_status( co );
				call_multiparty_state = tcore_call_object_get_multiparty_state( co );

				dbg("call_id                : %d", call_id);
				dbg("call_number_len        : %d", len);
				dbg("call_number            : \"%s\"", call_number);
				dbg("call_type              : %s (%d)", call_type==TCORE_CALL_TYPE_VOICE?"VOICE":
									(call_type==TCORE_CALL_TYPE_VIDEO?"VIDEO":
									(call_type==TCORE_CALL_TYPE_E911?"E911":
									(call_type==TCORE_CALL_TYPE_STDOTASP?"STDOTASP":
									(call_type==TCORE_CALL_TYPE_NONSTDOTASP?"NONSTDOTASP":"UNKNOWN")))), call_type);
				dbg("call_direction         : %s (%d)", call_direction==TRUE?"MO":"MT", call_direction);
				dbg("call_status            : %s (%d)", call_status== TCORE_CALL_STATUS_IDLE?"IDLE":
									(call_status== TCORE_CALL_STATUS_ACTIVE?"ACTIVE":
									(call_status== TCORE_CALL_STATUS_HELD?"HELD":
									(call_status== TCORE_CALL_STATUS_DIALING?"DIALING":
									(call_status== TCORE_CALL_STATUS_ALERT?"ALERT":
									(call_status== TCORE_CALL_STATUS_INCOMING?"INCOMING":
									(call_status== TCORE_CALL_STATUS_WAITING?"WAITING":"UNKNOWN")))))), call_status);
				dbg("call_multiparty_state  : %s (%d)", call_multiparty_state ==1?"T":"F", call_multiparty_state);

				g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
				g_variant_builder_add(&b, "{sv}", "call_id", g_variant_new_int32( call_id ));
				g_variant_builder_add(&b, "{sv}", "call_number", g_variant_new_string( call_number ));
				g_variant_builder_add(&b, "{sv}", "call_type", g_variant_new_int32( call_type ));
				g_variant_builder_add(&b, "{sv}", "call_direction", g_variant_new_boolean( call_direction ));
				g_variant_builder_add(&b, "{sv}", "call_state", g_variant_new_int32( call_status ));
				g_variant_builder_add(&b, "{sv}", "call_multiparty_state", g_variant_new_boolean( call_multiparty_state ));
				g_variant_builder_close(&b);

				tmp = g_slist_next( tmp );
			}
			g_slist_free(list);
		} else {
			dbg("[ check ] there is no call on state %s", i== TCORE_CALL_STATUS_IDLE?"(IDLE)":
								(i== TCORE_CALL_STATUS_ACTIVE?"(ACTIVE)":
								(i== TCORE_CALL_STATUS_HELD?"(HELD)":
								(i== TCORE_CALL_STATUS_DIALING?"(DIALING)":
								(i== TCORE_CALL_STATUS_ALERT?"(ALERT)":
								(i== TCORE_CALL_STATUS_INCOMING?"(INCOMING)":
								(i== TCORE_CALL_STATUS_WAITING?"(WAITING)":"(UNKNOWN)")))))));
		}

	}

	gv = g_variant_builder_end(&b);

	telephony_call_complete_get_status_all(call, invocation, gv);

	return TRUE;
}

static gboolean on_call_set_sound_path(TelephonyCall *call, GDBusMethodInvocation *invocation, gint sound_path, gboolean extra_volume_on, gpointer user_data)
{
	struct treq_call_set_sound_path req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.path = sound_path;
	req.extra_volume_on = extra_volume_on;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_set_sound_path ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_PATH );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_get_sound_volume_level(TelephonyCall *call, GDBusMethodInvocation *invocation, gint sound_device, gint sound_type, gpointer user_data)
{
	struct treq_call_get_sound_volume_level req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.device = sound_device;
	req.sound = sound_type;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_get_sound_volume_level ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_GET_SOUND_VOLUME_LEVEL );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {

		GVariantBuilder b;
		GVariant *result = 0;

		g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));
		g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));
		g_variant_builder_add(&b, "{sv}", "err", g_variant_new_int32(ret));
		g_variant_builder_close(&b);
		result = g_variant_builder_end(&b);

		telephony_call_complete_get_sound_volume_level(call, invocation, result, ret );

		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_set_sound_volume_level(TelephonyCall *call, GDBusMethodInvocation *invocation, gint sound_device, gint sound_type, gint sound_volume, gpointer user_data)
{
	struct treq_call_set_sound_volume_level req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.device = sound_device;
	req.sound = sound_type;
	req.volume = sound_volume;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_set_sound_volume_level ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_VOLUME_LEVEL );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_get_sound_mute_status(TelephonyCall *call, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	tcore_user_request_set_command( ur, TREQ_CALL_GET_SOUND_MUTE_STATUS );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_set_sound_mute_status(TelephonyCall *call, GDBusMethodInvocation *invocation, gint status, gint path, gpointer user_data)
{
	struct treq_call_set_sound_mute_status req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.path = path;
	req.status = status;

	dbg("[ check ] path : 0x%x, status : 0x%x", path, status);

	tcore_user_request_set_data( ur, sizeof( struct treq_call_set_sound_mute_status ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_MUTE_STATUS );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_set_sound_recording(TelephonyCall *call, GDBusMethodInvocation *invocation, gint recording_state, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_sound_recording req;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.state = (gboolean)recording_state;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_set_sound_recording ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_RECORDING );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_set_sound_equalization(TelephonyCall *call, GDBusMethodInvocation *invocation, gint eq_mode, gint eq_direction, gchar* eq_parameter, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_sound_equalization req;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.mode = eq_mode;
	req.direction = (enum telephony_call_sound_direction)eq_direction;
	memcpy( (char*)req.parameter, (const char*)eq_parameter, (MAX_CALL_EQ_PARAMETER_SIZE*2) );

	tcore_user_request_set_data( ur, sizeof( struct treq_call_set_sound_equalization ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_EQUALIZATION );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_set_sound_noise_reduction(TelephonyCall *call, GDBusMethodInvocation *invocation, gint nr_state, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_sound_noise_reduction req;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.status = (gboolean)nr_state;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_set_sound_noise_reduction ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_NOISE_REDUCTION );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_set_sound_noise_reduction(call, invocation, ret );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_set_sound_clock_status(TelephonyCall *call, GDBusMethodInvocation *invocation, gboolean clock_status, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_sound_clock_status req;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.status = clock_status;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_set_sound_clock_status ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_CLOCK_STATUS );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_set_preferred_voice_subscription(TelephonyCall *call, GDBusMethodInvocation *invocation,
	gint preferred_subscription, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_set_preferred_voice_subscription req;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	req.preferred_subs = preferred_subscription;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_set_preferred_voice_subscription ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_PREFERRED_VOICE_SUBSCRIPTION );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean on_call_get_preferred_voice_subscription(TelephonyCall *call, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (!check_access_control (invocation, AC_CALL, "r"))
		return TRUE;

	ur = MAKE_UR(ctx, call, invocation);

	tcore_user_request_set_command( ur, TREQ_CALL_GET_PREFERRED_VOICE_SUBSCRIPTION );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_call_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonyCall *call;

	call = telephony_call_skeleton_new();
	telephony_object_skeleton_set_call(object, call);
	g_object_unref(call);

	g_signal_connect (call,
			"handle-dial",
			G_CALLBACK (on_call_dial),
			ctx);

	g_signal_connect (call,
			"handle-answer",
			G_CALLBACK (on_call_answer),
			ctx);

	g_signal_connect (call,
			"handle-end",
			G_CALLBACK (on_call_end),
			ctx);

	g_signal_connect (call,
			"handle-start-cont-dtmf",
			G_CALLBACK (on_call_start_cont_dtmf),
			ctx);

	g_signal_connect (call,
			"handle-stop-cont-dtmf",
			G_CALLBACK (on_call_stop_cont_dtmf),
			ctx);

	g_signal_connect (call,
			"handle-send-burst-dtmf",
			G_CALLBACK (on_call_send_burst_dtmf),
			ctx);

	g_signal_connect (call,
			"handle-active",
			G_CALLBACK (on_call_active),
			ctx);

	g_signal_connect (call,
			"handle-hold",
			G_CALLBACK (on_call_hold),
			ctx);

	g_signal_connect (call,
			"handle-swap",
			G_CALLBACK (on_call_swap),
			ctx);

	g_signal_connect (call,
			"handle-join",
			G_CALLBACK (on_call_join),
			ctx);

	g_signal_connect (call,
			"handle-split",
			G_CALLBACK (on_call_split),
			ctx);

	g_signal_connect (call,
			"handle-transfer",
			G_CALLBACK (on_call_transfer),
			ctx);

	g_signal_connect (call,
			"handle-deflect",
			G_CALLBACK (on_call_deflect),
			ctx);

	g_signal_connect (call,
			"handle-get-privacy-mode",
			G_CALLBACK (on_call_get_privacy_mode),
			ctx);

	g_signal_connect (call,
			"handle-set-privacy-mode",
			G_CALLBACK (on_call_set_privacy_mode),
			ctx);

	g_signal_connect (call,
			"handle-get-status",
			G_CALLBACK (on_call_get_status),
			ctx);

	g_signal_connect (call,
			"handle-get-status-all",
			G_CALLBACK (on_call_get_status_all),
			ctx);


	g_signal_connect (call,
			"handle-set-sound-path",
			G_CALLBACK (on_call_set_sound_path),
			ctx);

	g_signal_connect (call,
			"handle-get-sound-volume-level",
			G_CALLBACK (on_call_get_sound_volume_level),
			ctx);

	g_signal_connect (call,
			"handle-set-sound-volume-level",
			G_CALLBACK (on_call_set_sound_volume_level),
			ctx);

	g_signal_connect (call,
			"handle-get-sound-mute-status",
			G_CALLBACK (on_call_get_sound_mute_status),
			ctx);

	g_signal_connect (call,
			"handle-set-sound-mute-status",
			G_CALLBACK (on_call_set_sound_mute_status),
			ctx);

	g_signal_connect (call,
			"handle-set-sound-recording",
			G_CALLBACK (on_call_set_sound_recording),
			ctx);

	g_signal_connect (call,
			"handle-set-sound-equalization",
			G_CALLBACK (on_call_set_sound_equalization),
			ctx);

	g_signal_connect (call,
			"handle-set-sound-noise-reduction",
			G_CALLBACK (on_call_set_sound_noise_reduction),
			ctx);

	g_signal_connect (call,
			"handle-set-sound-clock-status",
			G_CALLBACK (on_call_set_sound_clock_status),
			ctx);

	g_signal_connect (call,
			"handle-set-preferred-voice-subscription",
			G_CALLBACK (on_call_set_preferred_voice_subscription),
			ctx);

	g_signal_connect (call,
			"handle-get-preferred-voice-subscription",
			G_CALLBACK (on_call_get_preferred_voice_subscription),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_call_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	int i = 0;
	GSList *co_list;
	CoreObject *co_call;
	char *modem_name = NULL;
	TcorePlugin *p = NULL;

	modem_name = tcore_user_request_get_modem_name(ur);
	if (!modem_name)
		return FALSE;

	p = tcore_server_find_plugin(ctx->server, modem_name);
	free(modem_name);
	if (!p)
		return FALSE;

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_CALL);
	if (!co_list) {
		return FALSE;
	}

	co_call = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	if (!co_call) {
		return FALSE;
	}

	switch (command) {
		case TRESP_CALL_DIAL: {
			struct tresp_call_dial *resp = (struct tresp_call_dial*)data;

			dbg("receive TRESP_CALL_DIAL (err[%d])", resp->err);

			telephony_call_complete_dial(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_ANSWER: {
			struct tresp_call_answer *resp = (struct tresp_call_answer*)data;

			dbg("receive TRESP_CALL_ANSWER (err[%d] id[%d])", resp->err, resp->id);

			telephony_call_complete_answer(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_END: {
			struct tresp_call_end *resp = (struct tresp_call_end*)data;

			dbg("receive TRESP_CALL_END (err[%d] id[%d] type[%d])", resp->err, resp->id, resp->type);

			telephony_call_complete_end(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id, resp->type );

		} break;

		case TRESP_CALL_HOLD: {
			struct tresp_call_hold *resp = (struct tresp_call_hold*)data;

			dbg("receive TRESP_CALL_HOLD (err[%d] id[%d])", resp->err, resp->id);

			telephony_call_complete_hold(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_ACTIVE: {
			struct tresp_call_active *resp = (struct tresp_call_active*)data;

			dbg("receive TRESP_CALL_ACTIVE (err[%d] id[%d])", resp->err, resp->id);

			telephony_call_complete_active(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_SWAP: {
			struct tresp_call_swap *resp = (struct tresp_call_swap*)data;

 			dbg("receive TRESP_CALL_SWAP (err[%d] id[%d])", resp->err, resp->id);

			telephony_call_complete_swap(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_JOIN: {
			struct tresp_call_join *resp = (struct tresp_call_join*)data;

			dbg("receive TRESP_CALL_JOIN (err[%d] id[%d])", resp->err, resp->id);

			telephony_call_complete_join(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;


		case TRESP_CALL_SPLIT: {
			struct tresp_call_split *resp = (struct tresp_call_split*)data;

			dbg("receive TRESP_CALL_SPLIT (err[%d] id[%d])", resp->err, resp->id);

			telephony_call_complete_split(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_DEFLECT: {
			struct tresp_call_deflect *resp = (struct tresp_call_deflect*)data;

			dbg("receive TRESP_CALL_DEFLECT (err[%d] id[%d])", resp->err, resp->id);

			telephony_call_complete_deflect(dbus_info->interface_object, dbus_info->invocation, resp->err );

		} break;

		case TRESP_CALL_TRANSFER: {
			struct tresp_call_transfer *resp = (struct tresp_call_transfer*)data;

			dbg("receive TRESP_CALL_TRANSFER (err[%d] id[%d])", resp->err, resp->id);

			telephony_call_complete_transfer(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_START_CONT_DTMF: {
			struct tresp_call_dtmf *resp = (struct tresp_call_dtmf*)data;

			dbg("receive TRESP_CALL_START_CONT_DTMF (err[%d])", resp->err);

			telephony_call_complete_start_cont_dtmf(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_STOP_CONT_DTMF: {
			struct tresp_call_dtmf *resp = (struct tresp_call_dtmf*)data;

			dbg("receive TRESP_CALL_STOP_CONT_DTMF (err[%d])", resp->err);

			telephony_call_complete_stop_cont_dtmf(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_SEND_BURST_DTMF: {
			struct tresp_call_dtmf *resp = (struct tresp_call_dtmf*)data;

			dbg("receive TRESP_CALL_SEND_BURST_DTMF (err[%d])", resp->err);

			telephony_call_complete_send_burst_dtmf(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_GET_PRIVACY_MODE: {
			struct tresp_call_get_voice_privacy_mode *resp = (struct tresp_call_get_voice_privacy_mode*)data;

			dbg("receive TRESP_CALL_GET_PRIVACY_MODE (err[%d])", resp->err);
			dbg("Voice call privacy mode %d",resp->privacy_mode);

			telephony_call_complete_get_privacy_mode(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->privacy_mode);
		} break;

		case TRESP_CALL_SET_PRIVACY_MODE: {
			struct tresp_call_set_voice_privacy_mode *resp = (struct tresp_call_set_voice_privacy_mode *)data;

			dbg("receive TRESP_CALL_SET_PRIVACY_MODE (err[%d])", resp->err);

			telephony_call_complete_set_privacy_mode(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_SET_SOUND_PATH: {
			struct tresp_call_set_sound_path *resp = (struct tresp_call_set_sound_path*)data;

			dbg("receive TRESP_CALL_SET_SOUND_PATH (err[%d])", resp->err);

			telephony_call_complete_set_sound_path(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_SET_SOUND_VOLUME_LEVEL: {
			struct tresp_call_set_sound_volume_level *resp = (struct tresp_call_set_sound_volume_level*)data;

			dbg("receive TRESP_CALL_SET_SOUND_VOLUME_LEVEL (err[%d])", resp->err);

			telephony_call_complete_set_sound_volume_level(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_GET_SOUND_VOLUME_LEVEL: {
			struct tresp_call_get_sound_volume_level *resp = (struct tresp_call_get_sound_volume_level*)data;
			GVariant *result = 0;
			GVariantBuilder b;

			dbg("receive TRESP_CALL_GET_SOUND_VOLUME_LEVEL (err[%d])", resp->err);

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

			g_variant_builder_add(&b, "{sv}", "err", g_variant_new_int32(resp->err));

			if ( !resp->err ) {

				dbg("resp->record_num : [%d]", resp->record_num);

				for ( i=0; i<resp->record_num; i++ ) {
					dbg("sound_type : [%d], level:[%d]", resp->record[i].sound, resp->record[i].volume);
					g_variant_builder_add(&b, "{sv}", "type", g_variant_new_int32(resp->record[i].sound));
					g_variant_builder_add(&b, "{sv}", "level", g_variant_new_int32(resp->record[i].volume));
				}

			}

			g_variant_builder_close(&b);

			result = g_variant_builder_end(&b);

			telephony_call_complete_get_sound_volume_level(dbus_info->interface_object, dbus_info->invocation, result, resp->err );

		} break;

		case TRESP_CALL_SET_SOUND_MUTE_STATUS: {
			struct tresp_call_set_sound_mute_status *resp = (struct tresp_call_set_sound_mute_status*)data;

			dbg("receive TRESP_CALL_SET_SOUND_MUTE_STATUS (err[%d]", resp->err);
			telephony_call_complete_set_sound_mute_status(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_GET_SOUND_MUTE_STATUS: {
			struct tresp_call_get_sound_mute_status *resp = (struct tresp_call_get_sound_mute_status*)data;

			dbg("receive TRESP_CALL_GET_SOUND_MUTE_STATUS (err[%d] path[%d] status[%d])",
				resp->err, resp->path, resp->status);
			telephony_call_complete_get_sound_mute_status(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->path, resp->status );

		} break;

		case TRESP_CALL_SET_SOUND_RECORDING: {
			struct tresp_call_set_sound_recording *resp = (struct tresp_call_set_sound_recording*)data;
			telephony_call_complete_set_sound_recording(dbus_info->interface_object, dbus_info->invocation, resp->err );

		} break;

		case TRESP_CALL_SET_SOUND_EQUALIZATION: {
			struct tresp_call_set_sound_equalization *resp = (struct tresp_call_set_sound_equalization*)data;
			telephony_call_complete_set_sound_equalization(dbus_info->interface_object, dbus_info->invocation, resp->err );

		} break;

		case TRESP_CALL_SET_SOUND_NOISE_REDUCTION: {
			struct tresp_call_set_sound_noise_reduction *resp = (struct tresp_call_set_sound_noise_reduction*)data;
			telephony_call_complete_set_sound_noise_reduction(dbus_info->interface_object, dbus_info->invocation, resp->err );

		} break;

		case TRESP_CALL_SET_SOUND_CLOCK_STATUS: {
			struct tresp_call_set_sound_clock_status *resp = (struct tresp_call_set_sound_clock_status*)data;
			telephony_call_complete_set_sound_clock_status(dbus_info->interface_object, dbus_info->invocation, resp->err );

		} break;

		case TRESP_CALL_SET_PREFERRED_VOICE_SUBSCRIPTION: {
			struct tresp_call_set_preferred_voice_subscription *resp = (struct tresp_call_set_preferred_voice_subscription*)data;
			telephony_call_complete_set_preferred_voice_subscription(dbus_info->interface_object, dbus_info->invocation, resp->err );
		} break;

		case TRESP_CALL_GET_PREFERRED_VOICE_SUBSCRIPTION: {
			struct tresp_call_get_preferred_voice_subscription *resp = (struct tresp_call_get_preferred_voice_subscription*)data;
			telephony_call_complete_get_preferred_voice_subscription(dbus_info->interface_object, dbus_info->invocation,
				resp->preferred_subs, resp->err );
		} break;

		default:
			dbg("not handled command[%d]", command);
		break;

	}

	return TRUE;
}

gboolean dbus_plugin_call_notification(struct custom_data *ctx, CoreObject *source, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyCall *call;
	char *cp_name;

	if (!object) {
		dbg("object is 0");
		return FALSE;
	}
	cp_name = (char *)tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
	dbg("Notification!!! Command: [0x%x] CP Name: [%s]",
				command, cp_name);

	call = telephony_object_peek_call(TELEPHONY_OBJECT(object));

	switch (command) {
		case TNOTI_CALL_STATUS_IDLE: {
			struct tnoti_call_status_idle *idle = (struct tnoti_call_status_idle*)data;

			if ( idle->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] call status : idle (voice call)");
				telephony_call_emit_voice_call_status_idle( call, idle->id, idle->cause, 0, 0 );
			} else {
				dbg("[ check ] call status : idle (video call)");
				telephony_call_emit_video_call_status_idle( call, idle->id, idle->cause, 0, 0 );
			}

		} break;
		case TNOTI_CALL_STATUS_DIALING: {
			struct tnoti_call_status_dialing *dialing = (struct tnoti_call_status_dialing*)data;

			if ( dialing->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] call status : dialing (type[%d] id[%d]) (voice call)", dialing->type, dialing->id);
				telephony_call_emit_voice_call_status_dialing( call, dialing->id );
			} else {
				dbg("[ check ] call status : dialing (type[%d] id[%d]) (video call)", dialing->type, dialing->id);
				telephony_call_emit_video_call_status_dialing( call, dialing->id );
			}

		} break;
		case TNOTI_CALL_STATUS_ALERT: {
			struct tnoti_call_status_alert *alert = (struct tnoti_call_status_alert*)data;

			if ( alert->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] call status : alert (voice call)");
				telephony_call_emit_voice_call_status_alert( call, alert->id );
			} else {
				dbg("[ check ] call status : alert (video call)");
				telephony_call_emit_video_call_status_alert( call, alert->id );
			}

		} break;
		case TNOTI_CALL_STATUS_ACTIVE: {
			struct tnoti_call_status_active *active = (struct tnoti_call_status_active*)data;

			if ( active->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] call status : active (voice call)");
				telephony_call_emit_voice_call_status_active( call, active->id );
			} else {
				dbg("[ check ] call status : active (video call)");
				telephony_call_emit_video_call_status_active( call, active->id );
			}

		} break;
		case TNOTI_CALL_STATUS_HELD: {
			struct tnoti_call_status_held *held = (struct tnoti_call_status_held*)data;

			dbg("[ check ] call status : held");
			telephony_call_emit_voice_call_status_held( call, held->id );

		} break;
		case TNOTI_CALL_STATUS_INCOMING: {
			struct tnoti_call_status_incoming *incoming = (struct tnoti_call_status_incoming*)data;
			enum dbus_tapi_sim_slot_id slot_id;

			dbg("[ check ] call status : incoming");
			slot_id = get_sim_slot_id_by_cp_name(cp_name);

			if ( incoming->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] call status : incoming (voice call)");
				telephony_call_emit_voice_call_status_incoming( call, incoming->id );

				_launch_voice_call( incoming, slot_id);

			} else {
				dbg("[ check ] call status : incoming (video call)");
				telephony_call_emit_video_call_status_incoming( call, incoming->id );

				_launch_video_call( incoming, slot_id);
			}
		} break;

		case TNOTI_CALL_INFO_WAITING: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_WAITING : (%d)", *id);
			telephony_call_emit_waiting( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_FORWARDED: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_FORWARDED : (%d)", *id);
			telephony_call_emit_forwarded( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_FORWARDED_CALL: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_FORWARDED_CALL : (%d)", *id);
			telephony_call_emit_forwarded_call( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_BARRED_INCOMING: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_BARRED_INCOMING : (%d)", *id);
			telephony_call_emit_barred_incoming( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_BARRED_OUTGOING: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_BARRED_OUTGOING : (%d)", *id);
			telephony_call_emit_barred_outgoing( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_FORWARD_CONDITIONAL: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_FORWARD_CONDITIONAL : (%d)", *id);
			telephony_call_emit_forward_conditional( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_FORWARD_UNCONDITIONAL: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_FORWARD_UNCONDITIONAL : (%d)", *id);
			telephony_call_emit_forward_unconditional( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_HELD: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_HELD : (%d)", *id);
			telephony_call_emit_call_held( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_ACTIVE: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_ACTIVE : (%d)", *id);
			telephony_call_emit_call_active( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_JOINED: {
			int *id = (int*)data;

			dbg("[ check ] TNOTI_CALL_INFO_JOINED : (%d)", *id);
			telephony_call_emit_call_joined( call, (gint)*id );

		} break;

		case TNOTI_CALL_INFO_PRIVACY_MODE: {
			struct tnoti_call_info_voice_privacy_mode *privacy_info = (struct tnoti_call_info_voice_privacy_mode*)data;

			dbg("[ check ] TNOTI_CALL_INFO_PRIVACY_MODE : privacy mode ", privacy_info->privacy_mode);
			telephony_call_emit_call_privacy_mode( call, privacy_info->privacy_mode );

		} break;

		case TNOTI_CALL_OTASP_STATUS: {
			struct tnoti_call_otasp_status  *otasp = (struct tnoti_call_otasp_status *)data;

			dbg("[ check ] TNOTI_CALL_OTASP_STATUS : (%d)", otasp->otasp_status);
			telephony_call_emit_call_otasp_status( call, otasp->otasp_status );

		} break;

		case TNOTI_CALL_OTAPA_STATUS: {
			struct tnoti_call_otapa_status  *otapa = (struct tnoti_call_otapa_status *)data;

			dbg("[ check ] TNOTI_CALL_OTAPA_STATUS : (%d)", otapa->otapa_status);
			telephony_call_emit_call_otapa_status( call, otapa->otapa_status );

		} break;

		case TNOTI_CALL_SIGNAL_INFO: {

			struct tnoti_call_signal_info *sig_info = (struct tnoti_call_signal_info *)data;
			unsigned int signal;
			if (sig_info->signal_type == CALL_SIGNAL_TYPE_TONE) {
				signal = sig_info->signal.sig_tone_type;
			} else if(sig_info->signal_type == CALL_SIGNAL_TYPE_ISDN_ALERTING) {
				signal = sig_info->signal.sig_isdn_alert_type;
			} else if(sig_info->signal_type == CALL_SIGNAL_TYPE_IS54B_ALERTING) {
				signal = sig_info->signal.sig_is54b_alert_type;
			} else {
				err("Unknown Signal type");
				return FALSE;
			}
			dbg("[ check ] TNOTI_CALL_SIGNAL_INFO : Signal type (%d), Pitch type (%d), Signal %d", sig_info->signal_type, sig_info->pitch_type, signal);
			telephony_call_emit_call_signal_info( call, sig_info->signal_type, sig_info->pitch_type, signal);

		} break;

		case TNOTI_CALL_INFO_REC: {
				struct tnoti_call_info_rec *noti = (struct tnoti_call_info_rec *)data;
				gchar *param = NULL;
				if (noti->rec_info.type == CALL_REC_NAME_INFO) {
					param = g_strdup(noti->rec_info.data.name);
				} else if (noti->rec_info.type == CALL_REC_NUMBER_INFO) {
					param = g_strdup(noti->rec_info.data.number);
				} else {
					err("Unknown rec info type (%d)", noti->rec_info.type);
					return FALSE;
				}
				dbg("[ check ] TNOTI_CALL_INFO_REC : id:(%d) type:(%d), param:(%s)",
					noti->rec_info.id, noti->rec_info.type, param);
				telephony_call_emit_call_info_rec( call, noti->rec_info.id, noti->rec_info.type, param);
				g_free(param);
			} break;

		case TNOTI_CALL_SOUND_PATH: {
			struct tnoti_call_sound_path *noti = (struct tnoti_call_sound_path*)data;
			telephony_call_emit_call_sound_path( call, noti->path );


		} break;

		case TNOTI_CALL_SOUND_RINGBACK_TONE: {
			struct tnoti_call_sound_ringback_tone *noti = (struct tnoti_call_sound_ringback_tone*)data;
			telephony_call_emit_call_sound_ringback_tone( call, (gint)noti->status );

		} break;

		case TNOTI_CALL_SOUND_WBAMR: {
			struct tnoti_call_sound_wbamr *noti = (struct tnoti_call_sound_wbamr*)data;
			telephony_call_emit_call_sound_wbamr( call, (gint)noti->status );

		} break;

		case TNOTI_CALL_SOUND_EQUALIZATION: {
			struct tnoti_call_sound_equalization *noti = (struct tnoti_call_sound_equalization*)data;
			telephony_call_emit_call_sound_equalization( call, (gint)noti->mode, (gint)noti->direction );

		} break;

		case TNOTI_CALL_SOUND_NOISE_REDUCTION: {
			struct tnoti_call_sound_noise_reduction *noti = (struct tnoti_call_sound_noise_reduction*)data;
			telephony_call_emit_call_sound_noise_reduction( call, (gint)noti->status );

		} break;

		case TNOTI_CALL_SOUND_CLOCK_STATUS: {
			struct tnoti_call_sound_clock_status *noti = (struct tnoti_call_sound_clock_status*)data;
			telephony_call_emit_call_sound_clock_status( call, noti->status );

		} break;

		case TNOTI_CALL_PREFERRED_VOICE_SUBSCRIPTION: {
			struct tnoti_call_preferred_voice_subscription *noti = (struct tnoti_call_preferred_voice_subscription*)data;
			telephony_call_emit_call_preferred_voice_subscription( call, noti->preferred_subs );

		} break;

		default:
			dbg("not handled command[%d]", command);
		break;
	}

	return TRUE;
}

