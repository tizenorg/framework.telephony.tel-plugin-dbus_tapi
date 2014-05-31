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

#define MAX_CALL_STATUS_NUM 7

static void _launch_voice_call( struct tnoti_call_status_incoming* incoming )
{
	char id[2] = {0, };
	char cli[2] = {0, };
	char forward[2] = {0, };
	char active_line[2] = {0, };
	char cna[2] = {0, };
	char number[83] = {0, };
	char name[83] = {0, };

	bundle *kb  = 0;

	snprintf( id, 2, "%d", incoming->id );
	dbg("id : [%s]", id );
	snprintf( cli, 2, "%d", incoming->cli.mode );
	dbg("cli : [%s]", id );
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

	kb = bundle_create();

	/* AppSvc */
	appsvc_set_operation(kb, APPSVC_OPERATION_CALL);
	appsvc_set_uri(kb,"tel:MT");

	appsvc_add_data(kb, "launch-type", "MT");
	appsvc_add_data(kb, "handle", id);
	appsvc_add_data(kb, "number", number);
	appsvc_add_data(kb, "name_mode", cna);
	appsvc_add_data(kb, "name", name);
	appsvc_add_data(kb, "clicause", cli);
	appsvc_add_data(kb, "fwded", forward);
	appsvc_add_data(kb, "activeline", active_line);

	appsvc_run_service(kb, 0, NULL, NULL);
	bundle_free(kb);
}

static void _launch_video_call( struct tnoti_call_status_incoming* incoming )
{
	char id[2] = {0, };
	char cli[2] = {0, };
	char forward[2] = {0, };
	char number[83] = {0, };
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

	kb = bundle_create();
	bundle_add(kb, "KEY_CALL_TYPE", "mt");
	bundle_add(kb, "KEY_CALL_HANDLE", id);
	bundle_add(kb, "KEY_CALLING_PARTY_NUMBER", number);
	bundle_add(kb, "KEY_CLI_CAUSE", cli);
	bundle_add(kb, "KEY_FORWARDED", forward);

	ret = aul_launch_app("com.samsung.vtmain", kb);
	bundle_free(kb);

	dbg("VT AUL return %d",ret);
}

static gboolean on_call_dial(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_type, gchar* call_number, gpointer user_data)
{
	struct treq_call_dial req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.type = call_type;

	if ( call_number )
		memcpy( req.number, call_number, MAX_CALL_DIAL_NUM_LEN );

	tcore_user_request_set_data( ur, sizeof( struct treq_call_dial ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_DIAL );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_dial(call, invocation, ret);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_answer(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gint answer_type, gpointer user_data)
{
	struct treq_call_answer req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.id = call_id;
	req.type = answer_type;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_answer ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_ANSWER );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_answer(call, invocation, ret, -1 );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_end(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gint end_type, gpointer user_data)
{
	struct treq_call_end req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.id = call_id;
	req.type = end_type;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_end ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_END );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_end(call, invocation, ret, -1, -1 );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_dtmf(TelephonyCall *call, GDBusMethodInvocation *invocation, gchar *dtmf_string, gpointer user_data)
{
	struct treq_call_dtmf req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	if ( dtmf_string )
		memcpy( req.digits, dtmf_string, MAX_CALL_DTMF_DIGITS_LEN );

	tcore_user_request_set_data( ur, sizeof( struct treq_call_dtmf ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SEND_DTMF );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_dtmf(call, invocation, ret);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_active(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_active req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_active ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_ACTIVE );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_active(call, invocation, ret, -1 );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_hold(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_hold req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_hold ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_HOLD );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_hold(call, invocation, ret, -1 );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_swap(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_swap req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_swap ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SWAP );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_swap(call, invocation, ret, -1 );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_join(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_join req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_join ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_JOIN );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_join(call, invocation, ret, -1 );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_split(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_split req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_split ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SPLIT );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_split(call, invocation, ret, -1 );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_transfer(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data)
{
	struct treq_call_transfer req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.id = call_id;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_transfer ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_TRANSFER );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_transfer(call, invocation, ret, -1 );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_deflect(TelephonyCall *call, GDBusMethodInvocation *invocation, gchar *call_number, gpointer user_data)
{
	struct treq_call_deflect req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	if ( call_number )
		memcpy( req.number, call_number, MAX_CALL_NUMBER_LEN );

	tcore_user_request_set_data( ur, sizeof( struct treq_call_deflect ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_DEFLECT );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_deflect(call, invocation, ret );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_get_status(TelephonyCall *call, GDBusMethodInvocation *invocation, gint call_id, gpointer user_data )
{
	struct custom_data *ctx = user_data;
	TcorePlugin *plugin = 0;
	CoreObject *o = 0;
	CallObject *co = 0;

	gchar call_number[MAX_CALL_NUMBER_LEN];
	gint call_type;
	gboolean call_direction;
	gint call_status;
	gboolean call_multiparty_state;
	char *cp_name = GET_PLUGIN_NAME(invocation);

	/* OSP access this function already, can't modify this immediately */

	plugin = tcore_server_find_plugin(ctx->server, cp_name);
	if ( !plugin ) {
		dbg("[ error ] plugin : 0");
		return FALSE;
	}

	o = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_CALL);
	if ( !o ) {
		dbg("no core object call");
		return FALSE;
	}

	co = tcore_call_object_find_by_id( o, call_id );
	if ( !co ) {
		dbg("[ error ] co : 0");
		return FALSE;
	}

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
	char *cp_name = GET_PLUGIN_NAME(invocation);

	int len, i;

	/* OSP access this function already, can't modify this immediately */

	plugin = tcore_server_find_plugin(ctx->server, cp_name);
	if ( !plugin ) {
		dbg("[ error ] plugin : 0");
		return FALSE;
	}

	o = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_CALL);
	if ( !o )
		return FALSE;

	g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

	for ( i=0; i<MAX_CALL_STATUS_NUM; i++ ) {
		list = tcore_call_object_find_by_status( o, i );

		if ( list ) {

			GSList *tmp = 0;
			tmp = list;

			dbg("[ check ] there is a call on state (0x%x)", i);

			while ( tmp ) {

				co = (CallObject*)list->data;
				if ( !co ) {
					dbg("[ error ] call object : 0");
					tmp = tmp->next;
					continue;
				}

				call_id = tcore_call_object_get_id( co );
				len = tcore_call_object_get_number( co, call_number );
				if ( !len ) {
					dbg("[ check ] no number : (0x%d)", call_id);
				}

				call_type = tcore_call_object_get_type( co );
				call_direction = tcore_call_object_get_direction( co );

				if ( call_direction == TCORE_CALL_DIRECTION_OUTGOING ) {
					call_direction = TRUE;
				} else {
					call_direction = FALSE;
				}

				call_status = tcore_call_object_get_status( co );
				call_multiparty_state = tcore_call_object_get_multiparty_state( co );

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

		} else {
			dbg("[ check ] there is no call on state (0x%x)", i);

		}

	}

	gv = g_variant_builder_end(&b);

	telephony_call_complete_get_status_all(call, invocation, gv);

	g_variant_unref(gv);

	return TRUE;
}

static gboolean on_call_set_sound_path(TelephonyCall *call, GDBusMethodInvocation *invocation, gint sound_path, gboolean extra_volume_on, gpointer user_data)
{
	struct treq_call_sound_set_path req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.path = sound_path;
	req.extra_volume_on = extra_volume_on;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_sound_set_path ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_PATH );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_set_sound_path(call, invocation, ret);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_get_volume(TelephonyCall *call, GDBusMethodInvocation *invocation, gint sound_device, gint sound_type, gpointer user_data)
{
	struct treq_call_sound_get_volume_level req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.device = sound_device;
	req.sound = sound_type;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_sound_get_volume_level ), &req );
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

		telephony_call_complete_get_volume(call, invocation, ret, result );

		g_variant_unref(result);

		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_set_volume(TelephonyCall *call, GDBusMethodInvocation *invocation, gint sound_device, gint sound_type, gint sound_volume, gpointer user_data)
{
	struct treq_call_sound_set_volume_level req;
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.device = sound_device;
	req.sound = sound_type;
	req.volume = sound_volume;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_sound_set_volume_level ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_VOLUME_LEVEL );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_set_volume(call, invocation, ret);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_get_mute_status(TelephonyCall *call, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "r") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	tcore_user_request_set_command( ur, TREQ_CALL_GET_MUTE_STATUS );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_get_mute_status(call, invocation, ret, -1);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_mute(TelephonyCall *call, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	tcore_user_request_set_command( ur, TREQ_CALL_MUTE );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_mute(call, invocation, ret);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_unmute(TelephonyCall *call, GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "x") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	tcore_user_request_set_command( ur, TREQ_CALL_UNMUTE );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_unmute(call, invocation, ret);
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_set_sound_recording(TelephonyCall *call, GDBusMethodInvocation *invocation, gint recording_state, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_sound_set_recording req;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.state = (gboolean)recording_state;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_sound_set_recording ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_RECORDING );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_set_sound_recording(call, invocation, ret );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_set_sound_equalization(TelephonyCall *call, GDBusMethodInvocation *invocation, gint eq_mode, gint eq_direction, gchar* eq_parameter, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_sound_set_equalization req;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.mode = (gboolean)eq_mode;
	req.direction = (enum telephony_call_sound_direction)eq_direction;
	memcpy( (char*)req.parameter, (const char*)eq_parameter, (MAX_CALL_EQ_PARAMETER_SIZE*2) );

	tcore_user_request_set_data( ur, sizeof( struct treq_call_sound_set_equalization ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_EQUALIZATION );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_set_sound_equalization(call, invocation, ret );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}

static gboolean on_call_set_sound_noise_reduction(TelephonyCall *call, GDBusMethodInvocation *invocation, gint nr_state, gpointer user_data)
{
	struct custom_data *ctx = user_data;
	struct treq_call_sound_set_noise_reduction req;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.status = (gboolean)nr_state;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_sound_set_noise_reduction ), &req );
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
	struct treq_call_sound_set_clock_status req;
	UserRequest *ur;
	TReturn ret = 0;

	if (check_access_control(invocation, AC_CALL, "w") == FALSE)
		return FALSE;

	ur = MAKE_UR(ctx, call, invocation);
	if (ur == NULL) {
		dbg("[ error ] ur : 0");
		return FALSE;
	}

	req.status = clock_status;

	tcore_user_request_set_data( ur, sizeof( struct treq_call_sound_set_clock_status ), &req );
	tcore_user_request_set_command( ur, TREQ_CALL_SET_SOUND_CLOCK_STATUS );

	ret = tcore_communicator_dispatch_request( ctx->comm, ur );
	if ( ret != TCORE_RETURN_SUCCESS ) {
		telephony_call_complete_set_sound_clock_status(call, invocation, ret );
		dbg("[ error ] tcore_communicator_dispatch_request() : (0x%x)", ret);
		tcore_user_request_unref(ur);
		return FALSE;
	}

	return TRUE;
}




gboolean dbus_plugin_setup_call_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonyCall *call;

	call = telephony_call_skeleton_new();
	telephony_object_skeleton_set_call(object, call);
	g_object_unref(call);

	dbg("call = %p", call);

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
			"handle-dtmf",
			G_CALLBACK (on_call_dtmf),
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
			"handle-get-volume",
			G_CALLBACK (on_call_get_volume),
			ctx);

	g_signal_connect (call,
			"handle-set-volume",
			G_CALLBACK (on_call_set_volume),
			ctx);

	g_signal_connect (call,
			"handle-get-mute-status",
			G_CALLBACK (on_call_get_mute_status),
			ctx);

	g_signal_connect (call,
			"handle-mute",
			G_CALLBACK (on_call_mute),
			ctx);

	g_signal_connect (call,
			"handle-unmute",
			G_CALLBACK (on_call_unmute),
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

	return TRUE;
}

gboolean dbus_plugin_call_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	int i = 0;
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

	co_call = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL);
	if (!co_call)
		return FALSE;

	switch (command) {
		case TRESP_CALL_DIAL: {
			struct tresp_call_dial *resp = (struct tresp_call_dial*)data;

			dbg("receive TRESP_CALL_DIAL");
			dbg("resp->err : [%d]", resp->err);

			telephony_call_complete_dial(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_ANSWER: {
			struct tresp_call_answer *resp = (struct tresp_call_answer*)data;

			dbg("receive TRESP_CALL_ANSWER");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->id : [%d]", resp->id);

			telephony_call_complete_answer(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_END: {
			struct tresp_call_end *resp = (struct tresp_call_end*)data;

			dbg("receive TRESP_CALL_END");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->id : [%d]", resp->err);
			dbg("resp->type : [%d]", resp->type);

			telephony_call_complete_end(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id, resp->type );

		} break;

		case TRESP_CALL_HOLD: {
			struct tresp_call_hold *resp = (struct tresp_call_hold*)data;

			dbg("receive TRESP_CALL_HOLD");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->id : [%d]", resp->id);

			telephony_call_complete_hold(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_ACTIVE: {
			struct tresp_call_active *resp = (struct tresp_call_active*)data;

			dbg("receive TRESP_CALL_ACTIVE");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->id : [%d]", resp->id);

			telephony_call_complete_active(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_SWAP: {
			struct tresp_call_swap *resp = (struct tresp_call_swap*)data;

			dbg("receive TRESP_CALL_SWAP");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->id : [%d]", resp->id);

			telephony_call_complete_swap(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_JOIN: {
			struct tresp_call_join *resp = (struct tresp_call_join*)data;

			dbg("receive TRESP_CALL_JOIN");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->id : [%d]", resp->id);

			telephony_call_complete_join(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;


		case TRESP_CALL_SPLIT: {
			struct tresp_call_split *resp = (struct tresp_call_split*)data;

			dbg("receive TRESP_CALL_SPLIT");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->id : [%d]", resp->id);

			telephony_call_complete_split(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_DEFLECT: {
			struct tresp_call_deflect *resp = (struct tresp_call_deflect*)data;

			dbg("receive TRESP_CALL_DEFLECT");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->id : [%d]", resp->id);

			telephony_call_complete_deflect(dbus_info->interface_object, dbus_info->invocation, resp->err );

		} break;

		case TRESP_CALL_TRANSFER: {
			struct tresp_call_transfer *resp = (struct tresp_call_transfer*)data;

			dbg("receive TRESP_CALL_TRANSFER");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->id : [%d]", resp->id);

			telephony_call_complete_transfer(dbus_info->interface_object, dbus_info->invocation, resp->err, resp->id );

		} break;

		case TRESP_CALL_SEND_DTMF: {
			struct tresp_call_dtmf *resp = (struct tresp_call_dtmf*)data;

			dbg("receive TRESP_CALL_SEND_DTMF");
			dbg("resp->err : [%d]", resp->err);

			telephony_call_complete_dtmf(dbus_info->interface_object, dbus_info->invocation, resp->err);
		} break;

		case TRESP_CALL_SET_SOUND_PATH: {
			struct tresp_call_sound_set_path *resp = (struct tresp_call_sound_set_path*)data;

			dbg("receive TRESP_CALL_SET_SOUND_PATH");
			dbg("resp->err : [%d]", resp->err);

			telephony_call_complete_set_sound_path(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err);
		} break;

		case TRESP_CALL_SET_SOUND_VOLUME_LEVEL: {
			struct tresp_call_sound_set_volume_level *resp = (struct tresp_call_sound_set_volume_level*)data;

			dbg("receive TRESP_CALL_SET_SOUND_VOLUME_LEVEL");
			dbg("resp->err : [%d]", resp->err);

			telephony_call_complete_set_volume(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err);
		} break;

		case TRESP_CALL_GET_SOUND_VOLUME_LEVEL: {
			struct tresp_call_sound_get_volume_level *resp = (struct tresp_call_sound_get_volume_level*)data;
			GVariant *result = 0;
			GVariantBuilder b;

			dbg("receive TRESP_CALL_GET_SOUND_VOLUME_LEVEL");

			g_variant_builder_init(&b, G_VARIANT_TYPE("aa{sv}"));

			g_variant_builder_open(&b, G_VARIANT_TYPE("a{sv}"));

			dbg("resp->err : [%d]", resp->err);

			g_variant_builder_add(&b, "{sv}", "err", g_variant_new_int32(resp->err));

			if ( !resp->err ) {

				dbg("resp->record_num : [%d]", resp->record_num);

				for ( i=0; i<resp->record_num; i++ ) {
					dbg("resp->type : [%d]", resp->record[i].sound);
					dbg("resp->level : [%d]", resp->record[i].volume);

					g_variant_builder_add(&b, "{sv}", "type", g_variant_new_int32(resp->record[i].sound));
					g_variant_builder_add(&b, "{sv}", "level", g_variant_new_int32(resp->record[i].volume));
				} 

			}

			g_variant_builder_close(&b);

			result = g_variant_builder_end(&b);

			telephony_call_complete_get_volume(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err, result );

			g_variant_unref(result);

		} break;

		case TRESP_CALL_MUTE: {
			struct tresp_call_mute *resp = (struct tresp_call_mute*)data;

			dbg("receive TRESP_CALL_MUTE");
			dbg("resp->err : [%d]", resp->err);

			telephony_call_complete_mute(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err);
		} break;

		case TRESP_CALL_UNMUTE: {
			struct tresp_call_unmute *resp = (struct tresp_call_unmute*)data;

			dbg("receive TRESP_CALL_UNMUTE");
			dbg("resp->err : [%d]", resp->err);

			telephony_call_complete_unmute(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err);
		} break;

		case TRESP_CALL_GET_MUTE_STATUS: {
			struct tresp_call_get_mute_status *resp = (struct tresp_call_get_mute_status*)data;

			dbg("receive TRESP_CALL_GET_MUTE_STATUS");
			dbg("resp->err : [%d]", resp->err);
			dbg("resp->status : [%d]", resp->status);

			telephony_call_complete_get_mute_status(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err, resp->status );

		} break;

		case TRESP_CALL_SET_SOUND_RECORDING: {
			struct tresp_call_sound_set_recording *resp = (struct tresp_call_sound_set_recording*)data;
			telephony_call_complete_set_sound_recording(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err );

		} break;

		case TRESP_CALL_SET_SOUND_EQUALIZATION: {
			struct tresp_call_sound_set_equalization *resp = (struct tresp_call_sound_set_equalization*)data;
			telephony_call_complete_set_sound_equalization(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err );

		} break;

		case TRESP_CALL_SET_SOUND_NOISE_REDUCTION: {
			struct tresp_call_sound_set_noise_reduction *resp = (struct tresp_call_sound_set_noise_reduction*)data;
			telephony_call_complete_set_sound_noise_reduction(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err );

		} break;

		case TRESP_CALL_SET_SOUND_CLOCK_STATUS: {
			struct tresp_call_sound_set_clock_status *resp = (struct tresp_call_sound_set_clock_status*)data;
			telephony_call_complete_set_sound_clock_status(dbus_info->interface_object, dbus_info->invocation, (gint)resp->err );

		} break;


		default:
			dbg("not handled command[%d]", command);
		break;

	}

	return TRUE;
}

gboolean dbus_plugin_call_notification(struct custom_data *ctx, const char *plugin_name, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyCall *call;

	if (!object) {
		dbg("object is 0");
		return FALSE;
	}

	call = telephony_object_peek_call(TELEPHONY_OBJECT(object));
	dbg("call = %p", call);

	switch (command) {
		case TNOTI_CALL_STATUS_IDLE: {
			struct tnoti_call_status_idle *idle = (struct tnoti_call_status_idle*)data;

			dbg("[ check ] call status : idle");

			if ( idle->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] this is voice call");
				telephony_call_emit_voice_call_status_idle( call, idle->id, idle->cause, 0, 0 );
			} else {
				dbg("[ check ] this is video call");
				telephony_call_emit_video_call_status_idle( call, idle->id, idle->cause, 0, 0 );
			}


		} break;
		case TNOTI_CALL_STATUS_DIALING: {
			struct tnoti_call_status_dialing *dialing = (struct tnoti_call_status_dialing*)data;

			dbg("[ check ] call status : dialing");
			dbg("[ check ] call type : (%d)", dialing->type);
			dbg("[ check ] call id : (%d)", dialing->id);

			if ( dialing->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] this is voice call");
				telephony_call_emit_voice_call_status_dialing( call, dialing->id );
			} else {
				dbg("[ check ] this is video call");
				telephony_call_emit_video_call_status_dialing( call, dialing->id );
			}

		} break;
		case TNOTI_CALL_STATUS_ALERT: {
			struct tnoti_call_status_alert *alert = (struct tnoti_call_status_alert*)data;

			dbg("[ check ] call status : alert");

			if ( alert->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] this is voice call");
				telephony_call_emit_voice_call_status_alert( call, alert->id );
			} else {
				dbg("[ check ] this is video call");
				telephony_call_emit_video_call_status_alert( call, alert->id );
			}

		} break;
		case TNOTI_CALL_STATUS_ACTIVE: {
			struct tnoti_call_status_active *active = (struct tnoti_call_status_active*)data;

			dbg("[ check ] call status : active");

			if ( active->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] this is voice call");
				telephony_call_emit_voice_call_status_active( call, active->id );
			} else {
				dbg("[ check ] this is video call");
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

			dbg("[ check ] call status : incoming");

			if ( incoming->type != CALL_TYPE_VIDEO ) {
				dbg("[ check ] this is voice call");

				telephony_call_emit_voice_call_status_incoming( call, incoming->id );

				_launch_voice_call( incoming );

			} else {
				dbg("[ check ] this is video call");
				telephony_call_emit_video_call_status_incoming( call, incoming->id );

				_launch_video_call( incoming );
			}

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

		default:
			dbg("not handled command[%d]", command);
		break;
	}

	return TRUE;
}

