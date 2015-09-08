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
#include <co_gps.h>
#include <co_sim.h>
#include <co_ps.h>

#include "generated-code.h"
#include "common.h"

static gboolean
on_gps_set_frequency_aiding (TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		guchar data,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_GPS, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, gps, invocation);
	dbg("data=%d",data);

	tcore_user_request_set_data(ur, sizeof(data), (const char*)&data);
	tcore_user_request_set_command(ur, TREQ_GPS_SET_FREQUENCY_AIDING);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_gps_confirm_measure_pos (TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		const gchar *data,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	gboolean result = TRUE;
	guchar *decoded_data = NULL;
	gsize length;

	if (!check_access_control (invocation, AC_GPS, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, gps, invocation);

	decoded_data = g_base64_decode(data, &length);
	dbg("decoded length=%d", length);
	tcore_user_request_set_data(ur, length, decoded_data);
	tcore_user_request_set_command(ur, TREQ_GPS_CONFIRM_MEASURE_POS);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
		g_free(decoded_data);
		return TRUE;
	}

	telephony_gps_complete_confirm_measure_pos(gps, invocation, result);
	g_free(decoded_data);

	return TRUE;
}

static gboolean
on_enable_smart_assistant(TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_GPS, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, gps, invocation);

	tcore_user_request_set_command(ur, TREQ_ENABLE_SMART_ASSISTANT);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_disable_smart_assistant(TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_GPS, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, gps, invocation);

	tcore_user_request_set_command(ur, TREQ_DISABLE_SMART_ASSISTANT);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_sync_smart_assistant_area_list(TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		gint count,
		GVariant *gv,
		gpointer user_data)
{
	struct tel_smart_assistant_area_list req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	GVariantIter *iter = NULL;
	GVariant *b = NULL;
	int i = 0;
	gint item1, item2;
	dbg("enter count=%d", count);

	if (!check_access_control (invocation, AC_GPS, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, gps, invocation);
	memset(&req,0,sizeof(struct tel_smart_assistant_area_list));

	dbg("count=%d", count);
	if (count > SMART_ASSISTANT_AREA_LIST_MAX)
		count = SMART_ASSISTANT_AREA_LIST_MAX;

	req.count = count;

	g_variant_get (gv, "v", &b);
	g_variant_unref (gv);

	g_variant_get (b, "a(ii)", &iter);
	while(g_variant_iter_loop(iter,"(ii)",&item1, &item2)){
		req.area[i].index = item1;
		req.area[i].mode_state = item2;
		i++;
		if (i == count)
			break;
	}
	g_variant_iter_free(iter);

	tcore_user_request_set_data(ur, sizeof(struct tel_smart_assistant_area_list), &req);
	tcore_user_request_set_command(ur, TREQ_SYNC_SMART_ASSISTANT_AREA_LIST);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_del_smart_assistant_area_list(TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		gint count,
		GVariant *gv,
		gpointer user_data)
{
	struct tel_smart_assistant_area_list req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	GVariantIter *iter = NULL;
	GVariant *b = NULL;
	int i = 0;
	gint item1, item2;

	if (!check_access_control (invocation, AC_GPS, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, gps, invocation);
	memset(&req,0,sizeof(struct tel_smart_assistant_area_list));

	dbg("count=%d", count);
	if (count > SMART_ASSISTANT_AREA_LIST_MAX)
		count = SMART_ASSISTANT_AREA_LIST_MAX;

	req.count = count;

	g_variant_get (gv, "v", &b);
	g_variant_unref (gv);

	g_variant_get (b, "a(ii)", &iter);
	while(g_variant_iter_loop(iter,"(ii)",&item1, &item2)){
		req.area[i].index = item1;
		req.area[i].mode_state = item2;
		i++;
		if (i == count)
			break;
	}
	g_variant_iter_free(iter);

	tcore_user_request_set_data(ur, sizeof(struct tel_smart_assistant_area_list), &req);
	tcore_user_request_set_command(ur, TREQ_DEL_SMART_ASSISTANT_AREA_LIST);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_add_smart_assistant_area(TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		gint fn_index,
		gint mode_state,
		gpointer user_data)
{
	struct tel_smart_assistant_area req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_GPS, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, gps, invocation);
	req.index = fn_index;
	req.mode_state = mode_state;
	dbg("index=%d, mode_state=%d",req.index, req.mode_state);

	tcore_user_request_set_data(ur, sizeof(struct tel_smart_assistant_area), &req);
	tcore_user_request_set_command(ur, TREQ_ADD_SMART_ASSISTANT_AREA);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}
static gboolean
on_modify_smart_assistant_area(TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		gint fn_index,
		gint mode_state,
		gpointer user_data)
{
	struct tel_smart_assistant_area req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_GPS, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, gps, invocation);
	req.index = fn_index;
	req.mode_state = mode_state;
	dbg("index=%d, mode_state=%d",req.index, req.mode_state);

	tcore_user_request_set_data(ur, sizeof(struct tel_smart_assistant_area), &req);
	tcore_user_request_set_command(ur, TREQ_MODIFY_SMART_ASSISTANT_AREA);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

static gboolean
on_set_smart_assistant_info(TelephonyGps *gps,
		GDBusMethodInvocation *invocation,
		gint fn_index,
		gint lpp_state,
		gpointer user_data)
{
	struct treq_set_smart_assistant_info req;
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;

	if (!check_access_control (invocation, AC_GPS, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, gps, invocation);
	req.index = fn_index;
	req.lpp_state = lpp_state;
	dbg("index=%d, lpp_state=%d",req.index, req.lpp_state);

	tcore_user_request_set_data(ur, sizeof(struct treq_set_smart_assistant_info), &req);
	tcore_user_request_set_command(ur, TREQ_SET_SMART_ASSISTANT_INFO);
	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
	}

	return TRUE;
}

gboolean dbus_plugin_setup_gps_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonyGps *gps;

	gps = telephony_gps_skeleton_new();
	telephony_object_skeleton_set_gps(object, gps);

	g_object_unref(gps);

	dbg("gps = %p", gps);

	g_signal_connect (gps,
			"handle-set-frequency-aiding",
			G_CALLBACK (on_gps_set_frequency_aiding),
			ctx);

	g_signal_connect (gps,
			"handle-confirm-measure-pos",
			G_CALLBACK (on_gps_confirm_measure_pos),
			ctx);

	g_signal_connect (gps,
			"handle-enable-smart-assistant",
			G_CALLBACK (on_enable_smart_assistant),
			ctx);

	g_signal_connect (gps,
			"handle-disable-smart-assistant",
			G_CALLBACK (on_disable_smart_assistant),
			ctx);

	g_signal_connect (gps,
			"handle-sync-smart-assistant-area-list",
			G_CALLBACK (on_sync_smart_assistant_area_list),
			ctx);

	g_signal_connect (gps,
			"handle-del-smart-assistant-area-list",
			G_CALLBACK (on_del_smart_assistant_area_list),
			ctx);

	g_signal_connect (gps,
			"handle-add-smart-assistant-area",
			G_CALLBACK (on_add_smart_assistant_area),
			ctx);

	g_signal_connect (gps,
			"handle-modify-smart-assistant-area",
			G_CALLBACK (on_modify_smart_assistant_area),
			ctx);

	g_signal_connect (gps,
			"handle-set-smart-assistant-info",
			G_CALLBACK (on_set_smart_assistant_info),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_gps_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	const struct tresp_gps_set_frequency_aiding *resp_gps_frequency_aiding = data;
	const struct tresp_smart_assistant_result *resp_smart_assistant_result = data;

	GSList *co_list;
	CoreObject *co_gps;
	char *modem_name = NULL;
	TcorePlugin *p = NULL;

	modem_name = tcore_user_request_get_modem_name(ur);
	if (!modem_name)
		return FALSE;

	p = tcore_server_find_plugin(ctx->server, modem_name);
	free(modem_name);
	if (!p)
		return FALSE;

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_GPS);
	if (!co_list) {
		return FALSE;
	}

	co_gps = (CoreObject *)co_list->data;
	g_slist_free(co_list);

	if (!co_gps) {
		return FALSE;
	}

	switch (command) {
		case TRESP_GPS_SET_FREQUENCY_AIDING:
			dbg("TRESP_GPS_SET_FREQUENCY_AIDING result=%d", resp_gps_frequency_aiding->result);
			telephony_gps_complete_set_frequency_aiding(dbus_info->interface_object, dbus_info->invocation, resp_gps_frequency_aiding->result);
			break;

		case TRESP_ENABLE_SMART_ASSISTANT:
			dbg("TRESP_ENABLE_SMART_ASSISTANT result=%d", resp_smart_assistant_result->result);
			telephony_gps_complete_enable_smart_assistant(dbus_info->interface_object, dbus_info->invocation, resp_smart_assistant_result->result);
			break;

		case TRESP_DISABLE_SMART_ASSISTANT:
			dbg("TRESP_ENABLE_SMART_ASSISTANT result=%d", resp_smart_assistant_result->result);
			telephony_gps_complete_disable_smart_assistant(dbus_info->interface_object, dbus_info->invocation, resp_smart_assistant_result->result);
			break;

		case TRESP_SYNC_SMART_ASSISTANT_AREA_LIST:
			dbg("TRESP_SYNC_SMART_ASSISTANT_AREA_LIST result=%d", resp_smart_assistant_result->result);
			telephony_gps_complete_sync_smart_assistant_area_list(dbus_info->interface_object, dbus_info->invocation, resp_smart_assistant_result->result);
			break;

		case TRESP_DEL_SMART_ASSISTANT_AREA_LIST:
			dbg("TRESP_DEL_SMART_ASSISTANT_AREA_LIST result=%d", resp_smart_assistant_result->result);
			telephony_gps_complete_del_smart_assistant_area_list(dbus_info->interface_object, dbus_info->invocation, resp_smart_assistant_result->result);
			break;

		case TRESP_ADD_SMART_ASSISTANT_AREA:
			dbg("TRESP_ADD_SMART_ASSISTANT_AREA result=%d", resp_smart_assistant_result->result);
			telephony_gps_complete_add_smart_assistant_area(dbus_info->interface_object, dbus_info->invocation, resp_smart_assistant_result->result);
			break;

		case TRESP_MODIFY_SMART_ASSISTANT_AREA:
			dbg("TRESP_MODIFY_SMART_ASSISTANT_AREA result=%d", resp_smart_assistant_result->result);
			telephony_gps_complete_modify_smart_assistant_area(dbus_info->interface_object, dbus_info->invocation, resp_smart_assistant_result->result);
			break;

		case TRESP_SET_SMART_ASSISTANT_INFO:
			dbg("TRESP_SET_SMART_ASSISTANT_INFO result=%d", resp_smart_assistant_result->result);
			telephony_gps_complete_set_smart_assistant_info(dbus_info->interface_object, dbus_info->invocation, resp_smart_assistant_result->result);
			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}

gboolean dbus_plugin_gps_notification(struct custom_data *ctx, CoreObject *source, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	TelephonyGps *gps;

	if (!object) {
		dbg("object is NULL");
		return FALSE;
	}
	dbg("Notification!!! Command: [0x%x] CP Name: [%s]",
				command, tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source)));

	gps = telephony_object_peek_gps(TELEPHONY_OBJECT(object));
	switch (command) {
		case TNOTI_GPS_ASSIST_DATA:
		{
			gchar *encoded_data = NULL;
			dbg("gps(%p) TNOTI_GPS_ASSIST_DATA. data=%p, data_len=%d", gps, data, data_len);
			encoded_data = g_base64_encode((const guchar*)data, data_len);
			telephony_gps_emit_assist_data(gps, encoded_data);
			g_free(encoded_data);
		}
			break;

		case TNOTI_GPS_MEASURE_POSITION:
		{
			gchar *encoded_data = NULL;
			dbg("gps(%p) TNOTI_GPS_MEASURE_POSITION. data=%p, data_len=%d", gps, data, data_len);
			encoded_data = g_base64_encode((const guchar*)data, data_len);
			telephony_gps_emit_measure_position(gps, encoded_data);
			g_free(encoded_data);
		}
			break;

		case TNOTI_GPS_RESET_ASSIST_DATA:
			dbg("gps(%p) TNOTI_GPS_RESET_ASSIST_DATA", gps);
			telephony_gps_emit_reset_assist_data(gps);
			break;

		case TNOTI_GPS_FREQUENCY_AIDING_DATA:
		{
			gchar *encoded_data = NULL;
			dbg("gps(%p) TNOTI_GPS_FREQUENCY_AIDING_DATA. data=%p, data_len=%d", gps, data, data_len);
			encoded_data = g_base64_encode((const guchar*)data, data_len);
			telephony_gps_emit_frequency_aiding(gps, encoded_data);
			g_free(encoded_data);
		}
			break;

		case TNOTI_SMART_ASSISTANT_AREA_STATUS:
		{
			const struct tnoti_smart_assistant_area_status *noti = data;
			dbg("gps(%p) TNOTI_SMART_ASSISTANT_AREA_STATUS", gps);
			telephony_gps_emit_area_status(gps, noti->area_status, noti->index);
		}
			break;

		case TNOTI_SMART_ASSISTANT_SYNC_STATUS:
		{
			const struct tnoti_smart_assistant_sync_status *noti = data;
			dbg("gps(%p) TNOTI_SMART_ASSISTANT_SYNC_STATUS", gps);
			telephony_gps_emit_sync_status(gps, noti->init_status, noti->init_fail_cause);
		}
			break;

		default:
			dbg("not handled cmd[0x%x]", command);
			break;
	}

	return TRUE;
}

