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
#include <queue.h>
#include <user_request.h>

#include "generated-code.h"
#include "common.h"

#define TYPE_FACTORY		0x00020000
#define MAKE_REQ_CMD(id)	(TREQ_CUSTOM|TYPE_FACTORY|id)
#define GET_OEM_ID(cmd)	(cmd&0x0000FFFF)

static void _emit_oem_response(struct dbus_request_info *dbus_info, int oem_id, const void *data, unsigned int data_len)
{
	if (!dbus_info || !oem_id || !data || !data_len) {
		dbg("Invalid Data! dbus_info=%p, oem_id=0x%x, data=%p, data_len=%d", dbus_info, oem_id, data, data_len);
		return ;
	}

	if (dbus_info->interface_object) {
		gchar *encoded_data = g_base64_encode((const guchar*)data, data_len);
		if (dbus_info->invocation) {
			telephony_oem_complete_send_oem_data_with_response(dbus_info->interface_object, dbus_info->invocation, oem_id, encoded_data);
		} else {
			telephony_oem_emit_oem_data(dbus_info->interface_object, oem_id, encoded_data);
		}
		g_free(encoded_data);
	}
}

static void _emit_oem_notification(TelephonyOEM *oem, int oem_id, const void *data, unsigned int data_len)
{
	gchar *encoded_data = NULL;

	if (!oem || !oem_id || !data || !data_len) {
		dbg("Invalid Data! oem=%p, oem_id=0x%x, data=%p, data_len=%d", oem, oem_id, data, data_len);
		return ;
	}

	encoded_data = g_base64_encode((const guchar*)data, data_len);
	telephony_oem_emit_oem_data(oem, oem_id, encoded_data);
	g_free(encoded_data);
}

static gboolean
send_oem_data(TelephonyOEM *oem,
	GDBusMethodInvocation *invocation,
	gint arg_oem_id,
	const gchar *arg_data,
	gpointer user_data,
	gboolean remove_invocation)
{
	struct custom_data *ctx = user_data;
	UserRequest *ur = NULL;
	TReturn ret;
	gint result = 1;
	guchar *decoded_data = NULL;
	gsize length;

	if (!check_access_control (invocation, AC_MODEM, "w"))
		return TRUE;

	ur = MAKE_UR(ctx, oem, invocation);
	decoded_data = g_base64_decode(arg_data, &length);

	tcore_user_request_set_data(ur, length, decoded_data);
	g_free(decoded_data);

	tcore_user_request_set_command(ur, MAKE_REQ_CMD(arg_oem_id));

	ret = tcore_communicator_dispatch_request(ctx->comm, ur);
	if (ret != TCORE_RETURN_SUCCESS) {
		FAIL_RESPONSE (invocation, DEFAULT_MSG_REQ_FAILED);
		tcore_user_request_unref(ur);
		return TRUE;
	}

	if (remove_invocation) {
		struct dbus_request_info *dbus_info = tcore_user_request_ref_user_info(ur);
		if (dbus_info)
			dbus_info->invocation = NULL;

		telephony_oem_complete_send_oem_data(oem, invocation, result);
	}
	return TRUE;
}

static gboolean
on_send_oem_data (TelephonyOEM *oem,
	GDBusMethodInvocation *invocation,
	gint arg_oem_id,
	const gchar *arg_data,
	gpointer user_data)
{
	return send_oem_data(oem, invocation, arg_oem_id, arg_data, user_data, TRUE);
}

static gboolean
on_send_oem_data_with_response (TelephonyOEM *oem,
	GDBusMethodInvocation *invocation,
	gint arg_oem_id,
	const gchar *arg_data,
	gpointer user_data)
{
	return send_oem_data(oem, invocation, arg_oem_id, arg_data, user_data, FALSE);
}

gboolean dbus_plugin_setup_oem_interface(TelephonyObjectSkeleton *object, struct custom_data *ctx)
{
	TelephonyOEM *oem;

	oem = telephony_oem_skeleton_new();
	telephony_object_skeleton_set_oem(object, oem);

	g_object_unref(oem);

	dbg("oem = %p", oem);

	g_signal_connect (oem,
			"handle-send-oem-data",
			G_CALLBACK (on_send_oem_data),
			ctx);

	g_signal_connect (oem,
			"handle-send-oem-data-with-response",
			G_CALLBACK (on_send_oem_data_with_response),
			ctx);

	return TRUE;
}

gboolean dbus_plugin_oem_response(struct custom_data *ctx, UserRequest *ur, struct dbus_request_info *dbus_info, enum tcore_response_command command, unsigned int data_len, const void *data)
{
	_emit_oem_response(dbus_info, GET_OEM_ID(command), data, data_len);
 	return TRUE;
}

gboolean dbus_plugin_oem_notification(struct custom_data *ctx, CoreObject *source, TelephonyObjectSkeleton *object, enum tcore_notification_command command, unsigned int data_len, const void *data)
{
	_emit_oem_notification(telephony_object_peek_oem(TELEPHONY_OBJECT(object)), GET_OEM_ID(command), data, data_len);
	return TRUE;
}

