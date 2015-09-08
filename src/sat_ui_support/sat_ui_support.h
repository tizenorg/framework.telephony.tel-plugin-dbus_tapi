#ifndef SAT_UI_SUPPORT_H_
#define SAT_UI_SUPPORT_H_

#include <glib.h>
#include <gio/gio.h>

#include <tcore.h>
#include <storage.h>
#include <server.h>
#include <type/sat.h>
#include "../common.h"

#define PKG_ID_SAT_UI "org.tizen.sat-ui"
#define PKG_ID_SAT_UI_2 "org.tizen.sat-ui-2"

#define RELAUNCH_INTERVAL 50*1000 //100ms
#define RETRY_MAXCOUNT 3

gboolean sat_ui_support_terminate_sat_ui(void);
gboolean sat_ui_check_app_is_running(const char* app_id);
gboolean sat_ui_support_launch_call_application(enum tel_sat_proactive_cmd_type cmd_type, GVariant *data, enum dbus_tapi_sim_slot_id slot_id);
gboolean sat_ui_support_launch_browser_application(enum tel_sat_proactive_cmd_type cmd_type, GVariant *data, enum dbus_tapi_sim_slot_id slot_id);
gboolean sat_ui_support_launch_ciss_application(enum tel_sat_proactive_cmd_type cmd_type, GVariant *data, enum dbus_tapi_sim_slot_id slot_id);
gboolean sat_ui_support_launch_setting_application(enum tel_sat_proactive_cmd_type cmd_type, GVariant *data, enum dbus_tapi_sim_slot_id slot_id);
gboolean sat_ui_support_launch_sat_ui(enum tel_sat_proactive_cmd_type cmd_type, GVariant *data, enum dbus_tapi_sim_slot_id slot_id);
gboolean sat_ui_support_exec_bip(GDBusConnection *connection, const gchar *path, enum tel_sat_proactive_cmd_type cmd_type, GVariant *data);
gboolean sat_ui_support_exec_evtdw(GDBusConnection *connection, const gchar *path, enum tel_sat_proactive_cmd_type cmd_type, GVariant *data);
gboolean sat_ui_support_storage_init(Server *server);

#endif /* SAT_UI_SUPPORT_H_ */
