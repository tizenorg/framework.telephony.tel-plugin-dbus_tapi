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

#include <glib.h>

#include <tcore.h>
#include <plugin.h>

#include "dtapi_common.h"

#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION 1
#endif

static gboolean on_load()
{
	dbg("i'm load!");

	return TRUE;
}

static gboolean on_init(TcorePlugin *p)
{
	gboolean ret;

	dbg("i'm init!");

	if (!p)
		return FALSE;

	ret = dtapi_init(p);
	dbg("DTAPI initialization: [%s]", (ret == TRUE ? "Successful" : "Fail"));

	return ret;
}

static void on_unload(TcorePlugin *p)
{
	dbg("i'm unload");

	if (!p)
		return;

	dtapi_deinit(p);
}

/* DBUS Communicator descriptor */
EXPORT_API struct tcore_plugin_define_desc plugin_define_desc = {
	.name = "NEW_DBUS_COMMUNICATOR",
	.priority = TCORE_PLUGIN_PRIORITY_HIGH,
	.version = PLUGIN_VERSION,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
