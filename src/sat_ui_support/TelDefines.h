/*
 * tel-plugin-dbus_tapi
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd. All rights reserved.
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

/**
 * @ingroup		TelephonyAPI
 * @addtogroup	COMMON_TAPI	COMMON
 * @{
 *
 * @file TelDefines.h
 * @brief  This file  provides #defines required for Telephony server and TAPI Client Library
 */

#ifndef _TEL_DEFINES_H_
#define _TEL_DEFINES_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Machine independence */
typedef long TS_INT32;
typedef unsigned long TS_UINT32;

typedef int TS_INT;
typedef unsigned int TS_UINT;
typedef double TS_DOUBLE;

typedef int TS_BOOL;

/* Programming concept */
typedef unsigned char TS_BYTE;
typedef unsigned short TS_WORD;
typedef unsigned long TS_DWORD;
typedef unsigned char TS_UINT8;
typedef char TS_INT8;
typedef unsigned short TS_UINT16;
typedef unsigned long TS_ULONG;
typedef unsigned long long TS_UINT64;
typedef unsigned short TS_USHORT;

#ifndef TRUE
#define TRUE		1
#endif

#ifndef FALSE
#define FALSE		0
#endif

#ifndef DEPRECATED
#define DEPRECATED __attribute__((deprecated))
#endif

typedef int HObj;

#ifdef __cplusplus
}
#endif

#endif /* _TEL_DEFINES_H_ */

/**
 *  @}
 */
