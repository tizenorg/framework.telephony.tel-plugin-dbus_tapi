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
 * @open
 * @ingroup			TelephonyAPI
 * @addtogroup		COMMON_TAPI	COMMON
 * @{
 *	These error codes are used by Applications.
 */


#ifndef _TEL_ERR_H_
#define _TEL_ERR_H_

#ifdef __cplusplus
extern "C"
{
#endif

/************************************************************
**    Errors defined in  "+CME ERROR" ,
**    - see 3GPP TS 27.007
**    - ranges are 0x00 ~ 0x7FFF
************************************************************/
/**
	Error codes sent by the modem in response to the above operations.
*/
typedef enum
{
  /* GENERAL ERRORS */
  TAPI_OP_GEN_ERR_PHONE_FAILURE	= 0,						/* 0 */
  TAPI_OP_GEN_ERR_NO_CONNECTION_TO_PHONE,					/* 1 */
  TAPI_OP_GEN_ERR_PHONE_ADAPTOR_LINK_RESERVED,			/* 2 */
  TAPI_OP_GEN_ERR_OPER_NOT_ALLOWED,						/* 3 */
  TAPI_OP_GEN_ERR_OPER_NOT_SUPPORTED,						/* 4 */
  TAPI_OP_GEN_ERR_PH_SIM_PIN_REQU,						/* 5 */
  TAPI_OP_GEN_ERR_PH_FSIM_PIN_REQU,						/* 6 */
  TAPI_OP_GEN_ERR_PH_FSIM_PUK_REQU,						/* 7 */
  TAPI_OP_GEN_ERR_SIM_NOT_INSERTED	=10,					/* 10 */
  TAPI_OP_GEN_ERR_SIM_PIN_REQU,							/* 11 */
  TAPI_OP_GEN_ERR_SIM_PUK_REQU,							/* 12 */
  TAPI_OP_GEN_ERR_SIM_FAILURE,							/* 13 */
  TAPI_OP_GEN_ERR_SIM_BUSY,								/* 14 */
  TAPI_OP_GEN_ERR_SIM_WRONG,								/* 15 */
  TAPI_OP_GEN_ERR_INCORRECT_PW,							/* 16 */
  TAPI_OP_GEN_ERR_SIM_PIN2_REQU,							/* 17 */
  TAPI_OP_GEN_ERR_SIM_PUK2_REQU,							/* 18 */
  TAPI_OP_GEN_ERR_MEM_FULL	= 20,							/* 20 */
  TAPI_OP_GEN_ERR_INVALID_INDEX,							/* 21 */
  TAPI_OP_GEN_ERR_NOT_FOUND,								/* 22 */
  TAPI_OP_GEN_ERR_MEM_FAILURE,							/* 23 */
  TAPI_OP_GEN_ERR_TEXT_STR_TOO_LONG,						/* 24 */
  TAPI_OP_GEN_ERR_INVALID_CHARACTERS_IN_TEXT_STR,			/* 25 */
  TAPI_OP_GEN_ERR_DIAL_STR_TOO_LONG,						/* 26 */
  TAPI_OP_GEN_ERR_INVALID_CHARACTERS_IN_DIAL_STR,			/* 27 */
  TAPI_OP_GEN_ERR_NO_NET_SVC	= 30,						/* 30 */
  TAPI_OP_GEN_ERR_NET_TIMEOUT,							/* 31 */
  TAPI_OP_GEN_ERR_NET_NOT_ALLOWED_EMERGENCY_CALLS_ONLY,	/* 32 */
  TAPI_OP_GEN_ERR_NET_PERS_PIN_REQU	= 40,					/* 40 */
  TAPI_OP_GEN_ERR_NET_PERS_PUK_REQU,						/* 41 */
  TAPI_OP_GEN_ERR_NET_SUBSET_PERS_PIN_REQU,				/* 42 */
  TAPI_OP_GEN_ERR_NET_SUBSET_PERS_PUK_REQU,				/* 43 */
  TAPI_OP_GEN_ERR_SVC_PROVIDER_PERS_PIN_REQU,				/* 44 */
  TAPI_OP_GEN_ERR_SVC_PROVIDER_PERS_PUK_REQU,				/* 45 */
  TAPI_OP_GEN_ERR_CORPORATE_PERS_PIN_REQU,				/* 46 */
  TAPI_OP_GEN_ERR_CORPORATE_PERS_PUK_REQU,				/* 47 */
  TAPI_OP_GEN_ERR_HIDDEN_KEY_REQU,						/* 48 */
  TAPI_OP_GEN_ERR_UNKNOWN	= 100,						/* 100 */

  /* Errors related to a failure to perform an Attach */
  TAPI_OP_GEN_ERR_ILLEGAL_MS	= 103,					/* 103 */
  TAPI_OP_GEN_ERR_ILLEGAL_ME	= 106,					/* 106 */
  TAPI_OP_GEN_ERR_GPRS_SVC_NOT_ALLOWED,					/* 107 */
  TAPI_OP_GEN_ERR_PLMN_NOT_ALLOWED	= 111,				/* 111 */
  TAPI_OP_GEN_ERR_LOCATION_AREA_NOT_ALLOWED,				/* 112 */
  TAPI_OP_GEN_ERR_ROAMING_NOT_ALLOWED_IN_THIS_LOCATION_AREA,/* 113 */

  /* Errors related to a failure to Activate a Context */
  TAPI_OP_GEN_ERR_SVC_OPT_NOT_SUPPORTED	= 132,			/* 132 */
  TAPI_OP_GEN_ERR_REQ_SVC_OPT_NOT_SUBSCRIBED,				/* 133 */
  TAPI_OP_GEN_ERR_SVC_OPT_TEMPORARILY_OUT_OF_ORDER,		/* 134 */
  TAPI_OP_GEN_ERR_UNSPECIFIED_GPRS_ERR	= 148,			/* 148 */
  TAPI_OP_GEN_ERR_PDP_AUTHENTICATION_FAILURE,				/* 149 */
  TAPI_OP_GEN_ERR_INVALID_MOBILE_CLASS,					/* 150 */

  /* VBS / VGCS and eMLPP -related errors */
  TAPI_OP_GEN_ERR_VBS_VGCS_NOT_SUPPORTED_BY_THE_NET	= 151,  /* 151 */
  TAPI_OP_GEN_ERR_NO_SVC_SUBSCRIPTION_ON_SIM,				/* 152 */
  TAPI_OP_GEN_ERR_NO_SUBSCRIPTION_FOR_GROUP_ID,			/* 153 */
  TAPI_OP_GEN_ERR_GROUP_ID_NOT_ACTIVATED_ON_SIM,			/* 154 */
  TAPI_OP_GEN_ERR_NO_MATCHING_NOTI	= 155,				/* 155 */
  TAPI_OP_GEN_ERR_VBS_VGCS_CALL_ALREADY_PRESENT,			/* 156 */
  TAPI_OP_GEN_ERR_CONGESTION,								/* 157 */
  TAPI_OP_GEN_ERR_NET_FAILURE,							/* 158 */
  TAPI_OP_GEN_ERR_UPLINK_BUSY,							/* 159 */
  TAPI_OP_GEN_ERR_NO_ACCESS_RIGHTS_FOR_SIM_FILE	= 160,	/* 160 */
  TAPI_OP_GEN_ERR_NO_SUBSCRIPTION_FOR_PRIORITY,			/* 161 */
  TAPI_OP_GEN_ERR_OPER_NOT_APPLICABLE_OR_NOT_POSSIBLE,	/* 162 */


  TAPI_OP_GEN_ERR_NONE	= 0x8000,				/* 0x8000 : No Errors */

  /* General Common Errors : 0x8000 - 0x80FF */
  TAPI_OP_GEN_ERR_INVALID_IPC,							/* 0x8001 : Invalid IPC_GSM Parameter or Format */
  TAPI_OP_GEN_ERR_PHONE_OFFLINE,							/* 0x8002 : */
  TAPI_OP_GEN_ERR_CMD_NOT_ALLOWED,						/* 0x8003 : */
  TAPI_OP_GEN_ERR_PHONE_IS_INUSE,							/* 0x8004 : */
  TAPI_OP_GEN_ERR_INVALID_STATE	= 0x8005,					/* 0x8005 : */

  TAPI_OP_GEN_ERR_NO_BUFFER,								/* 0x8006 :  No internal free buffers */
  TAPI_OP_GEN_ERR_OPER_REJ,								/* 0x8007 :  Operation Rejected */
  TAPI_OP_GEN_ERR_INSUFFICIENT_RESOURCE,					/* 0x8008 : insufficient resource */
  TAPI_OP_GEN_ERR_NET_NOT_RESPOND,						/* 0x8009 : Network not responding */
  TAPI_OP_GEN_ERR_SIM_PIN_ENABLE_REQ	= 0x800A,			/* 0x800A : SIM Pin Enable Required */
  TAPI_OP_GEN_ERR_SIM_PERM_BLOCKED,					/* 0x800B : SIM Permanent Blocked */
  TAPI_OP_GEN_ERR_SIM_PHONEBOOK_RESTRICTED,				/*0x800C: SIM Phonebook Restricted*/
  TAPI_OP_GEM_ERR_FIXED_DIALING_NUMBER_ONLY,				/*0x800D: Restricted By FDN Mode */

  /* Reserved : 0x800E ~ 0x80FF */
  TAPI_OP_GEN_ERR_800E_RESERVED_START	= 0x800E,			/* 0x800E */

  TAPI_OP_GEN_ERR_80FF_RESERVED_END	= 0x80ff,				/* 0x80FF */

  /* the other errors */
  TAPI_OP_GEN_ERR_OTHERS				= 0xFFFE,				  /* 0xFFFE */

  TAPI_OP_GEN_ERR_MAX					= 0xFFFF

}tapi_phone_err_t;

typedef enum {
	TAPI_PDP_FAILURE_CAUSE_NORMAL						= 0x00,		  // 0x00 : Normal Process ( no problem )
	TAPI_PDP_FAILURE_CAUSE_REL_BY_USER					= 0x01,		  // Call Released by User
	TAPI_PDP_FAILURE_CAUSE_REGULAR_DEACTIVATION			= 0x02,		  // Regular de-activation
	TAPI_PDP_FAILURE_CAUSE_LLC_SNDCP					= 0x03,		  // LLC SNDCP failure
	TAPI_PDP_FAILURE_CAUSE_INSUFFICIENT_RESOURCE		= 0x04,		  // Insufficient resources
	TAPI_PDP_FAILURE_CAUSE_UNKNOWN_APN					= 0x05,		  // Missing or unknown APN
	TAPI_PDP_FAILURE_CAUSE_UNKNOWN_PDP_ADDRESS			= 0x06,		  // Unknown PDP address or type
	TAPI_PDP_FAILURE_CAUSE_USER_AUTH_FAILED				= 0x07,		  // Unknown PDP address or type
	TAPI_PDP_FAILURE_CAUSE_ACT_REJ_GGSN					= 0x08,		  // Unknown PDP address or type
	TAPI_PDP_FAILURE_CAUSE_ACT_REJ_UNSPECIFIED			= 0x09,		  // Unknown PDP address or type
	TAPI_PDP_FAILURE_CAUSE_SVC_OPTION_NOT_SUPPORTED		= 0x0A,		  // Service option not supported
	TAPI_PDP_FAILURE_CAUSE_SVC_NOT_SUBSCRIBED			= 0x0B,		  // Requested service option not subscribed
	TAPI_PDP_FAILURE_CAUSE_SVC_OPT_OUT_ORDER			= 0x0C,		  // Service out of order
    TAPI_PDP_FAILURE_CAUSE_NSAPI_USED					= 0x0D,		  // NSAPI already used
	TAPI_PDP_FAILURE_CAUSE_QOS_NOT_ACCEPTED				= 0x0E,		  // QoS not accepted
	TAPI_PDP_FAILURE_CAUSE_NETWORK_FAILURE				= 0x0F,		  // Network Failure
    TAPI_PDP_FAILURE_CAUSE_REACT_REQUIRED				= 0x10,		  // Reactivation Required
	TAPI_PDP_FAILURE_CAUSE_FEATURE_NOT_SUPPORTED		= 0x11,		  // Feature not supported
	TAPI_PDP_FAILURE_CAUSE_TFT_FILTER_ERROR				= 0x12,		  // TFT or filter error
	TAPI_PDP_FAILURE_CAUSE_UNKOWN_PDP_CONTEXT			= 0x13,		  // Unknown PDP context
	TAPI_PDP_FAILURE_CAUSE_INVALID_MSG					= 0x14,		  // Invalid MSG
	TAPI_PDP_FAILURE_CAUSE_PROTOCOL_ERROR				= 0x15,		  // Protocol error
	TAPI_PDP_FAILURE_CAUSE_MOBILE_FAILURE_ERROR			= 0x16,		  // Mobile failure error
	TAPI_PDP_FAILURE_CAUSE_TIMEOUT_ERROR				= 0x17,		  // Timeout error
	TAPI_PDP_FAILURE_CAUSE_UNKNOWN_ERROR				= 0x18,		  // Unknown error
	TAPI_PDP_FAILURE_CAUSE_MAX ,
} tapi_pdp_err_t;

#ifdef __cplusplus
}
#endif

#endif // _TEL_ERR_H_

/**
* @}
*/
