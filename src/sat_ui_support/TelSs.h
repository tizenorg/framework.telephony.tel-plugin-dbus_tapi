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
 * @ingroup		TelephonyAPI
 * @addtogroup  SS_TAPI	SS(Supplementary services)
 * @{
 *
 * @file TelSs.h

 @brief This file serves as a "C" header file and defines structures for Tapi Supplementary Services\n
 It contains a sample set of constants, enums, structs that would be required by applications.
 */

#ifndef _TEL_SS_H_
#define _TEL_SS_H_

#include <TelDefines.h>
#include <TelErr.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** maximum length of barring password */
#define TAPI_SS_GSM_BARR_PW_LEN_MAX				4 /**<Maximum length of barring password */

/** maximum length of dial digit */
#define TAPI_CALL_DIALDIGIT_LEN_MAX				82 /**<maximum length of dial digit *///( To Accommodate Unpacked string length, which will be greater than 182, 182* 8 /7 = 208, Packed len = 182* 7/8 = 160)
#define TAPI_SS_USSD_DATA_SIZE_MAX				208	 /**<User-to-user data maximum size */
#define TAPI_SS_RECORD_NUM_MAX					5 /**< SS record maximum size */
#define TAPI_SS_AOC_CURRENCY_LEN_MAX			3 /**< maximum length of AOC currency */

/* Supplementary Svc */
#define TAPI_SS_ADDRESS_LEN_MAX					40
#define TAPI_SS_CCBS_SIZE_MAX					5
#define TAPI_SS_TELECOMM_SERVCE_SIZE_MAX		13
#define TAPI_SS_PHONE_NUM_LEN_MAX				33
#define TAPI_SS_MMISTRING_LEN_MAX				33
#define TAPI_SS_PWD_LEN_MAX						5
#define TAPI_MAX_RELEASE_COMPLETE_DATA_LEN		260
#define TAPI_MAX_ULONG							0xffffffff

/**
 *  This enumeration defines the call forwarding flavor.
 */
typedef enum {
	TAPI_SS_CF_WHEN_CFU = 0x01, /* 0x01 : Call Forwarding Unconditional */
	TAPI_SS_CF_WHEN_CFB,        /* 0x02 : Call Forwarding Mobile Busy */
	TAPI_SS_CF_WHEN_CFNRy,      /* 0x03 : Call Forwarding No Reply */
	TAPI_SS_CF_WHEN_CFNRc,      /* 0x04 : Call Forwarding Not Reachable */
	TAPI_SS_CF_WHEN_CF_ALL,     /* 0x05 : All Call Forwarding */
	TAPI_SS_CF_WHEN_CFC,        /* 0x06 : All Conditional Call Forwarding */
	TAPI_SS_CF_WHEN_MAX         /* 0x07 : Max */
} TelSsForwardWhen_t;

/**
 * The various types of call barring. Note, only one type of incoming barring and only one type of outgoing barring may be active at any time.
 */
typedef enum {
	TAPI_SS_CB_TYPE_BAOC = 0x01,                /* 0x01 : Barring All Outgoing Calls */
	TAPI_SS_CB_TYPE_BOIC,                /* 0x02 : Barring Outgoing International Calls */
	TAPI_SS_CB_TYPE_BOIC_NOT_HC, /* 0x03 : Barring Outgoing International Calls
								 except to Home Country */
	TAPI_SS_CB_TYPE_BAIC,                /* 0x04 : Barring All Incoming Calls */
	TAPI_SS_CB_TYPE_BIC_ROAM,       /* 0x05 : Barring Incoming Calls when roam,
									outside of the Home Country */
	TAPI_SS_CB_TYPE_AB,                   /* 0x06 : All Barring Services */
	TAPI_SS_CB_TYPE_AOB,                 /* 0x07 : All Outgoing Barring Services */
	TAPI_SS_CB_TYPE_AIB,                  /* 0x08 : All Incoming Barring Services */
	TAPI_SS_CB_TYPE_BIC_NOT_SIM, /* 0x09 : Barring Incoming Calls which is
								 not stored in the SIM memory */
	TAPI_SS_CB_TYPE_MAX
} TelSsBarringType_t;

/**
 * This enumeration defines the ussd Indication Type
 */
typedef enum {
	TAPI_SS_USSD_STATUS_NOTIFY = 0x00, /**< notify : to display USSD data to user */
	TAPI_SS_USSD_STATUS_NO_ACTION_REQUIRE = 0x01, /**< No further user action required */
	TAPI_SS_USSD_STATUS_ACTION_REQUIRE = 0x02, /**< Further user action required*/
	TAPI_SS_USSD_STATUS_TERMINATED_BY_NET = 0x03, /**< 0x03 : USSD terminated by network */
	TAPI_SS_USSD_STATUS_OTHER_CLIENT = 0x04, /**< 0x04 : other local client has responded */
	TAPI_SS_USSD_STATUS_NOT_SUPPORT = 0x05, /**< 0x05 : operation not supported */
	TAPI_SS_USSD_STATUS_TIME_OUT = 0x06 /**< 0x06 : Time out when there is no response from network */
} TelSsUssdStatus_t;

/**
 *
 * This enum defines the values for USSD type.
 */
typedef enum {
	TAPI_SS_USSD_TYPE_USER_INIT = 0x01, /**< USSD request type User Initiated. */
	TAPI_SS_USSD_TYPE_USER_RSP, /**< USSD request type User Response. */
	TAPI_SS_USSD_TYPE_USER_REL /**< USSD request type User Release. */
} TelSsUssdType_t;

/**
 *  This enumeration defines the call barring operation mode .
 */
typedef enum {
	TAPI_SS_CB_MODE_ACTIVATE, /**< Activate call barring  */
	TAPI_SS_CB_MODE_DEACTIVATE, /**< De Activate call barring */
} TelSsBarringMode_t;

/**
 *  This enumeration defines the call barring operation mode .
 */
typedef enum {
	TAPI_SS_CW_MODE_ACTIVATE, /**< Activate call barring  */
	TAPI_SS_CW_MODE_DEACTIVATE, /**< De Activate call barring */
} TelSsCallWaitingMode_t;

/**
 *  This enumeration defines the call type .
 */
typedef enum {
	/* TELESERVICE */
	TAPI_SS_CLASS_ALL_TELE=0x10,                        /* 0x10 : All Teleservices */
	TAPI_SS_CLASS_VOICE=0x11,                              /* 0x11 : All Voice ( telephony ) */
	TAPI_SS_CLASS_ALL_DATA_TELE=0x12,             /* 0x12 : All Data Teleservices */
	TAPI_SS_CLASS_FAX=0x13,                                /* 0x13 : All Fax Service */
	TAPI_SS_CLASS_SMS=0x16,                                /* 0x16 : SMS service	 */
	TAPI_SS_CLASS_VGCS=0x17,                              /* 0x17 : Voice Group Call Service */
	TAPI_SS_CLASS_VBS=0x18,                                /* 0x18 : Voice Broadcast */
	TAPI_SS_CLASS_ALL_TELE_EXPT_SMS=0x19,    /* 0x19 : All teleservice except SMS */

	/* BEARER SERVICE */
	TAPI_SS_CLASS_ALL_BEARER=0x20,                  /* 0X20 : all bearer services */
	TAPI_SS_CLASS_ALL_ASYNC=0x21,                    /* 0x21 : All Async services */
	TAPI_SS_CLASS_ALL_SYNC=0x22,                      /* 0x22 : All sync services*/
	TAPI_SS_CLASS_ALL_CS_SYNC=0x24,                /* 0x24 : All Circuit switched sync */
	TAPI_SS_CLASS_ALL_CS_ASYNC=0x25,              /* 0x25 : All Circuit switched async */
	TAPI_SS_CLASS_ALL_DEDI_PS=0x26,                /* 0x26 : All Dedicated packet Access */
	TAPI_SS_CLASS_ALL_DEDI_PAD=0x27,              /* 0x27 : All Dedicated PAD Access */
	TAPI_SS_CLASS_ALL_DATA_CDA=0x28,		/*0x28 : All Data CDA*/

	/* PLMN SPECIFIC TELESERVICE */
	TAPI_SS_CLASS_PLMN_TELE_ALL = 0x50,         /*0x50 : PLMN specific teleservices*/
	TAPI_SS_CLASS_PLMN_TELE_1 = 0x51,              /*0x51 :PLMN specific teleservice 1*/
	TAPI_SS_CLASS_PLMN_TELE_2 = 0x52,             /*0x52 : PLMN specific teleservice 2*/
	TAPI_SS_CLASS_PLMN_TELE_3 = 0x53,             /*0x53 : PLMN specific teleservice 3*/
	TAPI_SS_CLASS_PLMN_TELE_4 = 0x54,             /*0x54 : PLMN specific teleservice 4*/
	TAPI_SS_CLASS_PLMN_TELE_5 = 0x55,             /*0x55 : PLMN specific teleservice 5*/
	TAPI_SS_CLASS_PLMN_TELE_6 = 0x56,             /*0x56 : PLMN specific teleservice 6*/
	TAPI_SS_CLASS_PLMN_TELE_7 = 0x57,             /*0x57 : PLMN specific teleservice 7*/
	TAPI_SS_CLASS_PLMN_TELE_8 = 0x58,             /*0x58 : PLMN specific teleservice 8*/
	TAPI_SS_CLASS_PLMN_TELE_9 = 0x59,             /*0x59 : PLMN specific teleservice 9*/
	TAPI_SS_CLASS_PLMN_TELE_A = 0x60,           /*0x60 :PLMN specific teleservice 10*/
	TAPI_SS_CLASS_PLMN_TELE_B = 0x61,           /*0x61 :PLMN specific teleservice 11*/
	TAPI_SS_CLASS_PLMN_TELE_C = 0x62,             /*0x62 : PLMN specific teleservice 12*/
	TAPI_SS_CLASS_PLMN_TELE_D = 0x63,             /*0x63 : PLMN specific teleservice 13*/
	TAPI_SS_CLASS_PLMN_TELE_E = 0x64,             /*0x64 : PLMN specific teleservice 14*/
	TAPI_SS_CLASS_PLMN_TELE_F = 0x65,             /*0x65 : PLMN specific teleservice 15*/

	/* PLMN SPECIFIC BEARER SERVICE */
	TAPI_SS_CLASS_PLMN_BEAR_ALL = 0x70,         /*0x70 : All PLMN specific bearer services*/
	TAPI_SS_CLASS_PLMN_BEAR_1 = 0x71,              /*0x71 :PLMN specific bearer service 1*/
	TAPI_SS_CLASS_PLMN_BEAR_2 = 0x72,             /*0x72 : PLMN specific bearer service  2*/
	TAPI_SS_CLASS_PLMN_BEAR_3 = 0x73,             /*0x73 : PLMN specific bearer service  3*/
	TAPI_SS_CLASS_PLMN_BEAR_4 = 0x74,             /*0x74 : PLMN specific bearer service  4*/
	TAPI_SS_CLASS_PLMN_BEAR_5 = 0x75,             /*0x75 : PLMN specific bearer service  5*/
	TAPI_SS_CLASS_PLMN_BEAR_6 = 0x76,             /*0x76 : PLMN specific bearer service  6*/
	TAPI_SS_CLASS_PLMN_BEAR_7 = 0x77,             /*0x77 : PLMN specific bearer service  7*/
	TAPI_SS_CLASS_PLMN_BEAR_8 = 0x78,             /*0x78 : PLMN specific bearer service  8*/
	TAPI_SS_CLASS_PLMN_BEAR_9 = 0x79,             /*0x79 : PLMN specific bearer service  9*/
	TAPI_SS_CLASS_PLMN_BEAR_A = 0x80,            /*0x80 : PLMN specific bearer service  10*/
	TAPI_SS_CLASS_PLMN_BEAR_B = 0x81,             /*0x81 : PLMN specific bearer service  11*/
	TAPI_SS_CLASS_PLMN_BEAR_C = 0x82,            /*0x82 : PLMN specific bearer service  12*/
	TAPI_SS_CLASS_PLMN_BEAR_D = 0x83,            /*0x83 : PLMN specific bearer service  13*/
	TAPI_SS_CLASS_PLMN_BEAR_E = 0x84,             /*0x84 : PLMN specific bearer service  14*/
	TAPI_SS_CLASS_PLMN_BEAR_F = 0x85,             /*0x85 : PLMN specific bearer service  15*/

	/* CPHS - AUXILIARY SERVICE */
	TAPI_SS_CLASS_AUX_VOICE = 0x89,			/* 0x89 : All Auxiliary Voice ( Auxiliary telephony ) */

	TAPI_SS_CLASS_ALL_GPRS_BEARER=0x99,       /* 0x99 : All GPRS bearer services */
	TAPI_SS_CLASS_ALL_TELE_BEARER=0xFF,        /* 0xFF : all tele and bearer services */
} TelSsClass_t;

/**
 *  This enumeration defines the forward mode .
 */
typedef enum {
	TAPI_SS_CF_MODE_DISABLE_EV, /**< Deactivate call forwarding  */
	TAPI_SS_CF_MODE_ENABLE_EV, /**< Activate call forwarding */
	TAPI_SS_CF_MODE_REGISTRATION_EV, /**< Register Call forwarding  */
	TAPI_SS_CF_MODE_ERASURE_EV, /**< De-register call forwarding */
} TelSsForwardMode_t;

typedef enum {
	TAPI_SS_CF_NO_REPLY_TIME_5_SECS = 5, /**< Timer value set to 5secs*/
	TAPI_SS_CF_NO_REPLY_TIME_10_SECS = 10, /**< Timer value set to 10secs*/
	TAPI_SS_CF_NO_REPLY_TIME_15_SECS = 15, /**< Timer value set to 15secs*/
	TAPI_SS_CF_NO_REPLY_TIME_20_SECS = 20, /**< Timer value set to 20secs*/
	TAPI_SS_CF_NO_REPLY_TIME_25_SECS = 25, /**< Timer value set to 25secs*/
	TAPI_SS_CF_NO_REPLY_TIME_30_SECS = 30, /**< Timer value set to 30secs*/
} TelSsNoReplyTime_t;

/**
 *  Describes whether a supplementary service request was a success or a failure; and if it failed, why.
 */
typedef enum {
	TAPI_SS_SUCCESS=0x0, /**<  SS operation was successful */

	TAPI_SS_UNKNOWNSUBSCRIBER= 0x01, /**< SS error indicating unknown/illegal subscriber.  */
	TAPI_SS_ILLEGALSUBSCRIBER= 0x09, /**<This error is returned when illegality of the access has been @n
	 established by use of authentication procedure. */

	TAPI_SS_BEARERSERVICENOTPROVISIONED= 0x0a, /**<The network returns this error when it is requested to  @n
	 perform an operation on a supplementary service  */
	TAPI_SS_TELESERVICENOTPROVISIONED= 0x0b, /**<The network returns this error when it is requested to perform  @n
	 an operation on a supplementary service  */
	TAPI_SS_ILLEGALEQUIPMENT= 0x0c, /**<This error is returned when the IMEI check procedure has shown that  @n
	 the IMEI is blacklisted or not whitelisted  */
	TAPI_SS_CALLBARRED= 0x0d, /**< This error is returned by the network to the MS when call independent subscriber control procedures are barred by the operator */
	TAPI_SS_ILLEGALSSOPERATION=0x10, /**<This error is returned by the network when it is requested to perform an illegal operation @n
	 which is defined as not applicable for the relevant supplementary service */
	TAPI_SS_ERRORSTATUS= 0x11, /**<This error is returned by the network when it is requested to perform an operation @n
	 which is not compatible with the current status of the relevant supplementary service. */
	TAPI_SS_NOTAVAILABLE= 0x12, /**< SS not available in network */
	TAPI_SS_SUBSCRIPTIONVIOLATION= 0x13, /**< SS service subscription violation. */
	TAPI_SS_INCOMPATIBILITY= 0x14, /**< This error is returned by the network when it is requested for a supplementary service operation incompatible with the @n
	 status of another supplementary service or with the teleservice or bearer service for which the operation is requested */
	TAPI_SS_FACILITYNOTSUPPORTED= 0x15, /**< SS service facility not supported  */
	TAPI_SS_ABSENTSUBSCRIBER= 0x1b, /**< This error is returned when the subscriber has activated the detach service or the system detects the absence condition */

	TAPI_SS_SYSTEMFAILURE= 0x22, /**< This error is returned by the network, when it cannot perform an operation because of a failure in the network */
	TAPI_SS_DATAMISSING= 0x23, /**< This error is returned by the network when an optional parameter is missing in an invoke component @n
	 or an inner data structure, while it is required by the context of the request. */
	TAPI_SS_UNEXPECTEDDATAVALUE= 0x24, /**< SS error indicating unexpected data value on network side *//**< SS operation barred.  */
	TAPI_SS_PWREGISTRATIONFAILURE= 0x25, /**< SS error indicating change password failure. */
	TAPI_SS_NEGATIVEPWCHECK= 0x26, /**< SS error indicating negative password check.  */
	TAPI_SS_NUMBEROFPWATTEMPTSVIOLATION= 0x2b, /**< SS error indicating barring password attempts violated.  */

	TAPI_SS_UNKNOWNALPHABET= 0x47, /**< SS error indicating unknown SS data coding of alphabet */
	TAPI_SS_USSDBUSY= 0x48, /**< SS error indicating USSD Busy(Already SS / USSD is ongoing).  */

	TAPI_SS_REJECTEDBYUSER= 0x79, /**< SS operation rejected by user.  */
	TAPI_SS_REJECTEDBYNETWORK=0x7a, /**< SS operation rejected by network.  */
	TAPI_SS_DEFLECTIONTOSERVEDSUBSCRIBER= 0x7b, /**< This error is returned if a diversion to the served  @n
	 subscriber's number was requested.  */
	TAPI_SS_SPECIALSERVICECODE= 0x7c, /**< This error is returned if diversion to a special service code was requested.  */
	TAPI_SS_INVALIDDEFLECTEDTONUMBER= 0x7d, /**< SS error indicating the invalid deflected to number.  */
	TAPI_SS_MAXNOMPTYEXCEEDED= 0x7e, /**< SS error indicating Maximum MPTY is reached.  */
	TAPI_SS_RESOURCESNOTAVAILABLE= 0x7f, /**< SS error indicating resources not available in network.  */

	TAPI_SS_TIMEREXPIRE, /**< SS operation timer expired on network. */
	TAPI_SS_NET_NOT_ALLOWED_EMERGENCY_CALLS_ONLY, /**< SS operation is not allowed by network.  */
	TAPI_SS_UNKNOWNERROR, /**< SS error indicating unknown error  */
	TAPI_SS_OEM_NOT_SUPPORTED /**< If oem do not support any of SS requests, then this error will be returned back */
} TelSsCause_t;

/**
 *   The status of a supplementary service feature (e.g. Call Forwarding or Call Barring). @n
 *   These enumerated values should be used as masks
 */
typedef enum {
	TAPI_SS_STATUS_REGISTERED = 0x01, /**< Provisioned & registered (but not active/active-quiescent */
	TAPI_SS_STATUS_PROVISIONED, /**<Provisioned but not registered (or active/active-quiescent) */
	TAPI_SS_STATUS_ACTIVE, /**< Provisioned & registered & active */
	TAPI_SS_STATUS_QUIESCENT, /**< Provisioned & registered & active but quiescent */
	TAPI_SS_STATUS_NOTHING /**< Not provisioned */
} TelSsStatus_t;

/**
 * These are the four types of identity presentation / restriction services.
 */
typedef enum {
	TAPI_CALLING_LINE_IDENTITY_PRESENTATION= 0x01, /**< identify the party calling this phone */
	TAPI_CALLING_LINE_IDENTITY_RESTRICTION, /**< hide the identity of this phone when calling others */
	TAPI_CONNECTED_LINE_IDENTITY_PRESENTATION, /**< identify the party to whom the calling party (this phone) is connected */
	TAPI_CONNECTED_LINE_IDENTITY_RESTRICTION, /**< restrict yourself from being identified by incoming calls, such as forwarded calls */
	TAPI_CALLED_LINE_IDENTITY_PRESENTATION, /**< Called line identity presentation  */
	TAPI_CALLING_NAME_PRESENTATION /**< Calling Name Presentation */
} TelSsLineIdentificationType_t;

/**
 *  This enumeration defines the cli service status .
 */
typedef enum {
	TAPI_CLI_STATUS_NOT_PROVISONED = 0x01, /**<Service not provided by the service provider */
	TAPI_CLI_STATUS_PROVISIONED, /**<Service is provided by the service provider */
	TAPI_CLI_STATUS_ACTIVATED, /**<Service is activated at the network */
	TAPI_CLI_STATUS_UNKOWN, /**<Service status is unknown*/
	TAPI_CLI_STATUS_TEMP_RESTRICTED, /**<Service is temporarily restricted */
	TAPI_CLI_STATUS_TEMP_ALLOWED /**<Service is temporarily allowed */
} TelSsCliStatus_t;

/**
 *  This enumeration defines the values for Cli service type .
 */
typedef enum {
	TAPI_SS_CLI_CLIP = 0x01, /**< Calling Line Identification Presentation. */
	TAPI_SS_CLI_CLIR = 0x02, /**<  Calling Line Identification Restriction. */
	TAPI_SS_CLI_COLP = 0x03, /**<  Connected Line Identification Presentation. */
	TAPI_SS_CLI_COLR = 0x04, /**<  Connected Line Identification Restriction. */
	TAPI_SS_CLI_CDIP = 0x05, /**<  Called Line Identification Presentation. */
	TAPI_SS_CLI_CNAP = 0x06, /**<  Calling Name Presentation.*/
} TelSsCliType_t;

/**
 * This enum defines the values for AOC type.
 */
typedef enum {
	TAPI_SS_AOC_TYPE_RESET = 0x00, /**< Specifies the Reset MAXACM Value. */
	TAPI_SS_AOC_TYPE_ACM = 0x01, /**< Specifies the Accumulated call meter. */
	TAPI_SS_AOC_TYPE_CCM = 0x02, /**< Specifies the Current call meter. */
	TAPI_SS_AOC_TYPE_MAXACM = 0x04, /**< Specifies the Max accumulated call meter. */
	TAPI_SS_AOC_TYPE_PUC = 0x08 /**< Specifies the Price per unit and currency.*/
} TelSsAocType_t;

typedef enum {
	TAPI_SS_TYPE_BARRING = 0x00,
	TAPI_SS_TYPE_FORWARDING,
	TAPI_SS_TYPE_WAITING,
	TAPI_SS_TYPE_CLI,
	TAPI_SS_TYPE_SEND_USSD,
	TAPI_SS_TYPE_MAX
}TelSsInfoType_t;

/**
 *  This structure  defines the different parameters related to forward info.
 */
typedef struct {
	TelSsClass_t Class;
	TelSsForwardMode_t Mode; /**< Forward Mode */
	TelSsForwardWhen_t Condition; /**< Forward Condition */
	char szPhoneNumber[TAPI_CALL_DIALDIGIT_LEN_MAX]; /**< Phone Number*/
	TelSsNoReplyTime_t NoReplyConditionTimer; /**< No reply wait time 5-30 secs in intervals of 5. */
} TelSsForwardInfo_t;

/**
 *  This structure defines the values for USSD request type.
 */
typedef struct {
	TelSsUssdType_t Type;
	int Length; /**< USSD  String Length */
	char szString[TAPI_SS_USSD_DATA_SIZE_MAX]; /**< USSD  String */
} TelSsUssdMsgInfo_t;

/**
 *  This structure  defines the different parameters related to call barring.
 */
typedef struct {
	TelSsClass_t Class; /**< Call type */
	TelSsBarringMode_t Mode; /**< Barring mode  */
	TelSsBarringType_t Type; /**< Barring type */
	char szPassword[TAPI_SS_GSM_BARR_PW_LEN_MAX]; /**< password */
} TelSsBarringInfo_t;

/**
 *  This structure  defines the different parameters related to call waiting.
 */
typedef struct {
	TelSsClass_t Class; /**< Call type */
	TelSsCallWaitingMode_t Mode; /**< Waiting mode  */
} TelSsWaitingInfo_t;

/**
 *  This structure  defines the SUPS information message notification type.
 */
typedef struct {
	TelSsCause_t Cause; /**< Cause */
	TelSsInfoType_t SsType; /**< SUPS Information  */
} TelSsInfo_t;

/**
 * This structure defines the release complete message notification type.
 */
typedef struct {
	unsigned char RelCompMsgLen; /**< Specifies the Release complete msg length.*/
	unsigned char szRelCompMsg[TAPI_MAX_RELEASE_COMPLETE_DATA_LEN]; /**<  Specifies the Release complete msg. */
} TelSsRelCompMsgInfo_t;

/**
 * This structure defines the values for AOC request type.
 */

typedef struct {
	float PPM;
	unsigned char CharTypeOfCurrency;
	unsigned char szCurrency[TAPI_SS_AOC_CURRENCY_LEN_MAX];
} TelAocPucInfo_t;

typedef struct {
	TelSsAocType_t AocType; /**< Specifies the AOC type. */
	unsigned int ACM; /**< Specifies the accumulated call meter value. */
	unsigned int MaxAcm; /**< Specifies the maximum value of ACM . */
	float CCM; /**< Specifies the Current call meter value. */
	float PPM; /**< Specifies the Price per unit value. */
	unsigned char CharTypeOfCurrency; /**< Specifies the Char type of currency. */
	unsigned char szCurrency[TAPI_SS_AOC_CURRENCY_LEN_MAX]; /**< Specifies the Currency characters. */
} TelCallAocInfo_t;

/**
 * This structure defines the values for ss call barring record
 */
typedef struct {
	int record_num;
	struct {
		TelSsClass_t Class;
		TelSsStatus_t Status; /**< SS status  */
		TelSsBarringType_t Flavour; /**< Call barring types providing various barring conditions on that basis call be barred */
	} record[TAPI_SS_RECORD_NUM_MAX]; /**< Specifies the  Maximum of TAPI_SS_RECORD_NUM_MAX records. */
} TelSsBarringResp_t;

/**
 * This structure defines the values for ss call forwarding record
 */
typedef struct {
	int record_num;
	struct {
		TelSsClass_t Class;
		TelSsStatus_t Status; /**< Call forwarding SS status */
		TelSsForwardWhen_t ForwardCondition; /**< Call forward types providing various conditions when call can be forwarded */
		int bCallForwardingNumberPresent; /**< Call forwarding number present or not */
		unsigned char NoReplyWaitTime;
		unsigned char szCallForwardingNumber[TAPI_CALL_DIALDIGIT_LEN_MAX + 1]; /**< forwarded number.[Null Terminated string]*/
	} record[TAPI_SS_RECORD_NUM_MAX]; /**< Specifies the  Maximum of TAPI_SS_RECORD_NUM_MAX records. */
} TelSsForwardResp_t;

/**
 * This structure defines the values for ss call waiting record
 */
typedef struct {
	int record_num;
	struct {
		TelSsClass_t Class;
		TelSsStatus_t Status; /**< SS status */
	} record[TAPI_SS_RECORD_NUM_MAX]; /**< Specifies the  Maximum of TAPI_SS_RECORD_NUM_MAX records. */
} TelSsWaitingResp_t;

/**
 * This structure defines the values for Calling line identity service
 */
typedef struct {
	TelSsLineIdentificationType_t Type; /**< Various line identification types */
	TelSsCliStatus_t Status; /**< Line identification status from network */
} TelSsCliResp_t;

typedef struct {
	TelSsUssdType_t Type;
	TelSsUssdStatus_t Status;
	int Length; /**< USSD  String Length */
	char szString[TAPI_SS_USSD_DATA_SIZE_MAX]; /**< USSD  String */
} TelSsUssdResp_t;

typedef struct {
	TelSsUssdStatus_t Status;
	int Length; /**< USSD  String Length */
	char szString[TAPI_SS_USSD_DATA_SIZE_MAX]; /**< USSD  String */
} TelSsUssdNoti_t;

typedef struct {
	float PPM; /**< Specifies the Price per unit value. */
	unsigned char CharTypeOfCurrency; /**< Specifies the Char type of currency. */
	unsigned char szCurrency[TAPI_SS_AOC_CURRENCY_LEN_MAX]; /**< Specifies the Currency characters. */
} TelSsAoc_ppm_info_t;

#ifdef __cplusplus
}
#endif

#endif // _TEL_SS_H_
/**
 * @}
 */
