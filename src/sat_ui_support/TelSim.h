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
 * @addtogroup	SIM_TAPI	SIM
 * @{
 *
 * @file TelSim.h

 @brief This file serves as a "C" header file defines structures for Tapi SIM Services. \n
 It contains a sample set of constants, enums, structs that would be required by applications.
 */

#ifndef _TELSIM_H_
#define _TELSIM_H_

#include <TelDefines.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** Maximum ICCID Length */
#define TAPI_SIM_ICCID_LEN_MAX 20

/** Alpha Id  max length */
#define TAPI_SIM_XDN_ALPHA_ID_MAX_LEN 30

/** Dialing number max length */
#define TAPI_SIM_XDN_DIALING_NUMBER_LEN	20

/** CSP profile entry count max length */
#define TAPI_SIM_CPHS_CUSTOMER_SERVICE_PROFILE_ENTRY_COUNT_MAX	11

/** Authentication code max length */
#define TAPI_SIM_AUTH_MAX_REQ_DATA_LEN 256

/** Authentication response data max length */
#define TAPI_SIM_AUTH_MAX_RESP_DATA_LEN 128

/** SAP APDU max length */
#define TAPI_SIM_APDU_MAX_LEN 256+2 // to be fine tuned according to lower layers, 2bytes for SW1 & SW2 should be added

/** SIM 3G Phone book EF Max count */
#define TAPI_SIM_PB_3G_FILE_MAX_COUNT 13

/** SAP Answer to Reset data max length */
#define TAPI_SIM_SAP_ATR_DATA	256

#define TAPI_SIM_NET_FULL_NAME_MAX_LEN 40

#define TAPI_SIM_NET_SHORT_NAME_MAX_LEN 10

#define TAPI_SIM_OPERATION_TIMEOUT 1234

/**
 * @enum TelSimCardType_t
 * This enumeration defines the card type.
 */
typedef enum {
	TAPI_SIM_CARD_TYPE_UNKNOWN, /**< Unknown card */
	TAPI_SIM_CARD_TYPE_GSM, /**< SIm(GSM) card*/
	TAPI_SIM_CARD_TYPE_USIM, /**< USIM card */
	TAPI_SIM_CARD_TYPE_RUIM,
	TAPI_SIM_CARD_TYPE_IMS,
} TelSimCardType_t;

/**
 * @enum TelSimFileID_t
 * This enumeration defines the card type.
 */
typedef enum {
	TAPI_SIM_EF_DIR = 0x2F00, /**< Root Directory for the USIM */
	TAPI_SIM_EF_ICCID = 0x2FE2, /**< the ICC Identification file	*/
	TAPI_SIM_EF_IMSI = 0x6F07, /**< the IMSI file                */
	TAPI_SIM_EF_SST = 0x6F38, /**< the SIM Service Table file   */
	TAPI_SIM_EF_EST = 0x6F56, /**< the Enabled Service Table file   */
	TAPI_SIM_EF_OPLMN_ACT = 0x6F61, /**< the OPLMN List file*/
	TAPI_SIM_EF_GID1 = 0x6F3E, /**< the Group Identifier Level 1 */
	TAPI_SIM_EF_GID2 = 0x6F3F, /**< the Group Identifier Level 2 */

	TAPI_SIM_EF_ELP = 0x2F05, /**< the Extended Language Preference file */
	TAPI_SIM_EF_LP = 0x6F05, /**< SIM: Language preference */
	TAPI_SIM_EF_ECC = 0x6FB7, /**< the Emergency Call Codes     */
	TAPI_SIM_EF_SPN = 0x6F46, /**< the Service Provider Name    */
	TAPI_SIM_EF_SPDI = 0x6FCD, /**< the Service provider display information*/
	TAPI_SIM_EF_PNN = 0x6FC5, /**< the PLMN Network Name File*/
	TAPI_SIM_EF_OPL = 0x6FC6, /**< the Operator PLMN List File*/
	TAPI_SIM_EF_MSISDN = 0x6F40, /**< MSISDN */

	TAPI_SIM_EF_SMS = 0x6F3C, /** < Short Messages file */
	TAPI_SIM_EF_SMSP = 0x6F42, /** < SMS Parameter */
	TAPI_SIM_EF_SMSS = 0x6F43, /** < SMS Status */
	TAPI_SIM_EF_CBMI = 0x6F45, /** < Cell Broadcast Message Identifier */
	TAPI_SIM_EF_MBDN = 0x6FC7, /** < SIM Mail Box Dialing Number file */

	TAPI_SIM_EF_USIM_MBI = 0x6FC9, /** < Mailbox Identifier -linear fixed*/
	TAPI_SIM_EF_USIM_MWIS = 0x6FCA, /** < Message Waiting Indication Status -linear fixed*/
	TAPI_SIM_EF_USIM_CFIS = 0x6FCB, /** < Call forward indication status -linear fixed*/

	/* CPHS FILE ID */
	TAPI_SIM_EF_CPHS_VOICE_MSG_WAITING = 0x6F11, /** < CPHS voice MSG waiting indication  */
	TAPI_SIM_EF_CPHS_SERVICE_STRING_TABLE = 0x6F12, /** < CPHS service string table  */
	TAPI_SIM_EF_CPHS_CALL_FORWARD_FLAGS = 0x6F13, /** < CPHS call forward flags  */
	TAPI_SIM_EF_CPHS_OPERATOR_NAME_STRING = 0x6F14, /** < CPHS operator name string  */
	TAPI_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE = 0x6F15, /** < CPHS customer service profile  */
	TAPI_SIM_EF_CPHS_CPHS_INFO = 0x6F16, /** < CPHS information  */
	TAPI_SIM_EF_CPHS_MAILBOX_NUMBERS = 0x6F17, /** < CPHS mail box numbers  */
	TAPI_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING = 0x6F18, /** < CPHS operator name short form string  */
	TAPI_SIM_EF_CPHS_INFORMATION_NUMBERS = 0x6F19, /** < CPHS information numbers  */
	/*  CPHS ALS FILE ID */
	TAPI_SIM_EF_CPHS_DYNAMICFLAGS = 0x6F9F, /** < CPHS Dynamics flags  */
	TAPI_SIM_EF_CPHS_DYNAMIC2FLAG = 0x6F92, /** < CPHS Dynamics2 flags  */
	TAPI_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2 = 0x6F98, /** < CPHS CSP2  */

	/* Invalid File ID, All the file ID are less than this Value*/
	TAPI_SIM_EF_INVALID = 0xFFFF, /**< Invalid file.*/
	TAPI_SIM_EF_OTHERS, /**< Element to indicate an unknown file.*/
}TelSimFileID_t;

/**
 * @enum TelSimFacilityStatus_t
 * This enumeration defines the pin status.
 */
typedef enum {
	TAPI_SIM_FACILITY_DISABLED = 0x00,
	TAPI_SIM_FACILITY_ENABLED = 0x01,
	TAPI_SIM_FACILITY_UNKNOWN = 0xFF
} TelSimFacilityStatus_t;

/**
 * @enum TelSimPinOperationResult_t
 * This enumeration defines the pin operation result from the lower layers.
 */
typedef enum {
	TAPI_SIM_PIN_OPERATION_SUCCESS, /**< Operation involving PIN (verification/change/enable/disable, etc) is successful.  */
	TAPI_SIM_BUSY, /**< SIM is busy  */
	TAPI_SIM_CARD_ERROR, /**< SIM card error - Permanently blocked and general errors   */
	TAPI_SIM_INCOMPATIBLE_PIN_OPERATION, /**< SIM Incompatible pin operation that is in case when invalid SIM command is given or incorrect parameters are supplied to the SIM. */
	TAPI_SIM_PIN_INCORRECT_PASSWORD, /**< SIM PIN  Incorrect password */
	TAPI_SIM_PUK_INCORRECT_PASSWORD, /**< SIM PUK Incorrect Password */
	TAPI_SIM_PUK_REQUIRED, /**< PUK Required */
	TAPI_SIM_PIN_REQUIRED, /**< PIN Required */
	TAPI_SIM_NCK_REQUIRED, /**< Network Control Key Required */
	TAPI_SIM_NSCK_REQUIRED, /**< Network Subset Control Key Required */
	TAPI_SIM_SPCK_REQUIRED, /**< Service Provider Control Key Required */
	TAPI_SIM_CCK_REQUIRED, /**< Corporate Control Key Required */
	TAPI_SIM_LOCK_REQUIRED, /**<  PH-SIM (phone-SIM) locked state **/
} TelSimPinOperationResult_t;

/**
 * @enum TelSimAccessResult_t
 * This enumeration defines the SIM access result from the lower layers.
 */
typedef enum {
	TAPI_SIM_ACCESS_SUCCESS, /**< Access to file successful.  */
	TAPI_SIM_ACCESS_CARD_ERROR, /**< SIM card error    */
	TAPI_SIM_ACCESS_FILE_NOT_FOUND, /**< File not found  */
	TAPI_SIM_ACCESS_ACCESS_CONDITION_NOT_SATISFIED, /**< Access condition is not fulfilled  */
	TAPI_SIM_ACCESS_FAILED, /**< Access failed.  */
} TelSimAccessResult_t;

/**
 * @enum TelSimPinType_t
 * This enumeration defines the pin type.
 */
typedef enum {
	TAPI_SIM_PTYPE_PIN1 = 0x00, /**< PIN 1 code */
	TAPI_SIM_PTYPE_PIN2 = 0x01, /**< PIN 2 code */
	TAPI_SIM_PTYPE_PUK1 = 0x02, /**< PUK 1 code */
	TAPI_SIM_PTYPE_PUK2 = 0x03, /**< PUK 2 code */
	TAPI_SIM_PTYPE_UPIN = 0x04, /**< Universal PIN - Unused now */
	TAPI_SIM_PTYPE_ADM = 0x05, /**< Administrator - Unused now */
	TAPI_SIM_PTYPE_SIM = 0x06 /**< SIM Lock code */
} TelSimPinType_t;

/**
 * @enum TelSimTypeOfNum_t
 * This enumeration defines the type of number.
 */
typedef enum {
	TAPI_SIM_TON_UNKNOWN = 0, /**< unknown */
	TAPI_SIM_TON_INTERNATIONAL = 1, /**< international number */
	TAPI_SIM_TON_NATIONAL = 2, /**< national number */
	TAPI_SIM_TON_NETWORK_SPECIFIC = 3, /**< network specific number */
	TAPI_SIM_TON_DEDICATED_ACCESS = 4, /**< subscriber number */
	TAPI_SIM_TON_ALPHA_NUMERIC = 5, /**< alphanumeric, GSM 7-bit default alphabet) */
	TAPI_SIM_TON_ABBREVIATED_NUMBER = 6, /**< abbreviated number */
	TAPI_SIM_TON_RESERVED_FOR_EXT = 7 /**< reserved for extension */
} TelSimTypeOfNum_t;

/**
 *  @enum TelSimTextEncrypt_t
 *   This enumeration defines the text encryption types
 */
typedef enum {
	TAPI_SIM_TEXT_ENC_ASCII, /**< ASCII Encoding */
	TAPI_SIM_TEXT_ENC_GSM7BIT, /**< GSM 7 Bit Encoding */
	TAPI_SIM_TEXT_ENC_UCS2, /**< UCS2 Encoding */
	TAPI_SIM_TEXT_ENC_HEX, /**< HEX Encoding */
} TelSimTextEncrypt_t;

/**
 * @enum TelSimNumberingPlanIdentity_t
 * This enumeration defines the numbering plan identifier.
 */
typedef enum {
	TAPI_SIM_NPI_UNKNOWN = 0, /**< Unknown */
	TAPI_SIM_NPI_ISDN_TEL = 1, /**< ISDN/Telephone numbering plan */
	TAPI_SIM_NPI_DATA_NUMBERING_PLAN = 3, /**< Data numbering plan */
	TAPI_SIM_NPI_TELEX = 4, /**< Telex numbering plan */
	TAPI_SIM_NPI_SVC_CNTR_SPECIFIC_PLAN = 5, /**< Service Center Specific plan */
	TAPI_SIM_NPI_SVC_CNTR_SPECIFIC_PLAN2 = 6, /**< Service Center Specific plan */
	TAPI_SIM_NPI_NATIONAL = 8, /**< National numbering plan */
	TAPI_SIM_NPI_PRIVATE = 9, /**< Private numbering plan */
	TAPI_SIM_NPI_ERMES_NUMBERING_PLAN = 10, /**< ERMES numbering plan */
	TAPI_SIM_NPI_RESERVED_FOR_EXT = 0xF /**< Reserved for extension */
} TelSimNumberingPlanIdentity_t;

/**
 * @enum TelSimEccEmergencyServiceInfo_t
 * This enumeration defines the emergency service type.
 */
typedef enum {
	TAPI_SIM_ECC_ESC_POLICE = 0x01, /**< Police */
	TAPI_SIM_ECC_ESC_AMBULANCE = 0x02, /**< Ambulance */
	TAPI_SIM_ECC_ESC_FIREBRIGADE = 0x04, /**< Fire brigade */
	TAPI_SIM_ECC_ESC_MARAINEGUARD = 0x08, /**< Marine guard */
	TAPI_SIM_ECC_ESC_MOUTAINRESCUE = 0x10, /**< Mountain rescue */
	TAPI_SIM_ECC_ESC_SPARE = 0x00 /**< Spare */
} TelSimEccEmergencyServiceInfo_t;

/**
 * @enum TelSimLanguagePreferenceCode_t
 * This enumeration defines the language indication code.
 */
typedef enum {
	TAPI_SIM_LP_GERMAN = 0x00, /**< German */
	TAPI_SIM_LP_ENGLISH = 0x01, /**< English */
	TAPI_SIM_LP_ITALIAN = 0x02, /**< Italian */
	TAPI_SIM_LP_FRENCH = 0x03, /**< French */
	TAPI_SIM_LP_SPANISH = 0x04, /**< Spanish */
	TAPI_SIM_LP_DUTCH = 0x05, /**< Dutch */
	TAPI_SIM_LP_SWEDISH = 0x06, /**< Swedish */
	TAPI_SIM_LP_DANISH = 0x07, /**< Danish */
	TAPI_SIM_LP_PORTUGUESE = 0x08, /**< Portuguese */
	TAPI_SIM_LP_FINNISH = 0x09, /**< Finnish */
	TAPI_SIM_LP_NORWEGIAN = 0x0A, /**< Norwegian */
	TAPI_SIM_LP_GREEK = 0x0B, /**< Greek */
	TAPI_SIM_LP_TURKISH = 0x0C, /**< Turkish */
	TAPI_SIM_LP_HUNGARIAN = 0x0D, /**< Hungarian */
	TAPI_SIM_LP_POLISH = 0x0E, /**< Polish */
	TAPI_SIM_LP_KOREAN = 0x0F, /**< Korean */
	TAPI_SIM_LP_CHINESE = 0x10, /**< Chinese */
	TAPI_SIM_LP_RUSSIAN = 0x11, /**< Russian */
	TAPI_SIM_LP_JAPANESE = 0x12, /**< Japanese */
	TAPI_SIM_LP_LANG_UNSPECIFIED = 0xFF /**< Unspecified */
} TelSimLanguagePreferenceCode_t;

/**
 * @enum TelSimCardStatus_t
 * This enumeration defines the SIM card status
 */
typedef enum {
	TAPI_SIM_STATUS_CARD_ERROR = 0x00, /**< Bad card / On the fly SIM gone bad **/
	TAPI_SIM_STATUS_CARD_NOT_PRESENT = 0x01, /**<  Card not present **/
	TAPI_SIM_STATUS_SIM_INITIALIZING = 0x02, /**<  SIM is Initializing state **/
	TAPI_SIM_STATUS_SIM_INIT_COMPLETED = 0x03, /**<  SIM Initialization ok **/
	TAPI_SIM_STATUS_SIM_PIN_REQUIRED = 0x04, /**<  PIN  required state **/
	TAPI_SIM_STATUS_SIM_PUK_REQUIRED = 0x05, /**<  PUK required state **/
	TAPI_SIM_STATUS_CARD_BLOCKED = 0x06, /**<  PIN/PUK blocked(permanently blocked- All the attempts for PIN/PUK failed) **/
	TAPI_SIM_STATUS_SIM_NCK_REQUIRED = 0x07, /**<  Network Control Key required state **/
	TAPI_SIM_STATUS_SIM_NSCK_REQUIRED = 0x08, /**<  Network Subset Control Key required state **/
	TAPI_SIM_STATUS_SIM_SPCK_REQUIRED = 0x09, /**<  Service Provider Control Key required state **/
	TAPI_SIM_STATUS_SIM_CCK_REQUIRED = 0x0a, /**<  Corporate Control Key required state **/
	TAPI_SIM_STATUS_CARD_REMOVED = 0x0b, /**<  Card removed **/
	TAPI_SIM_STATUS_SIM_LOCK_REQUIRED = 0x0c, /**<  PH-SIM (phone-SIM) locked state **/
	TAPI_SIM_STATUS_UNKNOWN = 0xff /**<  Unknown status. It can be initial status **/
} TelSimCardStatus_t;

/**
 * @enum TelSimCphsPhaseType_t
 * This enum gives the current CPHS phase of SIM card.
 */
typedef enum {
	TAPI_SIM_CPHS_PHASE1 = 0x01, /**< phase1  */
	TAPI_SIM_CPHS_PHASE2 = 0x02, /**< phase2  */
	TAPI_SIM_CPHS_PHASE_RFU = 0xff /**< RFU  */
} TelSimCphsPhaseType_t;

/**
 * @enum TelSimCphsIndexLevelIndicator_t
 * This struct gives CPHS index level indication.
 */
typedef enum {
	TAPI_SIM_CPHS_INDEX_LEVEL_ONE = 0x01, /**< SIM cphs index level one */
	TAPI_SIM_CPHS_INDEX_LEVEL_TWO = 0x02, /**< SIM cphs index level two */
	TAPI_SIM_CPHS_INDEX_LEVEL_THREE = 0x03, /**< SIM cphs index level three */
	TAPI_SIM_CPHS_INDEX_LEVEL_RFU = 0xff /**< SIM cphs index level rfu */
} TelSimCphsIndexLevelIndicator_t;

/**
 * @enum TelSimCphsCustomerServiceGroup_t
 * This struct gives CPHS group service type information .
 */
typedef enum {
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_CALL_OFFERING = 0x01, /**< Group csp offering*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_CALL_RESTRICTION = 0x02, /**< Group csp restriction*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_OTHER_SUPP_SERVICES = 0x03, /**< Group csp supplementary services*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_CALL_COMPLETION = 0x04, /**< Group csp completion*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_TELESERVICES = 0x05, /**< Group csp teleservices*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_CPHS_TELESERVICES = 0x06, /**< Group csp cphs teleservies*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_CPHS_FEATURES = 0x07, /**< Group csp cphs features*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_NUMBER_IDENTIFIERS = 0x08, /**< Group csp number identifiers*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_PHASE_SERVICES = 0x09, /**< Group csp phase services*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_VALUE_ADDED_SERVICES = 0xC0, /**< Group csp value added services*/
	TAPI_SIM_CPHS_CSP_SERVICE_GROUP_INFORMATION_NUMBERS = 0xD5 /**< Group csp information numbers*/
} TelSimCphsCustomerServiceGroup_t;

/**
 * @enum TelSimMailboxType_t
 * This enum gives mailbox type.
 */
typedef enum {
	TAPI_SIM_MAILBOX_VOICE = 0x01, /**< CFIS voice*/
	TAPI_SIM_MAILBOX_VOICE2 = 0x02, /**< CFIS voice*/
	TAPI_SIM_MAILBOX_FAX = 0x03, /**< CFIS fax*/
	TAPI_SIM_MAILBOX_DATA = 0x04, /**< CFIS data*/
} TelSimMailboxType_t;

/**
 * @enum TelSimDynamicFlagsSelectedLineId_t
 * This enum gives dynamics flag selected line  information.
 */
typedef enum {
	TAPI_SIM_DYNAMIC_FLAGS_LINE1 = 0x01, /**< line 1 */
	TAPI_SIM_DYNAMIC_FLAGS_LINE2 = 0x00, /**< line 2*/
	TAPI_SIM_DYNAMIC_FLAGS_RFU = 0xff /**< rfu*/
} TelSimDynamicFlagsSelectedLineId_t;

/**
 * @enum tapi_sim_dynamic2_flag_als_status_t
 * This enum gives dynamics2 flag selected line  information.
 */
typedef enum {
	TAPI_SIM_PIN2_ACCESSIBLE_FLAGS_LOCKED = 0x01, /**< Dynamic flags locked */
	TAPI_SIM_PIN2_ACCESSIBLE_FLAGS_UNLOCKED = 0x00, /**< Dynamic flags unlocked */
	TAPI_SIM_PIN2_ACCESSIBLE_FLAGS_RFU = 0xff /**< rfu */
} TelSimDynamic2FlagAlsStatus_t;


/**
 * @enum TelSimAuthenticationType_t
 * This is used for Authentication Procedure by using SIM.
 */
typedef enum {
	TAPI_SIM_AUTH_TYPE_IMS = 0x00, /**< IMS Authentication */
	TAPI_SIM_AUTH_TYPE_GSM, /**< GSM Authentication */
	TAPI_SIM_AUTH_TYPE_3G, /**< 3G Authentication */
	TAPI_SIM_AUTH_TYPE_MAX /**< TBD */
} TelSimAuthenticationType_t;

/**
 * @enum TelSimAuthenticationResult_t
 * This is used for Authentication Procedure.
 */
typedef enum {
	TAPI_SIM_AUTH_NO_ERROR = 0x00, /**< ISIM no error */
	TAPI_SIM_AUTH_CANNOT_PERFORM, /**< status - can't perform authentication */
	TAPI_SIM_AUTH_SKIP_RESPONSE, /**< status - skip authentication response */
	TAPI_SIM_AUTH_MAK_CODE_FAILURE, /**< status - MAK(Multiple Activation Key) code failure */
	TAPI_SIM_AUTH_SQN_FAILURE, /**< status - SQN(SeQuenceNumber) failure */
	TAPI_SIM_AUTH_SYNCH_FAILURE, /**< status - synch failure */
	TAPI_SIM_AUTH_UNSUPPORTED_CONTEXT, /**< status - unsupported context */
	TAPI_SIM_AUTH_MAX /**< TBD */
} TelSimAuthenticationResult_t;

/**
 * @enum TelSimLockType_t
 *	This structure gives security lock type enum values
 */
typedef enum {
	TAPI_SIM_LOCK_PS = 0x01, /** < PH-SIM (phone-SIM) locked.Lock Phone to SIM/UICC card
	 *	(MT asks password when other than current SIM/UICC card inserted;
	 *	MT may remember certain amount of previously used cards thus not
	 *	requiring password when they are inserted
	 */
	TAPI_SIM_LOCK_PF, /** < PH-FSIM (phone-first-SIM) Lock Phone to the very
	 * First inserted SIM/UICC card(MT asks password when other than the first SIM/UICC
	 * card is inserted
	 */
	TAPI_SIM_LOCK_SC, /** < SIM Lock (PIN, PIN2, PUK, PUK2) Lock SIM/UICC card ( SIM asks password in ME power-up and
	 *	when this command is issued
	 */
	TAPI_SIM_LOCK_FD, /** < FDN - SIM card or active application in the UICC (GSM or USIM)
	 *	fixed dialing memory feature */
	TAPI_SIM_LOCK_PN, /**< Network Personalization */
	TAPI_SIM_LOCK_PU, /** < network subset Personalization */
	TAPI_SIM_LOCK_PP, /** < service Provider Personalization */
	TAPI_SIM_LOCK_PC, /** < Corporate Personalization */
} TelSimLockType_t;

/**
 * @enum TelSimLockKey_t
 *	This structure gives security lock key information enum values
 */
typedef enum {
	TAPI_SIM_LOCK_KEY_NOT_NEED = 0x00, /**< key not need */
	TAPI_SIM_LOCK_KEY_PIN = 0x01, /**< PIN required */
	TAPI_SIM_LOCK_KEY_PUK = 0x02, /**< PUK required */
	TAPI_SIM_LOCK_KEY_PIN2 = 0x03, /**< PIN2 required */
	TAPI_SIM_LOCK_KEY_PUK2 = 0x04, /**< PUK2 required */
	TAPI_SIM_LOCK_PERM_BLOCKED = 0x05, /**< Permanent block SIM */
} TelSimLockStatus_t;

/**
 * @enum TelSimSapPowerMode_t
 * This enum gives the SAP message Ids between SAP client and SAP server.
 */
typedef enum {
	TAPI_SIM_SAP_POWER_SIM_ON_REQ, /**< SAP Client request about power SIM on in Server */
	TAPI_SIM_SAP_POWER_SIM_OFF_REQ, /**< SAP Client request about power SIM off in Server */
	TAPI_SIM_SAP_RESET_SIM_REQ, /**< SAP Client request about SIM reset in Server */
} TelSimSapPowerMode_t;

/**
 * @enum TelSimSapConnectionStatus_t
 * This enum gives the SAP connection status information .
 */
typedef enum {
	TAPI_SIM_SAP_CONNECTION_STATUS_OK = 0x00, /**< connect successfully */
	TAPI_SIM_SAP_CONNECTION_STATUS_UNABLE_TO_ESTABLISH, /**< unable to establish connection */
	TAPI_SIM_SAP_CONNECTION_STATUS_NOT_SUPPORT_MAX_SIZE, /**< when server does not support message length that client want send */
	TAPI_SIM_SAP_CONNECTION_STATUS_TOO_SMALL_MAX_SIZE /**< when client want to connect with very small message length which is not supported by Server */
} TelSimSapConnectionStatus_t;

/**
 * @enum TelSimSapDissconnectType_t
 * This enum gives the SAP  disconnect type information.
 */
typedef enum {
	TAPI_SIM_SAP_DISCONNECT_TYPE_GRACEFUL = 0x00, /**< disconnection procedure ends after finishing current work */
	TAPI_SIM_SAP_DISCONNECT_TYPE_IMMEDIATE /**<  disconnection procedure ends immediately*/
} TelSimSapDissconnectType_t;

/**
 * @enum TelSimSapStatusInfo_t
 * This enum gives the SAP current connection status information
 */
typedef enum {
	TAPI_SIM_SAP_STATUS_UNKNOWN = 0x00, /**<  SAP server connection status - unknown*/
	TAPI_SIM_SAP_STATUS_NO_SIM, /**<  SAP server connection status - no SIM*/
	TAPI_SIM_SAP_STATUS_NOT_READY, /**<  SAP server connection status - not ready*/
	TAPI_SIM_SAP_STATUS_READY, /**<  SAP server connection status - ready*/
	TAPI_SIM_SAP_STATUS_CONNECTED /**<  SAP server connection status - connected*/
} TelSimSapStatusInfo_t;

/**
 * @enum TelSimSapCardStatus_t
 * This enum gives the SIM card status if server`s status changed about connection with subscription module
 */
typedef enum {
	TAPI_SIM_SAP_CARD_STATUS_UNKNOWN = 0x00, /**<  SAP server status(card reader status) - unknown*/
	TAPI_SIM_SAP_CARD_STATUS_RESET, /**<  SAP server status(card reader status) - reset*/
	TAPI_SIM_SAP_CARD_STATUS_NOT_ACCESSIBLE, /**<  SAP server status(card reader status) - not accessible*/
	TAPI_SIM_SAP_CARD_STATUS_REMOVED, /**<  SAP server status(card reader status) - removed*/
	TAPI_SIM_SAP_CARD_STATUS_INSERTED, /**<  SAP server status(card reader status) - inserted*/
	TAPI_SIM_SAP_CARD_STATUS_RECOVERED /**<  SAP server status(card reader status) - recovered*/
} TelSimSapCardStatus_t;

/**
 * @enum TelSimSapResultCode_t
 * This enum gives the SAP result information.
 */
typedef enum {
	TAPI_SIM_SAP_RESULT_CODE_OK = 0x00, /**<  SAP operation result - ok*/
	TAPI_SIM_SAP_RESULT_CODE_NO_REASON, /**<  SAP operation result - no reason*/
	TAPI_SIM_SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE, /**<  SAP operation result - not accessible*/
	TAPI_SIM_SAP_RESULT_CODE_CARD_ALREADY_POWER_OFF, /**<  SAP operation result - card already power off*/
	TAPI_SIM_SAP_RESULT_CODE_CARD_REMOVED, /**<  SAP operation result - card removed*/
	TAPI_SIM_SAP_RESULT_CODE_CARD_ALREADY_POWER_ON, /**<  SAP operation result - card already power on*/
	TAPI_SIM_SAP_RESULT_CODE_DATA_NOT_AVAILABLE, /**<  SAP operation result - data not available*/
	TAPI_SIM_SAP_RESULT_CODE_NOT_SUPPORT /**<  SAP operation result - not support*/
} TelSimSapResultCode_t;

/**
 * @enum TelSimSapProtocol_t
 * This enum gives SAP transport protocol type
 */
typedef enum {
	TAPI_SIM_SAP_PROTOCOL_T0, /**< T = 0, character*/
	TAPI_SIM_SAP_PROTOCOL_T1 /**< T = 1, block*/
} TelSimSapProtocol_t;

/**
 * @enum TelSimPbAccessResult_t
 * This enumeration defines the Phone book access result
 */
typedef enum {
	TAPI_SIM_PB_SUCCESS, /**< SIM phonebook operation successful. */
	TAPI_SIM_PB_FAIL, /**< SIM phonebook operation failure. */
	TAPI_SIM_PB_INVALID_INDEX, /**< The index passed was not a valid index. */
	TAPI_SIM_PB_INVALID_NUMBER_LENGTH, /**< The number length is exceeds the max length allowed (or 0). */
	TAPI_SIM_PB_INVALID_NAME_LENGTH, /**< The name length is exceeds the max length allowed (or 0). */
	TAPI_SIM_PB_ACCESS_CONDITION_NOT_SATISFIED, /**< Access condition for PB file is not satisfied. */
} TelSimPbAccessResult_t;

/**
 * @enum TelSimPbFileType_t
 * This enumeration defines  different storage types to be selected in SIM or USIM
 */
typedef enum {
	TAPI_SIM_PB_FDN, /**< Fixed Dialing Number */
	TAPI_SIM_PB_ADN, /**< SIM - ADN	 */
	TAPI_SIM_PB_SDN, /**< Service Dialing Number  */
	TAPI_SIM_PB_3GSIM, /**< USIM - 3G phone book */
	TAPI_SIM_PB_AAS, /**< Additional number Alpha String */
	TAPI_SIM_PB_GAS, /**< Grouping identifier Alpha String */
	TAPI_SIM_PB_UNKNOWNN = 0xFF, /**< Unknown file type */
} TelSimPbType_t;

/**
 * @enum TelSimPb3GFileType_t
 *  This enumeration defines the different storage field types in 3G Phone book.
 */
typedef enum {
	/* for 3G phone storage field type */
	TAPI_PB_3G_NAME = 0x01, /**< Name */
	TAPI_PB_3G_NUMBER, /**< Number */
	TAPI_PB_3G_ANR1, /**< First Another number*/
	TAPI_PB_3G_ANR2, /**< Second Another number */
	TAPI_PB_3G_ANR3, /**< Third Another number */
	TAPI_PB_3G_EMAIL1, /**< First Email */
	TAPI_PB_3G_EMAIL2, /**< Second Email */
	TAPI_PB_3G_EMAIL3, /**< Third Email */
	TAPI_PB_3G_EMAIL4, /**< Fourth Email */
	TAPI_PB_3G_SNE, /**< Second name entry of main name*/
	TAPI_PB_3G_GRP, /**< Group  */
	TAPI_PB_3G_PBC, /** <1 byte control info and 1 byte hidden info*/
} TelSimPb3GFileType_t;

/**
 * This data structure defines the data for the Imsi information.
 */
typedef struct {
	char szMcc[3 + 1]; /**< mobile country code */
	char szMnc[3 + 1]; /**< mobile network code */
	char szMsin[10 + 1]; /**< mobile station identification number */
} TelSimImsiInfo_t;

typedef struct {
	char name[30+1];
	char number[6+1];
	TelSimEccEmergencyServiceInfo_t category;
}TelSimEcc_t;

typedef struct {
	int ecc_count;
	TelSimEcc_t list[15];
}TelSimEccList_t;

/**
 *This data structure defines the data which is provided a unique identification number for the (U)ICC.
 */
typedef struct {
	int icc_length; /**< Integrated Circuit Card number length */
	char icc_num[TAPI_SIM_ICCID_LEN_MAX]; /**< Integrated Circuit Card number */
} TelSimIccIdInfo_t;

typedef struct {
	int line1;
	int line2;
}TelSimCallForwardingInfo_t;

typedef struct {
	int line1;
	int line2;
	int fax;
	int video;
}TelSimMessageWaitingInfo_t;

typedef struct {
	TelSimMailboxType_t type;
	char name[TAPI_SIM_XDN_DIALING_NUMBER_LEN+1];
	char number[TAPI_SIM_XDN_ALPHA_ID_MAX_LEN+1];
	TelSimTypeOfNum_t ton;
}TelSimMailboxInfo_t;

typedef struct {
	int count;
	TelSimMailboxInfo_t list[4]; //max is 4
}TelSimMailboxList_t;

/**
 *	This data structure represents MSISDN information
 */
typedef struct {
	char num[TAPI_SIM_XDN_DIALING_NUMBER_LEN + 1]; /**< MSISDN number. If not exist, Null string will be returned*/
	char name[TAPI_SIM_XDN_ALPHA_ID_MAX_LEN + 1]; /**< MSISDN name. If not exist, Null string will be returned*/
} TelSimSubscriberInfo_t;

typedef struct {
	int count;
	TelSimSubscriberInfo_t list[3]; //max is 3
}TelSimMsisdnList_t;

typedef struct {
	char plmn[6+1];
	int b_umts;
	int b_gsm;
}TelSimOplmnwact_t;

typedef struct {
	int count;
	TelSimOplmnwact_t list[30]; //max is 30
}TelSimOplmnwactList_t;

typedef struct {
	unsigned char display_condition; /**< display condition (1 byte) */
	unsigned char spn[TAPI_SIM_NET_FULL_NAME_MAX_LEN + 1]; /**< SPN */
}TelSimSpn_t;

typedef struct {
	unsigned char full_name[TAPI_SIM_NET_FULL_NAME_MAX_LEN + 1];
	unsigned char short_name[TAPI_SIM_NET_SHORT_NAME_MAX_LEN + 1];
}TelSimCphsNetName_t;

/**
 *This is used for authentication request procedure.
 */
typedef struct {
	TelSimAuthenticationType_t auth_type; /**< Authentication type */
	int rand_length; /**< the length of RAND */
	int autn_length; /**< the length of AUTN. it is not used in case of GSM AUTH */
	char rand_data[TAPI_SIM_AUTH_MAX_REQ_DATA_LEN]; /**< RAND data */
	char autn_data[TAPI_SIM_AUTH_MAX_REQ_DATA_LEN]; /**< AUTN data. it is not used in case of GSM AUTH */
} TelSimAuthenticationData_t;

/**
 * This is used for result data of authentication.
 */
typedef struct {
	TelSimAuthenticationType_t auth_type; /**< authentication type */
	TelSimAuthenticationResult_t auth_result; /**< authentication result */
	int resp_length; /**< response length. IMS and 3G case, it stands for RES_AUTS. GSM case, it stands for SRES. */
	char resp_data[TAPI_SIM_AUTH_MAX_RESP_DATA_LEN]; /**< response data. IMS and 3G case, it stands for RES_AUTS. GSM case, it stands for SRES. */
	int authentication_key_length; /**< the length of authentication key, Kc*/
	char authentication_key[TAPI_SIM_AUTH_MAX_RESP_DATA_LEN]; /**< the data of of authentication key, Kc*/
	int cipher_length; /**< the length of cipher key length */
	char cipher_data[TAPI_SIM_AUTH_MAX_RESP_DATA_LEN]; /**< cipher key */
	int integrity_length; /**< the length of integrity key length */
	char integrity_data[TAPI_SIM_AUTH_MAX_RESP_DATA_LEN]; /**< integrity key */
} TelSimAuthenticationResponse_t;


/**
 * This structure contains information about pin data.
 * SIM PIN DATA. For PIN handling (Change, UnBlock) & for Type of PIN information.
 */
typedef struct {
	TelSimPinType_t type; /**< Pin type */
	unsigned char* pw; /**< PIN code */
	unsigned int pw_len; /**< PIN code length*/
} TelSimSecPw_t;

/**
 * This data structure defines the data for the PIN Information.
 */
typedef struct {
	TelSimPinType_t type; /**< Specifies the PIN or PUK type.*/
	int retry_count; /**< Number of attempts remaining for PIN/PUK verification.*/
} TelSimSecResult_t;

/**
 * This structure is used to en/disable facility
 */
typedef struct {
	TelSimLockType_t lock_type; /**< Facility type */
	unsigned char *pw; /**< password */
	int pw_len; /**< password length */
} TelSimFacilityPw_t;

typedef struct {
	TelSimLockType_t type; /**< Specifies the PIN or PUK type.*/
	int retry_count; /**< Number of attempts remaining for PIN/PUK verification.*/
} TelSimFacilityResult_t;

typedef struct {
	TelSimLockType_t type;
	TelSimFacilityStatus_t f_status;
}TelSimFacilityInfo_t;

/**
 *
 * This structure is used to get information about LOCK_TYPE
 */
typedef struct {
	TelSimLockType_t lock_type; /**< Lock type */
	TelSimLockStatus_t lock_status; /**< Lock key */
	int retry_count; /**< retry counts */
} TelSimLockInfo_t;

/**
 * This data structure defines the data for the apdu.
 */
typedef struct {
	unsigned short apdu_len;
	unsigned char* apdu;
} TelSimApdu_t;

/**
 * This data structure defines the data for the Response of sending apdu.
 */
typedef struct {
	unsigned short apdu_resp_len;
	unsigned char apdu_resp[TAPI_SIM_APDU_MAX_LEN];
} TelSimApduResp_t;

/**
 * This data structure defines the data for the Response of sending apdu.
 */
typedef struct {
	unsigned short atr_resp_len;
	unsigned char atr_resp[TAPI_SIM_APDU_MAX_LEN];
} TelSimAtrResp_t;


/**CPHS related structs **/

/**
 *	This sturcture gives information of available optional CPHS SIM files.
 */
typedef struct {
	/* Byte 2 - bit1 & 2*/
	int bCustomerServiceProfile; /**< Customer Service Profile (CSP)  */
	/* Byte 2 - bit3 & 4*/
	int bServiceStringTable; /**< Service String Table (SST) */
	/* Byte 2 - bit5 & 6*/
	int bMailBoxNumbers; /**< MailBoxNumbers */
	/* Byte 2 - bit7 & 8*/
	int bOperatorNameShortForm; /**< Short form of operator name */
	/* Byte 3 - bit1 & 2*/
	int bInformationNumbers; /**< Information numbers */
} TelSimCphsServiceTable_t;

/*
 These requirements are additional to the GSM 900 and DCS1800 recommendations.
 They apply to all products which are to be compliant with the CPHS specification.

 In addition to those SIM storage fields previously defined in DCS1800 to support
 existing MS features and services, the Association has defined the following fields  :-

 1)	Call Forwarding flag						(mandatory)
 2)	Voice message waiting flag					(mandatory)
 3)	PLMN operator name						(mandatory)
 4)	Customer Service Profile (CSP)				(optional)
 5)	CPHS Information							(mandatory)
 6)	Mailbox Numbers							(optional)
 7)	Information Numbers						(optional)

 */

/*
 DATA FIELD - 6F 16: CPHS INFORMATION
 Access Conditions:
 READ	CHV1
 UPDATE	ADM
 */
/**
 *
 *This structure gives CPHS information data.
 */
typedef struct {
	TelSimCphsPhaseType_t CphsPhase; /**< CPHS phase type */
	TelSimCphsServiceTable_t CphsServiceTable; /**< CPHS service table */
} TelSimCphsInfo_t;

/*
 DATA FIELD -6F 11: Voice message waiting flag
 Access Conditions:
 READ	CHV1
 UPDATE	CHV1
 */
/**
 *
 * This struct gives CPHS voice message waiting flag information .
 */
typedef struct {
	int bWaitVoiceMsgLine1; /**< VoiceMsgLine 1 */
	int bWaitVoiceMsgLine2; /**< VoiceMsgLine 2 */
	int bWaitFaxMsg; /**< FAX Msg */
	int bWaitDataMsg; /**< Data Msg */
} TelSimCphsVoiceMsgWaitFlagInfo_t;

/*
 DATA FIELD -6F 13: Call forwarding flags
 Access Conditions:
 READ	CHV1
 UPDATE	CHV1
 */
/**
 * This struct gives CPHS call forwarding flag information.
 */
typedef struct {
	int bCallForwardUnconditionalLine1; /**< CallForwardUnconditionalLine 1 */
	int bCallForwardUnconditionalLine2; /**< CallForwardUnconditionalLine 2 */
	int bCallForwardUnconditionalFax; /**< CallForwardUnconditional FAX */
	int bCallForwardUnconditionalData; /**<CallForwardUnconditional data*/
	int bCallForwardUnconditionalSms; /**< CallForwardUnconditional SMS */
	int bCallForwardUnconditionalBearer; /**< CallForwardUnconditional bearer*/
} TelSimCphsCallForwardingFlagInfo_t;

/*
 DATA FIELD -6F 19: Information Numbers
 Access Conditions:
 READ	CHV1
 UPDATE	CHV1
 */
/**
 * This struct gives CPHS information numbers data.
 */
typedef struct {
	int bUsed; /**< SIM CPHS index level one */
	unsigned char AlphaIdLength; /**< length of alpha identifier */

	TelSimCphsIndexLevelIndicator_t IndexLevelIndicator; /**< SIM CPHS index level one */
	int PremiumServiceIndicator; /**< SIM CPHS index level one */
	int NetworkSpecificIndicator; /**< SIM CPHS index level one */
	unsigned char Alpha_id[TAPI_SIM_XDN_ALPHA_ID_MAX_LEN + 1]; /**<  Alpha Identifier */

	unsigned long DiallingnumLength; /**< Length of BCD number/SSC contents */
	TelSimTypeOfNum_t TypeOfNumber; /**< TON */
	TelSimNumberingPlanIdentity_t NumberingPlanIdentity; /**< NPI */
	char DiallingNum[TAPI_SIM_XDN_DIALING_NUMBER_LEN + 1]; /**< dialing Number/SSC String */
	unsigned char Ext1RecordId; /**< Extensiion1 Record Identifier */
} TelSimCphsInformationNum_t;

/*
 DATA FIELD- 6F 15: Customer Service Profile (Storing a list of service options which are relevant to that specific customer)
 Access Conditions:
 READ	CHV1
 UPDATE	CHV1
 */
/**
 *
 * This struct gives CPHS service call offering information.
 */
typedef struct {
	int bCallForwardingUnconditional; /**< CallForwarding Unconditional */
	int bCallForwardingOnUserBusy; /**< CallForwarding On UserBusy */
	int bCallForwardingOnNoReply; /**< CallForwarding On NoReply */
	int bCallForwardingOnUserNotReachable; /**< CallForwarding On User Not Reachable */
	int bCallTransfer; /**< Call Transfer */
} TelSimCphsServiceCallOffering_t;

/**
 *
 * This struct gives CPHS service call restriction information.
 */
typedef struct {
	int bBarringOfAllOutgoingCalls; /**< Barring Of All Outgoing Calls*/
	int bBarringOfOutgoingInternationalCalls; /**< Barring Of Outgoing International Calls */
	int bBarringOfOutgoingInternationalCallsExceptHplmn; /**< Barring Of Outgoing International Calls Except HPLMN */
	int bBarringOfAllIncomingCallsRoamingOutsideHplmn; /**< Barring Of All Incoming Calls Roaming Outside HPLMN */
	int bBarringOfIncomingCallsWhenRoaming; /**< Barring Of IncomingCalls When Roaming */
} TelSimCphsServiceCallRestriction_t;

/**
 *
 * This struct gives CPHS service SS  information.
 */
typedef struct {
	int bMultiPartyService; /**< MultiPartyService*/
	int bClosedUserGroup; /**< ClosedUserGroup*/
	int bAdviceOfCharge; /**< AdviceOfCharge*/
	int bPreferentialClosedUserGroup; /**< PreferentialClosedUserGroup*/
	int bClosedUserGroupOutgoingAccess; /**< ClosedUserGroupOutgoingAccess*/
} TelSimCphsServiceOtherSupplimentaryService_t;

/**
 *
 * This struct gives CPHS service call complete information.
 */
typedef struct {
	int bCallHold; /**< Call Hold*/
	int bCallWaiting; /**< Call Waiting*/
	int bCompletionOfCallToBusySubscriber; /**< Completion Of Call To Busy Subscriber*/
	int bUserUserSignalling; /**< User User Signaling*/
} TelSimCphsServiceCallComplete_t;

/**
 *
 * This struct gives CPHS service teleservices  information.
 */
typedef struct {
	int bShortMessageMobileOriginated; /**< Short Message Mobile Originated*/
	int bShortMessageMobileTerminated; /**< Short Message Mobile Terminated*/
	int bShortMessageCellBroadcast; /**< Short Message Cell Broadcast*/
	int bShortMessageReplyPath; /**< Short  Message Reply Path*/
	int bShortMessageDeliveryConf; /**< Short Message Delivery Conf*/
	int bShortMessageProtocolIdentifier; /**< Short Message Protocol Identifier*/
	int bShortMessageValidityPeriod; /**< Short Message Validity Period*/
} TelSimCphsServiceTeleservices_t;

/**
 *
 * This struct gives CPHS alternative line service  information.
 */
typedef struct {
	int bAlternativeLineService; /**< Alternative Line Service*/
} TelSimCphsServiceCphsTeleservices_t;

/**
 *
 * This struct gives CPHS string service table information.
 */
typedef struct {
	int bStringServiceTable; /**< String Service Table*/
} TelSimCphsServiceCphsFeatures_t;

/**
 *
 * This struct gives CPHS service number identifier  information.
 */
typedef struct {
	int bCallingLineIdentificationPresent; /**< Calling Line Identification Present*/
	int bConnectedLineIdentificationRestrict; /**< Connected Line Identification Restrict*/
	int bConnectedLineIdentificationPresent; /**< Connected Line Identification Present*/
	int bMaliciousCallIdentifier; /**< Malicious Call Identifier*/
	int bCallingLineIdentificationSend; /**< Calling Line Identification Send*/
	int bCallingLineIdentificationBlock; /**< Calling Line Identification Block*/
} TelSimCphsServiceNumberIdentifier_t;

/**
 *
 * This struct gives CPHS service phase services information.
 */
typedef struct {
	int bMenuForGprs; /**< Menu For GPRS*/
	int bMenuForHighSpeedCsd; /**< Menu For HighSpeedCsd*/
	int bMenuForVoiceGroupCall; /**< Menu For VoiceGroupCall*/
	int bMenuForVoiceBroadcastService; /**< Menu For VoiceBroadcastService*/
	int bMenuForMultipleSubscriberProfile; /**< Menu For MultipleSubscriberProfile*/
	int bMenuForMultipleBand; /**< Menu For MultipleBand*/
} TelSimCphsServicePhaseServices_t;

/**
 *
 * This struct gives CPHS value added service   information.
 */
typedef struct {
	int bRestrictMenuForManualSelection; /**< RestrictMenu For ManualSelection*/
	int bRestrictMenuForVoiceMail; /**< RestrictMenu For VoiceMail*/
	int bRestrictMenuForMoSmsAndPaging; /**< RestrictMenu For MoSmsAndPaging*/
	int bRestrictMenuForMoSmsWithEmialType; /**< RestrictMenu For MoSmsWithEmialType*/
	int bRestrictMenuForFaxCalls; /**< RestrictMenu For FaxCalls*/
	int bRestrictMenuForDataCalls; /**< RestrictMenu For DataCalls*/
	int bRestrictMenuForChangeLanguage; /**< RestrictMenu For ChangeLanguage*/
} TelSimCphsServiceValueAddedServices_t;

/**
 *
 * This struct gives CPHS service information number data.
 */
typedef struct {
	int bInformationNumbers; /**< Information Numbers*/
} TelSimCphsServiceInformationNumbers_t;

/**
 *
 * This struct gives CPHS service profile entry  information.
 */
typedef struct {
	TelSimCphsCustomerServiceGroup_t CustomerServiceGroup; /**< customer service group*/
	union {
		TelSimCphsServiceCallOffering_t CallOffering; /**< call offering*/
		TelSimCphsServiceCallRestriction_t CallRestriction; /**< call restriction*/
		TelSimCphsServiceOtherSupplimentaryService_t OtherSuppServices; /**< other SS services*/
		TelSimCphsServiceCallComplete_t CallComplete; /**< call complete*/
		TelSimCphsServiceTeleservices_t Teleservices; /**< teleservices*/
		TelSimCphsServiceCphsTeleservices_t CphsTeleservices; /**< CPHS teleservices*/
		TelSimCphsServiceCphsTeleservices_t CphsFeatures; /**< CPHS features*/
		TelSimCphsServiceNumberIdentifier_t NumberIdentifiers; /**< number identifiers*/
		TelSimCphsServicePhaseServices_t PhaseServices; /**< phase services*/
		TelSimCphsServiceValueAddedServices_t ValueAddedServices; /**< value added services*/
		TelSimCphsServiceInformationNumbers_t InformationNumbers; /**< information numbers*/
	} u;
} TelSimCphsCustomerServiceProfileEntry_t;

/**
 *
 * This struct gives CPHS service profile information.
 */
typedef struct {
	TelSimCphsCustomerServiceProfileEntry_t ServiceProfileEntry[TAPI_SIM_CPHS_CUSTOMER_SERVICE_PROFILE_ENTRY_COUNT_MAX]; /**< service profile entry*/
} TelSimCphsCustomerServiceProfileInfo_t;

/**
 *
 * This struct gives dynamics flag selected line  information.
 */
typedef struct {
	TelSimDynamicFlagsSelectedLineId_t DynamicFlags; /**< Dynamic flags information */
} TelSimDynamicFlagsInfo_t;

/**
 *
 * This struct gives dynamics flag selected line  information.
 */
typedef struct {
	TelSimDynamic2FlagAlsStatus_t Dynamic2Flag; /**< Dynamic flags status */
} TelSimDynamic2FlagsInfo_t;


/**
 * This data structure gives the phone book availability of current SIM.
 */
typedef struct {
	int b_fdn; /**< Fixed Dialing Number */
	int b_adn; /**< SIM - ADN(2G phonebook	 */
	int b_sdn; /**< Service Dialing Number  */
	int b_3g; /**< USIM - 3G phonebook */
	int b_aas; /**< Additional number Alpha String phonebook */
	int b_gas; /**< Grouping information Alpha String phonebook */
} TelSimPbList_t;

typedef struct {
	TelSimPbType_t phonebook_type;
	unsigned short index;
	unsigned short next_index; //this field is not used in add/update case

	unsigned char name[60];
	TelSimTextEncrypt_t dcs;

	unsigned char number[40];
	TelSimTypeOfNum_t ton;

	/* following field is valid in only USIM*/
	unsigned char sne[60];
	TelSimTextEncrypt_t sne_dcs;
	unsigned char anr1[40];
	TelSimTypeOfNum_t anr1_ton;
	unsigned char anr2[40];
	TelSimTypeOfNum_t anr2_ton;
	unsigned char anr3[40];
	TelSimTypeOfNum_t anr3_ton;

	unsigned char email1[60];
	unsigned char email2[60];
	unsigned char email3[60];
	unsigned char email4[60];

	unsigned short group_index; //GRP
	unsigned short pb_control; //PBC
} TelSimPbRecord_t;

/**
 *	This data structure defines the phone book storage count information.
 */
typedef struct {
	TelSimPbType_t StorageFileType; /**< Storage  file type */
	unsigned short TotalRecordCount; /**< Total record count */
	unsigned short UsedRecordCount; /**< Used record count */
} TelSimPbStorageInfo_t;

/**
 * This data structure gives the phone book entry information.
 */
typedef struct {
	TelSimPbType_t StorageFileType; /**< Storage  file type */
	unsigned short PbIndexMin; /**< Phone book minimum index*/
	unsigned short PbIndexMax; /**< Phone book maximum index */
	unsigned short PbNumLenMax; /**< Phone number maximum length */
	unsigned short PbTextLenMax; /**< Text maximum length */
} TelSimPbEntryInfo_t;

/**
 *
 This structure gives 3G phone book capability information.
 */
typedef struct {
	TelSimPb3GFileType_t field_type; /**< 3G phonebook file type */
	unsigned short index_max; /**< max index */
	unsigned short text_max; /**< max text length */
	unsigned short used_count; /**< used record count */
} TelSimPb3GFileTypeCapabiltyInfo_t;

/**
 *
 * This data structure defines the data for the SIM PHONEBOOK & ITS CAPABILITIES information.
 * It refers to EF_PBR
 */
typedef struct {
	unsigned short FileTypeCount; /**< phonebook file type count */
	TelSimPb3GFileTypeCapabiltyInfo_t FileTypeInfo[TAPI_SIM_PB_3G_FILE_MAX_COUNT]; /**< phonebook file type information */
} TelSimPbCapabilityInfo_t;



/* SAP (SIM Access Profile) related interface structures and enum */
/**
 * This struct gives the SAP ATR response data information.
 */
typedef struct {
	int atr_len; /**<  SAP ATR response data length */
	unsigned char atr_data[TAPI_SIM_SAP_ATR_DATA]; /**<  SAP ATR response data */
} TelSapAtrInfo_t;

/* SAP transfer APDU request */

/**
 * This data structure gives the SAP APDU data information.
 */
typedef struct {
	int apdu_len; /**<  SAP APDU length */
	unsigned char apdu_data[TAPI_SIM_APDU_MAX_LEN]; /**<  SAP APDU data */
} TelSapApduData_t;


#ifdef __cplusplus
}
#endif

#endif // _TELSIM_H_
/**
 * @}
 */
