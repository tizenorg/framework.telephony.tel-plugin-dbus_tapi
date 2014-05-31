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
 * @addtogroup 	SAT_TAPI	SAT
 * @{
 *
 * @file TelSatObj.h

 @brief This file serves as a "C" header file defines structures for Telephony SAT Services. \n
 It contains a sample set of constants, enums, structs that would be required by applications.
 */

#ifndef _TEL_SAT_OBJ_H_
#define _TEL_SAT_OBJ_H_

#include <TelDefines.h>
#include <TelSim.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define EXTENDED_ASCII 1

#define TAPI_SAT_DIALLING_NUMBER_LEN_MAX				200	 /**<	max length of dialing number 		*/
#define TAPI_SAT_ALPHA_ID_LEN_MAX						255	 /**<	max length of  alpha identifier		*/
#define TAPI_SAT_TEXT_STRING_LEN_MAX					500	 /**<	max length of text string -when the string data is in 7Bit packed format, this length is not enough to support the maximum size so should increase the value to a value > 275 */
#define TAPI_SAT_SUB_ADDR_LEN_MAX						30	 /**<	max length of sub address 		*/
#define TAPI_SAT_CCP_DATA_LEN_MAX						30	 /**<	max length of ccp data 		*/
#define TAPI_SAT_ITEM_TEXT_LEN_MAX						45	 /**<	max length of item text 		*/
#define TAPI_SAT_SMS_TPDU_SMS_DATA_LEN_MAX				175	 /**<	max length of sms tpdu data 		*/
#define TAPI_SAT_SS_STRING_LEN_MAX						160	 /**<	max length of ss string		*/
#define TAPI_SAT_USSD_STRING_LEN_MAX					255	 /**<	max length of ussd string 		*/
#define TAPI_SAT_FILE_ID_LIST_MAX_COUNT					255	 /**<	max count of file id list		*/
#define TAPI_SAT_ITEMS_NEXT_ACTION_INDI_LIST_MAX_COUNT	50	 /**<	max count of items next action indication list	*/
#define TAPI_SAT_EVENT_LIST_MAX_COUNT					17	 /**<	max count of sat event list 		*/
#define TAPI_SAT_IMG_INSTANT_RAW_DATA_LEN_MAX			256	 /**<	max length of image instant raw		*/
#define TAPI_SAT_CLUT_DATA_LEN_MAX						256	 /**<	max length of clut data 		*/
#define TAPI_SAT_IMG_DATA_FILE_PATH_LEN_MAX				50	 /**<   max length of image data file name (Icon, CLUT)		*/
#define TAPI_SAT_ICON_LIST_MAX_COUNT					50	 /**<	max count of icon list 		*/
#define TAPI_SAT_DTMF_STRING_LEN_MAX					30	 /**<	max length of dtmf string		*/
#define TAPI_SAT_DATE_TIME_AND_TIME_ZONE_LEN			7	 /**<	max length of date time and time zone		*/
#define TAPI_SAT_URL_LEN_MAX							129	 /**<	max length of url 		*/
#define TAPI_SAT_BEARER_LIST_MAX_COUNT					50	 /**<	max count of bearer list 		*/
#define TAPI_SAT_PROVISIONING_FILE_PATH_LEN_MAX			50	 /**<	max length of provisioning file path 	*/
#define TAPI_SAT_BEARER_PARAMS_LEN_MAX					10	 /**<	max length of bearer parameters 		*/
#define TAPI_SAT_CHANNEL_DATA_STRING_LEN_MAX			255	 /**<	max length of channel data string 		*/
#define TAPI_SAT_CHANNEL_STATUS_LEN						2	 /**<	max length of channel status 		*/
#define TAPI_SAT_CHANNEL_ID_LEN							3	 /**<	max length of channel id 		*/
#define TAPI_SAT_OTHER_ADDR_LEN_MAX						30	 /**<	max length of other address 		*/
#define TAPI_SAT_PORT_NUMBER_LEN						2	 /**<	max length of port number 		*/
#define TAPI_SAT_NET_ACC_NAM_LEN_MAX					30	 /**<	max length of net acc name		*/
#define TAPI_SAT_AID_LEN_MAX							128	 /**<	max length of aid 		*/
#define TAPI_SAT_REMOTE_ENTITY_ADDR_LEN_MAX				50	 /**<	max length of remote entity address 	*/
#define TAPI_SAT_ITEM_TEXT_ATTRIBUTES_LIST_MAX_COUNT	50	 /**<	max count of item text attributes list		*/
#define TAPI_SAT_MCC_CODE_LEN							3	 /**<	max length of mcc 		*/
#define TAPI_SAT_MNC_CODE_LEN							3	 /**<	max length of mnc 		*/
#define TAPI_SAT_LAC_CODE_LEN							2	 /**<	max length of lac 		*/
#define TAPI_SAT_CELL_ID_LEN							2	 /**<	max length of cell id	*/

/**
 * @enum TelSatAlphabetFormatType_t
 * This enum lists the Alphabet Format.
 */
typedef enum {
	TAPI_SAT_ALPHABET_FORMAT_SMS_DEFAULT = 0x00, /**<	ALPHABET FROMAT SMS DEFAULT 		*/
	TAPI_SAT_ALPHABET_FORMAT_8BIT_DATA = 0x01, /**<	ALPHABET FROMAT 8BIT DATA 		*/
	TAPI_SAT_ALPHABET_FORMAT_UCS2 = 0x02, /**<	ALPHABET FROMAT UCS2 		*/
	TAPI_SAT_ALPHABET_FORMAT_RESERVED = 0x03 /**<	ALPHABET FROMAT RESERVED 		*/
} TelSatAlphabetFormatType_t;

/**
 * @enum TelSatMsgClassType_t
 * This enum lists the message class.
 */
typedef enum {
	TAPI_SAT_MSG_CLASS_NONE = 0x00, /**<	none 	*/
	TAPI_SAT_MSG_CLASS_0 = 0x01, /**<	class 0 		*/
	TAPI_SAT_MSG_CLASS_1, /**<	class 1 Default meaning:ME-specific 		*/
	TAPI_SAT_MSG_CLASS_2, /**<	class 2 SIM specific message 		*/
	TAPI_SAT_MSG_CLASS_3, /**<	class 3 Default meaning: TE specific 		*/
	TAPI_SAT_MSG_CLASS_RESERVED = 0xFF /**<	class reserved 		*/
} TelSatMsgClassType_t;

/**
 * @enum TelSatCommandType_t
 * This enum lists the type of command and the next action indicator.
 */
typedef enum {
	TAPI_SAT_CMD_TYPE_NONE = 0x00, /**<	command type - None 		*/

	TAPI_SAT_CMD_TYPE_REFRESH = 0x01, /**<	command type - refresh 		*/
	TAPI_SAT_CMD_TYPE_MORE_TIME = 0x02, /**<	command type - more time		*/
	TAPI_SAT_CMD_TYPE_SETUP_EVENT_LIST = 0x05, /**<	command type - setup event list 		*/
	TAPI_SAT_CMD_TYPE_SETUP_CALL = 0x10, /**<	command type - setup call		*/
	TAPI_SAT_CMD_TYPE_SEND_SS = 0x11, /**<	command type - send ss		*/
	TAPI_SAT_CMD_TYPE_SEND_USSD = 0x12, /**<	command type - send ussd		*/
	TAPI_SAT_CMD_TYPE_SEND_SMS = 0x13, /**<	command type - send sms 		*/
	TAPI_SAT_CMD_TYPE_SEND_DTMF = 0x14, /**<	command type - send dtmf 		*/
	TAPI_SAT_CMD_TYPE_LAUNCH_BROWSER = 0x15, /**<	command type - launch browser 		*/
	TAPI_SAT_CMD_TYPE_PLAY_TONE = 0x20, /**<	command type - play tone		*/
	TAPI_SAT_CMD_TYPE_DISPLAY_TEXT = 0x21, /**<	command type - display text		*/
	TAPI_SAT_CMD_TYPE_GET_INKEY = 0x22, /**<	command type - get inkey		*/
	TAPI_SAT_CMD_TYPE_GET_INPUT = 0x23, /**<	command type - get input		*/
	TAPI_SAT_CMD_TYPE_SELECT_ITEM = 0x24, /**<	command type - select item		*/
	TAPI_SAT_CMD_TYPE_SETUP_MENU = 0x25, /**<	command type - setup menu		*/
	TAPI_SAT_CMD_TYPE_PROVIDE_LOCAL_INFO = 0x26, /**<	command type - provide local info 		*/
	TAPI_SAT_CMD_TYPE_SETUP_IDLE_MODE_TEXT = 0x28, /**<	command type - setup idle mode text		*/
	TAPI_SAT_CMD_TYPE_LANGUAGE_NOTIFICATION = 0x35, /**<	command type - language notification		*/
	TAPI_SAT_CMD_TYPE_OPEN_CHANNEL = 0x40, /**<	command type - open channel -class e		*/
	TAPI_SAT_CMD_TYPE_CLOSE_CHANNEL = 0x41, /**<	command type - close channel - class e		*/
	TAPI_SAT_CMD_TYPE_RECEIVE_DATA = 0x42, /**<	command type - receive data -class e 		*/
	TAPI_SAT_CMD_TYPE_SEND_DATA = 0x43, /**<	command type - send data 		*/
	TAPI_SAT_CMD_TYPE_GET_CHANNEL_STATUS = 0x44, /**<	command type - get channel status -class e 		*/
	TAPI_SAT_CMD_TYPE_END_OF_APP_EXEC = 0xFD, /**<	inform to End the execution of a Proactive Command*/
	TAPI_SAT_CMD_TYPE_END_PROACTIVE_SESSION = 0xFE, /**<	inform end proactive session		*/
	TAPI_SAT_CMD_TYPE_RESERVED = 0xFF /**<	command type - reserved		*/
} TelSatCommandType_t;

/**
 * @enum TelSatCmdQualiRefresh_t
 * This enum lists the Command qualifier values for Refresh command.
 */
typedef enum {
	TAPI_SAT_REFRESH_SIM_INIT_AND_FULL_FCN = 0x00, /**<	command qualifier for REFRESH SIM INIT AND FULL FILE CHANGE_NOTIFICATION		*/
	TAPI_SAT_REFRESH_FCN = 0x01, /**<	command qualifier for REFRESH FILE CHANGE NOTIFICATION		*/
	TAPI_SAT_REFRESH_SIM_INIT_AND_FCN = 0x02, /**<	command qualifier for REFRESH SIM INIT AND FILE CHANGE NOTIFICATION		*/
	TAPI_SAT_REFRESH_SIM_INIT = 0x03, /**<	command qualifier for REFRESH SIM INIT		*/
	TAPI_SAT_REFRESH_SIM_RESET = 0x04, /**<	command qualifier for REFRESH SIM RESET		*/
	TAPI_SAT_REFRESH_3G_APPLICATION_RESET = 0x05, /**<	command qualifier for REFRESH 3G APPLICATION RESET		*/
	TAPI_SAT_REFRESH_3G_SESSION_RESET = 0x06, /**<	command qualifier for REFRESH 3G SESSION RESET		*/
	TAPI_SAT_REFRESH_RESERVED = 0xFF /**<	command qualifier for REFRESH RESERVED		*/
} TelSatCmdQualiRefresh_t;

/**
 * @enum TelSatCmdQualiSetupCall_t
 * This enum lists the Command qualifier values for setup call command.
 */
typedef enum {
	TAPI_SAT_SETUP_CALL_IF_ANOTHER_CALL_NOT_BUSY = 0x00, /**<	command qualifier for SETUP CALL IF ANOTHER CALL NOT BUSY		*/
	TAPI_SAT_SETUP_CALL_IF_ANOTHER_CALL_NOT_BUSY_WITH_REDIAL = 0x01, /**<	command qualifier for SETUP CALL IF ANOTHER CALL NOT BUSY WITH REDIAL		*/
	TAPI_SAT_SETUP_CALL_PUT_ALL_OTHER_CALLS_ON_HOLD = 0x02, /**<	command qualifier for SETUP CALL PUTTING ALL OTHER CALLS ON HOLD		*/
	TAPI_SAT_SETUP_CALL_PUT_ALL_OTHER_CALLS_ON_HOLD_WITH_REDIAL = 0x03, /**<	command qualifier for SETUP CALL PUTTING ALL OTHER CALLS ON HOLD WITH REDIAL		*/
	TAPI_SAT_SETUP_CALL_DISCONN_ALL_OTHER_CALLS = 0x04, /**<	command qualifier for SETUP CALL DISCONNECTING ALL OTHER CALLS		*/
	TAPI_SAT_SETUP_CALL_DISCONN_ALL_OTHER_CALLS_WITH_REDIAL = 0x05, /**<	command qualifier for SETUP CALL DISCONNECTING ALL OTHER CALLS WITH REDIAL		*/
	TAPI_SAT_SETUP_CALL_RESERVED = 0xFF /**<	command qualifier for SETUP CALL RESERVED 		*/
} TelSatCmdQualiSetupCall_t;

/**
 * @enum TelSatDisplayTextPriorityType_t
 * This is associated with the command qualifier for display text.
 */
typedef enum {
	TAPI_SAT_MSG_PRIORITY_NORMAL = 0, /**<	MSG PRIORITY NORMAL 		*/
	TAPI_SAT_MSG_PRIORITY_HIGH = 1 /**<	MSG PRIORITY HIGH 		*/
} TelSatDisplayTextPriorityType_t;

/**
 * @enum TelSatDisplayTextMsgClearType_t
 * This is associated with the command qualifier for display text.
 */
typedef enum {
	TAPI_SAT_AUTO_CLEAR_MSG_AFTER_A_DELAY = 0, /**<	message clear type -  AUTO CLEAR MSG AFTER A DELAY		*/
	TAPI_SAT_WAIT_FOR_USER_TO_CLEAR_MSG = 1 /**<	message clear type -  WAIT FOR USER TO CLEAR MSG		*/
} TelSatDisplayTextMsgClearType_t;

/**
 * @enum TelSatInkeyType_t
 * This is associated with the command qualifier for get inkey.
 */
typedef enum {
	TAPI_SAT_INKEY_TYPE_CHARACTER_SET_ENABLED = 0, /**<	command qualifier for  INKEY TYPE CHARACTER SET ENABLED		*/
	TAPI_SAT_INKEY_TYPE_YES_NO_REQUESTED = 1 /**<	command qualifier for  INKEY TYPE YES NO REQUESTED 		*/
} TelSatInkeyType_t;

/**
 * @enum TelSatUseInputAlphabetType_t
 * This is associated with the command qualifier for get input.
 */
typedef enum {
	TAPI_SAT_USER_INPUT_ALPHABET_TYPE_SMS_DEFAULT = 1, /**<	command qualifier for  ALPHABET TYPE SMS DEFAULT 		*/
	TAPI_SAT_USER_INPUT_ALPHABET_TYPE_UCS2 = 2 /**<	command qualifier for  ALPHABET TYPE UCS2 		*/
} TelSatUseInputAlphabetType_t;

/**
 * @enum TelSatDisplayVibrateAlertType_t
 * This is associated with the command qualifier for play tone command.
 */
typedef enum {
	TAPI_SAT_VIBRATE_ALERT_OPTIONAL = 0, /**<	VIBRATE ALERT UPTO THE TERMINAL		*/
	TAPI_SAT_VIBRATE_ALERT_REQUIRED = 1 /**<	VIBRATE, IF AVAILABLE, WITH TONE. 		*/
} TelSatDisplayVibrateAlertType_t;

/**
 * @enum TelSatPresentationType_t
 * This is associated with the command qualifier for select item command.
 */
typedef enum {
	TAPI_SAT_PRESENTATION_TYPE_NOT_SPECIFIED = 0x00, /**<	command qualifier for PRESENTATION TYPE NOT SPECIFIED */
	TAPI_SAT_PRESENTATION_TYPE_DATA_VALUE = 0x01, /**<	command qualifier for PRESENTATION TYPE DATA VALUE 		*/
	TAPI_SAT_PRESENTATION_TYPE_NAVIGATION_OPTION = 0x02 /**<	command qualifier for PRESENTATION TYPE NAVIGATION OPTION	*/
} TelSatPresentationType_t;

/**
 * @enum TelSatSelectionPreferenceType_t
 * This is associated with the command qualifier for select item command.
 */
typedef enum {
	TAPI_SAT_SELECTION_PREFERENCE_NONE_REQUESTED = 0, /**<	command qualifier for SELECTION PREFERENCE NONE REQUESTED		*/
	TAPI_SAT_SELECTION_PREFERENCE_USING_SOFT_KEY = 1 /**<	command qualifier for SELECTION PREFERENCE USING SOFT KEY 		*/
} TelSatSelectionPreferenceType_t;

/**
 * @enum TelSatCmdQualiProvideLocalInfo_t
 * This enum defines the Command qualifier values for provide local info command.
 */
typedef enum {
	TAPI_SAT_PROVIDE_DATE_TIME_AND_TIME_ZONE = 0x03, /**<	command qualifier for PROVIDE DATE TIME AND TIME ZONE 		*/
	TAPI_SAT_PROVIDE_LANGUAGE_SETTING = 0x04, /**<	command qualifier for PROVIDE LANGUAGE SETTING 		*/
	TAPI_SAT_PROVIDE_IMEISV = 0x08, TAPI_SAT_PROVIDE_RESERVED = 0xFF /**<	reserved 		*/
} TelSatCmdQualiProvideLocalInfo_t;

/**
 * @enum TelSatCmdQualiLaunchBrowser_t
 * This enum defines the Command qualifier values for launch browser command.
 */
typedef enum {
	TAPI_SAT_LAUNCH_BROWSER = 0, /**<	command qualifier for  LAUNCH BROWSER		*/
	TAPI_SAT_NOT_USED = 1, /**<	command qualifier for  NOT USED		*/
	TAPI_SAT_USE_EXISTING_BROWSER = 2, /**<	command qualifier for  USE EXISTING BROWSER if secure session, do not use it.		*/
	TAPI_SAT_CLOSE_AND_LAUNCH_NEW_BROWSER = 3, /**<	command qualifier for CLOSE AND LAUNCH NEW BROWSER  		*/
	TAPI_SAT_NOT_USED2 = 4, /**<	command qualifier for  NOT USED2		*/
	TAPI_SAT_LB_RESERVED = 0xFF /**<	reserved	*/
} TelSatCmdQualiLaunchBrowser_t;

/**
 * @enum TelSatDeviceIdentitiesTagType_t
 * This enum lists the device identity tag value IDs.
 */
typedef enum {
	TAPI_SAT_DEVICE_ID_KEYPAD = 0x01, /**<	DEVICE ID KEYPAD 		*/
	TAPI_SAT_DEVICE_ID_DISPLAY = 0x02, /**<	DEVICE ID DISPLAY 		*/
	TAPI_SAT_DEVICE_ID_EARPIECE = 0x03, /**<	DEVICE ID EARPIECE 		*/

	TAPI_SAT_DEVICE_ID_SIM = 0x81, /**<	DEVICE ID SIM 		*/
	TAPI_SAT_DEVICE_ID_ME = 0x82, /**<	DEVICE ID ME		*/
	TAPI_SAT_DEVICE_ID_NETWORK = 0x83, /**<	DEVICE ID NETWORK 		*/

	TAPI_SAT_DEVICE_ID_RESERVED = 0XFF /**<	reserved	*/
} TelSatDeviceIdentitiesTagType_t;

/**
 * @enum TelSatTimeUnitType_t
 * This enum lists the time units for the duration data object.
 */
typedef enum {
	TAPI_SAT_TIME_UNIT_MINUTES = 0x0, /**<	time unit - minutes 		*/
	TAPI_SAT_TIME_UNIT_SECONDS = 0x01, /**<	time unit - second  		*/
	TAPI_SAT_TIME_UNIT_TENTHS_OF_SECONDS = 0x02, /**<	time unit - tenths of seconds 		*/
	TAPI_SAT_TIME_UNIT_RESERVED = 0xFF /**<	reserved	*/
} TelSatTimeUnitType_t;

/**
 * @enum TelSatResultType_t
 * This enum lists the values for the RESULT data object - General Response.
 */
typedef enum {
	TAPI_SAT_R_SUCCESS = 0x0, /**<	command performed successfully */
	TAPI_SAT_R_SUCCESS_WITH_PARTIAL_COMPREHENSION = 0x01, /**<	command performed with partial comprehension 	*/
	TAPI_SAT_R_SUCCESS_WITH_MISSING_INFO = 0x02, /**<	command performed, with missing information 	*/

	TAPI_SAT_R_REFRESH_PERFORMED_WITH_ADDITIONAL_EFS_READ = 0x03, /**<	REFRESH PERFORMED WITH ADDITIONAL EFS READ 		*/
	TAPI_SAT_R_SUCCESS_BUT_REQUESTED_ICON_NOT_DISPLAYED = 0x04, /**<	command performed but REQUESTED ICON NOT DISPLAYED			*/
	TAPI_SAT_R_SUCCESS_BUT_MODIFIED_BY_CALL_CONTROL_BY_SIM = 0x05, /**<	command performed but MODIFIED BY CALL CONTROL BY SIM		*/
	TAPI_SAT_R_SUCCESS_LIMITED_SERVICE = 0x06, /**<	command performed with LIMITED SERVICE		*/
	TAPI_SAT_R_SUCCESS_WITH_MODIFICATION = 0x07, /**<	command performed with MODIFICATION		*/
	TAPI_SAT_R_REFRESH_PRFRMD_BUT_INDICATED_USIM_NOT_ACTIVE = 0x08, /**<	REFRESH PERFORMED BUT INDICATED USIM NOT ACTIVE 		*/

	TAPI_SAT_R_PROACTIVE_SESSION_TERMINATED_BY_USER = 0x10, /**<	proactive sim application session terminated by user		*/
	TAPI_SAT_R_BACKWARD_MOVE_BY_USER = 0x11, /**<	backward move in the proactive sim application session request by the user 		*/
	TAPI_SAT_R_NO_RESPONSE_FROM_USER = 0x12, /**<	no response from user		*/

	TAPI_SAT_R_HELP_INFO_REQUIRED_BY_USER = 0x13, /**<	HELP INFO REQUIRED BY USER 		*/
	TAPI_SAT_R_USSD_OR_SS_TRANSACTION_TERMINATED_BY_USER = 0x14, /**<	USSD OR SS TRANSACTION TERMINATED BY USER	*/

	TAPI_SAT_R_ME_UNABLE_TO_PROCESS_COMMAND = 0x20, /**<	ME currently unable to process command 		*/
	TAPI_SAT_R_NETWORK_UNABLE_TO_PROCESS_COMMAND = 0x21, /**<	Network currently unable to process command 		*/
	TAPI_SAT_R_USER_DID_NOT_ACCEPT_CALL_SETUP_REQ = 0x22, /**<	User did not accept call setup request 		*/
	TAPI_SAT_R_USER_CLEAR_DOWN_CALL_BEFORE_CONN = 0x23, /**<	User cleared down call before connection or network released		*/

	TAPI_SAT_R_INTERACTION_WITH_CC_BY_SIM_IN_TMP_PRBLM = 0x25, /**<	INTERACTION WITH CALL CONTROL BY SIM IN TEMPORARY PROBLEM 		*/
	TAPI_SAT_R_LAUNCH_BROWSER_GENERIC_ERROR_CODE = 0x26, /**<	LAUNCH BROWSER GENERIC ERROR CODE 		*/

	TAPI_SAT_R_BEYOND_ME_CAPABILITIES = 0x30, /**<	command beyond ME's capabilities 		*/
	TAPI_SAT_R_COMMAND_TYPE_NOT_UNDERSTOOD_BY_ME = 0x31, /**<	command type not understood by ME 		*/
	TAPI_SAT_R_COMMAND_DATA_NOT_UNDERSTOOD_BY_ME = 0x32, /**<	command data not understood by ME		*/
	TAPI_SAT_R_COMMAND_NUMBER_NOT_KNOWN_BY_ME = 0x33, /**<	command number not known by ME 		*/
	TAPI_SAT_R_SS_RETURN_ERROR = 0x34, /**<	SS return error		*/
	TAPI_SAT_R_SMS_RP_ERROR = 0x35, /**<	SMS rp-error		*/
	TAPI_SAT_R_ERROR_REQUIRED_VALUES_ARE_MISSING = 0x36, /**<	Error, required values are missing 		*/

	TAPI_SAT_R_USSD_RETURN_ERROR = 0x37, /**<	USSD_RETURN_ERROR 		*/
	TAPI_SAT_R_INTRCTN_WITH_CC_OR_SMS_CTRL_PRMNT_PRBLM = 0x39, /**<	INTERACTION WITH CALL CONTROL OR SMS CONTROL PERMANENT PROBLEM 		*/
	TAPI_SAT_R_BEARER_INDEPENDENT_PROTOCOL_ERROR = 0x3A, /**<	BEARER INDEPENDENT PROTOCOL ERROR 		*/
	TAPI_SAT_R_FRAMES_ERROR = 0x3C /**<	FRAMES ERROR 		*/
} TelSatResultType_t;

/**
 * @enum TelSatMeProblemType_t
 * This enum lists the values for the Additional response for the RESULT object and specifies a particular ME PROBLEM.
 */
typedef enum {
	TAPI_SAT_ME_PROBLEM_NO_SPECIFIC_CAUSE = 0x0, /**<	ME problem with NO SPECIFIC CAUSE		*/
	TAPI_SAT_ME_PROBLEM_SCREEN_BUSY = 0x01, /**<	ME problem with SCREEN BUSY		*/
	TAPI_SAT_ME_PROBLEM_ME_BUSY_ON_CALL = 0x02, /**<	ME problem with ME BUSY ON CALL		*/
	TAPI_SAT_ME_PROBLEM_ME_BUSY_ON_SS = 0x03, /**<	ME problem with ME_BUSY ON SS		*/
	TAPI_SAT_ME_PROBLEM_NO_SERVICE = 0x04, /**<	ME problem with NO SERVICE		*/
	TAPI_SAT_ME_PROBLEM_ACCESS_CONTROL_CLASS_BAR = 0x05, /**<	ME problem with ACCESS CONTROL CLASS BAR		*/
	TAPI_SAT_ME_PROBLEM_RADIO_RES_NOT_GRANTED = 0x06, /**<	ME problem with RADIO RES NOT GRANTED		*/
	TAPI_SAT_ME_PROBLEM_NOT_IN_SPEECH_CALL = 0x07, /**<	ME problem with NOT IN SPEECH CALL	*/
	TAPI_SAT_ME_PROBLEM_ME_BUSY_ON_USSD = 0x08, /**<	ME problem with ME BUSY ON USSD		*/
	TAPI_SAT_ME_PROBLEM_ME_BUSY_ON_SEND_DTMF_CMD = 0x09, /**<	ME problem with ME BUSY ON SEND DTMF CMD	*/
	TAPI_SAT_ME_PROBLEM_NO_USIM_ACTIVE = 0x0A, /**<	ME problem with NO USIM ACTIVE 		*/
	TAPI_SAT_ME_PROBLEM_INVALID = 0xFF /**<	ME problem with INVALID 		*/
} TelSatMeProblemType_t;

/**
 * @enum TelSatNetworkProblemType_t
 * This enum lists the values for the Additional response for the RESULT object and specifies a particular network PROBLEM.
 */
typedef enum {
	TAPI_SAT_NETWORK_PROBLEM_NO_SPECIFIC_CAUSE = 0x0, /**<	Network problem with no specific cause 		*/
	TAPI_SAT_NETWORK_PROBLEM_USER_BUSY = 0x91 /**<	Network problem with USER BUSY 		*/
} TelSatNetworkProblemType_t;

/**
 * @enum TelSatSsProblemType_t
 * This enum lists the values for the Additional response for the RESULT object related to SEND SS.
 */
typedef enum {
	TAPI_SAT_SS_PROBLEM_NO_SPECIFIC_CAUSE = 0, /**<	SS problem with no specific cause  		*/
	TAPI_SAT_SS_PROBLEM_FACILITY_NOT_SUPPORTED = 0x15 /**<	SS problem with FACILITY NOT SUPPORTED		*/
} TelSatSsProblemType_t;

/**
 * @enum TelSatSmsProblemType_t
 * This enum lists the values for the Additional response for the RESULT object related to SEND SMS.
 */
typedef enum {
	TAPI_SAT_SMS_PROBLEM_NO_SPECIFIC_CAUSE = 0 /**<	SMS problem with no specific cause		*/
} TelSatSmsProblemType_t;

/**
 * @enum TelSatUssdProblemType_t
 * This enum lists the values for the Additional response for the RESULT object related to SEND USSD STRING.
 */
typedef enum {
	TAPI_SAT_USSD_PROBLEM_NO_SPECIFIC_CAUSE = 0, /**<	USSD problem with no specific cause 		*/
	TAPI_SAT_USSD_PROBLEM_UNKNOWN_ALPHABET = 0x47 /**<	USSD problem with UNKNOWN ALPHABET		*/
} TelSatUssdProblemType_t;

/**
 * @enum TelSatCallCtrlProblemType_t
 * This enum lists the values for the Additional response for the RESULT object related to CALL CONTROL or MO SMS CONTROL.
 */
typedef enum {
	TAPI_SAT_CC_PROBLEM_NO_SPECIFIC_CAUSE = 0, /**<	Call Control problem with no specific cause		*/
	TAPI_SAT_CC_PROBLEM_ACTION_NOT_ALLOWED = 1, /**<	Call Control problem with action not allowed	*/
	TAPI_SAT_CC_PROBLEM_REQUEST_TYPE_HAS_CHANGED = 2 /**<	Call Control problem with request type has changed	*/
} TelSatCallCtrlProblemType_t;

/**
 * @enum TelSatLaunchBrowserProblemType_t
 * This enum lists the values for the Additional response for the RESULT object related to LAUNCH BROWSER PROBLEM
 */
typedef enum {
	TAPI_SAT_BROWSER_PROBLEM_NO_SPECIFIC_CAUSE = 0, /**<	Browser problem with no specific cause 		*/
	TAPI_SAT_BROWSER_PROBLEM_BEARER_UNAVAILABLE = 1, /**<	Browser problem with bearer unavailable		*/
	TAPI_SAT_BROWSER_PROBLEM_BROWSER_UNAVAILABLE = 2, /**<	Browser problem with browser unavailable		*/
	TAPI_SAT_BROWSER_PRBLM_ME_UNABLE_TO_READ_PROV_DATA = 3 /**<	Browser problem with ME unable to read provisioning data		*/
} TelSatLaunchBrowserProblemType_t;

/**
 * @enum TelSatBipProblemType_t
 * This enum lists the values for the Additional response for the RESULT object.
 *  Permanent Problems  ::: 12.12.11 ADDITIONAL INFORMATION :  BEARER INDEPENDENT PROTOCOL
 */
typedef enum {
	TAPI_SAT_BIP_PROBLEM_NO_SPECIFIC_CAUSE = 0x00, /**<	BIP problem with no specific cause	*/
	TAPI_SAT_BIP_PROBLEM_NO_CHANNEL_AVAILABLE = 0x01, /**<	BIP problem with no channel available		*/
	TAPI_SAT_BIP_PROBLEM_CHANNEL_CLOSED = 0x02, /**<	BIP problem with channel closed 		*/
	TAPI_SAT_BIP_PROBLEM_CHANNEL_ID_NOT_VALID = 0x03, /**<	BIP problem with channel id not valid 		*/
	TAPI_SAT_BIP_PROBLEM_BUF_SIZE_NOT_AVAILABLE = 0x04, /**<	BIP problem with buffer size not available 		*/
	TAPI_SAT_BIP_PROBLEM_SECURITY_ERROR = 0x05, /**<	BIP problem with security error 		*/
	TAPI_SAT_BIP_PRBLM_SIM_ME_IF_TRNSPRT_LEVEL_NOT_AVL = 0x06, /**<	BIP problem with SIM ME interface transport level not available		*/
	TAPI_SAT_BIP_REMOTE_DEV_NOT_REACHABLE = 0x07, /**<	BIP problem with remote device not reachable		*/
	TAPI_SAT_BIP_SERVICE_ERROR = 0x08, /**<	BIP service error 		*/
	TAPI_SAT_BIP_SERVICE_IDENTIFIER_UNKNOWN = 0x09 /**<	BIP service identifier unknown 		*/
} TelSatBipProblemType_t;

/**
 * @enum TelSatSmsTpduType_t
 * This enum lists the values for the SMS TPDU type.
 */
typedef enum {
	TAPI_SAT_SMS_TPDU_TYPE_DELIVER_TPDU = 0, /**<	sms tpdu type - DELIVER TPDU	*/
	TAPI_SAT_SMS_TPDU_TYPE_DELIVER_RPT = 1, /**<	sms tpdu type - DELIVER RPT 	*/
	TAPI_SAT_SMS_TPDU_TYPE_SUBMIT_TPDU = 2, /**<	sms tpdu type - SUBMIT TPDU		*/
	TAPI_SAT_SMS_TPDU_TYPE_SUBMIT_RPT = 3, /**<	sms tpdu type - SUBMIT RPT	*/
	TAPI_SAT_SMS_TPDU_TYPE_STATUS_RPT = 4, /**<	sms tpdu type - STATUS RPT	*/
	TAPI_SAT_SMS_TPDU_TYPE_TPDU_CMD = 5 /**<	sms tpdu type - TPDU CMD	*/
} TelSatSmsTpduType_t;

/**
 * @enum TelSatToneType_t
 * This enum lists the values tones type.
 */
typedef enum {
	// standard supervisory tones
	TAPI_SAT_DIAL_TONE = 0x01, /**<	TONE TYPE DIAL TONE 		*/
	TAPI_SAT_CALLED_SUBSCRIBER_BUSY = 0x02, /**<	TONE TYPE CALLED SUBSCRIBER BUSY		*/
	TAPI_SAT_CONGESTION = 0x03, /**<	TONE TYPE CONGESTION	*/
	TAPI_SAT_RADIO_PATH_ACK = 0x04, /**<	TONE TYPE RADIO PATH ACK	*/
	TAPI_SAT_RADIO_PATH_NOT_AVAILABLE_CALL_DROPPED = 0x05, /**<	TONE TYPE RADIO PATH NOT AVAILABLE CALL DROPPED	*/
	TAPI_SAT_ERR_SPECIAL_INFO = 0x06, /**<	TONE TYPE ERR SPECIAL INFO	*/
	TAPI_SAT_CALL_WAITING_TONE = 0x07, /**<	TONE TYPE CALL WAITING TONE		*/
	TAPI_SAT_RINGING_TONE = 0x08, /**<	TONE TYPE RINGING TONE	*/

	// ME proprietary tones
	TAPI_SAT_GENERAL_BEEP = 0x10, /**<	TONE TYPE GENERAL BEEP 		*/
	TAPI_SAT_POSITIVE_ACK_TONE = 0x11, /**<	TONE TYPE POSITIVE ACK TONE 		*/
	TAPI_SAT_NEGATIVE_ACK_OR_ERROR_TONE = 0x12, /**<	TONE TYPE NEGATIVE ACK OR ERROR TONE 		*/
	TAPI_SAT_RINGING_TONE_SLCTD_BY_USR_FOR_INCOM_SPEECH_CALL = 0x13, /**<	TONE TYPE RINGING TONE SELECTED BY USER FOR INCOMING SPEECH CALL 		*/
	TAPI_SAT_ALERT_TONE_SELECTED_BY_USER_FOR_INCOMING_SMS = 0x14, /**<	TONE TYPE ALERT TONE SELECTED BY USER FOR INCOMING SMS 		*/
	TAPI_SAT_CRITICAL_ALERT = 0x15, /**<	TONE TYPE CRITICAL ALERT 		*/

	//Themed tones
	TAPI_SAT_HAPPY_TONE = 0x30, /**<	TONE TYPE HAPPY TONE		*/
	TAPI_SAT_SAD_TONE = 0x31, /**<	TONE TYPE SAD TONE	 		*/
	TAPI_SAT_URGENT_ACTION_TONE = 0x32, /**<	TONE TYPE URGENT ACTION TONE 		*/
	TAPI_SAT_QUESTION_TONE = 0x33, /**<	TONE TYPE QUESTION TONE 		*/
	TAPI_SAT_MESSAGE_RECEIVED_TONE = 0x34, /**<	TONE TYPE MESSAGE RECEIVED TONE 		*/

	//Melody tones
	TAPI_SAT_MELODY_1 = 0x40, /**<	TONE TYPE MELODY 1 		*/
	TAPI_SAT_MELODY_2 = 0x41, /**<	TONE TYPE MELODY 2 		*/
	TAPI_SAT_MELODY_3 = 0x42, /**<	TONE TYPE MELODY 3 		*/
	TAPI_SAT_MELODY_4 = 0x43, /**<	TONE TYPE MELODY 4 		*/
	TAPI_SAT_MELODY_5 = 0x44, /**<	TONE TYPE MELODY 5 		*/
	TAPI_SAT_MELODY_6 = 0x45, /**<	TONE TYPE MELODY 6 		*/
	TAPI_SAT_MELODY_7 = 0x46, /**<	TONE TYPE MELODY 7		*/
	TAPI_SAT_MELODY_8 = 0x47, /**<	TONE TYPE MELODY 8 		*/

	TAPI_SAT_TONE_TYPE_RESERVED = 0xFF /**<	TONE TYPE RESERVED		*/
} TelSatToneType_t;

/**
 * @enum TelSatEventDownloadType_t
 * This enum lists event types required by ME to monitor and report to SIM.
 */
typedef enum {
	TAPI_EVENT_SAT_DW_TYPE_MT_CALL = 0,
	TAPI_EVENT_SAT_DW_TYPE_CALL_CONNECTED = 1,
	TAPI_EVENT_SAT_DW_TYPE_CALL_DISCONNECTED = 2,
	TAPI_EVENT_SAT_DW_TYPE_LOCATION_STATUS = 3,
	TAPI_EVENT_SAT_DW_TYPE_USER_ACTIVITY = 4, /**<	data download type - USER_ACTIVITY		*/
	TAPI_EVENT_SAT_DW_TYPE_IDLE_SCREEN_AVAILABLE = 5, /**<	data download type - IDLE SCREEN AVAILABLE		*/
	TAPI_EVENT_SAT_DW_TYPE_CARD_READER_STATUS = 6,
	TAPI_EVENT_SAT_DW_TYPE_LANGUAGE_SELECTION = 7, /**<	data download type - LANGUAGE SELECTION		*/
	TAPI_EVENT_SAT_DW_TYPE_BROWSER_TERMINATION = 8, /**<	data download type - BROWSER TERMINATION		*/
	TAPI_EVENT_SAT_DW_TYPE_DATA_AVAILABLE = 9, /**<	data download type -DATA AVAILABLE 		*/
	TAPI_EVENT_SAT_DW_TYPE_CHANNEL_STATUS = 0x0A, /**<	data download type - CHANNEL STATUS		*/
	TAPI_EVENT_SAT_DW_TYPE_ACCESS_TECHNOLOGY_CHANGED = 0x0B,
	TAPI_EVENT_SAT_DW_TYPE_DISPLAY_PARAMETERS_CHANGED = 0x0C,
	TAPI_EVENT_SAT_DW_TYPE_LOCAL_CONNECTION = 0x0D,
	TAPI_EVENT_SAT_DW_TYPE_NW_SEARCH_MODE_CHANGED = 0X0E,
	TAPI_EVENT_SAT_DW_TYPE_BROWSING_STATUS = 0X0F,
	TAPI_EVENT_SAT_DW_TYPE_FRAMES_INFORMATION_CHANGED = 0X10,
	TAPI_EVENT_SAT_DW_TYPE_RESERVED_FOR_3GPP = 0X11,
	TAPI_EVENT_SAT_DW_TYPE_UNKNOWN = 0xFF /**<	data download type - unknown		*/
} TelSatEventDownloadType_t;

/**
 * @enum TelSatImageCodingSchemeType_t
 * This enum lists image coding scheme types required by ME to show.
 */
typedef enum {
	TAPI_SAT_SIM_IMAGE_CODING_SCHEME_BASIC = 0x11, /**<	IMAGE CODING SCHEME BASIC 		*/
	TAPI_SAT_SIM_IMAGE_CODING_SCHEME_COLOUR = 0x21, /**<	IMAGE CODING SCHEME COLOUR		*/
	TAPI_SAT_SIM_IMAGE_CODING_SCHEME_RESERVED = 0xFF /**<	   RESERVED 		*/
} TelSatImageCodingSchemeType_t;

/**
 * @enum TelSatIconQualifierType_t
 * This enum defines the icon qualifier.
 */
typedef enum {
	TAPI_SAT_ICON_QUALI_SELF_EXPLANATORY = 0, /**<	ICON QUALI SELF EXPLANATORY 	*/
	TAPI_SAT_ICON_QUALI_NOT_SELF_EXPLANATORY = 1, /**<	ICON QUALI NOT SELF EXPLANATORY 	*/
	TAPI_SAT_ICON_QUALI_RESERVED = 0xFF /**<	  RESERVED	*/
} TelSatIconQualifierType_t;

/**
 * @enum TelSatBcRepeatIndicatorType_t
 * This enum defines the SIM ATK BC repeat indicator type.
 */
typedef enum {
	TAPI_SAT_BC_REPEAT_INDI_ALTERNATE_MODE = 0x01, /**<	BC REPEAT ALTERNATE MODE		*/
	TAPI_SAT_BC_REPEAT_INDI_SEQUENTIAL_MODE = 0x03, /**<	BC REPEAT SEQUENTIAL MODE		*/
	TAPI_SAT_BC_REPEAT_INDI_RESERVED = 0xFF /**<	RESERVED	*/
} TelSatBcRepeatIndicatorType_t;

/**
 * @enum TelSatCallCtrlStringType_t
 * This enum defines call control string type.
 */
typedef enum {
	TAPI_SAT_CC_VOICE = 0x00, /**<	Call Control String Type - voice 		*/
	TAPI_SAT_CC_SS = 0x01, /**<	Call Control String Type - ss 		*/
	TAPI_SAT_CC_USSD = 0x02, /**<	Call Control String Type - ussd		*/
	TAPI_SAT_CC_NONE = 0xFF /**<	Call Control String Type - none 		*/
} TelSatCallCtrlStringType_t;

/**
 * @enum TelSatLanguageType_t
 * This enum lists the language values.
 */
typedef enum {
	TAPI_SAT_LP_GERMAN = 0x00, /**<	GERMAN 		*/
	TAPI_SAT_LP_ENGLISH = 0x01, /**<	ENGLISH		*/
	TAPI_SAT_LP_ITALIAN = 0x02, /**<	ITALIAN		*/
	TAPI_SAT_LP_FRENCH = 0x03, /**<	FRENCH 		*/
	TAPI_SAT_LP_SPANISH = 0x04, /**<	SPANISH		*/
	TAPI_SAT_LP_DUTCH = 0x05, /**<	DUTCH 		*/
	TAPI_SAT_LP_SWEDISH = 0x06, /**<	SWEDISH	*/
	TAPI_SAT_LP_DANISH = 0x07, /**<	DANISH	*/
	TAPI_SAT_LP_PORTUGUESE = 0x08, /**<	PORTUGUESE	*/
	TAPI_SAT_LP_FINNISH = 0x09, /**<	FINNISH	*/
	TAPI_SAT_LP_NORWEGIAN = 0x0A, /**<	NORWEGIAN	*/
	TAPI_SAT_LP_GREEK = 0x0B, /**<	GREEK	*/
	TAPI_SAT_LP_TURKISH = 0x0C, /**<	TURKISH	*/
	TAPI_SAT_LP_HUNGARIAN = 0x0D, /**<	HUNGARIAN	*/
	TAPI_SAT_LP_POLISH = 0x0E, /**<	POLISH	*/
	TAPI_SAT_LP_LANG_UNSPECIFIED = 0x0F /**<	LANGUAGE UNSPECIFIED	*/
} TelSatLanguageType_t;

/**
 * @enum TelSatBrowserIdentityType_t
 * This enum lists the SAT browser identity type.
 */
typedef enum {
	TAPI_SAT_BROWSER_ID_DEFAULT = 0x0, /**<	DEFAULT BROWSER 		*/
	TAPI_SAT_BROWSER_ID_WML, /**<	BROWSER WML	*/
	TAPI_SAT_BROWSER_ID_HTML, /**<	BROWSER HTML	*/
	TAPI_SAT_BROWSER_ID_XHTML, /**<	BROWSER XHTML	*/
	TAPI_SAT_BROWSER_ID_CHTML, /**<	BROWSER CHTML	*/
	TAPI_SAT_BROWSER_ID_RESERVED = 0xFF /**<	RESERVED	*/
} TelSatBrowserIdentityType_t;

/**
 * @enum TelSatBearerType_t
 * This enum lists the SAT bearer type.
 */
typedef enum {
	TAPI_SAT_BEARER_TYPE_SMS = 0x0, /**<	BEARER SMS 		*/
	TAPI_SAT_BEARER_TYPE_CSD = 0x1, /**<	BEARER CSD 		*/
	TAPI_SAT_BEARER_TYPE_USSD = 0x2, /**<	BEARER USSD		*/
	TAPI_SAT_BEARER_TYPE_GPRS = 0x3, /**<	BEARER GPRS		*/
	TAPI_SAT_BEARER_TYPE_RESERVED = 0xFF /**<	BEARER RESERVED		*/
} TelSatBearerType_t;

/**
 * @enum TelSatBrowserTerminationCauseType_t
 * This enum lists the SAT browser termination cause type.
 */
typedef enum {
	TAPI_SAT_BROWSER_TERMINATED_BY_USER = 0, /**<	BROWSER TERMINATED BY USER 		*/
	TAPI_SAT_BROWSER_TERMINATED_BY_ERROR = 1, /**<	BROWSER TERMINATED BY ERROR		*/
} TelSatBrowserTerminationCauseType_t;

/**
 * @enum TelSatBearerDescType_t
 * This enum lists the SAT bearer destination type.
 */
typedef enum {
	TAPI_SAT_BEARER_CSD = 0x1, /**<	BEARER DESC CSD 		*/
	TAPI_SAT_BEARER_GPRS = 0x2, /**<	BEARER DESC GPRS 		*/
	TAPI_SAT_BEARER_DEFAULT_BEARER_FROM_TRANSPORT_LAYER = 0x3, /**<	BEARER DESC DEFAULT BEARER FROM TRANSPORT LAYER		*/
	TAPI_SAT_BEARER_LOCAL_LINK_TECHNOLOGY_INDEPENDENT = 0x4, /**<	BEARER DESC LOCAL LINK TECHNOLOGY INDEPENDENT		*/
	TAPI_SAT_BEARER_BLUETOOTH = 0x5, /**<	BEARER DESC BLUETOOTH	*/
	TAPI_SAT_BEARER_IrDA = 0x6, /**<	BEARER DESC IrDA	*/
	TAPI_SAT_BEARER_RS232 = 0x7, /**<	BEARER DESC RS232	*/
	TAPI_SAT_BEARER_USB = 0x10, /**<	BEARER DESC USB	*/
	TAPI_SAT_BEARER_RESERVED = 0xFF /**<	RESERVED	*/
} TelSatBearerDescType_t;

/**
 * @enum TelSatBearerParamCsdDataRateType_t
 * This enum lists the SAT bearer parameter csd data rate. refer TS 27.007
 */
typedef enum {
	TAPI_SAT_BIP_DR_AUTOBAUDING = 0, /**<	CSD data rate - AUTOBAUDING		*/
	TAPI_SAT_BIP_DR_300BPS_V21 = 1, /**<	CSD data rate -300BPS V21 		*/
	TAPI_SAT_BIP_DR_1200BPS_V22 = 2, /**<	CSD data rate - 1200BPS V22		*/
	TAPI_SAT_BIP_DR_1200_75BPS_V23 = 3, /**<	CSD data rate -1200 75BPS V23	 		*/
	TAPI_SAT_BIP_DR_2400BPS_V22 = 4, /**<	CSD data rate -2400BPS V22 		*/
	TAPI_SAT_BIP_DR_2400BPS_V26 = 5, /**<	CSD data rate - 2400BPS V26			*/
	TAPI_SAT_BIP_DR_4800BPS_V32 = 6, /**<	CSD data rate - 4800BPS V32		*/
	TAPI_SAT_BIP_DR_9600BPS_V32 = 7, /**<	CSD data rate - 9600BPS V32		*/
	TAPI_SAT_BIP_DR_9600BPS_V34 = 12, /**<	CSD data rate - 9600BPS_V34		*/
	TAPI_SAT_BIP_DR_14400BPS_V34 = 14, /**<	CSD data rate -14400BPS V34 		*/
	TAPI_SAT_BIP_DR_19200BPS_V34 = 15, /**<	CSD data rate -19200BPS V34 		*/
	TAPI_SAT_BIP_DR_28800BPS_V34 = 16, /**<	CSD data rate -28800BPS V34 		*/
	TAPI_SAT_BIP_DR_33600BPS_V34 = 17, /**<	CSD data rate -33600BPS V34 		*/
	TAPI_SAT_BIP_DR_1200BPS_V120 = 34, /**<	CSD data rate -1200BPS V120		*/
	TAPI_SAT_BIP_DR_2400BPS_V120 = 36, /**<	CSD data rate -2400BPS V120 		*/
	TAPI_SAT_BIP_DR_4800BPS_V120 = 38, /**<	CSD data rate -4800BPS V120 		*/
	TAPI_SAT_BIP_DR_9600BPS_V120 = 39, /**<	CSD data rate -9600BPS V120 		*/
	TAPI_SAT_BIP_DR_14400BPS_V120 = 43, /**<	CSD data rate -14400BPS V120 		*/
	TAPI_SAT_BIP_DR_19200BPS_V120 = 47, /**<	CSD data rate -19200BPS V120 		*/
	TAPI_SAT_BIP_DR_28800BPS_V120 = 48, /**<	CSD data rate -28800BPS V120 		*/
	TAPI_SAT_BIP_DR_38400BPS_V120 = 49, /**<	CSD data rate -38400BPS V120 		*/
	TAPI_SAT_BIP_DR_48000BPS_V120 = 50, /**<	CSD data rate -48000BPS V120 		*/
	TAPI_SAT_BIP_DR_56000BPS_V120 = 51, /**<	CSD data rate -56000BPS V120 		*/
	TAPI_SAT_BIP_DR_300BPS_V110 = 65, /**<	CSD data rate - 300BPS V110		*/
	TAPI_SAT_BIP_DR_1200BPS_V110 = 66, /**<	CSD data rate -1200BPS V110 		*/
	TAPI_SAT_BIP_DR_2400BPS_V110_OR_X31_FALG_STUFFING = 68, /**<	CSD data rate - 2400BPS V110 OR X31 FALG STUFFING		*/
	TAPI_SAT_BIP_DR_4800BPS_V110_OR_X31_FALG_STUFFING = 70, /**<	CSD data rate - 4800BPS V110 OR X31 FALG STUFFING		*/
	TAPI_SAT_BIP_DR_9600BPS_V110_OR_X31_FALG_STUFFING = 71, /**<	CSD data rate - 9600BPS V110 OR X31 FALG STUFFING		*/
	TAPI_SAT_BIP_DR_14400BPS_V110_OR_X31_FALG_STUFFING = 75, /**<	CSD data rate - 14400BPS V110 OR X31 FALG STUFFING		*/
	TAPI_SAT_BIP_DR_19200BPS_V110_OR_X31_FALG_STUFFING = 79, /**<	CSD data rate -19200BPS V110 OR X31 FALG STUFFING 		*/
	TAPI_SAT_BIP_DR_28800BPS_V110_OR_X31_FALG_STUFFING = 80, /**<	CSD data rate -28800BPS V110 OR X31 FALG STUFFING 		*/
	TAPI_SAT_BIP_DR_38400BPS_V110_OR_X31_FALG_STUFFING = 81, /**<	CSD data rate -38400BPS V110 OR X31 FALG STUFFING 		*/
	TAPI_SAT_BIP_DR_48000BPS_V110_OR_X31_FALG_STUFFING = 82, /**<	CSD data rate -48000BPS V110 OR X31 FALG STUFFING 		*/
	TAPI_SAT_BIP_DR_56000BPS_V110_OR_X31_FALG_STUFFING = 83, /**<	CSD data rate -56000BPS V110 OR X31 FALG STUFFING 		*/
	TAPI_SAT_BIP_DR_64000BPS = 84, /**<	CSD data rate -64000BPS 		*/
	TAPI_SAT_BIP_DR_56000BPS_BIT_TRANSPERENT = 115, /**<	CSD data rate -56000BPS BIT TRANSPERENT 		*/
	TAPI_SAT_BIP_DR_64000BPS_BIT_TRANSPERENT = 116, /**<	CSD data rate -64000BPS BIT TRANSPERENT 		*/
	TAPI_SAT_BIP_DR_32000BPS_PIAFS32K = 120, /**<	CSD data rate -32000BPS PIAFS32K		*/
	TAPI_SAT_BIP_DR_64000BPS_PIAFS64K = 121, /**<	CSD data rate - 64000BPS PIAFS64K		*/
	TAPI_SAT_BIP_DR_28800BPS_MULTIMEDIA = 130, /**<	CSD data rate -28800BPS MULTIMEDIA 		*/
	TAPI_SAT_BIP_DR_32000BPS_MULTIMEDIA = 131, /**<	CSD data rate -32000BPS MULTIMEDIA 		*/
	TAPI_SAT_BIP_DR_33600BPS_MULTIMEDIA = 132, /**<	CSD data rate - 33600BPS MULTIMEDIA		*/
	TAPI_SAT_BIP_DR_56000BPS_MULTIMEDIA = 133, /**<	CSD data rate -56000BPS MULTIMEDIA 		*/
	TAPI_SAT_BIP_DR_64000BPS_MULTIMEDIA = 134 /**<	CSD data rate -64000BPS MULTIMEDIA 		*/
} TelSatBearerParamCsdDataRateType_t;

/**
 * @enum TelSatBearerParamCsdBearerServiceType_t
 * This enum lists the SAT bearer parameter csd bearer service
 */
typedef enum {
	TAPI_SAT_BIP_CSD_BS_DATA_CIRCUIT_ASYNC_UDI = 0, /**<	CSD Bearer service - DATA CIRCUIT ASYNCHRONOUS UDI 		*/
	TAPI_SAT_BIP_CSD_BS_DATA_CIRCUIT_SYNC = 1, /**<	CSD Bearer service - DATA CIRCUIT SYNCHRONOUS UDI 		*/
	TAPI_SAT_BIP_CSD_BS_PAD_ACCESS_ASYNC_UDI = 2, /**<	CSD Bearer service - PAD ACCESS ASYNCHRONOUS UDI			*/
	TAPI_SAT_BIP_CSD_BS_PACKET_ACCESS_SYNC = 3, /**<	CSD Bearer service - PACKET ACCESS SYNCHRONOUS UDI 		*/
	TAPI_SAT_BIP_CSD_BS_DATA_CIRCUIT_ASYNC_RDI = 4, /**<	CSD Bearer service - DATA CIRCUIT ASYNCHRONOUS RDI 		*/
	TAPI_SAT_BIP_CSD_BS_DATA_CIRCUIT_SYNC_RDI = 5, /**<	CSD Bearer service - DATA CIRCUIT SYNCHRONOUS RDI 		*/
	TAPI_SAT_BIP_CSD_BS_PAD_ACCESS_ASYNC_RDI = 6, /**<	CSD Bearer service - PAD ACCESS ASYNCHRONOUS RDI  		*/
	TAPI_SAT_BIP_CSD_BS_PACKET_ACCESS_SYNC_RDI = 7 /**<	CSD Bearer service - PACKET ACCESS SYNCHRONOUS RDI 		*/
} TelSatBearerParamCsdBearerServiceType_t;

/**
 * @enum TelSatBearerParamCsdConnectionElementType_t
 * This enum lists the SAT bearer parameter csd connection element
 */
typedef enum {
	TAPI_SAT_BIP_CSD_CONN_ELEM_TRANSPARENT = 0, /**<	CSD connection element - TRANSPARENT		*/
	TAPI_SAT_BIP_CSD_CONN_ELEM_NON_TRANSPARENT = 1, /**<	CSD connection element - NON TRANSPARENT  		*/
	TAPI_SAT_BIP_CSD_CONN_ELEM_BOTH_TRANSPARENT_PREF = 2, /**<	CSD connection element -BOTH TRANSPARENT PREFFERED 		*/
	TAPI_SAT_BIP_CSD_CONN_ELEM_BOTH_NON_TRANSPARENT_PREF = 3 /**<	CSD connection element -  NON TRANSPARENT PREFFERED		*/
} TelSatBearerParamCsdConnectionElementType_t;

/**
 * @enum TelSatBearerParamGprsPrecedenceClassType_t
 * This enum lists the SAT bearer parameter GPRS precedence class. refer  TS 23.107
 */
typedef enum {
	TAPI_SAT_BIP_GPRS_PRECED_CLASS_HIGH_PRIORITY = 0x01, /**<	GPRS precedence class -HIGH PRIORITY		*/
	TAPI_SAT_BIP_GPRS_PRECED_CLASS_NORM_PRIORITY = 0x02, /**<	GPRS precedence class -NORM PRIORITY		*/
	TAPI_SAT_BIP_GPRS_PRECED_CLASS_LOW_PRIORITY = 0x03 /**<	GPRS precedence class - LOW PRIORITY		*/
} TelSatBearerParamGprsPrecedenceClassType_t;

/**
 * @enum TelSatBearerParamGprsDelayClassType_t
 * This enum lists the SAT bearer parameter GPRS delay class.
 */
typedef enum {
	TAPI_SAT_BIP_GPRS_DELAY_CLASS_1 = 0x01, /**<	GPRS delay class - 1		*/
	TAPI_SAT_BIP_GPRS_DELAY_CLASS_2 = 0x02, /**<	GPRS delay class -	2	*/
	TAPI_SAT_BIP_GPRS_DELAY_CLASS_3 = 0x03, /**<	GPRS delay class -	3	*/
	TAPI_SAT_BIP_GPRS_DELAY_CLASS_4 = 0x04 /**<	GPRS delay class - 4		*/
} TelSatBearerParamGprsDelayClassType_t;

/**
 * @enum TelSatBearerParamGprsReliabilityClassType_t
 * This enum lists the SAT bearer parameter GPRS Reliability class.
 */
typedef enum {
	TAPI_SAT_BIP_GPRS_RELIABILITY_CLASS_1 = 0x01, /**<	GPRS Reliability class -1 		*/
	TAPI_SAT_BIP_GPRS_RELIABILITY_CLASS_2 = 0x02, /**<	GPRS Reliability class -2		*/
	TAPI_SAT_BIP_GPRS_RELIABILITY_CLASS_3 = 0x03, /**<	GPRS Reliability class -3		*/
	TAPI_SAT_BIP_GPRS_RELIABILITY_CLASS_4 = 0x04, /**<	GPRS Reliability class -4 		*/
	TAPI_SAT_BIP_GPRS_RELIABILITY_CLASS_5 = 0x05 /**<	GPRS Reliability class -5		*/
} TelSatBearerParamGprsReliabilityClassType_t;

/**
 * @enum TelSatBearerParamGprsPeakThroughputClassType_t
 * This enum lists the SAT bearer parameter GPRS peak throughput class.
 */
typedef enum {
	TAPI_SAT_BIP_GPRS_PEAK_THROUGHPUT_CLASS_UPTO_8KBPS = 0x01, /**<	GPRS peak throughput class- UPTO 8KBPS		*/
	TAPI_SAT_BIP_GPRS_PEAK_THROUGHPUT_CLASS_UPTO_16KBPS = 0x02, /**<	GPRS peak throughput class- UPTO 16KBPS		*/
	TAPI_SAT_BIP_GPRS_PEAK_THROUGHPUT_CLASS_UPTO_32KBPS = 0x03, /**<	GPRS peak throughput class-UPTO 32KBPS		*/
	TAPI_SAT_BIP_GPRS_PEAK_THROUGHPUT_CLASS_UPTO_64KBPS = 0x04, /**<	GPRS peak throughput class-UPTO 64KBPS		*/
	TAPI_SAT_BIP_GPRS_PEAK_THROUGHPUT_CLASS_UPTO_128KBPS = 0x05, /**<	GPRS peak throughput class- UPTO 128KBPS			*/
	TAPI_SAT_BIP_GPRS_PEAK_THROUGHPUT_CLASS_UPTO_256KBPS = 0x06, /**<	GPRS peak throughput class- UPTO 256KBPS			*/
	TAPI_SAT_BIP_GPRS_PEAK_THROUGHPUT_CLASS_UPTO_512KBPS = 0x07, /**<	GPRS peak throughput class- UPTO 512KBPS		*/
	TAPI_SAT_BIP_GPRS_PEAK_THROUGHPUT_CLASS_UPTO_1024KBPS = 0x08, /**<	GPRS peak throughput class-UPTO 1024KBPS		*/
	TAPI_SAT_BIP_GPRS_PEAK_THROUGHPUT_CLASS_UPTO_2048KBPS = 0x09 /**<	GPRS peak throughput class- UPTO 2048KBPS		*/
} TelSatBearerParamGprsPeakThroughputClassType_t;

/**
 * @enum TelSatBearerParamGprsMeanThroughputClassType_t
 * This enum lists the SAT bearer parameter GPRS mean throughput class.
 */
typedef enum {
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_DOT_22_BPS = 0x01, /**<	GPRS mean throughput class - DOT 22 BPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_DOT_44_BPS = 0x02, /**<	GPRS mean throughput class - DOT 44 BPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_1_DOT_11_BPS = 0x03, /**<	GPRS mean throughput class -1 DOT 11 BPS 		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_2_DOT_2_BPS = 0x04, /**<	GPRS mean throughput class -2 DOT 2 BPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_2_DOT_4_BPS = 0x05, /**<	GPRS mean throughput class -2 DOT 4 BPS 		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_11_DOT_1_BPS = 0x06, /**<	GPRS mean throughput class - 11 DOT 1 BPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_22BPS = 0x07, /**<	GPRS mean throughput class -22BPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_44BPS = 0x08, /**<	GPRS mean throughput class - 44BPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_111BPS = 0x09, /**<	GPRS mean throughput class - 111BPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_DOT_22_KBPS = 0x0A, /**<	GPRS mean throughput class - DOT 22 KBPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_DOT_44_KBPS = 0x0B, /**<	GPRS mean throughput class -DOT 44 KBPS 		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_1_DOT_11_KBPS = 0x0C, /**<	GPRS mean throughput class -1 DOT 11 KBPS 		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_2_DOT_2_KBPS = 0x0D, /**<	GPRS mean throughput class -2 DOT 2 KBPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_4_DOT_4_KBPS = 0x0E, /**<	GPRS mean throughput class - 4 DOT 4 KBPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_11_DOT_1_KBPS = 0x0F, /**<	GPRS mean throughput class -11 DOT 1 KBPS 		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_22KBPS = 0x10, /**<	GPRS mean throughput class - 22KBPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_44KBPS = 0x11, /**<	GPRS mean throughput class - 44KBPS		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_111KBPS = 0x12, /**<	GPRS mean throughput class -111KBPS 		*/
	TAPI_SAT_BIP_GPRS_MEAN_THROUGHPUT_CLASS_BEST_EFFORT = 0x13 /**<	GPRS mean throughput class - BEST EFFORT		*/
} TelSatBearerParamGprsMeanThroughputClassType_t;

/**
 * @enum TelSatBearerParamGprsPdpType_t
 * This enum lists the SAT bearer parameter GPRS pdp type.
 */
typedef enum {
	TAPI_SAT_BIP_GPRS_PDP_TYPE_IP = 0x02, /**<	bearer parameter GPRS pdp type - IP 		*/
	TAPI_SAT_BIP_GPRS_PDP_TYPE_RESERVED = 0xff /**<	reserved 		*/
} TelSatBearerParamGprsPdpType_t;

/**
 * @enum TelSatBearerParamLocalLinksServiceIdentityType_t
 * This enum lists the SAT bearer parameters local links service identity.
 */
typedef enum {
	TAPI_SAT_BIP_LL_SERVICE_IDENT_VALUE_ASSIGNED_BY_USIM = 0x00, /**<	local links service identity - value assigned by USIM 		*/
	TAPI_SAT_BIP_LL_SERVICE_IDENT_VALUE_ASSIGNED_BY_REMOTED_DEVICE = 0xFF /**<	local links service identity - value assigned by remote service	*/
} TelSatBearerParamLocalLinksServiceIdentityType_t;

/**
 * @enum TelSatChannelStatusType_t
 * This enum lists the SAT channel status type.
 */
typedef enum {
	TAPI_SAT_CS_LINK_ESTABLISHED_OR_PDP_CTX_NOT_ACTIVATED, /**<	channel status type-CS LINK ESTABLISHED OR PDP CTX NOT ACTIVATED		*/
	TAPI_SAT_CS_LINK_ESTABLISHED_OR_PDP_CTX_ACTIVATED, /**<	channel status type-CS LINK ESTABLISHED OR PDP CTX ACTIVATED 		*/
	TAPI_SAT_UICC_SERVER_MODE_TCP_IN_CLOSED_STATE, /**<	channel status type-UICC SERVER MODE TCP IN CLOSED STATE		*/
	TAPI_SAT_UICC_SERVER_MODE_TCP_IN_LISTEN_STATE, /**<	channel status type-UICC SERVER MODE TCP IN LISTEN STATE		*/
	TAPI_SAT_UICC_SERVER_MODE_TCP_IN_ESTABLISHED_STATE, /**<	channel status type-UICC SERVER MODE TCP IN ESTABLISHED STATE		*/
	TAPI_SAT_UICC_SERVER_MODE_RESERVED /**<	reserved 		*/
} TelSatChannelStatusType_t;

/**
 * @enum TelSatChannelStatusInfoType_t
 * This enum lists the SAT channel status info type.
 */
typedef enum {
	TAPI_SAT_CHANNEL_STATUS_NO_FURTHER_INFO_AVAILABLE = 0, /**<	CHANNEL STATUS NO FURTHER INFO AVAILABLE 		*/
	TAPI_SAT_CHANNEL_STATUS_NOT_USED = 1, /**<	CHANNEL STATUS NOT USED 		*/
	TAPI_SAT_CHANNEL_STATUS_LINK_DROPPED = 5 /**<	CHANNEL STATUS LINK DROPPED	*/
} TelSatChannelStatusInfoType_t;

/**
 * @enum TelSatAddressType_t
 * This enum lists the SAT address type.
 */
typedef enum {
	TAPI_SAT_ADDR_TYPE_IPv4 = 0x21, /**<	address type - IPv4	*/
	TAPI_SAT_ADDR_TYPE_IPv6 = 0x57, /**<	address type - IPv6	*/
	TAPI_SAT_ADDR_RESERVED = 0xFF /**<	reserved		*/
} TelSatAddressType_t;

/**
 * @enum TelSatTransportProtocolType_t
 * This enum lists the SAT transport protocol type.
 */
typedef enum {
	TAPI_SAT_TP_TYPE_UDP_UICC_CLIENT = 0x01, /**<	transport protocol type- UDP UICC CLIENT	*/
	TAPI_SAT_TP_TYPE_TCP_UICC_CLIENT = 0x02, /**<	transport protocol type-TCP UICC CLIENT  	*/
	TAPI_SAT_TP_TYPE_TCP_UICC_SERVER = 0x03 /**<	transport protocol type- TCP UICC SERVER	*/
} TelSatTransportProtocolType_t;

/**
 * @enum TelSatRemoteEntityAddrCodingType_t
 * This enum lists the SAT remote entity address coding type.
 */
typedef enum {
	TAPI_SAT_REMOTE_ENTITY_ADDR_CODING_TYPE_IEEE802_48BIT = 0, /**<	remote entity address coding type- IEEE802 48BIT		*/
	TAPI_SAT_REMOTE_ENTITY_ADDR_CODING_TYPE_IRDA_32BIT = 1, /**<	remote entity address coding type- IRDA 32BIT		*/
	TAPI_SAT_REMOTE_ENTITY_ADDR_CODING_TYPE_RESERVED = 0xFF /**<	reserved		*/
} TelSatRemoteEntityAddrCodingType_t;

/**
 * This structure defines the Address data object.
 */
typedef struct {
	TelSimTypeOfNum_t ton; /**<	type of number 		*/
	TelSimNumberingPlanIdentity_t npi; /**<	number plan identity 		*/
	unsigned char diallingNumberLen; /**<	dialing number length 		*/
	char diallingNumber[TAPI_SAT_DIALLING_NUMBER_LEN_MAX]; /**<	dialing number 	*/
} TelSatAddressInfo_t;

/**
 * This structure defines the data coding scheme object.
 */
typedef struct {
	int bIsCompressedFormat; /**<	flag to verify compressed format 	*/
	TelSatAlphabetFormatType_t alphabetFormat; /**<	alphabet format Type 		*/
	TelSatMsgClassType_t msgClass; /**<	Type of message class 		*/
	unsigned char rawDcs; /**<	raw dcs info 		*/
} TelSatDataCodingSchemeInfo_t;

/**
 * This structure defines the Alpha ID data object.
 */
typedef struct {
	int bIsPresent; /**<	flag for checking existence of alpha identifier 	*/
	TelSatDataCodingSchemeInfo_t dcs; /**<	dcs info 		*/
	unsigned char stringLen; /**<	alpha identifier length 		*/
	char string[TAPI_SAT_ALPHA_ID_LEN_MAX]; /**<	alpha identifier info 	*/
} TelSatAlphaIdentifierInfo_t;

/**
 * This structure defines the Sub Address data object.
 */
typedef struct {
	unsigned char subAddressLen; /**<	sub address length 		*/
	char subAddress[TAPI_SAT_SUB_ADDR_LEN_MAX]; /**<	sub address 		*/
} TelSatSubAddressInfo_t;

/**
 * This structure defines the Capability Configuration Parameters data object.
 */
typedef struct {
	unsigned char dataLen; /**<	capability configuration parameter length 	*/
	char data[TAPI_SAT_CCP_DATA_LEN_MAX]; /**<	capability configuration parameter  	*/
} TelSatCapaConfigParamInfo_t;

/**
 * This struct defines the Command qualifier values for send SMS command.
 */
typedef struct {
	int bIsPackingByMeRequired; /**<	flag to verify packing requirement, if FALSE, packing by ME not required	*/
} TelSatCmdQualiSendSms_t;

/**
 * This struct defines the Command qualifier values for display text command.
 */
typedef struct {
	TelSatDisplayTextPriorityType_t msgPriority; /**<	message priority  		*/
	TelSatDisplayTextMsgClearType_t msgClear; /**<	message clear type 		*/
} TelSatCmdQualiDisplayText_t;

/**
 * This struct defines the Command qualifier values for get inkey command.
 */
typedef struct {
	TelSatInkeyType_t inkeyType; /**<	inkey type 		*/
	int bIsUsingAlphabetSet; /**<	flag for checking whether using alphabet set or not. if FALSE, digits(0-9,*,#and+) only 	*/
	TelSatUseInputAlphabetType_t alphabetType; /**<	alphabet type 		*/
	int bIsImmediateResponseRequired;/**<	flag for checking whether immediate response required or not 		*/
	int bIsHelpInfoAvailable; /**<	flag for checking whether help info available or not. if FALSE, no help information available 	*/
} TelSatCmdQualiGetInkey_t;

/**
 * This struct defines the Command qualifier values for get input command.
 */
typedef struct {
	int bIsUsingAlphabetSet; /**<	flag for checking whether using alphabet set. if FALSE, digits(0-9,*,#and+) only	*/
	TelSatUseInputAlphabetType_t alphabetType; /**<	alphabet type. only using alphabet set case.		*/
	int bIsMeEchoUserInput; /**<	flag for checking whether ME should echo user input. if FALSE, user input shall not be displayed*/
	int bIsUserInputUnpackedFormat; /**<	flag for checking whether user input is in unpacked format or not.  if FALSE, user input in SMS packed format	*/
	int bIsHelpInfoAvailable; /**<	flag to verify if help info available or not. if FALSE, no help information available	*/
} TelSatCmdQualiGetInput_t;

/**
 * This struct defines the Command qualifier values for play tone command.
 */
typedef struct {
	TelSatDisplayVibrateAlertType_t vibrateAlert; /**<	type of vibrate alert		*/
} TelSatCmdQualiPlayTone_t;

/**
 * This struct defines the Command qualifier values for select item command.
 */
typedef struct {
	TelSatPresentationType_t presentationType; /**<	type of presentation. only presentation type specified		*/
	TelSatSelectionPreferenceType_t selectionPreference; /**<	type of selection preference 		*/
	int bIsHelpInfoAvailable; /**<	flag for checking whether help info available or not. if FALSE, no help information available	*/
} TelSatCmdQualiSelectItem_t;

/**
 * This struct defines the Command qualifier values for setup menu command.
 */
typedef struct {
	TelSatSelectionPreferenceType_t selectionPreference; /**<	type of selection preference 		*/
	int bIsHelpInfoAvailable; /**<	flag to verify help info available or not. if FALSE, no help information available	*/
} TelSatCmdQualiSetupMenu_t;

/**
 * This struct defines the Command qualifier values for language notification command.
 */
typedef struct {
	int bSpecificLanguageNotification; /**<	flag for specific language notification. if FALSE, non-specific language notification 	*/
} TelSatCmdQualiLanguageNotification_t;

/**
 * SAT command qualifier open channel
 */
typedef struct {
	int bIsEstablishImmediateLink; /**<	flag whether establishing immediate link or not. if FALSE, on demand link establishment	*/
	int bIsAutomaticReconnection; /**<	flag whether automatic reconnection or not. if FALSE, no automatic reconnection	*/
	int bIsModeBackground; /**<	flag whether background mode or not. 		*/
} TelSatCmdQualiOpenChannel_t;

/**
 * SAT command qualifier send data
 */
typedef struct {
	int bIsSendDataImmediately; /**<	flag whether to send data immediately or not. if FALSE, store data in Tx buffer*/
} TelSatCmdQualiSendData_t;

/**
 * This structure contains the command number, type and the qualifier objects of a SATK command.
 */
typedef struct {
	unsigned char commandNumber; /**< specific command number	*/
	TelSatCommandType_t commandType; /**<	proactive command type		*/

	union {
		TelSatCmdQualiRefresh_t cmdQualiRefresh; /**<	refresh command qualifier info	*/
		TelSatCmdQualiSetupCall_t cmdQualiSetupCall; /**<	setup call command qualifier info	*/
		TelSatCmdQualiSendSms_t cmdQualiSendSms; /**<	send sms command qualifier info	*/
		TelSatCmdQualiDisplayText_t cmdQualiDisplayText; /**<	display text command qualifier info	*/
		TelSatCmdQualiGetInkey_t cmdQualiGetInkey; /**<	get inkey command qualifier info	*/
		TelSatCmdQualiGetInput_t cmdQualiGetInput; /**<	get input command qualifier info	*/
		TelSatCmdQualiPlayTone_t cmdQualiPlayTone; /**<	play tone command qualifier info	*/
		TelSatCmdQualiSelectItem_t cmdQualiSelectItem; /**<	select item command qualifier info	*/
		TelSatCmdQualiSetupMenu_t cmdQualiSetupMenu; /**<	setup menu command qualifier info	*/
		TelSatCmdQualiProvideLocalInfo_t cmdQualiProvideLocalInfo;/**<	provide local info command qualifier info	*/
		TelSatCmdQualiLanguageNotification_t cmdQualiLanguageNotification;/**<	language notification command qualifier info	*/
		TelSatCmdQualiLaunchBrowser_t cmdQualiLaunchBrowser; /**<	launch Browser command qualifier info	*/
		TelSatCmdQualiOpenChannel_t cmdQualiOpenChannel; /**<	Open channel command qualifier info	*/
		TelSatCmdQualiSendData_t cmdQualiSendData; /**<	send data command qualifier info	*/
	} u; /**<	Union  	*/
} TelSatCommandDetailInfo_t;

/**
 * This struct defines the device identity values.
 */
typedef struct {
	TelSatDeviceIdentitiesTagType_t source; /**<	device identity tag for source	*/
	TelSatDeviceIdentitiesTagType_t destination; /**<	device identity for destination	*/
} TelSatDeviceIdentitiesInfo_t;

/**
 * This structure defines the Duration data object.
 */
typedef struct {
	TelSatTimeUnitType_t timeUnit; /**<	time units for the duration data		*/
	unsigned char timeInterval; /**<	time interval		*/
} TelSatDurationInfo_t;

/**
 * This structure defines the menu item data object.
 */
typedef struct {
	unsigned char itemId; /**<	item identifier 		*/
	unsigned char textLen; /**<	text length 		*/
	unsigned char text[TAPI_SAT_ITEM_TEXT_LEN_MAX + 1]; /**<	text information		*/
} TelSatMenuItemInfo_t;

/**
 * This structure defines the item identifier object.
 */
typedef struct {
	unsigned char selectedItemIdentifier; /**<	selected item identifier		*/
} TelSatItemIdentifierInfo_t;

/**
 * This structure defines expected user response length.
 */
typedef struct {
	unsigned char min; /**<	user response length minimum value		*/
	unsigned char max; /**<	user response length maximum value 		*/
} TelSatRespLenInfo_t;

/**
 * This structure defines RESUlT data object.
 */
typedef struct {
	TelSatResultType_t generalResult; /**<	general result	*/
	TelSatMeProblemType_t meProblem; /**<	additional information on general result	*/
} TelSatResultInfo_t;

/**
 * This structure defines RESUlT data object.
 */
typedef struct {
	TelSatSmsTpduType_t tpduType; /**<	SMS TPDU TYPE 	*/
	unsigned char dataLen; /**<	SMS TPDU DATA LENGTH 	*/
	unsigned char data[TAPI_SAT_SMS_TPDU_SMS_DATA_LEN_MAX]; /**< SMS TPDU DATA*/
} TelSatSmsTpduInfo_t;

/**
 * This structure defines SS STRING data object.
 */
typedef struct {
	TelSimTypeOfNum_t ton; /**<	type of number	*/
	TelSimNumberingPlanIdentity_t npi; /**<	number plan identity 	*/
	unsigned char stringLen; /**<	ss string length 	*/
	char string[TAPI_SAT_SS_STRING_LEN_MAX]; /**<	ss string 	*/
} TelSatSsStringInfo_t;

/**
 * This structure defines TEXT STRING data object.
 */
typedef struct {
	int bIsDigitOnly; /**<	flag for checking whether only digits used or not	*/
	TelSatDataCodingSchemeInfo_t dcs; /**<	data coding scheme		*/
	unsigned short stringLen; /**<	text length 		*/
	char string[TAPI_SAT_TEXT_STRING_LEN_MAX + 1]; /**<	text string 	*/
} TelSatTextTypeInfo_t;

/**
 * This structure defines menu item text object.
 */
typedef struct {
	int bIsDigitOnly; /**<	flag for checking whether only digits used or not	*/
	TelSatDataCodingSchemeInfo_t dcs; /**<	data coding scheme		*/
	unsigned char stringLen; /**<	menu item string length	*/
	char* pString; /**<	Menu Item String */
} TelSatMenuItemTextInfo_t;

/**
 * This structure defines tone object.
 */
typedef struct {
	TelSatToneType_t type; /**<	tone type	*/
} TelSatToneInfo_t;

/**
 * This structure defines USSD string data object.
 */
typedef struct {
	TelSatDataCodingSchemeInfo_t dcs; /**<	data coding scheme	*/
	unsigned char ussdStringLen; /**<	ussd string length	*/
	char ussdString[TAPI_SAT_USSD_STRING_LEN_MAX]; /**<	ussd string	*/
} TelSatUssdStringInfo_t;

/**
 * This structure defines File list data object.
 */
typedef struct {
	unsigned char fileCount; /**<	file count	*/
//	TelSimFileName_t fileId[TAPI_SAT_FILE_ID_LIST_MAX_COUNT]; /**<	file identifier	*/
} TelSatFileListInfo_t;

/**
 * This structure defines default text data object.
 */
typedef struct {
	int bIsPresent; /**<	flag for checking whether default text exists or not	*/
	int bIsDigitOnly; /**<	flag for checking whether only digits used or not	*/
	TelSatDataCodingSchemeInfo_t dcs; /**<	data coding scheme	*/
	unsigned char stringLen; /**<	default text string length 		*/
	char string[TAPI_SAT_TEXT_STRING_LEN_MAX]; /**<	default text	*/
} TelSatDefaultTextInfo_t;

/**
 * This structure defines Next Action Indicator List data object.
 */
typedef struct {
	unsigned char listCount; /**<	next action identifier count	*/
	unsigned char list[TAPI_SAT_ITEMS_NEXT_ACTION_INDI_LIST_MAX_COUNT]; /**<	next action identifier list	*/
} TelSatItemsNextActionIndiListInfo_t;

/**
 * This structure defines event list data object.
 */
typedef struct {
	unsigned char eventListCount; /**<	event list count	*/
	TelSatEventDownloadType_t list[TAPI_SAT_EVENT_LIST_MAX_COUNT]; /**<	event list */
} TelSatEventListInfo_t;

/**
 * This structure defines icon info object.
 */
typedef struct {
	unsigned char width; /**<	icon width  		*/
	unsigned char height; /**<	icon height  	*/
	TelSatImageCodingSchemeType_t ics; /**<	image coding scheme 	*/
	unsigned short iconDataLen; /**<	icon data length 	*/
	unsigned short clutDataLen; /**<	clut data length	*/
	char iconFile[TAPI_SAT_IMG_DATA_FILE_PATH_LEN_MAX];
	char clutFile[TAPI_SAT_IMG_DATA_FILE_PATH_LEN_MAX];
} TelSatIconInfo_t;

/**
 * This structure defines icon data object.
 */
typedef struct {
	int bIsPresent; /**<	flag for checking whether icon identifier exists or not		*/
	TelSatIconQualifierType_t iconQualifier; /**<	icon qualifier type		*/
	unsigned char iconIdentifier; /**<	icon identifier		*/
	TelSatIconInfo_t iconInfo; /**<	icon info	*/
} TelSatIconIdentifierInfo_t;

/**
 * This structure defines icon identifier data object.
 */
typedef struct {
	int bIsPresent; /**<	flag for checking whether icon identifier exists or not	*/
	TelSatIconQualifierType_t iconListQualifier; /**<	icon list qualifier	*/
	unsigned char iconCount; /**<	icon count	*/
	unsigned char iconIdentifierList[TAPI_SAT_ICON_LIST_MAX_COUNT]; /**<	icon identifier list	*/
	TelSatIconInfo_t iconInfo[TAPI_SAT_ICON_LIST_MAX_COUNT]; /**<	icon list info	*/
} TelSatIconIdentifierListInfo_t;

/**
 * This structure defines SAT bc repeat indicator Info
 */
typedef struct {
	TelSatBcRepeatIndicatorType_t indType; /**<	bc repeat indicator type	*/
} TelSatBcRepeatIndicatorInfo_t;

/**
 * This structure defines call control strings.
 */
typedef struct {
	TelSatCallCtrlStringType_t callCtrlStringType; /**<	call control type	*/
	union {
		TelSatAddressInfo_t voiceString; /**<	voice call string	*/
		TelSatSsStringInfo_t ssString; /**<	ss string	*/
		TelSatUssdStringInfo_t ussdString; /**<	ussd string	*/
	} u; /**<	Union  	*/
} TelSatCallCtrlAddressStringInfo_t;

/**
 * This structure defines the Action requested call control data.
 */
typedef struct {
	TelSatCallCtrlAddressStringInfo_t callCtrlAddString; /**< Call control address string */
	TelSatCapaConfigParamInfo_t ccp1; /**< Capability configuration parameter 1 */
	TelSatSubAddressInfo_t subAddress; /**< Subaddress */
	TelSatAlphaIdentifierInfo_t alphaId; /**< Alpha identifier */
	TelSatBcRepeatIndicatorInfo_t bcRepeatIndicator; /**< Bc repeat indicator */
	TelSatCapaConfigParamInfo_t ccp2; /**< Capability configuration parameter 2 */
} TelSatCallCtrlRequestedActionInfo_t;

/**
 * This structure defines dtmf string data object.
 */
typedef struct {
	unsigned char stringLen; /**<	dtmf string lengh	*/
	char dtmfTone[TAPI_SAT_DTMF_STRING_LEN_MAX]; /**<	dtmf tone data	*/
} TelSatDtmfStringInfo_t;

/**
 * This structure defines language data object.
 */
typedef struct {
	TelSatLanguageType_t language; /**<	language type	*/
} TelSatLanguageInfo_t;

/**
 * This structure defines date time and time zone data object.
 */
typedef struct {
	unsigned char year; /**<	year	*/
	unsigned char month; /**<	month	*/
	unsigned char day; /**<	day	*/
	unsigned char hour; /**<	hour	*/
	unsigned char minute; /**<	minute	*/
	unsigned char second; /**<	second	*/
	unsigned char timeZone; /**<	timeZone	*/
} TelSatDataTimeZoneInfo_t;

/**
 * This structure defines SAT browser identities.
 */
typedef struct {
	TelSatBrowserIdentityType_t browserIdentity; /**<	browser identity	*/
} TelSatBrowserIdentitiesInfo_t;

/**
 * This structure defines SAT browser URL Data Object.
 */
typedef struct {
	char string[TAPI_SAT_URL_LEN_MAX + 1]; /**<	url string	*/
} TelSatUrlInfo_t;

/**
 * This structure defines SAT bearer type.
 */
typedef struct {
	unsigned char listLen; /**<	bearer list length	*/
	TelSatBearerType_t bearerList[TAPI_SAT_BEARER_LIST_MAX_COUNT]; /**<	bearer list	*/
} TelSatBearerInfo_t;

/**
 * This structure defines SAT provisioning reference.
 */
typedef struct {
	char provisioningFilePath[TAPI_SAT_PROVISIONING_FILE_PATH_LEN_MAX]; /**<	provisioning file path	*/
} TelSatProvisioningRefInfo_t;

/**
 * This structure defines SAT browser termination cause.
 */
typedef struct {
	TelSatBrowserTerminationCauseType_t cause; /**<	browser termination cause	*/
} TelSatBrowserTerminationCauseInfo_t;

/**
 * This structure defines SAT Csd bearer parameters .
 */
typedef struct {
	TelSatBearerParamCsdDataRateType_t dataRate; /**<	bearer csd data rate	*/
	TelSatBearerParamCsdBearerServiceType_t bearerService; /**<	bearer csd service type	*/
	TelSatBearerParamCsdConnectionElementType_t connectionElement; /**<	bearer connection element type	*/
} TelSatBearerParametersCsdInfo_t;

/**
 * This structure defines SAT bearer parameters GPRS.
 */
typedef struct {
	TelSatBearerParamGprsPrecedenceClassType_t precedenceClass; /**<	bearer gprs	precedence class	*/
	TelSatBearerParamGprsDelayClassType_t delayClass; /**<	bearer gprs delay	*/
	TelSatBearerParamGprsReliabilityClassType_t reliabilityClass; /**<	bearer gprs reliability	*/
	TelSatBearerParamGprsPeakThroughputClassType_t peakThroughputClass;/**<	bearer gprs peak throughput	*/
	TelSatBearerParamGprsMeanThroughputClassType_t meanThroughputClass;/**<	bearer gprs mean throughput	*/
	TelSatBearerParamGprsPdpType_t pdpType; /**<	bearer gprs pdp type	*/
} TelSatBearerParametersGprsInfo_t;

/**
 * This structure defines SAT bearer parameters local links.
 */
typedef struct {
	TelSatBearerParamLocalLinksServiceIdentityType_t serviceIdentifier; /**<	bearer local link service identifier 		*/
	char serviceRecord[TAPI_SAT_BEARER_PARAMS_LEN_MAX]; /**<	bearer local link service record	*/
} TelSatBearerParametersLocalLinksInfo_t;

/**
 * This structure defines SAT bearer description.
 */
typedef struct {
	TelSatBearerDescType_t bearerType; /**<	bearer type	*/
	union {
		TelSatBearerParametersCsdInfo_t bearerParamsCsd; /**<	csd	*/
		TelSatBearerParametersGprsInfo_t bearerParamsGprs; /**<	gprs	*/
		TelSatBearerParametersLocalLinksInfo_t bearerParamsLocalLinks; /**<	local link	*/
	} bearer_params; /**<Union */
} TelSatBearerDescriptionInfo_t;

/**
 * This structure defines SAT channel data.
 */
typedef struct {
	unsigned char channelDataStringLen; /**<	channel data length	*/
	char channelDataString[TAPI_SAT_CHANNEL_DATA_STRING_LEN_MAX]; /**<	channel data 	*/
} TelSatChannelDataInfo_t;

/**
 * This structure defines SAT channel data length.
 */
typedef struct {
	unsigned char channelDataLen; /**<	channel data length	*/
} TelSatChannelDataLengthInfo_t;

/**
 * This structure defines SAT buffer size.
 */
typedef struct {
	unsigned char bufferSize[2]; /**<	channel data buffer size	*/
} TelSatBufferSizeInfo_t;

/**
 * This structure defines SAT channel status.
 */
typedef struct {
	unsigned char channelId; /**<	channel id	*/
	TelSatChannelStatusType_t status; /**<	channel status		*/
	TelSatChannelStatusInfoType_t channelInfo; /**<	channel status info 	*/
} TelSatChannelStatusInfo_t;

/**
 * This structure defines SAT other address.
 */
typedef struct {
	TelSatAddressType_t addressType; /**<	channel address type	*/
	unsigned char addressLen; /**<	channel address length	*/
	char address[TAPI_SAT_OTHER_ADDR_LEN_MAX]; /**<	channel address	*/
} TelSatOtherAddressInfo_t;

/**
 * This structure defines SIM me interface transport level.
 */
typedef struct {
	TelSatTransportProtocolType_t transportProtocolType; /**<	transport protocol type	*/
	unsigned short portNumber; /**<	port number	*/
} TelSatSimMeInterfaceTransportLevelInfo_t;

/**
 * This structure defines SAT network access name.
 */
typedef struct {
	unsigned char length; /**<	network access name length	*/
	unsigned char netAccName[TAPI_SAT_NET_ACC_NAM_LEN_MAX]; /**<	network access name	*/
} TelSatnetworkAccessNameInfo_t;

/**
 * This structure defines SAT aid.
 */
typedef struct {
	char aid[TAPI_SAT_AID_LEN_MAX]; /**<	application Id	*/
} TelSatAidInfo_t;

/**
 * This structure defines SAT remote entity address.
 */
typedef struct {
	TelSatRemoteEntityAddrCodingType_t codingType; /**<	remote entity address coding type	*/
	unsigned short length; /**<	remote entity address length	*/
	unsigned char remoteEntityAddress[TAPI_SAT_REMOTE_ENTITY_ADDR_LEN_MAX]; /**<	remote entity address data	*/
} TelSatRemoteEntityAddressInfo_t;

/**
 * This structure defines SAT text attribute.
 */
typedef struct {
	unsigned char textFormatting[4]; /**<	text attribute -e.g. bold, center align, etc	*/
} TelSatTextAttributeInfo_t;

/**
 * This structure defines SAT text attribute list.
 */
typedef struct {
	unsigned int listCount; /**<	text attribute list count		*/
	TelSatTextAttributeInfo_t list[TAPI_SAT_ITEM_TEXT_ATTRIBUTES_LIST_MAX_COUNT]; /**<	text attribute list info	*/
} TelSatTextAttributeListInfo_t;

#ifdef __cplusplus
}
#endif

#endif	/* _TEL_SAT_OBJ_H_ */

/**
 * @}
 */
