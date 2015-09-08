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
 * @addtogroup	SAT_TAPI	SAT
 * @{
 *
 * @file TelSatProactvCmd.h

 @brief This file serves as a "C" header file defines structures for Tapi SAT Proactive commands and terminal response Services. \n
 It contains a sample set of constants, enums, structs that would be required by applications.
 */

#ifndef _TEL_SAT_PROACTV_CMD_H_
#define _TEL_SAT_PROACTV_CMD_H_

#include <TelSatObj.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define TAPI_SAT_MENU_ITEM_COUNT_MAX			40	/**<	max count of sat menu items	*/
#define TAPI_SAT_PROVISIONING_REF_MAX_COUNT		10	/**<	max count of sat provisioning reference	*/

/**
 * This structure contains the data objects for DISPLAY TEXT proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices */
} TelSatMoreTimeIndInfo_t;

/**
 * This structure contains the data objects for DISPLAY TEXT proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatTextTypeInfo_t text; /**<	display text info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	int bImmediateRespRequested; /**<	flag for checking whether immediate response required or not	*/
	TelSatDurationInfo_t duration; /**<	duration for which text should be displayed	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatDisplayTextIndInfo_t;

/**
 * This structure contains the data objects for GET INKEY proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatTextTypeInfo_t text; /**<	display text info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatDurationInfo_t duration; /**<	duration for which text should be displayed	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatGetInkeyIndInfo_t;

/**
 * This structure contains the data objects for GET INPUT proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatTextTypeInfo_t text; /**<	display text info	*/
	TelSatRespLenInfo_t respLen; /**<	input response length	*/
	TelSatTextTypeInfo_t defaultText; /**<	default text info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatGetInputIndInfo_t;

/**
 * This structure contains the data objects for PLAY TONE proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatToneInfo_t tone; /**<	tone info	*/
	TelSatDurationInfo_t duration; /**<	duration for which tone should be played	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatPlayToneIndInfo_t;

/**
 * This structure contains the data objects for SETUP MENU proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	unsigned char menuItemCount; /**<	count of menu items	*/
	TelSatMenuItemInfo_t menuItem[TAPI_SAT_MENU_ITEM_COUNT_MAX]; /**<	menu item data	*/
	TelSatItemsNextActionIndiListInfo_t itemNextActionIndList; /**<	next action indication list	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatIconIdentifierListInfo_t iconIdList; /**<	icon identifier list info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
	TelSatTextAttributeListInfo_t itemTextAttributeList; /**<	item text attribute list	*/
} TelSatSetupMenuIndInfo_t;

/**
 * This structure contains the data objects for SELECT ITEM proactive command indication data.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatItemsNextActionIndiListInfo_t itemNextActionIndList; /**<	next action indication list	*/
	unsigned char defaultItemIdentifier; /**<	default item identifier(default selected item id)	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatIconIdentifierListInfo_t iconIdList; /**<	icon identifier list info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
	TelSatTextAttributeListInfo_t itemTextAttributeList; /**<	item text attribute list	*/
	unsigned char menuItemCount; /**<	count of menu items	*/
	TelSatMenuItemInfo_t menuItem[TAPI_SAT_MENU_ITEM_COUNT_MAX]; /**<	menu item data	*/
} TelSatSelectItemIndInfo_t;

/**
 * This structure contains the data objects for SEND SHORT MESSAGE proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatAddressInfo_t address; /**<	address for sending sms	*/
	TelSatSmsTpduInfo_t smsTpdu; /**<	sms tpdu info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatSendSmsIndInfo_t;

/**
 * This structure contains the data objects for SEND SS proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatSsStringInfo_t ssString; /**<	ss string	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatSendSsIndInfo_t;

/**
 * This structure contains the data objects for SEND USSD proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatUssdStringInfo_t ussdString; /**<	ussd string info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatSendUssdIndInfo_t;

/**
 * This structure contains the data objects for SETUP CALL proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAddressInfo_t address; /**<	setup call address info*/
	TelSatCapaConfigParamInfo_t ccp; /**<	capability configuration parameter	*/
	TelSatSubAddressInfo_t subAddress; /**<	setup call sub address	*/
	TelSatDurationInfo_t duration; /**<	command execution time duration	*/
	TelSatAlphaIdentifierInfo_t userConfirmPhaseAlphaId;/**<	user Confirmation Phase AlphaId	*/
	TelSatAlphaIdentifierInfo_t callSetupPhaseAlphaId; /**<	call Setup Phase AlphaId	*/
	TelSatIconIdentifierInfo_t userConfirmPhaseIconId; /**<	user Confirmation Phase IconId	*/
	TelSatIconIdentifierInfo_t callSetupPhaseIconId; /**<	call Setup Phase IconId	*/
	TelSatTextAttributeInfo_t userConfirmPhaseTextAttribute; /**<	user Confirmation Phase Text Attribute	*/
	TelSatTextAttributeInfo_t callSetupPhaseTextAttribute; /**<	call Setup PhaseText Attribute	*/
} TelSatSetupCallIndInfo_t;

/**
 * This structure contains the data objects for REFRESH proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatFileListInfo_t fileList; /**<	file list for refresh	*/
	TelSatAidInfo_t aid; /**<	application Id	*/
} TelSatRefreshIndInfo_t;

/**
 * This structure contains the data objects for PROVIDE LOCAL INFO proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/

} TelSatProvideLocalInfoIndInfo_t;

/**
 * This structure contains the data objects for SETUP EVENT LIST proactive command indication data.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatEventListInfo_t eventList; /**<	event list contains events which are required by USIM application	*/

} TelSatSetupEventListIndInfo_t;

/**
 * This structure contains the data objects for SETUP IDLE MODE TEXT proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatTextTypeInfo_t text; /**<	text to be shown on idle screen	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatSetupIdleModeTextIndInfo_t;

/**
 * This structure contains the data objects for SEND DTMF COMMAND proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatDtmfStringInfo_t dtmfString; /**<	dtmf string	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatSendDtmfIndInfo_t;

/**
 * This structure contains the data objects for LANGUAGE NOTIFICATION proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatLanguageInfo_t language; /**<	language info from USIM application	*/
} TelSatLanguageNotificationIndInfo_t;

/**
 * This structure contains the data objects for LAUNCH BROWSER proactive command indication.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatBrowserIdentitiesInfo_t browserId; /**<	browser identity	*/
	TelSatUrlInfo_t url; /**<	url	*/
	TelSatBearerInfo_t bearer; /**<	bearer which is used by browser	*/
	unsigned char provisioningRefCount; /**<	provisioning reference count	*/
	TelSatProvisioningRefInfo_t provisioningRef[TAPI_SAT_PROVISIONING_REF_MAX_COUNT]; /**<	provisioning reference data	*/
	TelSatTextTypeInfo_t text; /**<	display text info	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatLaunchBrowserIndInfo_t;

/**
 * This structure contains the data objects for OPEN CHANNEL CSB proactive command indication data.
 */
typedef struct {
	TelSatAddressInfo_t address; /**<	channel address	*/
	TelSatSubAddressInfo_t subAddress; /**<	channel sub address	*/
	TelSatDurationInfo_t duration1; /**<	connection require time	*/
	TelSatDurationInfo_t duration2; /**<	connection require time2	*/
	TelSatBearerParametersCsdInfo_t bearerParamsCsd; /**<	csd info	*/
	TelSatBufferSizeInfo_t bufferSize; /**<	bufferSize	*/
	TelSatOtherAddressInfo_t otherAddress; /**<	otherAddress	*/
	TelSatTextTypeInfo_t userLogin; /**<	userLogin	*/
	TelSatTextTypeInfo_t userPassword; /**<	userPassword	*/
	TelSatSimMeInterfaceTransportLevelInfo_t simMeInterfaceTransportLevel; /**<	simMeInterfaceTransportLevel	*/
	TelSatOtherAddressInfo_t dataDestinationAddress; /**<	dataDestinationAddress	*/
} TelSatOpenChannelCsbInfo_t;

/**
 * This structure contains the data objects for OPEN CHANNEL (packet) proactive command indication data.
 */
typedef struct {
	TelSatBearerParametersGprsInfo_t bearerParamsGprs; /**<	gprs info	*/
	TelSatBufferSizeInfo_t bufferSize; /**<	bufferSize	*/
	TelSatnetworkAccessNameInfo_t networkAccessName; /**<	networkAccessName	*/
	TelSatOtherAddressInfo_t otherAddress; /**<	otherAddress	*/
	TelSatTextTypeInfo_t userLogin; /**<	userLogin	*/
	TelSatTextTypeInfo_t userPassword; /**<	userPassword	*/
	TelSatSimMeInterfaceTransportLevelInfo_t simMeInterfaceTransportLevel; /**<	simMeInterfaceTransportLevel	*/
	TelSatOtherAddressInfo_t dataDestinationAddress; /**<	dataDestinationAddress	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatOpenChannelpdbInfo_t;

/**
 * This structure contains the data objects for OPEN CHANNEL LOCAL LINK proactive command indication data.
 */
typedef struct {
	TelSatDurationInfo_t duration1; /**<	command execution time duration1	*/
	TelSatDurationInfo_t duration2; /**<	command execution time duration2	*/
	TelSatBearerParametersLocalLinksInfo_t bearerParamsLocalLinks; /**<	local link info	*/
	TelSatBufferSizeInfo_t bufferSize; /**<	bufferSize	*/
	TelSatTextTypeInfo_t userPassword; /**<	userPassword	*/
	TelSatSimMeInterfaceTransportLevelInfo_t simMeInterfaceTransportLevel; /**<	simMeInterfaceTransportLevel	*/
	TelSatOtherAddressInfo_t dataDestinationAddress; /**<	dataDestinationAddress	*/
	TelSatRemoteEntityAddressInfo_t remoteEntityAddress; /**<	remoteEntityAddress	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatOpenChannelLocalBearerInfo_t;

/**
 * This structure contains the data objects for OPEN CHANNEL (DEFAULT BEARER) proactive command indication data.
 */
typedef struct {
	TelSatBufferSizeInfo_t bufferSize; /**<	bufferSize	*/
	TelSatOtherAddressInfo_t otherAddress; /**<	otherAddress	*/
	TelSatTextTypeInfo_t userLogin; /**<	userLogin	*/
	TelSatTextTypeInfo_t userPassword; /**<	userPassword	*/
	TelSatSimMeInterfaceTransportLevelInfo_t simMeInterfaceTransportLevel;/**<	simMeInterfaceTransportLevel	*/
	TelSatOtherAddressInfo_t dataDestinationAddress; /**<	dataDestinationAddress	*/
} TelSatOpenChannelDefaultBearerInfo_t;

/**
 * This structure contains the data objects for OPEN CHANNEL (UICC Server Mode) proactive command indication data.
 */
typedef struct {
	TelSatBufferSizeInfo_t bufferSize; /**<	bufferSize	*/
	TelSatSimMeInterfaceTransportLevelInfo_t simMeInterfaceTransportLevel; /**<	simMeInterfaceTransportLevel	*/
} TelSatOpenChannelUiccServerModeInfo_t;

/**
 * This structure contains the data objects for OPEN CHANNEL proactive command indication data.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	int bIsUiccServerMode; /**<	flag whether UICC server mode or not	*/
	TelSatBearerDescType_t bearerType; /**<	bearer destination type	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	union {
		TelSatOpenChannelCsbInfo_t csBearer; /**<	cs info	*/
		TelSatOpenChannelpdbInfo_t pdBearer; /**<	pbd info	*/
		TelSatOpenChannelLocalBearerInfo_t locBearer; /**<	local link info	*/
		TelSatOpenChannelDefaultBearerInfo_t defaultBearer; /**<	defaultBearer	*/
		TelSatOpenChannelUiccServerModeInfo_t uiccServerMode; /**<	uiccServerMode	*/
	} details; /**< Open Channel Details */
} TelSatOpenChannelIndInfo_t;

/**
 * This structure contains the data objects for CLOSE CHANNEL proactive command indication data.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatTextAttributeInfo_t textAttribute; /**<	text attribute info -e.g. bold, center align	*/
} TelSatCloseChannelIndInfo_t;

/**
 * This structure contains the data objects for RECEIVE DATA proactive command indication data.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatChannelDataLengthInfo_t channelDataLen; /**<	channel data length	*/
} TelSatReceiveDataIndInfo_t;

/**
 * This structure contains the data objects for SEND DATA proactive command indication data.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
	TelSatAlphaIdentifierInfo_t alphaId; /**<	alpha identifier(string) info	*/
	TelSatIconIdentifierInfo_t iconId; /**<	icon identifier info	*/
	TelSatChannelDataInfo_t channel_data; /**<	channel data for sending	*/
} TelSatSendDataIndInfo_t;

/**
 * This structure contains the data objects for GET CHANNEL STATUS proactive command indication data.
 */
typedef struct {
	TelSatCommandDetailInfo_t commandDetail; /**<	command detail info. includes command number, type, qualifier	*/
	TelSatDeviceIdentitiesInfo_t deviceIdentities; /**<	device identities info. includes source and destination devices	*/
} TelSatGetChannelStatusIndInfo_t;

/**
 * This structure contains the data object for END PROACTIVE SESSION command indication.
 */
typedef struct {
	TelSatCommandType_t commandType; /**<	proactive command type	*/
} TelSatEndProactiveSessionIndInfo_t;

/**
 * This structure contains the data objects for PROACTIVE command indication union data.
 */
typedef struct {
	union {
		TelSatMoreTimeIndInfo_t moreTime;
		TelSatDisplayTextIndInfo_t displayText; /**<	Parsed proactive command info from TLV to Telephony data type - display text	*/
		TelSatGetInkeyIndInfo_t getInkey; /**<	Parsed proactive command info from TLV to Telephony data type - getInkey	*/
		TelSatGetInputIndInfo_t getInput; /**<	Parsed proactive command info from TLV to Telephony data type - getInput	*/
		TelSatPlayToneIndInfo_t playTone; /**<	Parsed proactive command info from TLV to Telephony data type - play tone	*/
		TelSatSetupMenuIndInfo_t setupMenu; /**<	Parsed proactive command info from TLV to Telephony data type - setup menu	*/
		TelSatSelectItemIndInfo_t selectItem; /**<	Parsed proactive command info from TLV to Telephony data type - select item	*/
		TelSatSendSmsIndInfo_t sendSms; /**<	Parsed proactive command info from TLV to Telephony data type - send sms	*/
		TelSatSendSsIndInfo_t sendSs; /**<	Parsed proactive command info from TLV to Telephony data type - send ss	*/
		TelSatSendUssdIndInfo_t sendUssd; /**<	Parsed proactive command info from TLV to Telephony data type - send  ussd	*/
		TelSatSetupCallIndInfo_t setupCall; /**<	Parsed proactive command info from TLV to Telephony data type - setup call	*/
		TelSatRefreshIndInfo_t refresh; /**<	Parsed proactive command info from TLV to Telephony data type - refresh	*/
		TelSatProvideLocalInfoIndInfo_t provideLocInfo; /**<	Parsed proactive command info from TLV to Telephony data type - provide local info	*/
		TelSatLaunchBrowserIndInfo_t launchBrowser; /**<	Parsed proactive command info from TLV to Telephony data type - launch browser	*/
		TelSatSetupIdleModeTextIndInfo_t idleText; /**<	Parsed proactive command info from TLV to Telephony data type - setup idle mode text	*/
		TelSatSendDtmfIndInfo_t sendDtmf; /**<	Parsed proactive command info from TLV to Telephony data type - send dtmf	*/
		TelSatLanguageNotificationIndInfo_t languageNotification;/**<	Parsed proactive command info from TLV to Telephony data type - language notification	*/
		TelSatSetupEventListIndInfo_t setupEventList; /**<	Parsed proactive command info from TLV to Telephony data type - setup event list	*/
		TelSatOpenChannelIndInfo_t openChannel; /**<	Parsed proactive command info from TLV to Telephony data type - open channel	*/
		TelSatCloseChannelIndInfo_t closeChannel; /**<	Parsed proactive command info from TLV to Telephony data type - close channel	*/
		TelSatReceiveDataIndInfo_t receiveData; /**<	Parsed proactive command info from TLV to Telephony data type - receive data	*/
		TelSatSendDataIndInfo_t sendData; /**<	Parsed proactive command info from TLV to Telephony data type - send data	*/
		TelSatGetChannelStatusIndInfo_t getChannelStatus; /**<	Parsed proactive command info from TLV to Telephony data type - get channel status	*/
	} cmdInfo; /**<	Union	*/
} TelSatProactiveCmdData_t;

/**
 * This structure contains the data objects for the Terminal Response of DISPLAY TEXT proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
} TelSatDisplayTextRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of GET INKEY proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	TelSatTextTypeInfo_t text; /**<	inserted key info	*/
	TelSatDurationInfo_t duration;
} TelSatGetInkeyRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of PLAY TONE proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
} TelSatPlayToneRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of MORE TIME proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
} TelSatMoreTimeRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SETUP MENU proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
} TelSatSetupMenuRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of GET INPUT proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	TelSatTextTypeInfo_t text; /**<	inserted string info	*/
} TelSatGetInputRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SELECT ITEM proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	int bOtherInfo; /**<	flag to check whether other information is required or not	*/
	unsigned char itemIdentifier; /**<	item identifier	*/
} TelSatSelectItemRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of PROVIDE LOCAL INFORMATION proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	int bOtherInfo; /**<	flag to check whether other information is required or not	*/
	TelSatCmdQualiProvideLocalInfo_t infoType; /**<	local info type - e.g. time zone or language info, etc	*/
	union {
		TelSatDataTimeZoneInfo_t timeZoneInfo; /**<	current time zone info	*/
		TelSatLanguageInfo_t languageInfo; /**<	current ME language setting info	*/
	} u; /**<	Union	*/
} TelSatProvideLocalInfoRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SETUP EVENT LIST proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
} TelSatSetupEventListRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SEND SMS proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	TelSatCallCtrlProblemType_t additionalCallCtrlProblemInfo; /**<	call control problem	*/
} TelSatSendSmsRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SET UP CALL proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	int bOtherInfo; /**<	flag to check whether other information are required or not	*/
	TelSatNetworkProblemType_t networkProblem; /**<	network problem during setup call	*/
	TelSatCallCtrlProblemType_t permanentCallCtrlProblem; /**<	permanent call control problem	*/
	TelSatCallCtrlRequestedActionInfo_t callCtrlRequestedAction; /**<	call control requested action info	*/
	TelSatResultInfo_t result2; /**<	additional response on general result	*/
	TelSatTextTypeInfo_t text; /**<	text string info	*/
	int bIsTapiCause; /**<	flag to check whether tapi makes problem or not	*/
	unsigned long tapiCause; /**<	tapi call level cause	*/
	unsigned long tapiSsCause; /**<	tapi ss level cause	*/
} TelSatSetupCallRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SEND SS proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	int bOtherInfo; /**<	flag to check whether whether other information is required or not	*/
	TelSatSsProblemType_t additionalSsProblemInfo; /**<	additional ss problem */
	TelSatCallCtrlProblemType_t additionalCallCtrlProblemInfo; /**<	additional call control problem	*/
	TelSatCallCtrlRequestedActionInfo_t callCtrlRequestedAction; /**<	call control requested action info	*/
	TelSatResultInfo_t result2; /**<	additional response on general result	*/
	TelSatTextTypeInfo_t text; /**<	text string info	*/
} TelSatSendSsRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SEND USSD proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	int bOtherInfo; /**<	flag to check whether other information is required or not	*/
	TelSatUssdProblemType_t additionalUssdProblemInfo; /**<	additional ussd problem	*/
	TelSatCallCtrlProblemType_t additionalCallCtrlProblemInfo; /**<	additional call control problem	*/
	int bCallCtrlHasModification; /**<	flag to check whether modification happens during call control	*/
	TelSatTextTypeInfo_t text; /**<	text string info	*/
	TelSatCallCtrlRequestedActionInfo_t callCtrlRequestedAction; /**<	call control requested action info	*/
	TelSatResultInfo_t result2; /**<	additional response on general result	*/
	TelSatTextTypeInfo_t text2; /**<	text string info	*/
} TelSatSendUssdRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of REFRESH proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
} TelSatRefreshRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of GET CHANNEL STATUS proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	int bOtherInfo; /**<	flag whether other information are required or not	*/
	TelSatBipProblemType_t additionalProblemInfo; /**<	bip specific problem info	*/
	TelSatChannelStatusInfo_t channelStatus; /**<	channel Status	*/
} TelSatGetChannelStatusRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of CLOSE CHANNEL proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	TelSatBipProblemType_t additionalProblemInfo; /**<	bip specific problem info	*/
} TelSatCloseChannelRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of OPEN CHANNEL proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	int bOtherInfo; /**<	flag whether other information are required or not */
	TelSatBearerDescriptionInfo_t bearerDescription; /**<	bearerDescription	*/
	TelSatBipProblemType_t additionalProblemInfo; /**<	bip specific problem info	*/
	TelSatChannelStatusInfo_t channelStatus; /**<	channelStatus	*/
	TelSatBufferSizeInfo_t bufferSize; /**<	bufferSize	*/
} TelSatOpenChannelRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of LANGAUGE NOTIFICATION proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
} TelSatLanguageNotificationRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of LAUNCH BROWSER proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	TelSatLaunchBrowserProblemType_t additionalProblemInfo; /**<	browser specific problem info	*/
} TelSatLaunchBrowserRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of RECEIVE DATA proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	TelSatBipProblemType_t additionalProblemInfo; /**<	bip specific problem info	*/
	int bOtherInfo; /**<	flag whether other information are required or not	*/
	TelSatChannelDataInfo_t channel_data; /**<	channel data	*/
	unsigned char channelDataLen; /**<	channel data length	*/
} TelSatReceiveDataRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SEND DATA proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
	TelSatBipProblemType_t additionalProblemInfo; /**<	bip specific problem info	*/
	unsigned char channelDataLen; /**<	channel data length	*/
} TelSatSendDataRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SETUP IDLE MODE TEXT proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
} TelSatSetupIdlemodeTextRespInfo_t;

/**
 * This structure contains the data objects for the Terminal Response of SEND DTMF proactive command.
 */
typedef struct {
	TelSatResultInfo_t result; /**<	result whether current proactive command request was executed successfully or not	*/
} TelSatSendDtmfRespInfo_t;

/**
 * This contains the data structures to be used to send proactive command response.
 */
typedef struct {
	unsigned char commandNumber; /**<	  proactive command number	*/
	TelSatCommandType_t commandType; /**<	  proactive command type	*/
	union {
		TelSatMoreTimeRespInfo_t moreTime;
		TelSatDisplayTextRespInfo_t displayText; /**<	terminal response info from displayText proactive command	*/
		TelSatGetInkeyRespInfo_t getInkey; /**<	terminal response info from getInkey proactive command	*/
		TelSatGetInputRespInfo_t getInput; /**<	terminal response info from getInput proactive command	*/
		TelSatPlayToneRespInfo_t playTone; /**<	terminal response info from playTone proactive command	*/
		TelSatSetupMenuRespInfo_t setupMenu; /**<	terminal response info from setupMenu proactive command	*/
		TelSatSelectItemRespInfo_t selectItem; /**<	terminal response info from selectItem proactive command	*/
		TelSatSendSmsRespInfo_t sendSms; /**<	terminal response info from sendSms proactive command	*/
		TelSatSendSsRespInfo_t sendSs; /**<	terminal response info from sendSs proactive command	*/
		TelSatSendUssdRespInfo_t sendUssd; /**<	terminal response info from sendUssd proactive command	*/
		TelSatSetupCallRespInfo_t setupCall; /**<	terminal response info from setupCall proactive command	*/
		TelSatRefreshRespInfo_t refresh; /**<	terminal response info from refresh proactive command	*/
		TelSatProvideLocalInfoRespInfo_t provideLocInfo; /**<	terminal response info from provide Local Info proactive command	*/
		TelSatLaunchBrowserRespInfo_t launchBrowser; /**<	terminal response info from launch Browser proactive command	*/
		TelSatSetupIdlemodeTextRespInfo_t idleText; /**<	terminal response info from setup idle mode text proactive command	*/
		TelSatSendDtmfRespInfo_t sendDtmf; /**<	terminal response info from send Dtmf proactive command	*/
		TelSatLanguageNotificationRespInfo_t languageNotification; /**<	terminal response info from language Notification proactive command	*/
		TelSatSetupEventListRespInfo_t setupEventList; /**<	terminal response info from setup Event List proactive command	*/
		TelSatOpenChannelRespInfo_t openChannel; /**<	terminal response info from openChannel proactive command	*/
	} terminalRespInfo; /**<	Union	*/
} TelSatRespInfo_t;

/*
 *SAT Icon Data
 */

typedef struct {
	unsigned char iconId;
	unsigned char imgType;
	unsigned char imgLen;
	unsigned char imgData[256];
} TelSatIconDataResp_t;

typedef struct {
	unsigned char iconId;
	unsigned char imgType;
	unsigned char fileId[2];
	unsigned char reqDataLen[2];
	unsigned char offset[2];
} TelsatIconDataGet_t;

#ifdef __cplusplus
}
#endif

#endif	/* _TEL_SAT_PROACTV_CMD_H_ */

/**
 * @}
 */
