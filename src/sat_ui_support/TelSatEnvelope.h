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
* @file TelSatEnvelope.h

     @brief This file serves as a "C" header file defines structures for Tapi Sat envelope command Services. \n
      It contains a sample set of constants, enums, structs that would be required by applications.
 */

#ifndef _TEL_SAT_ENVELOPE_H_
#define _TEL_SAT_ENVELOPE_H_

#include <TelSatObj.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @enum TelSatCallType_t
 * This enum indicates the SAT call type
 */
typedef enum
{
	TAPI_SAT_CALL_TYPE_MO_VOICE = 0X00,	/**<	call type -  mo voice	*/
	TAPI_SAT_CALL_TYPE_MO_SMS,			/**<	call type - mo sms	*/
	TAPI_SAT_CALL_TYPE_SS,				/**<	call type -  ss	*/
	TAPI_SAT_CALL_TYPE_USSD,			/**<	call type -  ussd	*/
	TAPI_SAT_PDP_CNTXT_ACT,				/**<	call type -  pdp context action	*/
	TAPI_SAT_CALL_TYPE_MAX				/**<	call type -  max	*/
}TelSatCallType_t;

/**
 * @enum TelSatCallCtrlResultType_t
 * This enum indicates the result of call control by SIM.
 */
typedef enum
{
	TAPI_SAT_CALL_CTRL_R_ALLOWED_NO_MOD			= 0,		/**<	call control result type -  ALLOWED WITH NO MOD	*/
	TAPI_SAT_CALL_CTRL_R_NOT_ALLOWED			= 1,		/**<	call control result type -  NOT ALLOWED	*/
	TAPI_SAT_CALL_CTRL_R_ALLOWED_WITH_MOD		= 2,		/**<	call control result type -  ALLOWED WITH MOD	*/
	TAPI_SAT_CALL_CTRL_R_RESERVED				= 0xFF		/**<	call control result type -  RESERVED	*/

} TelSatCallCtrlResultType_t;

/**
 * @enum TelSatEnvelopeResp_t
 * This enum indicates the general result of sending an envelope command to USIM.
 */
typedef enum
{
	TAPI_SAT_ENVELOPE_SUCCESS,	/**<	envelope result - success	*/
	TAPI_SAT_ENVELOPE_SIM_BUSY,	/**<	envelope result - USIM busy	*/
	TAPI_SAT_ENVELOPE_FAILED	/**<	envelope result - failed	*/

}TelSatEnvelopeResp_t;

//	8.	MENU SELECTION
/**
 * This structure contains the data objects for MENU SELECTION envelope.
 */
typedef struct
{
	unsigned char		itemIdentifier;		/**<	menu selection item identifier	*/
	int				bIsHelpRequested;	/**<	flag to check whether help information required or not	*/
} TelSatMenuSelectionReqInfo_t;

//	9.1 CALL CONTROL BY SIM
/**
 * This struct contains the data objects for Call Control result data sent by USIM.
 */
typedef struct
{
	TelSatAddressInfo_t				address;			/**<	call number	*/
	TelSatSubAddressInfo_t			subAddress;			/**<	call number sub address	*/
	TelSatBcRepeatIndicatorType_t	bcRepeatIndicator;	/**<	bc repeat indicator */
	TelSatCapaConfigParamInfo_t		ccp1;				/**<	capability configuration parameter1	*/
	TelSatCapaConfigParamInfo_t		ccp2;				/**<	capability configuration parameter2	*/
}TelSatVoiceCallCtrlIndInfo_t;

/**
 * This struct contains SAT ss control result data sent by USIM.
 */
typedef struct
{
	TelSatSsStringInfo_t			ssString;			/**<	ss number	*/
	TelSatSubAddressInfo_t			subAddress;			/**<	ss sub address */
	TelSatBcRepeatIndicatorType_t	bcRepeatIndicator;	/**<	bc repeat indicator	*/
	TelSatCapaConfigParamInfo_t		ccp1;				/**<	capability configuration parameter1	*/
	TelSatCapaConfigParamInfo_t		ccp2;				/**<	capability configuration parameter2	*/
}TelSatSsCtrlIndInfo_t;

/**
 * This struct contains SAT mo SMS control configuration data
 */
typedef struct
{
	TelSatAddressInfo_t		rpDestAddress;	/**<	sms control rp destination address	*/
	TelSatAddressInfo_t		tpDestAddress;	/**<	sms control tp destination address	*/
} TelSatMoSmsCtrlIndInfo_t;

/**
 * This struct contains SAT call control configuration data
 */
typedef struct
{
	TelSatCallType_t					callType;		/**<	call type	*/
	TelSatCallCtrlResultType_t			callCtrlResult;	/**<	call control result	*/
	TelSatAlphaIdentifierInfo_t			alphaIdentifier;/**<	alpha identifier	*/
	unsigned char						callId;			/**<	call id	*/
	TelSatCallType_t					oldCallType;	/**<	old call type	*/
	union
	{
		TelSatVoiceCallCtrlIndInfo_t	voiceCallData;	/**<	voice call control data	*/
		TelSatSsCtrlIndInfo_t			ssData;			/**<	ss control data	*/
		TelSatMoSmsCtrlIndInfo_t		smsData;
	}u;													/**<	Union		*/
} TelSatCallCtrlIndInfo_t;

//	9.2 MO SHORT MESSAGE CONTROL BY SIM RESULT
/**
 * This struct contains SAT mo ss control request data
 */
 typedef struct
{
	TelSatCallCtrlResultType_t		callCtrlResult;		/**<	call control result	*/
	TelSatAlphaIdentifierInfo_t		alphaIdentifier;	/**<	alpha identifier	*/
	TelSatMoSmsCtrlIndInfo_t		smsData;			/**<	sms control data	*/
}TelSatMoSMCtrlResult_t;

//	11.5 EVENT DOWNLOAD - USER ACTIVITY EVENT
/**
 * This struct contains SAT user activity event request data
 */
typedef struct
{
	TelSatEventListInfo_t				eventList;			/**<	event List	*/
	TelSatDeviceIdentitiesInfo_t		deviceIdentities;	/**<	device identities info	*/

} TelSatUserActivityEventReqInfo_t;

//	11.6 EVENT DOWNLOAD - IDLE SCREEN AVAILABLE EVENT
/**
 * This structure contains the data objects for IDLE SCREEN AVAILABLE event download.
 */
typedef struct
{
	TelSatEventDownloadType_t	eventData;	/**<	event type	*/
} TelSatIdleScreenAvailableEventReqInfo_t;

//	11.8 EVENT DOWNLOAD - LANGUAGE SELECTION EVENT
/**
 * This structure contains the data objects for LANGUAGE SELECTION event download.
 */
typedef struct
{
	TelSatLanguageType_t	 language;		/**<	selected language info	*/
} TelSatLanguageSelectionEventReqInfo_t;

//	11.9 EVENT DOWNLOAD - BROWSER TERMINATION EVENT
/**
 * This structure contains the data objects for BROWSER TERMINATION event download.
 */
typedef struct
{
	TelSatBrowserTerminationCauseType_t		browserTerminationCause;	/**<	browser Termination Cause	*/
} TelSatBrowserTerminationEventReqInfo_t;

//	11.10 EVENT DOWNLOAD - DATA AVAILABLE EVENT
/**
 * This struct contains SAT data available event request data
 */
typedef struct
{
	TelSatEventListInfo_t			eventList;			/**<	event List	*/
	TelSatDeviceIdentitiesInfo_t	deviceIdentities;	/**<	device identities info	*/
	TelSatChannelStatusInfo_t		channelStatus;		/**<	channel status	*/
	TelSatChannelDataLengthInfo_t	channelDataLen;		/**<	channel data length	*/

} TelSatDataAvailableEventReqInfo_t;

//	11.11 EVENT DOWNLOAD - CHANNEL STATUS EVENT
/**
 * This struct contains SAT channel status even request data
 */
typedef struct
{
	TelSatEventListInfo_t			eventList;			/**<	event list	*/
	TelSatDeviceIdentitiesInfo_t	deviceIdentities;	/**<	device identities info	*/
	TelSatChannelStatusInfo_t		channelStatus;		/**<	channel Status	*/
} TelSatChannelStatusEventReqInfo_t;

#ifdef __cplusplus
}
#endif

#endif	/* _TEL_SAT_ENVELOPE_H_ */

/**
 * @}
 */
