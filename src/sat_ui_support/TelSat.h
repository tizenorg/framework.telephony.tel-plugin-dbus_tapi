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
* @file TelSat.h

     @brief This file serves as a "C" header file defines structures for Telephony SAT Services. \n
      It contains a sample set of constants, enums, structs that would be required by applications.


 */

#ifndef _TEL_SAT_H_
#define _TEL_SAT_H_

#include <TelDefines.h>
#include <TelCall.h>
#include <TelSs.h>
#include <TelSatObj.h>
#include <TelSatProactvCmd.h>
#include <TelSatEnvelope.h>
#include <TelSim.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define TAPI_SAT_DEF_TITLE_LEN_MAX			50 /**< max length for Menu Title */
#define TAPI_SAT_DEF_ITEM_STR_LEN_MAX		50 /**< max length for Menu Item  */
#define TAPI_SAT_DEF_TEXT_STRING_LEN_MAX	500 /**< max length for Text String  */
#define TAPI_SAT_DEF_BIT_MASK_CONTACT		0x01 /**< Bit Mask for Contact */
#define TAPI_SAT_DEF_BIT_MASK_MSG			0x02 /**< Bit Mask for Msg */
#define TAPI_SAT_DEF_BIT_MASK_OTHER			0x04 /**< Bit Mask for Psh */
#define TAPI_SAT_REFRESH_FILE_LIST			20 /**< Refresh File List*/
#define TAPI_SAT_DEF_SS_LEN_MAX             250
#define TAPI_SAT_DEF_USSD_LEN_MAX           250

//	Telephony UI USER CONFIRM TYPE
/**
 * @enum TelSatUiUserConfirmType_t
 * This enumeration defines the UI User Confirm Type.
 */
typedef enum
{
	TAPI_SAT_USER_CONFIRM_YES,						/**<This Enum Informs That user confirms yes */
	TAPI_SAT_USER_CONFIRM_NO_OR_CANCEL,				/**<This enum informs that user confirms no/cancel */
	TAPI_SAT_USER_CONFIRM_HELP_INFO,				/**<This enum informs that user wants help information */
	TAPI_SAT_USER_CONFIRM_END,						/**<This enum informs that user confirms end */
	TAPI_SAT_USER_CONFIRM_TIMEOUT,					/**<This enum informs that user did not respond */
}TelSatUiUserConfirmType_t;

//	Telephony UI INKEY TYPE
/**
 * @enum TelSatUiInkeyYesNoCaseType_t
 * This enumeration defines the UI Inkey Type Yes or No.
 */
typedef enum
{
	TAPI_SAT_INKEY_CONFIRM_NO				= 0x00,			/**<No*/
	TAPI_SAT_INKEY_CONFIRM_YES				= 0x01,			/**<Yes*/
}TelSatUiInkeyYesNoCaseType_t;

//	Telephony UI DISPLAY STATUS
/**
 * @enum TelSatUiDisplayStatusType_t
 * This enumeration defines the UI Display Status.
 */
typedef enum
{
	TAPI_SAT_DISPLAY_SUCCESS				= 0x00,					/**<This enum informs  UI display success*/
	TAPI_SAT_DISPLAY_FAIL					= 0x01,					/**<This enum informs  UI display failure*/
}TelSatUiDisplayStatusType_t;

//	TELEPHONY REFRESH APPLICATION TYPE
/**
 * @enum TelSatRefreshAppType_t
 * This enumeration defines the Refresh Application Type.
 */
 typedef enum
{
	TAPI_SAT_REFRESH_CONTACT = 0x00,				/**<refresh application type - Phonebook*/
	TAPI_SAT_REFRESH_MSG,							/**<refresh application type - SMS*/
	TAPI_SAT_REFRESH_OTHER,							/**<refresh application type - other*/
	TAPI_SAT_REFRESH_MAX,							/**<Maximum Enumeration Value*/
}TelSatRefreshAppType_t;

//	Telephony COMMAND PERFORMED RESULT
/**
 * @enum TelSatCommandPerformResultType_t
 * This enumeration defines the Result of Proactive Command execution.
 */
typedef enum
{
	TAPI_SAT_CMD_PERFORM_SUCCESS = 0x00,		/**<command performed successfully*/
	TAPI_SAT_CMD_PERFORM_FAIL,					/**<command execution failed*/
	TAPI_SAT_CMD_PERFORM_MAX,					/**<Maximum Enumeration Value*/
}TelSatCommandPerformResultType_t;

//	Telephony CALL CONTROL TYPE
/**
 * @enum TelSatCallCtrlType_t
 * This enumeration defines Call Control Type.
 */
typedef enum
{
	TAPI_SAT_CALL_CNF_NONE	= 0x00,		/**<call control confirm type - None*/
	TAPI_SAT_CALL_CNF_CALL,			/**<call control confirm type - call*/
	TAPI_SAT_CALL_CNF_SS,				/**<call control confirm type - ss*/
	TAPI_SAT_CALL_CNF_USSD,				/**<call control confirm type - ussd*/
	TAPI_SAT_CALL_CNF_MAX,				/**<Maximum Enumeration Value*/
}TelSatCallCtrlType_t;

//	SAT UI USER CONFIRMATION INFO
/**
 * This structure defines the user confirmation data.
 */
typedef struct
{
	int						commandId;				/**<Proactive Command Number sent by USIM*/
	TelSatCommandType_t		commandType;			/**<Proactive Command Type*/
	TelSatUiUserConfirmType_t	keyType;				/**<User Response Type*/
	unsigned char*				pAdditionalData;		/**<Additional Data*/
	int							dataLen;				/**<Additional Data Length*/
}TelSatUiUserConfirmInfo_t;

//	Telephony TEXT INFO
/**
 * This structure defines the character data for sat engine data structure.
 */
typedef struct
{
	unsigned short	stringLen;										/**<character data length*/
	unsigned char		string[TAPI_SAT_DEF_TEXT_STRING_LEN_MAX+1];		/**<character data*/
}TelSatTextInfo_t;

//	Telephony MAIN MENU TITLE INFO
/**
 * This structure defines the main menu title to check sat menu.
 */
typedef struct
{
	int				bIsMainMenuPresent;		/**<flag to check sat main menu existence*/
	TelSatTextInfo_t	mainMenuTitle;			/**<main menu title data*/
}TelSatMainMenuTitleInfo_t;

//	Telephony DISPLAY TEXT DATA
/**
 * This structure defines the display text proactive command for sat ui.
 */
typedef struct
{
	int							commandId;					/**<Proactive Command Number sent by USIM*/
	TelSatTextInfo_t				text;						/**<character data to display on screen*/
	unsigned int					duration;					/**<the duration of display */
	int							bIsPriorityHigh;			/**<indicates whether the text is to be displayed if some other app is using the screen.*/
	int							bIsUserRespRequired;		/**<indicates whether user response required or Not*/
	int							b_immediately_resp;
	TelSatIconIdentifierInfo_t	iconId;						/**< Icon Identifier */
}TelSatDisplayTextInd_t;

//	Telephony INKEY DATA
/**
 * This structure defines the get inkey proactive command data for sat ui.
 */
typedef struct
{
	int							commandId;				/**<Proactive Command Number sent by USIM*/
	TelSatInkeyType_t				keyType;				/**<input Type:Character Set or Yes/No*/
	TelSatUseInputAlphabetType_t	inputCharMode;			/**<input character mode(SMS default, UCS2)*/
	int							bIsNumeric;				/**<is input character numeric(0-9, *, # and +)*/
	int							bIsHelpInfoAvailable;	/**<help info request flag*/
	TelSatTextInfo_t				text;					/**<character data to display on screen*/
	unsigned int					duration;				/**<the duration of display*/
	TelSatIconIdentifierInfo_t		iconId;					/**<Icon Identifier*/
}TelSatGetInkeyInd_t;

//	Telephony GET INPUT DATA
/**
 * This structure defines the get input proactive command data for sat ui.
 */
typedef struct
{
	int							commandId;				/**<Proactive Command Number sent by USIM*/
	TelSatUseInputAlphabetType_t	inputCharMode;			/**<input character mode(SMS default, UCS2)*/
	int							bIsNumeric;				/**<is input character numeric(0-9, *, # and +)*/
	int							bIsHelpInfoAvailable;	/**<flag for help info request */
	int							bIsEchoInput;			/**<indicates whether to show input data on screen or not*/
	TelSatTextInfo_t				text;					/**<character data to display on screen*/
	TelSatRespLenInfo_t				respLen;				/**<input data min, max length*/
	TelSatTextInfo_t				defaultText;			/**<default input character data*/
	TelSatIconIdentifierInfo_t		iconId;					/**<Icon Identifier*/
}TelSatGetInputInd_t;

//	Telephony PLAY TONE DATA
/**
 * This structure defines the play tone proactive command data for application.
 */
typedef struct
{
	int						commandId;	/**<Proactive Command Number sent by USIM*/
	TelSatTextInfo_t			text;		/**<character data to display on screen*/
	TelSatToneInfo_t			tone;		/**<tone info	*/
	unsigned int				duration;	/**<the duration for playing tone*/
	TelSatIconIdentifierInfo_t	iconId;		/**<Icon Identifier*/
}TelSatPlayToneInd_t;

//	Telephony UI info
/**
 * This structure defines the data for sat ui.
 */
typedef struct
{
	int						commandId;		/**<Proactive Command Number sent by USIM*/
	int						user_confirm;
	TelSatTextInfo_t			text;			/**<character data to display on screen*/
	TelSatIconIdentifierInfo_t	iconId;			/**<Icon Identifier*/
}TelSatSendUiInfo_t;

//	Telephony MENU ITEM DATA FOR SETUP MENU
/**
 * This structure defines the menu item info for setup menu.
 */
typedef struct
{
	char itemString[TAPI_SAT_DEF_ITEM_STR_LEN_MAX + 6];	/**<menu item character data*/
	char itemId;											/**<identifies the item on the menu that user selected*/
}TelSatMenuInfo_t;

//	Telephony SETUP MENU INFO
/**
 * This structure defines the sat main menu info.
 */
typedef struct
{
	int commandId;	/**<Proactive Command Number sent by USIM*/
	int	bIsMainMenuPresent;
	char satMainTitle[TAPI_SAT_DEF_TITLE_LEN_MAX + 1];	/**<menu title text*/
	TelSatMenuInfo_t satMainMenuItem[TAPI_SAT_MENU_ITEM_COUNT_MAX];	/**< menu items*/
	unsigned short satMainMenuNum;	/**<number of menu items*/
	int	bIsSatMainMenuHelpInfo;	/**<flag for help information request */
	int	bIsUpdatedSatMainMenu;
	TelSatIconIdentifierInfo_t iconId;	/**<Icon Identifier*/
	TelSatIconIdentifierListInfo_t iconIdList;	/**<List of Icon Identifiers*/
}TelSatSetupMenuInfo_t;

//	Telephony SELECT ITEM DATA
/**
 * This structure defines the select item proactive command data for sat ui.
 */
typedef struct
{
	int							commandId;									/**<Proactive Command Number sent by USIM*/
	int							bIsHelpInfoAvailable;						/**<flag for help information request*/
	TelSatTextInfo_t				text;										/**<menu title text*/
	char							defaultItemIndex;							/**<selected default item - default value is 0*/
	char							menuItemCount;								/**<number of menu items*/
	TelSatMenuItemInfo_t			menuItem[TAPI_SAT_MENU_ITEM_COUNT_MAX];		/**<menu items*/
	TelSatIconIdentifierInfo_t		iconId;										/**<Icon Identifier*/
	TelSatIconIdentifierListInfo_t	iconIdList;									/**<List of Icon Identifiers*/

}TelSatSelectItemInd_t;

//	Telephony IDLE MODE TEXT DATA
/**
 * This structure defines the setup idle mode text proactive command for idle application.
 */
typedef struct
{
	int						commandId;			/**<Proactive Command Number sent by USIM*/
	TelSatTextInfo_t			text;				/**<character data to display on screen*/
	TelSatIconIdentifierInfo_t	iconId;
} TelSatSetupIdleModeTextInd_t;

//	Telephony REFRESH DATA
/**
 * This structure defines the refresh proactive command data for sat ui.
 */
typedef struct
{
	int							commandId;			/**<Proactive Command Number sent by USIM*/
	unsigned int				duration;			/**<the duration of display*/
	TelSatCmdQualiRefresh_t		refreshType;		/**<refresh mode*/
}TelSatRefreshIndUiInfo_t;

//	Telephony REFRESH DATA
/**
 * This structure defines the refresh proactive command data for applications which are concerned with files resident on USIM .
 */
typedef struct
{
	int						commandId;								/**<Proactive Command Number sent by USIM*/
	TelSatRefreshAppType_t		appType;								/**<concerned application type */
	TelSatCmdQualiRefresh_t		refreshMode;							/**<refresh mode*/
	unsigned char					fileCount;								/**<refresh file count*/
	TelSimFileID_t				fileId[TAPI_SAT_REFRESH_FILE_LIST];		/**<refresh file identifier*/
}TelSatRefreshInd_t;

//	Telephony END PROACTIVE COMMAND INFO
/**
 * This structure defines the data objects to indicate to sat ui, the end of execution of a specific proactive command by other application.
 */
typedef struct
{
	int									commandId;			/**<Proactive Command Number sent by USIM*/
	char									commandType;		/**< Command Type*/
	TelSatCommandPerformResultType_t		result;				/**<result of command execution by application*/
}TelSatProactiveCmdEndIndInfo_t;

//	Telephony SEND SMS DATA
/**
 * This structure defines the send sms proactive command data for sms application.
 */
typedef struct
{
	int					commandId;				/**<Proactive Command Number sent by USIM*/
	int					bIsPackingRequired;		/**<flag to check if packing required for sms tpdu*/
	TelSatAddressInfo_t	address;				/**<destination address*/
	TelSatSmsTpduInfo_t	smsTpdu;				/**<SMS TPDU data*/
} TelSatSendSmsIndSmsData_t;

//	Telephony SEND SS DATA
/**
 * This structure defines the send ss proactive command data for ss application.
 */
typedef struct
{
	int					commandId;		/**<Proactive Command Number sent by USIM*/
	TelSimTypeOfNum_t ton; /**<	type of number 		*/
	TelSimNumberingPlanIdentity_t npi; /**<	number plan identity 		*/
	unsigned short		ssStringLen;
	unsigned char		ssString[TAPI_SAT_DEF_SS_LEN_MAX+1];
}TelSatSendSsIndSsData_t;

//	Telephony USSD DATA
/**
 * This structure defines the send ussd proactive command data for ussd application.
 */
typedef struct
{
	int			commandId;		/**<Proactive Command Number sent by USIM*/
	unsigned char		rawDcs;			/**<data coding scheme*/
	unsigned short		ussdStringLen;
	unsigned char		ussdString[TAPI_SAT_DEF_USSD_LEN_MAX+1];
}TelSatSendUssdIndUssdData_t;

//	Telephony SEND DTMF DATA
/**
 * This structure defines the send dtmf proactive command data for dtmf application.
 */
typedef struct
{
	int					commandId;			/**<Proactive Command Number sent by USIM*/
	int					bIsHiddenMode;		/**<hidden mode flag*/
	TelSatTextInfo_t		dtmfString;			/**<dtmf string data*/
}TelSatSendDtmfIndDtmfData_t;

//	Telephony SETUP CALL  DATA
/**
 * This structure defines the setup call proactive command data for call application.
 */
typedef struct
{
	int							commandId;		/**<Proactive Command Number sent by USIM*/
	TelSatCmdQualiSetupCall_t		calltype;			/**<call type*/
	TelSatTextInfo_t				dispText;			/**<display data for calling*/
	TelSatTextInfo_t				callNumber;		/**<call number*/
	unsigned int					duration;			/**<maximum repeat duration*/
	TelSatIconIdentifierInfo_t		iconId;			/**<icon identifier for call application*/
}TelSatSetupCallIndCallData_t;

//	Telephony LAUNCH BROWSER DATA
/**
 * This structure defines the launch browser proactive command data for browser application.
 */
typedef struct
{
	int							commandId;		/**<Proactive Command Number sent by USIM*/
	TelSatUrlInfo_t					url;			/**<url to connect*/
	TelSatCmdQualiLaunchBrowser_t	launchType;		/**<launch type*/
	TelSatBrowserIdentityType_t	IdentityType;	/**<Browser Identity -default, html, etc*/
}TelSatLaunchBrowserIndBrowserData_t;

//	Telephony PROVIDE LOCAL INFO DATA
/**
 * This structure defines the provide local info proactive command data for application.
 */
typedef struct
{
	int commandId;										/**<Proactive Command Number sent by USIM*/
	TelSatCmdQualiProvideLocalInfo_t localInfoType;		/**<Provide Local Information Type*/
}TelSatProvideLocalInfoInd_t;

//	Telephony LANGUAGE NOTIFICATION DATA
/**
 * This structure defines the language notification proactive command data for application.
 */
typedef struct
{
	int							commandId;						/**<Proactive Command Number sent by USIM*/
	int							bSpecificLanguageNotification;  /**<flag for checking specific language notification. if FALSE, non-specific language notification	*/
	TelSatLanguageInfo_t			language;					/**<language info from USIM application	*/
}TelSatLanguageNotiInfoInd_t;

//	Telephony PLAY TONE RETURN INFO
/**
 * This structure defines the return result data for Play Tone proactive command.
 */
typedef struct
{
	TelSatResultType_t	resp;			/**<result response value*/
}TelSatSetupMenuRetInfo_t;

//	Telephony REFRESH RETURN INFO
/**
 * This structure defines the return result data for refresh proactive command.
 */
typedef struct
{
	TelSatRefreshAppType_t	appType;			/**<application type*/
	TelSatResultType_t		resp;				/**<result response value*/
}TelSatRefreshRetInfo_t;

//	Telephony CALL RETURN INFO
/**
 * This structure defines the return result data for setup call proactive command.
 */
typedef struct
{
	TelSatResultType_t				resp;							/**<result response value*/
	int							bIsTapiCauseExist;				/**<flag for checking tapi error cause */
	TelCallCause_t					tapiCause;						/**<tapi call error cause*/
	TelSsCause_t						ssCause;						/**<tapi ss error cause*/
	TelSatMeProblemType_t				meProblem;						/**<me problem error cause*/
	int								bIsOtherInfoExist;				/**<call control result existence flag*/
	TelSatCallCtrlProblemType_t		permanentCallCtrlProblem;		/**<call control problem type*/
	TelSatCallCtrlRequestedActionInfo_t	callCtrlRequestedAction;		/**<call control request data*/
	TelSatResultInfo_t			result2;						/**<call control envelope result value*/
	TelSatTextTypeInfo_t			text;							/**<call control envelope display data*/
}TelSatCallRetInfo_t;

//	Telephony SS RETURN INFO
/**
 * This structure defines the return result data for send ss proactive command.
 */
typedef struct
{
	TelSatResultType_t				resp;							/**<result response value*/
	TelSsCause_t						ssCause;						/**<error - ss cause*/
	TelSatTextInfo_t					ssString;						/**<ss result string*/
	TelSatMeProblemType_t			meProblem;						/**<error - me problem*/
	int								bIsOtherInfoExist;				/**<call control result exist flag*/
	TelSatCallCtrlProblemType_t			additionalCallCtrlProblemInfo;	/**<call control problem*/
	TelSatCallCtrlRequestedActionInfo_t	callCtrlRequestedAction;		/**<call control request data*/
	TelSatResultInfo_t					result2;						/**<call control envelope result value*/
}TelSatSsRetInfo_t;

//	Telephony USSD RETURN INFO
/**
 * This structure defines the return result data for send ussd proactive command.
 */
typedef struct
{
	TelSatResultType_t					resp;							/**<result response value*/
	TelSsCause_t						ssCause;						/**<error - ss cause*/
	TelSatTextInfo_t					ussdString;						/**<ussd result string*/
	TelSatDataCodingSchemeInfo_t		dcsUssdString;					/**<dcs of ussd result string */
	TelSatMeProblemType_t				meProblem;						/**<error - me problem*/
	int								bIsOtherInfoExist;				/**<call control result exist flag*/
	TelSatCallCtrlProblemType_t			additionalCallCtrlProblemInfo;	/**<call control problem*/
	int								bCallCtrlHasModification;		/**<call control request modification flag*/
	TelSatCallCtrlRequestedActionInfo_t	callCtrlRequestedAction;		/**<call control request data*/
	TelSatResultInfo_t					result2;						/**<call control envelope result value*/
	TelSatTextTypeInfo_t				text2;							/**<cc envelope display data */
}TelSatUssdRetInfo_t;

//	Telephony SMS RETURN INFO
/**
 * This structure defines the return result data for send sms proactive command.
 */
typedef struct
{
	TelSatResultType_t	resp;			/**<result response value*/
}TelSatSmsRetInfo_t;

//	Telephony DTMF RETUEN INFO
/**
 * This structure defines the return result data for send dtmf proactive command.
 */
typedef struct
{
	TelSatResultType_t	resp;			/**<result response value*/
}TelSatDtmfRetInfo_t;

//	Telephony BROWSER RETURN INFO
/**
 * This structure defines the return result data for launch browser proactive command.
 */
typedef struct
{
	TelSatResultType_t					resp;			/**<result response value*/
	TelSatLaunchBrowserProblemType_t    browserProblem;	/**<specific browser problem*/
}TelSatBrowserRetInfo_t;

//	Telephony SETUP IDLE MODE TEXT RETURN INFO
/**
 * This structure defines the return result data for setup idle mode text proactive command.
 */
typedef struct
{
	TelSatResultType_t	resp;			/**<result response value*/
}TelSatIdleTextRetInfo_t;

//	Telephony PLAY TONE RETURN INFO
/**
 * This structure defines the return result data for Play Tone proactive command.
 */
typedef struct
{
	TelSatResultType_t	resp;			/**<result response value*/
}TelSatPlayToneRetInfo_t;

//	Telephony  PROVIDE LOCAL INFO RETURN INFO
/**
 * This structure defines the return result data for setup idle mode text proactive command.
 */
typedef struct
{
	TelSatResultType_t					resp;			/**<result response value*/
	int								bOtherInfo;		/**<flag to check whether other information are required or not	*/
	TelSatCmdQualiProvideLocalInfo_t	infoType;		/**<local info type - e.g. time zone or language info, etc	*/
	union
	{
		TelSatDataTimeZoneInfo_t		timeZoneInfo;	/**<	current time zone info	*/
		TelSatLanguageInfo_t			languageInfo;	/**<	current ME language setting info	*/
	}u;													/**<	Union*/
}TelSatProvideLocalRetInfo_t;

//	Telephony LANGUAGE NOTI RETURN INFO
/**
 * This structure defines the return result data for setup idle mode text proactive command.
 */
typedef struct
	{
		TelSatResultType_t		 resp;				/**<result response value*/
	}TelSatLanguageNotiRetInfo_t;

//	Telephony DISPLAY TEXT RETURN INFO
/**
 * This structure defines the return result data for setup idle mode text proactive command.
 */
typedef struct
	{
		TelSatResultType_t		 resp;				/**<result response value*/
		TelSatMeProblemType_t	 meProblem;			/**<Me Problem Type */
	}TelSatDiplayTextRetInfo_t;

//	Telephony APPLICATIONS RETURN DATA
/**
 * This structure defines the common return result data for applications proactive command.
 */
typedef struct
{
	TelSatCommandType_t	commandType;						/**<Proactive Command type*/
	int commandId;											/**<Proactive Command Number sent by USIM*/
	union
		{
			TelSatSetupMenuRetInfo_t	setupMenu;			/**<result response value for setup menu*/
			TelSatRefreshRetInfo_t		refresh;				/**<result response value for refresh*/
			TelSatCallRetInfo_t			setupCall;				/**<result response value for setup call*/
			TelSatSsRetInfo_t			sendSs;					/**<result response value for send ss*/
			TelSatUssdRetInfo_t			sendUssd;				/**<result response value for send ussd*/
			TelSatSmsRetInfo_t			sendSms;				/**<result response value for send sms*/
			TelSatDtmfRetInfo_t			sendDtmf;				/**<result response value for send dtmf*/
			TelSatBrowserRetInfo_t		launchBrowser;			/**<result response value for launch browser*/
			TelSatIdleTextRetInfo_t		setupIdleModeText;		/**<result response value for setup idle mode text*/
			TelSatLanguageNotiRetInfo_t	languageNoti;			/**<result response value for language notification*/
			TelSatProvideLocalRetInfo_t provideLocalInfo;		/**<result response value for provide local info*/
			TelSatDiplayTextRetInfo_t   displayText;			/**<result response value for dsiplay text*/
			TelSatPlayToneRetInfo_t     playTone;				/**<result response value for play tone*/
		}appsRet;												/**< common union result value */
}TelSatAppsRetInfo_t;

//	Telephony CALL CONTROL CONFIRM  DATA FOR CALL
/**
 * This structure defines the call control confirm data for call.
 */
typedef struct
{
	TelSatTextInfo_t				address;					/**< call destination address*/
	TelSatTextInfo_t				subAddress;					/**< call SUB address*/
	TelSatBcRepeatIndicatorType_t	bcRepeatIndicator;			/**< bc repeat indicator*/
	TelSatTextInfo_t				ccp1;						/**< Configuration Capability Parameter 1*/
	TelSatTextInfo_t				ccp2;						/**< Configuration Capability Parameter 2*/
} TelSatCallCtrlIndCallData_t;

//	Telephony CALL CONTROL CONFIRM  DATA FOR SS
/**
 * This structure defines the call control confirm data for ss.
 */
typedef struct
{
	TelSatTextInfo_t				ssString;					/**< ss destination address*/
	TelSatTextInfo_t				subAddress;					/**< call SUB address*/
	TelSatBcRepeatIndicatorType_t	bcRepeatIndicator;			/**< bc repeat indicator*/
	TelSatTextInfo_t				ccp1;						/**< Configuration Capability Parameter 1*/
	TelSatTextInfo_t				ccp2;						/**< Configuration Capability Parameter 2*/
} TelSatCallCtrlIndSsData_t;

//	Telephony CALL CONTROL CONFIRM  DATA FOR USSD
/**
 * This structure defines the call control confirm data for ussd.
 */
typedef struct
{
	TelSatTextInfo_t		ussdString;			/**< ussd destination address*/
} TelSatCallCtrlIndUssdData_t;

//	Telephony READ FILE REQUEST DATA
/**
 * This structure defines the common call control confirm data.
 */
typedef struct
{
	TelSatCallType_t			callCtrlCnfType;				/**<call control confirm type - call, ss or ussd*/
	TelSatCallCtrlResultType_t	callCtrlResult;					/**<call control result*/
	TelSatTextInfo_t			dispData;						/**<call control display data*/
	int						bIsUserInfoDisplayEnabled;		/**<flag for checking existence of call control display */

	union
		{
			TelSatCallCtrlIndCallData_t		callCtrlCnfCallData;	/**<call control call address*/
			TelSatCallCtrlIndSsData_t		callCtrlCnfSsData;		/**<call control ss string*/
			TelSatCallCtrlIndUssdData_t		callCtrlCnfUssdData;	/**<call control ussd string*/
		}u;																/**<   Union*/
} TelSatCallCtrlIndData_t;

//	Telephony MO SMS CONTROL CONFIRMATION DATA
/**
 * This structure defines the mo sms control confirm data.
 */
typedef struct
{
	TelSatCallCtrlResultType_t		moSmsCtrlResult;			/**<envelope result*/
	int								bIsUserInfoDisplayEnabled;	/**<display present flag*/
	TelSatTextTypeInfo_t			dispData;					/**<display data for sending SMS*/
	TelSatTextTypeInfo_t			rpDestAddr;				/**<the RP_Destination_Address of the Service Center */
	TelSatTextTypeInfo_t			tpDestAddr;					/**<the TP_Destination_Address */
} TelSatMoSmCtrlIndData_t;

//	Telephony EVENT LIST INFO
/**
 * This structure defines the Event List Info.
 */
typedef struct
{
	int bIsEventDownloadActive;			/**<Is Event Download Active*/
	int bIsMtCallEvent;					/**<Is Mt Call Event*/
	int bIsCallConnected;				/**<Is Call Connected*/
	int bIsCallDisconnected;			/**<Is Call Disconnected*/
	int bIsLocationStatus;				/**<Is Location Status*/
	int bIsUserActivity;				/**<Is User Activity*/
	int bIsIdleScreenAvailable;			/**<Is Idle Screen Available*/
	int bIsCardReaderStatus;			/**<Is Card Reader Status*/
	int bIsLanguageSelection;			/**<Is Language Selection*/
	int bIsBrowserTermination;			/**<Is Browser Termination*/
	int bIsDataAvailable;				/**<Is Data Available*/
	int bIsChannelStatus;				/**<Is Channel Status*/
}	TelSatEventListData_t;

/**
 * This is the structure to be used by the Application to send envelope/event download data.
 * This contains the data structures to be used to send any envelope/event download data.
 */
typedef struct
{
	TelSatEventDownloadType_t					eventDownloadType;				/**<	eventDownload Type	*/

	union
	{
		int									bIdleScreenAvailable;			/**<flag to specify whether Idle Screen is Available or not*/
		TelSatLanguageSelectionEventReqInfo_t	languageSelectionEventReqInfo;	/**<Selected Language Information*/
		TelSatBrowserTerminationEventReqInfo_t	browserTerminationEventReqInfo;	/**<BrowserTermination Event Information	*/
		TelSatDataAvailableEventReqInfo_t		dataAvailableEventReqInfo;		/**<dataAvailableEventReqInfo	*/
		TelSatChannelStatusEventReqInfo_t		channelStatusEventReqInfo;		/**<channelStatusEventReqInfo	*/
	} u;																		/**<Union*/
} TelSatEventDownloadReqInfo_t;

#ifdef __cplusplus
}
#endif

#endif /* _TEL_SAT_H_ */

/**
* @}
*/
