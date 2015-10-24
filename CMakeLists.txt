CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(dbus-tapi-plugin C)

### Global setting ###
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")
SET(PKGCONFIGDIR "${PREFIX}/lib/pkgconfig" CACHE PATH PKGCONFIGDIR)
SET(CMAKE_INSTALL_PREFIX "${PREFIX}")
SET(INTROSPECTION "${CMAKE_SOURCE_DIR}/introspection")

# Set required packages
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED
	glib-2.0
	gio-2.0
	gio-unix-2.0
	libxml-2.0
	tcore
	aul
	appsvc
	capi-appfw-app-manager
	security-server
)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)


INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include/ ${CMAKE_SOURCE_DIR}/src/sat_ui_support/)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wextra -fvisibility=hidden -fPIC -fdata-sections -ffunction-sections -Wl,--gc-sections")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -O2 -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wdeclaration-after-statement -Wmissing-declarations -Wall -Wno-array-bounds -Wno-empty-body -Wno-ignored-qualifiers -Wswitch-default -Wno-unused-but-set-parameter -Wno-unused-but-set-variable")

ADD_DEFINITIONS("-DENABLE_KPI_LOGS")
ADD_DEFINITIONS("-DGCF")
ADD_DEFINITIONS("-DFEATURE_TLOG_DEBUG")
ADD_DEFINITIONS("-DTCORE_LOG_TAG=\"DBUS\"")
ADD_DEFINITIONS("-DPLUGIN_VERSION=${VERSION}")
ADD_DEFINITIONS("-DEXPORT_API=__attribute__((visibility(\"default\")))")
#ADD_DEFINITIONS("-DTIZEN_USE_DESKTOP_FILE")
#ADD_DEFINITIONS("-DTIZEN_SUPPORT_SAT_ICON")

IF (BOARD_PLATFORM_QCOM)
ADD_DEFINITIONS("-DTIZEN_PLATFORM_USE_QCOM_QMI")
ENDIF (BOARD_PLATFORM_QCOM)

MESSAGE(${CMAKE_C_FLAGS})
MESSAGE(${pkgs_LDFLAGS})

SET(SRCS
	src/desc-dtapi.c
	src/dtapi_main.c
	src/dtapi_common.c
	src/dtapi_network.c
	src/dtapi_phonebook.c
	src/dtapi_sim.c
	src/dtapi_sap.c
	src/dtapi_sms.c
	src/dtapi_sat.c
	src/dtapi_sat_manager.c
	src/sat_ui_support/sat_ui_support.c
	src/dtapi_ss.c
	src/dtapi_call.c
	src/dtapi_modem.c
	src/dtapi_oem.c
)

ADD_CUSTOM_COMMAND(
	WORKING_DIRECTORY
	OUTPUT ${CMAKE_BINARY_DIR}/generated-code.c
	COMMAND gdbus-codegen --interface-prefix org.tizen.telephony. --generate-c-code generated-code --c-namespace Telephony --c-generate-object-manager --generate-docbook generated-docs
	${INTROSPECTION}/manager.xml
	${INTROSPECTION}/network.xml
	${INTROSPECTION}/sim.xml
	${INTROSPECTION}/phonebook.xml
	${INTROSPECTION}/sap.xml
	${INTROSPECTION}/sat.xml
	${INTROSPECTION}/sms.xml
	${INTROSPECTION}/call.xml
	${INTROSPECTION}/ss.xml
	${INTROSPECTION}/modem.xml
	${INTROSPECTION}/oem.xml
	COMMENT "Generating GDBus .c/.h")

# library build
ADD_LIBRARY(dbus-tapi-plugin SHARED ${SRCS} ${CMAKE_BINARY_DIR}/generated-code.c)
TARGET_LINK_LIBRARIES(dbus-tapi-plugin ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(dbus-tapi-plugin PROPERTIES PREFIX "" OUTPUT_NAME dbus-tapi-plugin)

# install
INSTALL(TARGETS dbus-tapi-plugin
		LIBRARY DESTINATION lib/telephony/plugins)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION /usr/share/license RENAME tel-plugin-dbus_tapi)
