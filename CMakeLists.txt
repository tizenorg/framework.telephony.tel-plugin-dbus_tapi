CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(dbus-tapi-plugin C)

### Global setting ###
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")
SET(PKGCONFIGDIR "${PREFIX}/lib/pkgconfig" CACHE PATH PKGCONFIGDIR)
SET(CMAKE_INSTALL_PREFIX "${PREFIX}")

# Set required packages
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED glib-2.0 gobject-2.0 gio-2.0 gio-unix-2.0 tcore dlog aul appsvc security-server)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)


INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include/ ${CMAKE_SOURCE_DIR}/cmake_tmp ${CMAKE_SOURCE_DIR}/src/sat_ui_support/)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wdeclaration-after-statement -Wmissing-declarations -Wcast-align")

ADD_DEFINITIONS("-DFEATURE_DLOG_DEBUG")
ADD_DEFINITIONS("-DTCORE_LOG_TAG=\"DBUS_TAPI\"")
ADD_DEFINITIONS("-DPLUGIN_VERSION=${VERSION}")

MESSAGE(${CMAKE_C_FLAGS})
MESSAGE(${CMAKE_EXE_LINKER_FLAGS})

SET(SRCS
		src/desc-dbus.c
		src/common.c
		src/network.c
		src/phonebook.c
		src/sim.c
		src/sap.c
		src/sms.c
		src/sat.c
		src/sat_manager.c
		src/sat_ui_support/sat_ui_support.c
		src/ss.c
		src/call.c
		src/modem.c
		src/gps.c
)

ADD_CUSTOM_COMMAND(
	OUTPUT ${CMAKE_BINARY_DIR}/generated-code.c
	COMMAND gdbus-codegen --interface-prefix org.tizen.telephony. --generate-c-code generated-code --c-namespace Telephony --c-generate-object-manager --generate-docbook generated-docs ${CMAKE_SOURCE_DIR}/introspection/manager.xml ${CMAKE_SOURCE_DIR}/introspection/network.xml ${CMAKE_SOURCE_DIR}/introspection/sim.xml ${CMAKE_SOURCE_DIR}/introspection/phonebook.xml ${CMAKE_SOURCE_DIR}/introspection/sap.xml ${CMAKE_SOURCE_DIR}/introspection/sat.xml ${CMAKE_SOURCE_DIR}/introspection/sms.xml ${CMAKE_SOURCE_DIR}/introspection/call.xml ${CMAKE_SOURCE_DIR}/introspection/ss.xml ${CMAKE_SOURCE_DIR}/introspection/modem.xml ${CMAKE_SOURCE_DIR}/introspection/gps.xml
	COMMENT "Generating GDBus .c/.h")

# library build
ADD_LIBRARY(dbus-tapi-plugin SHARED ${SRCS}
	${CMAKE_BINARY_DIR}/generated-code.c)
TARGET_LINK_LIBRARIES(dbus-tapi-plugin ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(dbus-tapi-plugin PROPERTIES PREFIX "" OUTPUT_NAME dbus-tapi-plugin)
ADD_DEPENDENCIES(dbus-tapi-plugin XXX)


# install
INSTALL(FILES ${CMAKE_SOURCE_DIR}/res/tapi.conf DESTINATION ${PREFIX}/etc/dbus-1/system.d)
INSTALL(TARGETS dbus-tapi-plugin
		LIBRARY DESTINATION lib/telephony/plugins)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION /usr/share/license RENAME tel-plugin-dbus_tapi)
