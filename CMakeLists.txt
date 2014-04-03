cmake_minimum_required (VERSION 2.8)
project                (libevhtp)

INCLUDE (CheckFunctionExists)
INCLUDE (CheckIncludeFiles)
INCLUDE (CheckTypeSize)

CHECK_FUNCTION_EXISTS(alloca C_ALLOCA)
CHECK_FUNCTION_EXISTS(memcmp HAVE_MEMCMP)
CHECK_INCLUDE_FILES(alloca.h HAVE_ALLOCA_H)
CHECK_INCLUDE_FILES(strings.h HAVE_STRINGS_H)
CHECK_INCLUDE_FILES(string.h HAVE_STRING_H)
CHECK_INCLUDE_FILES(stdlib.h HAVE_STDLIB_H)
CHECK_INCLUDE_FILES(sys/time.h HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES(sys/times.h HAVE_SYS_TIMES_H)
CHECK_INCLUDE_FILES(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(memory.h HAVE_MEMORY_H)
CHECK_INCLUDE_FILES(stdarg.h HAVE_STDARG_PROTOTYPES)

CHECK_TYPE_SIZE("int" SIZEOF_INT)
CHECK_TYPE_SIZE("long" SIZEOF_LONG)
CHECK_TYPE_SIZE("short" SIZEOF_SHORT)

set     (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include (AddTargetSources)

if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()

set (EVHTP_DEPS_INSTALL ${PROJECT_BINARY_DIR}/install)

# -DEVHTP_ENABLE_SSL:STRING=ON
option (EVHTP_ENABLE_SSL        "Enable evhtp_ssl support"   ON)

# -DEVHTP_ENABLE_EVTHR:STRING=ON
option (EVHTP_ENABLE_EVTHR      "Enable evhtp_evthr support " ON)

# -DEVHTP_ENABLE_REGEX:STRING=ON
option (EVHTP_ENABLE_REGEX     "Enable evhtp_regex support"  ON)

# -DEVHTP_BUILD_SHARED:STRING=ON
option (EVHTP_BUILD_SHARED      "Build shared library too"   OFF)

# -DEVHTP_USE_DEFER_ACCEPT:STRING=ON
option (EVHTP_USE_DEFER_ACCEPT  "Enable TCP_DEFER_ACCEPT"    OFF)

find_library (EVHTP_LIBEVENT   event    REQUIRED)
find_path    (EVHTP_LIBEVENT_H event.h  REQUIRED)
find_path    (EVHTP_UNISTD_H   unistd.h REQUIRED)

if (EVHTP_ENABLE_SSL)
	find_package(OpenSSL)

	if (NOT OPENSSL_FOUND)
		message(FATAL_ERROR
			"-- OpenSSL not found, either install it, or set -DEVHTP_ENABLE_SSL:STRING=OFF")
	endif()

	if (NOT ${LIBEVENT_OPENSSL_LIBRARY})
		message(FATAL_ERROR
			"-- OpenSSL found, but event_openssl not found, recompile libevent or set -DEVHTP_ENABLE_SSL:STRING=OFF")
	endif()
endif()


if (EVHTP_ENABLE_EVTHR)
	find_library (EVHTP_PTHREAD   pthread)
	find_path    (EVHTP_PTHREAD_H pthread.h)

	if (NOT EVHTP_PTHREAD)
		message(FATAL_ERROR
			"-- lpthread not found, either install it, or set -DEVHTP_ENABLE_EVTHR:STRING=OFF")
	elseif (NOT EVHTP_PTHREAD_H)
		message(FATAL_ERROR
			"-- pthread.h not found, either install it, or set -DEVHTP_ENABLE_EVTHR:STRING=OFF")
	endif()
endif()

if (NOT LIB_INSTALL_DIR)
	set(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib")
endif()

if (NOT INCLUDE_INSTALL_DIR)
	set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/include)
endif()

set (EVHTP_VERSION_MAJOR 1)
set (EVHTP_VERSION_MINOR 2)
set (EVHTP_VERSION_PATCH 9)
set (EVHTP_VERSION       "${EVHTP_VERSION_MAJOR}.${EVHTP_VERSION_MINOR}.${EVHTP_VERSION_PATCH}")

if (EVHTP_BUILD_SHARED)
	set (EVHTP_BUILD_TYPE SHARED)
else()
	set (EVHTP_BUILD_TYPE STATIC)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${EVHTP_DEPS_INSTALL}/lib/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${EVHTP_DEPS_INSTALL}/lib/)

configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/src/evhtp/evhtp-config.h.in
	${EVHTP_DEPS_INSTALL}/include/evhtp/evhtp-config.h
)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories (${EVHTP_DEPS_INSTALL}/include)
link_directories    (${EVHTP_DEPS_INSTALL}/lib)

if (EVHTP_ENABLE_REGEX)
	include_directories (${EVHTP_DEPS_INSTALL}/include/evhtp/regex)
	include_directories (${EVHTP_DEPS_INSTALL}/include/evhtp/regex/oniguruma)
	include_directories (${CMAKE_CURRENT_SOURCE_DIR}/src/evhtp/regex/oniguruma)
	include_directories (${CMAKE_CURRENT_SOURCE_DIR}/src/evhtp/regex/oniguruma/enc)
	install (FILES
		${CMAKE_CURRENT_SOURCE_DIR}/src/evhtp/regex/oniguruma/onigposix.h
		DESTINATION ${INCLUDE_INSTALL_DIR}/evhtp/regex/oniguruma)
endif()


message(STATUS "CMAKE_BUILD_TYPE         : " ${CMAKE_BUILD_TYPE})
message(STATUS "CMAKE_BINARY_DIR         : " ${CMAKE_BINARY_DIR})
message(STATUS "CMAKE_CURRENT_BINARY_DIR : " ${CMAKE_CURRENT_BINARY_DIR})
message(STATUS "CMAKE_SOURCE_DIR         : " ${CMAKE_SOURCE_DIR})
message(STATUS "CMAKE_CURRENT_SOURCE_DIR : " ${CMAKE_CURRENT_SOURCE_DIR})
message(STATUS "PROJECT_BINARY_DIR       : " ${PROJECT_BINARY_DIR})
message(STATUS "PROJECT_SOURCE_DIR       : " ${PROJECT_SOURCE_DIR})
message(STATUS "CMAKE_MODULE_PATH        : " ${CMAKE_MODULE_PATH})
message(STATUS "CMAKE_COMMAND            : " ${CMAKE_COMMAND})
message(STATUS "CMAKE_ROOT               : " ${CMAKE_ROOT})
message(STATUS "CMAKE_SYSTEM             : " ${CMAKE_SYSTEM})
message(STATUS "CMAKE_SYSTEM_NAME        : " ${CMAKE_SYSTEM_NAME})
message(STATUS "CMAKE_SYSTEM_VERSION     : " ${CMAKE_SYSTEM_VERSION})
message(STATUS "CMAKE_SYSTEM_PROCESSOR   : " ${CMAKE_SYSTEM_PROCESSOR})
message(STATUS "CMAKE_C_FLAGS            : " ${CMAKE_C_FLAGS})
message(STATUS "CMAKE_CXX_FLAGS          : " ${CMAKE_CXX_FLAGS})
message(STATUS "CMAKE_C_COMPILER         : " ${CMAKE_C_COMPILER})
message(STATUS "CMAKE_CXX_COMPILER       : " ${CMAKE_CXX_COMPILER})
message(STATUS "CMAKE_AR                 : " ${CMAKE_AR})
message(STATUS "CMAKE_RANLIB             : " ${CMAKE_RANLIB})
message(STATUS "CMAKE_C_FLAGS_DEBUG      : " ${CMAKE_C_FLAGS_DEBUG})
message(STATUS "CMAKE_C_FLAGS_RELEASE    : " ${CMAKE_C_FLAGS_RELEASE})
message(STATUS "CMAKE_C_FLAGS_RELWDBGIFO : " ${CMAKE_C_FLAGS_RELWITHDEBINFO})
message(STATUS "CMAKE_INSTALL_PREFIX     : " ${CMAKE_INSTALL_PREFIX})
message(STATUS "Version                  : " ${EVHTP_VERSION_MAJOR}.${EVHTP_VERSION_MINOR}.${EVHTP_VERSION_PATCH})

add_subdirectory(src)
