add_subdirectory(parser)

if (EVHTP_ENABLE_EVTHR)
	add_subdirectory(evthr)
endif()

if (EVHTP_ENABLE_REGEX)
	add_subdirectory(regex)
endif()

get_property(libevhtp_SRCS GLOBAL PROPERTY libevhtp_SRCS)

set (LIBEVHTP_SOURCES ${libevhtp_SRCS})
add_library(libevhtp ${EVHTP_BUILD_TYPE} ${LIBEVHTP_SOURCES} evhtp.c)
set_target_properties(libevhtp PROPERTIES OUTPUT_NAME "evhtp")
