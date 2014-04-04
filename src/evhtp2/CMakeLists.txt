list(APPEND EVHTP_LIBS evhtp_parser)

if (EVHTP_ENABLE_EVTHR)
	add_library(evhtp_thr ${EVHTP_BUILD_TYPE} evhtp_thr.c)
	list(APPEND EVHTP_LIBS evhtp_thr)
endif()

if (EVHTP_ENABLE_REGEX)
	add_subdirectory(regex)
endif()

add_library(evhtp_parser ${EVHTP_BUILD_TYPE} evhtp_parser.c)

get_property(libevhtp_SRCS GLOBAL PROPERTY libevhtp_SRCS)
set (LIBEVHTP_SOURCES ${libevhtp_SRCS})
add_library(libevhtp ${EVHTP_BUILD_TYPE} ${LIBEVHTP_SOURCES} ${EVHTP_LIBS} evhtp.c)
set_target_properties(libevhtp PROPERTIES OUTPUT_NAME "evhtp")
