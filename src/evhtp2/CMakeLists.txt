if (EVHTP_ENABLE_EVTHR)
	add_target_sources(libevhtp evhtp_thr.c)
endif()

if (EVHTP_ENABLE_REGEX)
	add_subdirectory(regex)
endif()

add_target_sources(libevhtp evhtp.c)

get_property(libevhtp_SRCS GLOBAL PROPERTY libevhtp_SRCS)
set (LIBEVHTP_SOURCES ${libevhtp_SRCS})
add_library(libevhtp ${EVHTP_BUILD_TYPE} ${LIBEVHTP_SOURCES})
set_target_properties(libevhtp PROPERTIES OUTPUT_NAME "evhtp")
