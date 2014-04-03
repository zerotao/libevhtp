add_subdirectory(parser)

get_property(libevhtp_SRCS GLOBAL PROPERTY libevhtp_SRCS)

set (LIBEVHTP_SOURCES ${libevhtp_SRCS})
add_library(libevhtp ${EVHTP_BUILD_TYPE} ${LIBEVHTP_SOURCES})
set_target_properties(libevhtp PROPERTIES OUTPUT_NAME "evhtp")
