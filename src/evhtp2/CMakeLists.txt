if (EVHTP_ENABLE_EVTHR)
	add_library(evhtp_thr ${EVHTP_BUILD_TYPE} evhtp_thr.c)

	install(TARGETS evhtp_thr   DESTINATION ${LIB_INSTALL_DIR})
	install(FILES   evhtp_thr.h DESTINATION ${INCLUDE_INSTALL_DIR}/evhtp2)

endif()

if (EVHTP_ENABLE_SSL)
	add_library(evhtp_ssl ${EVHTP_BUILD_TYPE} evhtp_ssl.c)

	install(TARGETS evhtp_ssl   DESTINATION ${LIB_INSTALL_DIR})
	install(FILES   evhtp_ssl.h DESTINATION ${INCLUDE_INSTALL_DIR}/evhtp2)

endif()

if (EVHTP_ENABLE_REGEX)
	add_subdirectory(regex)
endif()

add_subdirectory(ws)

add_library(evhtp_parser ${EVHTP_BUILD_TYPE} evhtp_parser.c)

get_property(libevhtp_SRCS GLOBAL PROPERTY libevhtp_SRCS)
set (LIBEVHTP_SOURCES ${libevhtp_SRCS})
add_library(evhtp ${EVHTP_BUILD_TYPE} ${LIBEVHTP_SOURCES} evhtp_parser.c evhtp.c)

install(TARGETS evhtp_parser   DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS evhtp          DESTINATION ${LIB_INSTALL_DIR})
install(FILES   evhtp_parser.h DESTINATION ${INCLUDE_INSTALL_DIR}/evhtp2)
install(FILES   evhtp.h        DESTINATION ${INCLUDE_INSTALL_DIR}/evhtp2)
