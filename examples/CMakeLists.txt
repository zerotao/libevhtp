add_custom_target(examples)

list(APPEND EVHTP_LIBS evhtp)

if (EVHTP_ENABLE_EVTHR)
	list(APPEND EVHTP_LIBS evhtp_thr)
endif()

if (EVHTP_ENABLE_SSL)
	list(APPEND EVHTP_LIBS evhtp_ssl)
endif()

add_executable(test EXCLUDE_FROM_ALL test.c)
target_link_libraries(test ${EVHTP_LIBS} ${EVHTP_EXTERNAL_LIBS})

add_executable(test_basic EXCLUDE_FROM_ALL test_basic.c)
target_link_libraries(test_basic ${EVHTP_LIBS} ${EVHTP_EXTERNAL_LIBS})

add_executable(test_client EXCLUDE_FROM_ALL test_client.c)
target_link_libraries(test_client ${EVHTP_LIBS} ${EVHTP_EXTERNAL_LIBS})

add_executable(test_ws EXCLUDE_FROM_ALL test_ws.c)
target_link_libraries(test_ws ${EVHTP_LIBS} ${EVHTP_EXTERNAL_LIBS})

add_dependencies(examples test test_basic test_client test_ws)
