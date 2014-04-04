add_custom_target(examples)

add_executable(test EXCLUDE_FROM_ALL test.c)
target_link_libraries(test evhtp ${EVHTP_EXTERNAL_LIBS})

add_executable(test_basic EXCLUDE_FROM_ALL test_basic.c)
target_link_libraries(test_basic evhtp ${EVHTP_EXTERNAL_LIBS})

add_executable(test_client EXCLUDE_FROM_ALL test_client.c)
target_link_libraries(test_client evhtp ${EVHTP_EXTERNAL_LIBS})


add_dependencies(examples test test_basic test_client)
