cmake_minimum_required (VERSION 2.8)

project (foo)

add_definitions(-Wall -D _GNU_SOURCE)

add_executable(capture capture.c)
target_link_libraries(capture)
install (TARGETS capture DESTINATION bin)

add_executable(transmit transmit.c)
target_link_libraries(transmit)
install (TARGETS transmit DESTINATION bin)

add_executable(generate generate.c)
target_link_libraries(generate)
install (TARGETS generate DESTINATION bin)
