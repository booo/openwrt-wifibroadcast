cmake_minimum_required (VERSION 2.8)

project (foo)

add_definitions(-Wall -D _GNU_SOURCE)

add_executable(rx rx.c)
target_link_libraries(rx)
install (TARGETS rx DESTINATION bin)
