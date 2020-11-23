cmake_minimum_required (VERSION 2.8)

project (wifibroadcast)

add_definitions(-Wall -D _GNU_SOURCE)

add_executable(rx rx.c lib.c radiotap.c fec.c)
target_link_libraries(rx rt pcap)
install (TARGETS rx DESTINATION bin)

add_executable(tx tx.c lib.c radiotap.c fec.c)
target_link_libraries(tx rt pcap)
install (TARGETS tx DESTINATION bin)

add_executable(rx_status_test rx_status_test.c)
install (TARGETS rx_status_test DESTINATION bin)

add_executable(rx_status_csv rx_status_csv.c)
install (TARGETS rx_status_csv DESTINATION bin)
