cmake_minimum_required(VERSION 2.6)
project(cshark C)
add_definitions(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/build/modules")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set(SOURCES
	src/cshark.c
	src/cshark.h
	src/pcap.c
	src/pcap.h
	src/uclient.c
	src/uclient.h
	src/config.c
	src/config.h
)

add_executable(cshark ${SOURCES})

if(WITH_DEBUG)
  add_definitions(-DWITH_DEBUG -g3)
endif()

find_package(LIBUBOX REQUIRED)
include_directories(${LIBUBOX_INCLUDE_DIR})
target_link_libraries(cshark ${LIBUBOX_LIBRARIES})

find_package(LIBUCLIENT REQUIRED)
include_directories(${LIBUCLIENT_INCLUDE_DIR})
target_link_libraries(cshark ${LIBUCLIENT_LIBRARIES})

find_package(LIBPCAP REQUIRED)
include_directories(${LIBPCAP_INCLUDE_DIR})
target_link_libraries(cshark ${LIBPCAP_LIBRARIES})

find_package(UCI REQUIRED)
include_directories(${UCI_INCLUDE_DIR})
target_link_libraries(cshark ${UCI_LIBRARIES})

find_package(JSON-C REQUIRED)
include_directories(${JSON-C_INCLUDE_DIR})
target_link_libraries(cshark ${JSON-C_LIBRARIES})

# libdl must be on the system
target_link_libraries(cshark dl)

install(TARGETS cshark RUNTIME DESTINATION bin)
