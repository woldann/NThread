cmake_minimum_required(VERSION 3.10)
project(NThread C)

set(NTHREAD_MODULE_RULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/modulerules)
set(NTHREAD_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(NTHREAD_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB_RECURSE NTHREAD_HEADERS CONFIGURE_DEPENDS ${NTHREAD_INCLUDE_DIR}/*.h)
file(GLOB_RECURSE NTHREAD_SOURCES CONFIGURE_DEPENDS ${NTHREAD_SOURCE_DIR}/*.c)

add_library(NThread INTERFACE)

target_include_directories(NThread INTERFACE ${NTHREAD_INCLUDE_DIR})
target_include_directories(NThread INTERFACE ${NTHREAD_MODULE_RULES_DIR})
target_sources(NThread INTERFACE ${NTHREAD_SOURCES})

add_subdirectory(tests)

target_link_libraries(NThread INTERFACE Neptune)

