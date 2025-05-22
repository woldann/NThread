cmake_minimum_required(VERSION 3.10)
project(NThread C)

add_subdirectory(Neptune)

set(NEPTUNE_MODULE_RULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/modulerules)
set(NTHREAD_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(NTHREAD_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB_RECURSE NTHREAD_HEADERS CONFIGURE_DEPENDS ${NTHREAD_INCLUDE_DIR}/*.h)
file(GLOB_RECURSE NTHREAD_SOURCES CONFIGURE_DEPENDS ${NTHREAD_SOURCE_DIR}/*.c)

add_library(NThread INTERFACE)

target_include_directories(NThread INTERFACE ${NTHREAD_INCLUDE_DIR})
target_include_directories(Neptune INTERFACE ${NEPTUNE_MODULE_RULES_DIR})
target_sources(NThread INTERFACE ${NTHREAD_SOURCES})
target_link_libraries(NThread INTERFACE Neptune)


set(TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)
set(EXAMPLES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/examples)

add_executable(inject ${TESTS_DIR}/inject.c)
target_link_libraries(inject PRIVATE NThread)
target_compile_definitions(inject PRIVATE LOG_LEVEL_3 NEPTUNE_MODULERULES_HEADER="nthread_rules.h")
target_include_directories(inject PRIVATE ${NTHREAD_INCLUDE_DIR})

add_executable(dllinjecter ${EXAMPLES_DIR}/dllinjecter.c)
target_link_libraries(dllinjecter PRIVATE NThread)
target_compile_definitions(dllinjecter PRIVATE LOG_LEVEL_3 NEPTUNE_MODULERULES_HEADER="nthread_rules.h" LOG_FORCE_COLOR)
target_include_directories(dllinjecter PRIVATE ${NTHREAD_INCLUDE_DIR})

