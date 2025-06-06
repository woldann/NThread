cmake_minimum_required(VERSION 3.10)

set(NEPTUNE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/Neptune")

if(NOT TARGET Neptune)
    if(EXISTS "${NEPTUNE_DIR}" AND EXISTS "${NEPTUNE_DIR}/CMakeLists.txt")
        add_subdirectory(${NEPTUNE_DIR})
    else()
        message(STATUS "Neptune directory or CMakeLists.txt not found, skipping add_subdirectory(Neptune).")
    endif()
endif()

if(TARGET Neptune)
    add_executable(inject ${CMAKE_CURRENT_SOURCE_DIR}/inject.c)
    target_link_libraries(inject PRIVATE NThread Neptune)
    target_compile_definitions(inject PRIVATE LOG_LEVEL_3 NEPTUNE_MODULERULES_HEADER="nthread_rules.h")
    target_include_directories(inject PRIVATE ${NTHREAD_INCLUDE_DIR})
else()
    message(STATUS "Neptune target not found, skipping tests.")
endif()
