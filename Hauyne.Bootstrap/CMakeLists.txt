cmake_minimum_required(VERSION 3.10)
project(Hauyne.Bootstrap)

set(CMAKE_CXX_STANDARD 17)

add_library(Hauyne.Bootstrap SHARED dllmain.cpp)

target_link_libraries(Hauyne.Bootstrap PRIVATE dl pthread)

set_target_properties(Hauyne.Bootstrap PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin
    PREFIX "lib"
)
