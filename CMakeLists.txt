cmake_minimum_required(VERSION 3.12)
project(untitled2)

set(CMAKE_CXX_STANDARD 17)
file(GLOB typeinfo "typeinfo/*.hpp")
include_directories(typeinfo)

add_executable(untitled2 main.cpp typeinfo/CTypeInfoDump.cpp typeinfo/CTypeInfoText.cpp typeinfo/CTypeInfoDump.cpp)
target_include_directories(untitled2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/pelib/include)
target_link_libraries(untitled2 dbghelp.lib)
target_link_libraries(untitled2 ${CMAKE_CURRENT_SOURCE_DIR}/pelib/libpelib.a)