cmake_minimum_required(VERSION 3.12)
project(UEDllRemapper)

set(CMAKE_CXX_STANDARD 17)
file(GLOB typeinfo "typeinfo/*.hpp")
include_directories(typeinfo)

add_executable(UEDllRemapper main.cpp typeinfo/CTypeInfoDump.cpp typeinfo/CTypeInfoText.cpp typeinfo/CTypeInfoDump.cpp)
target_include_directories(UEDllRemapper PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/pelib/include)
target_link_libraries(UEDllRemapper dbghelp.lib)
target_link_libraries(UEDllRemapper ${CMAKE_CURRENT_SOURCE_DIR}/pelib/libpelib.a)