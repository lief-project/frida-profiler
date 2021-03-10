cmake_minimum_required(VERSION 3.15)
project(frida-profiler CXX)

add_executable(frida_profiler main.cpp)

set(FRIDA_LIBS )
set(FRIDA_INCLUDE_DIRS )

if(NOT FRIDA_LIBS)
  message(FATAL_ERROR "You need to provide the path to libfrida-gum.a (See frida-gum-devkit-XXX on https://github.com/frida/frida/releases)")
endif()

if(NOT FRIDA_INCLUDE_DIRS)
  message(FATAL_ERROR "You need to provide the path to Frida-Gum include dir (the directory that contains frida-gum.h)")
endif()

find_package(LIEF REQUIRED)

set_target_properties(frida_profiler PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
  POSITION_INDEPENDANT ON
)

target_include_directories(frida_profiler PRIVATE ${LIEF_INCLUDE_DIRS} ${FRIDA_INCLUDE_DIRS})

target_link_libraries(frida_profiler PRIVATE
  ${LIEF_LIBRARIES} ${FRIDA_LIBS}
  pthread dl resolv)
