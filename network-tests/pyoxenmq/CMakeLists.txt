cmake_minimum_required(VERSION 3.10)  # bionic's cmake version

# Has to be set before `project()`, and ignored on non-macos:
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.13 CACHE STRING "macOS deployment target (Apple clang only)")

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

set(PROJECT_NAME pyoxenmq)
project(${PROJECT_NAME}
    VERSION 0.1.0
    DESCRIPTION "pybind layer for oxenmq"
    LANGUAGES CXX)


if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

include(CheckCXXSourceCompiles)
include(CheckLibraryExists)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
  
option(SUBMODULE_CHECK "Enables checking that vendored library submodules are up to date" ON)
if(SUBMODULE_CHECK)
  find_package(Git)
  if(GIT_FOUND)
    function(check_submodule relative_path)
      execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE localHead)
      execute_process(COMMAND git rev-parse "HEAD:${relative_path}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE checkedHead)
      string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
      if (upToDate)
        message(STATUS "Submodule '${relative_path}' is up-to-date")
      else()
        message(FATAL_ERROR "Submodule '${relative_path}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
      endif()
    endfunction ()
    
    check_submodule(external/pybind11)
    check_submodule(external/oxen-mq)
  endif()
endif()

add_compile_options(-Wno-deprecated-declarations)

add_subdirectory(external/pybind11)

include(FindPkgConfig)
pkg_check_modules(oxenmq REQUIRED IMPORTED_TARGET GLOBAL liboxenmq)

add_subdirectory(pyoxenmq)
