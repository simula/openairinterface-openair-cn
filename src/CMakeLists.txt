################################################################################
# Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The OpenAirInterface Software Alliance licenses this file to You under 
# the Apache License, Version 2.0  (the "License"); you may not use this file
# except in compliance with the License.  
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------
# For more information about the OpenAirInterface (OAI) Software Alliance:
#      contact@openairinterface.org
################################################################################
# Author: laurent THOMAS, Lionel GAUTHIER
###############################################################################

cmake_minimum_required (VERSION 3.0.2)

#############################################
# Base directories, compatible with legacy OAI building
################################################
set (OPENAIRCN_DIR   $ENV{OPENAIRCN_DIR})
set (BUILD_TOP_DIR   ${OPENAIRCN_DIR}/build)
set (OPENAIRCN_BIN_DIR ${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY})

project (OpenAirInterface)

###########################################
# macros to define options as there is numerous options in oai
################################################
macro(add_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  add_definitions("-D${name}=${value}")
endmacro(add_option)

macro(add_boolean_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY TYPE BOOL)
  if (${value})
    add_definitions("-D${name}=1")
  else (${value})
    add_definitions("-D${name}=0")
  endif (${value})
endmacro(add_boolean_option)

macro(add_integer_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  add_definitions("-D${name}=${value}")
endmacro(add_integer_option)

macro(add_list1_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY STRINGS ${ARGN})
  if(NOT "${value}" STREQUAL "False")
    add_definitions("-D${name}=${value}")
  endif()
endmacro(add_list1_option)

macro(add_list2_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY STRINGS ${ARGN})
  if(NOT "${value}" STREQUAL "False")
    add_definitions("-D${value}=1")
  endif()
endmacro(add_list2_option)

macro(add_list_string_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY STRINGS ${ARGN})
  if(NOT "${value}" STREQUAL "False")
    add_definitions("-D${name}=\"${value}\"")
  endif()
endmacro(add_list_string_option)
################################################################
# Compilation flags
################################################################
# Build type
################################################################
if (CMAKE_BUILD_TYPE STREQUAL "")
   set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()
add_list_string_option(CMAKE_BUILD_TYPE "RelWithDebInfo" "Choose the type of build, options are: None(CMAKE_CXX_FLAGS or CMAKE_C_FLAGS used) Debug Release RelWithDebInfo MinSizeRel." Debug Release RelWithDebInfo MinSizeRel)
Message("Build type is ${CMAKE_BUILD_TYPE}")
if (CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  add_boolean_option(LOG_OAI True         "Thread safe logging API")
  add_boolean_option(LOG_OAI_MINIMAL True "Thread safe logging API, log only levels above NOTICE")
endif()
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_boolean_option(LOG_OAI True "Thread safe logging API")
endif()

################################################################
# Processor architecture
################################################################

Message("Architecture is ${CMAKE_SYSTEM_PROCESSOR}")
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7l")
  set(C_FLAGS_PROCESSOR "-gdwarf-2 -mfloat-abi=hard -mfpu=neon -lgcc -lrt")
else (CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7l")
  set(C_FLAGS_PROCESSOR "-msse4.2")
endif()
#
set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} ${C_FLAGS_PROCESSOR} -std=gnu99 -Wall -Wstrict-prototypes -fno-strict-aliasing -rdynamic -funroll-loops -Wno-packed-bitfield-compat -fPIC ")
# add autoTOOLS definitions that were maybe used!
set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_FCNTL_H=1 -DHAVE_ARPA_INET_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_SYS_SOCKET_H=1 -DHAVE_STRERROR=1 -DHAVE_SOCKET=1 -DHAVE_MEMSET=1 -DHAVE_GETTIMEOFDAY=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DHAVE_LIBSCTP"
)
# set a flag for changes in the source code
# these changes are related to hardcoded path to include .h files
add_definitions(-DCMAKER)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -fstack-protector-all -g -DMALLOC_CHECK_=3 -DDEBUG_IS_ON=1 -DTRACE_IS_ON=1 -O0 -fsanitize=address -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS} -g -DMALLOC_CHECK_=3  -DDEBUG_IS_ON -O1") 

################################################################
# Git Version 
################################################################
set(GIT_BRANCH        "UNKNOWN")
set(GIT_COMMIT_HASH   "UNKNOWN")
set(GIT_COMMIT_DATE   "UNKNOWN")

find_package(Git)
if(GIT_FOUND)
  message("git found: ${GIT_EXECUTABLE}")
  # Get the current working branch
  execute_process(
    COMMAND git rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_BRANCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  # Get the latest abbreviated commit hash of the working branch
  execute_process(
    COMMAND git log -1 --format=%h
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  
  # Get the latest commit date of the working branch
  execute_process(
    COMMAND git log -1 --format=%cd
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_DATE
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()


add_list_string_option(GIT_PACKAGE_NAME "NotDefined" "As per attribute name")
add_definitions("-DGIT_PACKAGE_VERSION=\"Branch: ${GIT_BRANCH} Abrev. Hash: ${GIT_COMMIT_HASH} Date: ${GIT_COMMIT_DATE}\"")
add_definitions("-DGIT_PACKAGE_BUGREPORT=\"openaircn-user@lists.eurecom.fr\"")

###############################################################################
# Include CMake modules to find other library
###############################################################################

set(CMAKE_MODULE_PATH "${OPENAIRCN_DIR}/build/modules" "${CMAKE_MODULE_PATH}")
include(FindPkgConfig)

pkg_search_module(LIBXML2 libxml-2.0 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIRS})
###############################################################################
# Include Check library for unit tests
###############################################################################

include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

###############################################################################
# Split repository for licensing reasons
###############################################################################
add_boolean_option( MOBILITY_REPO                   False    "Split repository for licensing reasons, values: False or path to local mounted folder ex /tmp/openair-cn-mobility")


###############################################################################
# Debug and build related options
###############################################################################
add_boolean_option( DAEMONIZE                       False    "Fork executable if true")
add_boolean_option( DEBUG_MUTEX                     False    "Trace mutex lock/unlock")
add_boolean_option( ASSERT_MUTEX                    False    "Raise segfault if can't lock mutex")

add_boolean_option( DISABLE_ITTI_DETECT_SUB_TASK_ID False    " ")
add_boolean_option( DISPLAY_LICENCE_INFO            False    "If a module has a licence banner to show")
add_boolean_option( ENABLE_ITTI                     True     "ITTI is internal messaging, should remain enabled for most targets")
add_integer_option( ITTI_TASK_STACK_SIZE            0        "pthread allocated stack size in bytes of an ITTI task, if 0, use default stack size ") 
add_boolean_option( ITTI_LITE                       False    "Do not use ITTI systematically for each message exchanged between layer modules") 
add_boolean_option( MESSAGE_CHART_GENERATOR         False    "For generating sequence diagrams")
add_boolean_option( DISABLE_EXECUTE_SHELL_COMMAND   False    "disable execution of C int system(const char *command);")
# NAS LAYER OPTIONS
##########################
add_boolean_option( EPC_BUILD                       False    "BUILD MME-xGW executable")
add_boolean_option( GTPV1U_LINEAR_TEID_ALLOCATION   False    "Teid allocation id mode versus pseudo random")
add_boolean_option( ENABLE_SDF_MARKING              False    "Should be set to true if you want to use patched GTP kernel module (old iptables/netfilter based design with marking)")
# S1AP LAYER OPTIONS
##########################
add_boolean_option(S1AP_DEBUG_LIST                  False    "Traces, option to be removed soon")
# SCTP LAYER OPTIONS
##########################
add_boolean_option(SCTP_DUMP_LIST                   False    "Traces, option to be removed soon")

add_boolean_option( TRACE_HASHTABLE                 False    "Trace hashtables operations ")
add_boolean_option( LOG_OAI                         False    "Thread safe logging utility")
add_boolean_option( LOG_OAI_CLEAN_HARD              False    "Thread safe logging utility option for cleaning inner structs")
add_boolean_option( SECU_DEBUG                      False    "Traces, option to be removed soon")
add_boolean_option( TRACE_3GPP_SPEC                 True     "Log hits of 3GPP specifications requirements")

###############################################################################
# Split repository for licensing reasons
###############################################################################
if(${MOBILITY_REPO})
  message ("Extra mobility repo configured")
else (${MOBILITY_REPO})
  message ("No mobility extra repo configured")
endif (${MOBILITY_REPO})


# System packages that are required
# We use either the cmake buildin, in ubuntu are in: /usr/share/cmake*/Modules/
# or cmake provide a generic interface to pkg-config that widely used
###################################

pkg_search_module(NETTLE nettle REQUIRED)
if(NOT ${NETTLE_FOUND})
  message( FATAL_ERROR "PACKAGE nettle not found: some targets will fail. Run SCRIPTS/build_mme -i or SCRIPTS/build_hss -i  again!")
else()
  include_directories(${NETTLE_INCLUDE_DIRS})
endif()

string(REGEX REPLACE "([0-9]+).*" "\\1" NETTLE_VERSION_MAJOR ${NETTLE_VERSION})
string(REGEX REPLACE "[0-9]+\\.([0-9]+).*" "\\1" NETTLE_VERSION_MINOR ${NETTLE_VERSION})
message ("NETTLE_VERSION_INSTALLED  = ${NETTLE_VERSION}")
message ("NETTLE_VERSION_MAJOR = ${NETTLE_VERSION_MAJOR}")
message ("NETTLE_VERSION_MINOR = ${NETTLE_VERSION_MINOR}")
if ("${NETTLE_VERSION_MAJOR}" STREQUAL "" OR "${NETTLE_VERSION_MINOR}" STREQUAL "")
    message( FATAL_ERROR "The nettle version is not detected properly..." )
endif()

add_definitions("-DNETTLE_VERSION_MAJOR=${NETTLE_VERSION_MAJOR}")
add_definitions("-DNETTLE_VERSION_MINOR=${NETTLE_VERSION_MINOR}")

pkg_search_module(CONFIG libconfig REQUIRED)
include_directories(${CONFIG_INCLUDE_DIRS})
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

pkg_search_module(LIBXML2 libxml-2.0 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIRS})

pkg_search_module(OPENSSL openssl REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})

pkg_search_module(CRYPTO libcrypto REQUIRED)
include_directories(${CRYPTO_INCLUDE_DIRS})

pkg_search_module(GTPNL libgtpnl REQUIRED)


find_library(LFDS lfds710 PATHS /usr/local/lib /usr/lib )

if ("${LFDS}" STREQUAL "LFDS-NOTFOUND")
  message(FATAL_ERROR "LIB LFDS not found, please install it" )
endif()

################################################################
# Add sub modules
################################################################

ADD_SUBDIRECTORY(common)
ADD_SUBDIRECTORY(gtpv1-u)
ADD_SUBDIRECTORY(gtpv2-c)
ADD_SUBDIRECTORY(s11)
ADD_SUBDIRECTORY(mme_app)
ADD_SUBDIRECTORY(nas)
ADD_SUBDIRECTORY(oai_sgw)
ADD_SUBDIRECTORY(sctp)
ADD_SUBDIRECTORY(secu)
ADD_SUBDIRECTORY(sgw)
ADD_SUBDIRECTORY(s1ap)
ADD_SUBDIRECTORY(s6a)
ADD_SUBDIRECTORY(udp)
ADD_SUBDIRECTORY(utils)
ENABLE_TESTING()
ADD_SUBDIRECTORY(test)
