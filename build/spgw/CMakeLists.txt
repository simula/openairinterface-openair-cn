cmake_minimum_required (VERSION 3.0.2)
# Override options for SPGW
set (  CMAKE_BUILD_TYPE                "Debug" )
set (  BYTE_ORDER=LITTLE_ENDIAN )
set (  DISABLE_ITTI_DETECT_SUB_TASK_ID True )
set (  DISPLAY_LICENCE_INFO            True )
set (  GTPV1U_LINEAR_TEID_ALLOCATION   False )
set (  LOG_OAI                         True )
set (  MESSAGE_CHART_GENERATOR         True )
set (  MEMORY_CHECK                    False )
set (  NW_GTPV2C_DISPLAY_LICENCE_INFO  True )
set (  PACKAGE_NAME                    "S/P-GW" )
set (  S1AP_DEBUG_LIST                 True )
set (  SECU_DEBUG                      False )
set (  SPGW_BUILD                      True )
set (  TRACE_HASHTABLE                 False )
set (  DISABLE_EXECUTE_SHELL_COMMAND   False )
set (  ENABLE_SDF_MARKING              False )
#############################################
# Base directories, compatible with legacy OAI building
################################################
set (OPENAIRCN_DIR   $ENV{OPENAIRCN_DIR})
set (BUILD_TOP_DIR   ${OPENAIRCN_DIR}/build)
set (SRC_TOP_DIR     $ENV{OPENAIRCN_DIR}/src)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../src/CMakeLists.txt)

pkg_search_module(GTPNL libgtpnl REQUIRED)

ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../src/oai_sgw ${CMAKE_CURRENT_BINARY_DIR}/oai_sgw)
ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../src/sgw ${CMAKE_CURRENT_BINARY_DIR}/sgw)
ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../src/gtpv1-u ${CMAKE_CURRENT_BINARY_DIR}/gtpv1-u)
