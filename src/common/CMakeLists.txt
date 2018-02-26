set(ASN1RELDIR r10.5)
set(ITTI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/itti)
include_directories(${PROJECT_SOURCE_DIR}/utils/lfds/liblfds6.1.1/liblfds611/inc)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/itti)
include_directories(${CMAKE_BINARY_DIR}/s1ap/${ASN1RELDIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/message_utils)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ITTI_ANALYZER)
include_directories(${PROJECT_SOURCE_DIR}/utils)
include_directories(${PROJECT_SOURCE_DIR}/utils/msc)
include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)
include_directories(${PROJECT_SOURCE_DIR}/utils/hashtable)

# TODO (amar) fix include leak
include_directories("${PROJECT_SOURCE_DIR}/nas")
include_directories("${PROJECT_SOURCE_DIR}/nas/emm")
include_directories("${PROJECT_SOURCE_DIR}/nas/emm/msg")
include_directories("${PROJECT_SOURCE_DIR}/nas/emm/sap")
include_directories("${PROJECT_SOURCE_DIR}/nas/ies")
include_directories("${PROJECT_SOURCE_DIR}/nas/util")
include_directories("${PROJECT_SOURCE_DIR}/nas/esm")
include_directories("${PROJECT_SOURCE_DIR}/nas/esm/msg")
include_directories("${PROJECT_SOURCE_DIR}/nas/api/network")
include_directories("${PROJECT_SOURCE_DIR}/nas/api/mme")
include_directories("${PROJECT_SOURCE_DIR}/mme_app")
include_directories(${PROJECT_SOURCE_DIR}/service303)

if (${ENABLE_ITTI})
  set(ITTI_FILES
      # add .h files if depend on (this one is generated)
      ${ITTI_DIR}/intertask_interface.h
      ${ITTI_DIR}/intertask_interface.c
      ${ITTI_DIR}/backtrace.c
      ${ITTI_DIR}/memory_pools.c
      ${ITTI_DIR}/signals.c
      ${ITTI_DIR}/timer.c
      ${CMAKE_CURRENT_SOURCE_DIR}/message_utils/service303_message_utils.c
      )
  add_library(ITTI ${ITTI_FILES})

  set(ITTI_LIB ITTI PARENT_SCOPE)
endif (${ENABLE_ITTI})

add_library(3GPP_TYPES
  ${CMAKE_CURRENT_SOURCE_DIR}/3gpp_24.008_cc_ies.c
  ${CMAKE_CURRENT_SOURCE_DIR}/3gpp_24.008_common_ies.c
  ${CMAKE_CURRENT_SOURCE_DIR}/3gpp_24.008_mm_ies.c
  ${CMAKE_CURRENT_SOURCE_DIR}/3gpp_24.008_gmm_ies.c
  ${CMAKE_CURRENT_SOURCE_DIR}/3gpp_24.008_gprs_common_ies.c
  ${CMAKE_CURRENT_SOURCE_DIR}/3gpp_24.008_sm_ies.c)
set(3GPP_TYPES_LIB 3GPP_TYPES PARENT_SCOPE)


