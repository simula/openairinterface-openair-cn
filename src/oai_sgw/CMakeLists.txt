set(ASN1RELDIR r10.5)
include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/common/itti)
include_directories(${CMAKE_BINARY_DIR}/s1ap/${ASN1RELDIR})
include_directories(${PROJECT_SOURCE_DIR}/common/message_utils)
include_directories(${PROJECT_SOURCE_DIR}/gtpv1-u)
include_directories(${PROJECT_SOURCE_DIR}/sgw)
include_directories(${PROJECT_SOURCE_DIR}/s11)
include_directories(${PROJECT_SOURCE_DIR}/udp)
include_directories(${PROJECT_SOURCE_DIR}/utils)
include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)
include_directories(${PROJECT_SOURCE_DIR}/utils/hashtable)
include_directories(${PROJECT_SOURCE_DIR}/utils/msc)

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

# Override options for S/P GW
set (  BYTE_ORDER=LITTLE_ENDIAN )
set (  DISABLE_ITTI_DETECT_SUB_TASK_ID true )
set (  DISPLAY_LICENCE_INFO            true )
set (  ENABLE_ITTI                     True )
set (  GTPV1U_LINEAR_TEID_ALLOCATION   False )
set (  LOG_OAI                         true )
set (  MESSAGE_CHART_GENERATOR         true )
set (  MEMORY_CHECK                    False )
set (  NW_GTPV2C_DISPLAY_LICENCE_INFO  True )
set (  S1AP_DEBUG_LIST                 True )
set (  SECU_DEBUG                      False )
set (  SPGW_BUILD                      True )
set (  TRACE_HASHTABLE                 False )
set (  DISABLE_EXECUTE_SHELL_COMMAND   False )



add_executable(spgw
  oai_sgw.c
  ${PROJECT_SOURCE_DIR}/common/common_types.c
  ${PROJECT_SOURCE_DIR}/common/itti_free_defined_msg.c
  )
target_link_libraries (spgw
      -Wl,--start-group
      BSTR CN_UTILS GTPV1U GTPV2C HASHTABLE 
      SGW S11_SGW UDP_SERVER ${MSC_LIB} ${ITTI_LIB}  ${3GPP_TYPES_LIB}
      -Wl,--end-group
      pthread m rt ${LFDS} ${GTPNL_LIBRARIES} ${CONFIG_LIBRARIES}
      )

