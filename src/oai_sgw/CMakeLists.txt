include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/common/itti)
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
include_directories("${PROJECT_SOURCE_DIR}/service303")
include_directories("${PROJECT_SOURCE_DIR}/openflow")

# Override options for S/P GW
set (  BYTE_ORDER=LITTLE_ENDIAN )
set (  DISABLE_ITTI_DETECT_SUB_TASK_ID True )
set (  DISPLAY_LICENCE_INFO            True )
set (  ENABLE_ITTI                     True )
set (  ENABLE_ITTI_ANALYZER            False )
set (  GTPV1U_LINEAR_TEID_ALLOCATION   False )
set (  LOG_OAI                         True )
set (  MESSAGE_CHART_GENERATOR         True )
set (  MEMORY_CHECK                    False )
set (  NW_GTPV2C_DISPLAY_LICENCE_INFO  True )
set (  S1AP_DEBUG_LIST                 True )
set (  SECU_DEBUG                      False )
set (  SPGW_BUILD                      True )
set (  TRACE_HASHTABLE                 False )
set (  DISABLE_EXECUTE_SHELL_COMMAND   False )

if ( NOT EMBEDDED_SGW )
  add_executable(spgw
      oai_sgw.c
      ${PROJECT_SOURCE_DIR}/common/3gpp_24.008.c
      ${PROJECT_SOURCE_DIR}/service303/service303_task.c
      ${PROJECT_SOURCE_DIR}/service303/service303_spgw_stats.c
      )
  if( ITTI_ANALYZER )
    add_executable(spgw ${PROJECT_BINARY_DIR}/messages_xml.h )
  endif( ITTI_ANALYZER )
  target_link_libraries (spgw
      -Wl,--start-group
      BSTR CN_UTILS LFDS GTPV1U GTPV2C HASHTABLE SERVICE303
      OPENFLOW SGW S11_SGW UDP_SERVER ${MSC_LIB} ${ITTI_LIB} ${GCOV_LIB}
      -Wl,--end-group
      pthread m rt ${GTPNL_LIBRARIES} ${CONFIG_LIBRARIES}
      )
  if ( ENABLE_OPENFLOW )
    target_link_libraries (spgw openvswitch)
  endif ( ENABLE_OPENFLOW )
endif ( NOT EMBEDDED_SGW )
