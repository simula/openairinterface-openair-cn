include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/common/itti)
include_directories(${PROJECT_SOURCE_DIR}/common/message_utils)
include_directories(${PROJECT_SOURCE_DIR}/secu)
include_directories(${PROJECT_SOURCE_DIR}/sgw)
include_directories(${PROJECT_SOURCE_DIR}/s1ap)
include_directories(${PROJECT_SOURCE_DIR}/utils)
include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)
include_directories(${PROJECT_SOURCE_DIR}/utils/hashtable)
include_directories(${PROJECT_SOURCE_DIR}/utils/msc)
include_directories(${PROJECT_SOURCE_DIR}/service303)

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


# Override options for MME
set (  BYTE_ORDER=LITTLE_ENDIAN )
set (  DISABLE_ITTI_DETECT_SUB_TASK_ID True )
set (  DISPLAY_LICENCE_INFO            False )
set (  ENABLE_ITTI                     True )
set (  ENABLE_ITTI_ANALYZER            False )
set (  ITTI_TASK_STACK_SIZE            2097152 )
set (  ITTI_LITE                       False )
set (  LOG_OAI                         True )
set (  LOG_OAI_CLEAN_HARD              False )
set (  MESSAGE_CHART_GENERATOR         True )
set (  MEMORY_CHECK                    False )
set (  MME_BUILD                       True )
set (  S1AP_DEBUG_LIST                 False )
set (  SECU_DEBUG                      False )
set (  SCTP_DUMP_LIST                  False )
set (  TRACE_HASHTABLE                 False )
set (  TRACE_3GPP_SPEC                 False )
add_definitions("-DPACKAGE_NAME=\"MME\"")
#TODO: TBD
add_definitions("-DPACKAGE_VERSION=\"0.1\"")
add_definitions("-DPACKAGE_BUGREPORT=\"TBD\"")

# Dependencies
pkg_search_module(OPENSSL openssl REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})

pkg_search_module(CRYPTO libcrypto REQUIRED)
include_directories(${CRYPTO_INCLUDE_DIRS})

pkg_search_module(NETTLE nettle REQUIRED)
include_directories(${NETTLE_INCLUDE_DIRS})

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

add_library(MME_APP
    mme_app_capabilities.c
    mme_app_context.c
    mme_app_if_nas_transport.c
    mme_app_main.c
    mme_app_bearer.c
    mme_app_authentication.c
    mme_app_detach.c
    mme_app_location.c
    mme_app_transport.c
    mme_app_ue_context.c
    mme_app_statistics.c
    mme_app_embedded_spgw.c
    mme_config.c
    s6a_2_nas_cause.c
    )

include_directories(${PROJECT_SOURCE_DIR}/sctp)
include_directories(${PROJECT_SOURCE_DIR}/udp)
include_directories(${PROJECT_SOURCE_DIR}/s11)
include_directories(${PROJECT_SOURCE_DIR}/s6a)

# MME executable
################################
add_executable(mme
    ${PROJECT_SOURCE_DIR}/oai_mme/oai_mme_log.c
    ${PROJECT_SOURCE_DIR}/oai_mme/oai_mme.c
    ${PROJECT_SOURCE_DIR}/common/common_types.c
    ${PROJECT_SOURCE_DIR}/common/3gpp_24.008.c
    ${PROJECT_SOURCE_DIR}/nas/nas_mme_task.c
    ${PROJECT_SOURCE_DIR}/service303/service303_task.c
    ${PROJECT_SOURCE_DIR}/service303/service303_mme_stats.c
    )
if( ITTI_ANALYZER )
  add_executable(mme ${PROJECT_BINARY_DIR}/messages_xml.h )
endif( ITTI_ANALYZER )

target_link_libraries (mme
    -Wl,--start-group
    LIB_NAS_MME S1AP_LIB S1AP_EPC SCTP_SERVER UDP_SERVER SECU_CN  S6A MME_APP
            S6A_SERVICE LFDS ${MSC_LIB} ${ITTI_LIB} ${GCOV_LIB} CN_UTILS
            HASHTABLE BSTR
    -Wl,--end-group
    pthread m sctp  rt crypt ${CRYPTO_LIBRARIES} ${OPENSSL_LIBRARIES}
      ${NETTLE_LIBRARIES} ${CONFIG_LIBRARIES} gnutls fdproto fdcore SERVICE303
    )
if ( NOT EMBEDDED_SGW )
  target_link_libraries (mme GTPV2C S11_MME)
elseif ( EMBEDDED_SGW )
  target_link_libraries (mme SGW)
endif ( NOT EMBEDDED_SGW )
