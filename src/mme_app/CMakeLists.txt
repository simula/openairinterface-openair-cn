set(ASN1RELDIR r10.5)
include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/common/itti)
include_directories(${PROJECT_SOURCE_DIR}/common/message_utils)
include_directories(${CMAKE_BINARY_DIR}/s1ap/${ASN1RELDIR})
include_directories(${PROJECT_SOURCE_DIR}/secu)
include_directories(${PROJECT_SOURCE_DIR}/sgw)
include_directories(${PROJECT_SOURCE_DIR}/s1ap)
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

add_library(MME_APP
    mme_app_capabilities.c
    mme_app_apn_selection.c
    mme_app_authentication.c
    mme_app_bearer.c
    mme_app_bearer_context.c
    mme_app_capabilities.c
    mme_app_context.c
    mme_app_detach.c
    mme_app_edns_emulation.c
    mme_app_itti_messaging.c
    mme_app_location.c
    mme_app_main.c
    mme_app_pdn_context.c
    mme_app_procedures.c
    mme_app_sgw_selection.c
    mme_app_statistics.c
    mme_app_transport.c
    mme_app_ue_context.c
    mme_config.c
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
    ${PROJECT_SOURCE_DIR}/common/itti_free_defined_msg.c
    ${PROJECT_SOURCE_DIR}/nas/nas_mme_task.c
    )

target_link_libraries (mme
    -Wl,--start-group
    LIB_NAS_MME S1AP_LIB S1AP_EPC S11_MME GTPV2C SCTP_SERVER UDP_SERVER SECU_CN  S6A MME_APP
            ${MSC_LIB} ${ITTI_LIB}  ${3GPP_TYPES_LIB} CN_UTILS
            HASHTABLE BSTR
    -Wl,--end-group
    pthread m sctp  rt crypt ${LFDS} ${CRYPTO_LIBRARIES} ${OPENSSL_LIBRARIES}
      ${NETTLE_LIBRARIES} ${CONFIG_LIBRARIES} gnutls fdproto fdcore 
    )
