# gtpv1u_sgw_defs.h is inculded from sgw.h and hence is retained in this
# directory as in in OAI.
set(ASN1RELDIR r10.5)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/common/itti)
include_directories(${CMAKE_BINARY_DIR}/s1ap/${ASN1RELDIR})
include_directories(${PROJECT_SOURCE_DIR}/utils)
include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)
include_directories(${PROJECT_SOURCE_DIR}/utils/msc)

# Header leaks of spgw_config.h, sgw_config.h, pgw_config.h, sgw.h
include_directories(${PROJECT_SOURCE_DIR}/sgw)

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

include_directories(${GTPNL_INCLUDE_DIRS})
include_directories(${PROJECT_SOURCE_DIR}/utils/hashtable)
set (GTPV1U_SRC
    gtpv1u_task.c
    gtpv1u_teid_pool.c
    gtp_tunnel_libgtpnl.c
    )
add_library(GTPV1U ${GTPV1U_SRC})

