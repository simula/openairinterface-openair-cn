# gtpv1u_sgw_defs.h is inculded from sgw.h and hence is retained in this
# directory as in in OAI.
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/common/itti)
include_directories(${PROJECT_SOURCE_DIR}/utils)
include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)
include_directories(${PROJECT_SOURCE_DIR}/utils/hashtable)
include_directories(${PROJECT_SOURCE_DIR}/utils/msc)
include_directories("${PROJECT_SOURCE_DIR}/openflow/controller")
include_directories(${PROJECT_SOURCE_DIR}/service303)

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

pkg_search_module(GTPNL libgtpnl REQUIRED)
include_directories(${GTPNL_INCLUDE_DIRS})

set (GTPV1U_SRC
    gtpv1u_task.c
    gtpv1u_teid_pool.c
    gtp_tunnel_libgtpnl.c
    gtp_tunnel_openflow.c
    )
add_library(GTPV1U ${GTPV1U_SRC})

target_link_libraries(GTPV1U OPENFLOW_CONTROLLER)
