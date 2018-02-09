include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/common/itti)
include_directories(${PROJECT_SOURCE_DIR}/gtpv1-u)
include_directories(${PROJECT_SOURCE_DIR}/sgw)
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

add_definitions("-DPACKAGE_NAME=\"S/P-GW\"")
#TODO: TBD
add_definitions("-DPACKAGE_VERSION=\"0.1\"")
add_definitions("-DPACKAGE_BUGREPORT=\"TBD\"")

add_library (SGW
    spgw_config.c
    pgw_config.c
    sgw_config.c
    s11_causes.c
    sgw_task.c
    sgw_handlers.c
    sgw_context_manager.c
    pgw_pco.c
    mobilityd_ue_ip_address_alloc.c
    sgw_paging.c
    )

target_link_libraries (SGW
    PUBLIC GTPV1U ${GTPNL_LIBRARIES})
