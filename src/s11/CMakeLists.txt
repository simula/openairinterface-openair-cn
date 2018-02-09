include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/common/itti)
include_directories(${PROJECT_SOURCE_DIR}/utils)
include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)
include_directories(${PROJECT_SOURCE_DIR}/utils/hashtable)
include_directories(${PROJECT_SOURCE_DIR}/utils/msc)
include_directories(${PROJECT_SOURCE_DIR}/gtpv2-c/nwgtpv2c-0.11/include)
include_directories(${PROJECT_SOURCE_DIR}/gtpv2-c/nwgtpv2c-0.11/shared)
include_directories(${PROJECT_SOURCE_DIR}/service303)
include_directories(${PROJECT_SOURCE_DIR}/mme_app)
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

add_library(S11_MME
    s11_common.c
    s11_ie_formatter.c
    s11_mme_task.c
    s11_mme_bearer_manager.c
    s11_mme_session_manager.c
    )

add_library(S11_SGW
    s11_common.c
    s11_ie_formatter.c
    s11_sgw.c
    s11_sgw_session_manager.c
    s11_sgw_bearer_manager.c
    )
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
