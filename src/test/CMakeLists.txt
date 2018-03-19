set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/../../build/modules/")
find_package(Check REQUIRED)
find_package(Threads REQUIRED)

include_directories(${CHECK_INCLUDE_DIRS})
include_directories(${SRC_TOP_DIR}/mme_app)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/sgw)
include_directories(${SRC_TOP_DIR}/utils)
include_directories(${SRC_TOP_DIR}/utils/bstr)
include_directories(${SRC_TOP_DIR}/utils/hashtable)

# Nas message headers are all pulled in.
include_directories("${SRC_TOP_DIR}/nas")
include_directories("${SRC_TOP_DIR}/nas/emm")
include_directories("${SRC_TOP_DIR}/nas/emm/msg")
include_directories("${SRC_TOP_DIR}/nas/emm/sap")
include_directories("${SRC_TOP_DIR}/nas/ies")
include_directories("${SRC_TOP_DIR}/nas/util")
include_directories("${SRC_TOP_DIR}/nas/esm")
include_directories("${SRC_TOP_DIR}/nas/esm/msg")
include_directories("${SRC_TOP_DIR}/nas/api/network")
include_directories("${SRC_TOP_DIR}/nas/api/mme")


set(MME_APP_UE_CONTEXT_IMSI_SRC
    test_mme_app_ue_context.c
    )

add_executable(test_mme_app_ue_context_imsi ${MME_APP_UE_CONTEXT_IMSI_SRC})
target_link_libraries(test_mme_app_ue_context_imsi MME_APP ${CHECK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
add_test(NAME test_mme_app_ue_context COMMAND test_mme_app_ue_context_imsi)
