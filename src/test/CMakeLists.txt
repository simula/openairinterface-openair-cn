set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/../build/modules/")
find_package(Check REQUIRED)
find_package(Threads REQUIRED)

set(ASN1RELDIR r10.5)
include_directories(${CHECK_INCLUDE_DIRS})
include_directories(${PROJECT_SOURCE_DIR}/mme_app)
include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${CMAKE_BINARY_DIR}/s1ap/${ASN1RELDIR})
include_directories(${PROJECT_SOURCE_DIR}/sgw)
include_directories(${PROJECT_SOURCE_DIR}/utils)
include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)
include_directories(${PROJECT_SOURCE_DIR}/utils/hashtable)
include_directories(${PROJECT_SOURCE_DIR}/service303)

# Nas message headers are all pulled in.
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


set(MME_APP_UE_CONTEXT_IMSI_SRC
    test_mme_app_ue_context.c
    )

add_executable(test_mme_app_ue_context_imsi ${MME_APP_UE_CONTEXT_IMSI_SRC})
target_link_libraries(test_mme_app_ue_context_imsi MME_APP ${CHECK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
add_test(NAME test_mme_app_ue_context COMMAND test_mme_app_ue_context_imsi)
