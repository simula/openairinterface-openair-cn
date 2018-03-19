add_definitions("-DPACKAGE_NAME=\"SPGW\"")

set(ASN1RELDIR r10.5)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/itti)
include_directories(${CMAKE_BINARY_DIR}/s1ap/${ASN1RELDIR})
include_directories(${SRC_TOP_DIR}/common/message_utils)
include_directories(${SRC_TOP_DIR}/gtpv1-u)
include_directories(${SRC_TOP_DIR}/sgw)
include_directories(${SRC_TOP_DIR}/s11)
include_directories(${SRC_TOP_DIR}/udp)
include_directories(${SRC_TOP_DIR}/utils)
include_directories(${SRC_TOP_DIR}/utils/bstr)
include_directories(${SRC_TOP_DIR}/utils/hashtable)
include_directories(${SRC_TOP_DIR}/utils/msc)

# TODO (amar) fix include leak
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
include_directories("${SRC_TOP_DIR}/mme_app")

add_executable(spgw
  oai_sgw.c
  ${SRC_TOP_DIR}/common/common_types.c
  ${SRC_TOP_DIR}/common/itti_free_defined_msg.c
  )
target_link_libraries (spgw
      -Wl,--start-group
      BSTR CN_UTILS GTPV1U GTPV2C HASHTABLE 
      SGW S11_SGW UDP_SERVER ${MSC_LIB} ITTI  3GPP_TYPES
      -Wl,--end-group
      pthread m rt ${LFDS} ${CONFIG_LIBRARIES} asan
      )

