add_definitions(-DASN1_MINIMUM_VERSION=924)

# Common headers
include_directories("${SRC_TOP_DIR}/common")
include_directories("${SRC_TOP_DIR}/common/itti")
include_directories("${SRC_TOP_DIR}/utils")
include_directories("${SRC_TOP_DIR}/mme")

# This is a fork of https://github.com/websnarf/bstrlib
# Evaluate if we want to pull the src directly from github.
include_directories("${SRC_TOP_DIR}/utils/bstr")
include_directories("${SRC_TOP_DIR}/utils/hashtable")
# Possibly unused.
include_directories("${SRC_TOP_DIR}/utils/msc")

# Nas message headers
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

# Possible header leak
include_directories("${SRC_TOP_DIR}/mme_app")
include_directories("${SRC_TOP_DIR}/sgw")

###############################################################################
# A difficulty: asn1c generates C code of a un-predictable list of files
# so, generate the c from asn1c once at cmake run time
# So, if someone modify the asn.1 source file in such as way that it will create
# (so creating new asn.1 objects instead of modifying the object attributes)
# New C code source file, cmake must be re-run (instead of re-running make only)
###############################################################################
set(S1AP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
if (${S1AP_RELEASE} STREQUAL "r8")
  make_version(S1AP_VERSION 8 10 0)
  set(S1AP_ASN_FILES "s1ap-8.10.0.asn1")
elseif (${S1AP_RELEASE} STREQUAL "r9")
  make_version(S1AP_VERSION 9 10 0)
  set(S1AP_ASN_FILES "s1ap-9.10.0.asn1")
elseif (${S1AP_RELEASE} STREQUAL "r10")
  make_version(S1AP_VERSION 10 9 0)
  set(S1AP_ASN_FILES "s1ap-10.9.0.asn1")
elseif (${S1AP_RELEASE} STREQUAL "r11")
  make_version(S1AP_VERSION 11 8 0)
  set(S1AP_ASN_FILES "s1ap-11.8.0.asn1")
elseif (${S1AP_RELEASE} STREQUAL "r12")
  make_version(S1AP_VERSION 12 7 0)
  set(S1AP_ASN_FILES "s1ap-12.7.0.asn1")
elseif (${S1AP_RELEASE} STREQUAL "r13")
  make_version(S1AP_VERSION 13 6 0)
  set(S1AP_ASN_FILES "s1ap-13.6.0.asn1")
elseif (${S1AP_RELEASE} STREQUAL "r14")
  make_version(S1AP_VERSION 14 5 0)
  set(S1AP_ASN_FILES "s1ap-14.5.0.asn1")
else (${S1AP_RELEASE} STREQUAL "r15")
  make_version(S1AP_VERSION 15 1 0)
  set(S1AP_ASN_FILES "s1ap-15.1.0.asn1")
endif(${S1AP_RELEASE} STREQUAL "r8")
add_definitions(-DS1AP_VERSION=${S1AP_VERSION})
set(S1AP_ASN_DIR ${S1AP_DIR}/messages/asn1/${S1AP_RELEASE})
# Set generated files in this folder to let IDE access generated code without configuring CMAKE_CURRENT_BINARY_DIR/... as a source code folder
#set(asn1_generated_dir ${CMAKE_CURRENT_BINARY_DIR})
#set(S1AP_C_DIR ${asn1_generated_dir}/GENERATED_S1AP_${S1AP_RELEASE})
set(asn1_generated_dir ${S1AP_ASN_DIR})
set(S1AP_C_DIR ${asn1_generated_dir}/GENERATED_S1AP)

if(EXISTS "${S1AP_C_DIR}/S1AP_asn_constant.h")
   MESSAGE("${S1AP_C_DIR}/S1AP_asn_constant.h exists, not regenerate all S1aP IEs from ASN1 definitions")
else()
  message("calling ASN1C_PREFIX=S1AP_ asn1c -pdu=all -fcompound-names -fno-include-deps -gen-PER -no-gen-OER -no-gen-example -D ${S1AP_C_DIR} ${S1AP_ASN_DIR}/${S1AP_ASN_FILES}")
  execute_process(COMMAND mkdir -p ${S1AP_C_DIR}
                COMMAND env "ASN1C_PREFIX=S1AP_" asn1c -pdu=all -fcompound-names -fno-include-deps -gen-PER -no-gen-OER -no-gen-example -D ${S1AP_C_DIR} ${S1AP_ASN_DIR}/${S1AP_ASN_FILES}
                RESULT_VARIABLE ret)
  if (NOT ${ret} STREQUAL 0)
    message(FATAL_ERROR "${ret}: error")
  endif (NOT ${ret} STREQUAL 0)
endif()

file(GLOB S1AP_source ${S1AP_C_DIR}/*.c)

file(GLOB s1ap_h ${S1AP_C_DIR}/*.h)
set(s1ap_h ${s1ap_h})


add_library(S1AP_LIB
  ${S1AP_source}
  ${S1AP_DIR}/s1ap_common.c
  )

include_directories ("${S1AP_C_DIR}")
include_directories ("${S1AP_DIR}")

if(${MOBILITY_REPO})
  include_directories ("${MOBILITY_REPO_SRC}/src/s1ap/")
  add_library(S1AP_EPC
    ${MOBILITY_REPO_SRC}/src/s1ap/s1ap_mobility_handover_signaling_handler.c
    ${S1AP_DIR}/s1ap_mme_encoder.c
    ${S1AP_DIR}/s1ap_mme_decoder.c
    ${S1AP_DIR}/s1ap_mme_handlers.c
    ${S1AP_DIR}/s1ap_mme_nas_procedures.c
    ${S1AP_DIR}/s1ap_mme.c
    ${S1AP_DIR}/s1ap_mme_itti_messaging.c
    ${S1AP_DIR}/s1ap_mme_retransmission.c
    ${S1AP_DIR}/s1ap_mme_ta.c
    )
else (${MOBILITY_REPO})
  add_library(S1AP_EPC
    ${S1AP_DIR}/s1ap_mme_encoder.c
    ${S1AP_DIR}/s1ap_mme_decoder.c
    ${S1AP_DIR}/s1ap_mme_handlers.c
    ${S1AP_DIR}/s1ap_mme_nas_procedures.c
    ${S1AP_DIR}/s1ap_mme.c
    ${S1AP_DIR}/s1ap_mme_itti_messaging.c
    ${S1AP_DIR}/s1ap_mme_retransmission.c
    ${S1AP_DIR}/s1ap_mme_ta.c
    )
endif ()
