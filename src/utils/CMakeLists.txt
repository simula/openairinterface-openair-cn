###############################################################################
# Utilities Library
###############################################################################

# libbstr
add_library(BSTR
    ${CMAKE_CURRENT_SOURCE_DIR}/bstr/bstraux.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bstr/bstrlib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bstr/buniutil.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bstr/utf8util.c
    )
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/bstr)

# libhashtable
add_library(HASHTABLE
    ${CMAKE_CURRENT_SOURCE_DIR}/hashtable/hashtable.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hashtable/obj_hashtable.c
    )
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/hashtable)
# pulls in dynamic_memory_checker.h
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
# log.h pulls in gcc_diag.h
include_directories(${PROJECT_SOURCE_DIR}/common)


###############################################################################
# Core Network Utils
###############################################################################

# log.c pulls in liblfds611.h
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/lfds/liblfds6.1.1/liblfds611/inc)
# log.c pulls in intertask_interface.h
include_directories(${PROJECT_SOURCE_DIR}/common/itti)

# log.c pulls in nas_messages_types.h which brings in the entire universe.
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
include_directories(${PROJECT_SOURCE_DIR}/service303)

if (MESSAGE_CHART_GENERATOR)
  add_library(MSC
      ${CMAKE_CURRENT_SOURCE_DIR}/msc/msc.c
      )
  set(MSC_LIB MSC)
endif()
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/msc)

set(CN_UTILS_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/conversions.c
    ${CMAKE_CURRENT_SOURCE_DIR}/enum_string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mcc_mnc_itu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dynamic_memory_check.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pid_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/TLVEncoder.c
    ${CMAKE_CURRENT_SOURCE_DIR}/TLVDecoder.c
    )

if (LOG_OAI)
  set(CN_UTILS_SRC ${CN_UTILS_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/log.c)
endif (LOG_OAI)

add_library(CN_UTILS ${CN_UTILS_SRC})

###############################################################################
# Lib LFDS
###############################################################################

# TODO(amar) 7.1 is available check if we should move up from 6.1.1
set(lfds ${CMAKE_CURRENT_SOURCE_DIR}/lfds/liblfds6.1.1/liblfds611/src/)
file(GLOB lfds_queue ${lfds}/lfds611_queue/*.c)
file(GLOB lfds_ring ${lfds}/lfds611_ringbuffer/*.c)
file(GLOB lfds_slist ${lfds}/lfds611_slist/*.c)
file(GLOB lfds_stack ${lfds}/lfds611_stack/*.c)
file(GLOB lfds_freelist ${lfds}/lfds611_freelist/*.c)

include_directories(${lfds})
add_library(LFDS
    ${lfds_queue} ${lfds_ring} ${lfds_slist} ${lfds_stack} ${lfds_freelist}
    ${lfds}/lfds611_liblfds/lfds611_liblfds_abstraction_test_helpers.c
    ${lfds}/lfds611_liblfds/lfds611_liblfds_aligned_free.c
    ${lfds}/lfds611_liblfds/lfds611_liblfds_aligned_malloc.c
    ${lfds}/lfds611_abstraction/lfds611_abstraction_free.c
    ${lfds}/lfds611_abstraction/lfds611_abstraction_malloc.c
    )
