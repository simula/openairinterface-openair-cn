set(ITTI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/itti)
include_directories(${PROJECT_SOURCE_DIR}/utils/lfds/liblfds6.1.1/liblfds611/inc)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/itti)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/message_utils)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ITTI_ANALYZER)
include_directories(${PROJECT_SOURCE_DIR}/utils)
include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)
include_directories(${PROJECT_SOURCE_DIR}/utils/hashtable)

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

if (${ENABLE_ITTI})
  set(ITTI_FILES
      # add .h files if depend on (this one is generated)
      ${ITTI_DIR}/intertask_interface.h
      ${ITTI_DIR}/intertask_interface.c
      ${ITTI_DIR}/backtrace.c
      ${ITTI_DIR}/memory_pools.c
      ${ITTI_DIR}/signals.c
      ${ITTI_DIR}/timer.c
      ${CMAKE_CURRENT_SOURCE_DIR}/message_utils/service303_message_utils.c
      )
  if (${ENABLE_ITTI_ANALYZER})
    set(ITTI_FILES
        ${ITTI_FILES}
        ${ITTI_DIR}/intertask_interface_dump.c
        ${CMAKE_CURRENT_BINARY_DIR}/messages_xml.h)

    include_directories("${CMAKE_CURRENT_BINARY_DIR}")
  endif (${ENABLE_ITTI_ANALYZER})

  add_library(ITTI ${ITTI_FILES})

  set(ITTI_LIB ITTI PARENT_SCOPE)
endif (${ENABLE_ITTI})

set(GCOV_LIB gcov)

#######################################################################
# itti symbolic debug print require to generate a specific include file
#######################################################################

if (${ENABLE_ITTI_ANALYZER})
  # retrieve the compiler options to send it to gccxml
  get_directory_property(DirDefs COMPILE_DEFINITIONS)
  foreach (d ${DirDefs})
    list(APPEND itti_compiler_options "-D${d}")
  endforeach ()
  get_directory_property(DirDefs INCLUDE_DIRECTORIES)
  foreach (d ${DirDefs})
    list(APPEND itti_compiler_options "-I${d}")
  endforeach ()

  set(ITTI_H ${ITTI_DIR}/intertask_interface_types.h)
  add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/messages.xml
      COMMAND gccxml ${itti_compiler_options} -fxml=${CMAKE_CURRENT_BINARY_DIR}/messages.xml ${ITTI_H}
      DEPENDS ${S1AP_OAI_generated}
  )

  add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/messages_xml.h
      COMMAND sed -e 's/ *//'   -e 's/\"/\\\\\"/g' -e 's/^/\"/' -e 's/$$/\\\\n\"/' ${CMAKE_CURRENT_BINARY_DIR}/messages.xml >
      ${CMAKE_CURRENT_BINARY_DIR}/messages_xml.h
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/messages.xml
  )
endif (${ENABLE_ITTI_ANALYZER})
