# Copyright (c) 2016-present, Facebook, Inc.
# All rights reserved.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree. An additional grant
# of patent rights can be found in the PATENTS file in the same directory.

find_package(Protobuf REQUIRED)
add_compile_options(-std=c++11)

set(OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")

set(PROTO_FILES
    "${PROTO_PATH}/common.proto"
    "${PROTO_PATH}/service303.proto"
    "${PROTO_PATH}/metricsd.proto"
)

include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)
include_directories("${OUTPUT_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/../common/service303")

add_library(SERVICE303
    service303.h
    service303.cpp
    )

  target_link_libraries(SERVICE303
    SERVICE303_LIB
    )
