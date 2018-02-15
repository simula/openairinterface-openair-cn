# Copyright (c) 2016-present, Facebook, Inc.
# All rights reserved.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree. An additional grant
# of patent rights can be found in the PATENTS file in the same directory.

include_directories("${PROJECT_BINARY_DIR}/protobuf")
include_directories("${PROJECT_SOURCE_DIR}/service_registry")

add_compile_options(-std=c++11)
add_library(SERVICE303_LIB
    MagmaService.h
    MagmaService.cpp
    MetricsSingleton.h
    MetricsSingleton.cpp
    MetricsRegistry.h
    ProcFileUtils.h
    ProcFileUtils.cpp
    )

  target_link_libraries(SERVICE303_LIB SERVICE_REGISTRY MAGMA_PROTOBUF)

  # Make sure anything that includes service303 includes the proto directory
  target_include_directories(SERVICE303_LIB PUBLIC ${COMMON_BIN_DIR}/protobuf)
