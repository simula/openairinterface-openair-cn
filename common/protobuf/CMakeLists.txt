# Copyright (c) 2016-present, Facebook, Inc.
# All rights reserved.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree. An additional grant
# of patent rights can be found in the PATENTS file in the same directory.

find_package(Protobuf REQUIRED)
add_compile_options(-std=c++11)
set(OPENAIRCN_DIR "/home/vagrant/openair-cn")
set(PROTO_PATH "${OPENAIRCN_DIR}/protos")
set(OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")

set(PROTO_FILES
    "${PROTO_PATH}/common.proto"
    "${PROTO_PATH}/service303.proto"
    "${PROTO_PATH}/metricsd.proto"
)

set(GRPC_PROTO_FILES
    "${PROTO_PATH}/service303.proto"
    )

list(APPEND PROTO_SRCS "")
list(APPEND PROTO_HDRS "")

# Build prometheus metrics protos
list(APPEND PROTO_SRCS ${OUTPUT_DIR}/protos/metrics.pb.cc)
list(APPEND PROTO_HDRS ${OUTPUT_DIR}/protos/metrics.pb.h)

get_filename_component(ABS_PATH ${PROTO_PATH}/prometheus/metrics.proto ABSOLUTE)
add_custom_command(
    OUTPUT "${OUTPUT_DIR}/protos/metrics.pb.cc"
           "${OUTPUT_DIR}/protos/metrics.pb.h"
    COMMAND ${PROTOBUF_PROTOC_EXECUTABLE}
    ARGS -I ${PROTO_PATH}/prometheus
    --cpp_out=${OUTPUT_DIR}/protos ${PROTO_PATH}/prometheus/metrics.proto
    DEPENDS ${ABS_PATH} ${PROTOBUF_PROTOC_EXECUTABLE}
    COMMENT "Running C++ protobuf compiler on metrics.proto"
    VERBATIM )

# build protobuf c++ bindings
foreach(PROTO_FILE ${PROTO_FILES})
    get_filename_component(ABS_PATH ${PROTO_FILE} ABSOLUTE)
    get_filename_component(BASE_NAME ${PROTO_FILE} NAME_WE)
    list(APPEND PROTO_SRCS ${OUTPUT_DIR}/protos/${BASE_NAME}.pb.cc)
    list(APPEND PROTO_HDRS ${OUTPUT_DIR}/protos/${BASE_NAME}.pb.h)

    add_custom_command(
        OUTPUT "${OUTPUT_DIR}/protos/${BASE_NAME}.pb.cc"
               "${OUTPUT_DIR}/protos/${BASE_NAME}.pb.h"
        COMMAND ${PROTOBUF_PROTOC_EXECUTABLE}
        ARGS -I ${OPENAIRCN_DIR} -I ${PROTO_PATH}/prometheus
        --cpp_out=${OUTPUT_DIR} ${ABS_PATH}
        DEPENDS ${ABS_PATH} ${PROTOBUF_PROTOC_EXECUTABLE}
        COMMENT "Running C++ protobuf compiler on ${PROTO_FILE}"
        VERBATIM )
endforeach()

# build gRPC c++ bindings
foreach(PROTO_FILE ${GRPC_PROTO_FILES})
    get_filename_component(ABS_PATH ${PROTO_FILE} ABSOLUTE)
    get_filename_component(BASE_NAME ${PROTO_FILE} NAME_WE)

    list(APPEND PROTO_SRCS ${OUTPUT_DIR}/protos/${BASE_NAME}.grpc.pb.cc)
    list(APPEND PROTO_HDRS ${OUTPUT_DIR}/protos/${BASE_NAME}.grpc.pb.h)

    add_custom_command(
        OUTPUT "${OUTPUT_DIR}/protos/${BASE_NAME}.grpc.pb.cc"
               "${OUTPUT_DIR}/protos/${BASE_NAME}.grpc.pb.h"
        COMMAND ${PROTOBUF_PROTOC_EXECUTABLE}
        ARGS -I ${OPENAIRCN_DIR} -I ${PROTO_PATH}/prometheus
        --grpc_out=${CMAKE_CURRENT_BINARY_DIR} --plugin=protoc-gen-grpc=/usr/local/bin/grpc_cpp_plugin ${ABS_PATH}
        DEPENDS ${ABS_PATH} ${PROTOBUF_PROTOC_EXECUTABLE}
        COMMENT "Running C++ grpc compiler on ${PROTO_FILE}"
        VERBATIM )
endforeach()



include_directories("${OUTPUT_DIR}")

add_library(MAGMA_PROTOBUF
    ${PROTO_SRCS}
    ${PROTO_HDRS}
    )

  target_link_libraries(MAGMA_PROTOBUF
    protobuf grpc++ grpc dl prometheus-cpp
    )
