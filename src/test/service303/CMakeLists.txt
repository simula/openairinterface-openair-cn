include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/service303")
include_directories(${PROJECT_SOURCE_DIR}/utils/bstr)

find_package(Protobuf REQUIRED)
add_compile_options(-std=c++11)

include_directories("${PROJECT_SOURCE_DIR}/../common/service303")
include_directories("${PROJECT_SOURCE_DIR}/../common/service_registry")
include_directories("${COMMON_BIN_DIR}/protobuf")

add_library(SERVICE303_TEST
    Service303Client.h
    Service303Client.cpp
    )

add_executable(service303_test test_service303.cpp)
add_executable(metrics_test test_metrics.cpp)

target_link_libraries(service303_test
    SERVICE303 SERVICE303_LIB SERVICE303_TEST BSTR gtest gtest_main pthread
    )

target_link_libraries(metrics_test
    SERVICE303 SERVICE303_LIB SERVICE303_TEST BSTR gtest gtest_main pthread
    )

add_test(test_metrics metrics_test)
add_test(test_service303_integration service303_test)
