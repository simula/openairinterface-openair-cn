# Copyright (c) 2016-present, Facebook, Inc.
# All rights reserved.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree. An additional grant
# of patent rights can be found in the PATENTS file in the same directory.

add_compile_options(-std=c++11)


add_library(SERVICE_REGISTRY
    ServiceRegistrySingleton.h
    ServiceRegistrySingleton.cpp
    ConfigUtils.h
    ConfigUtils.cpp
    )

  target_link_libraries(SERVICE_REGISTRY
     grpc++ dl yaml-cpp
    )
