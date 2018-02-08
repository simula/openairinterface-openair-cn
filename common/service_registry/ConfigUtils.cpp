/**
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

#include <string>
#include <iostream>


#include "ConfigUtils.h"

namespace magma {
  const std::string ConfigUtils::CONFIG_DIR = "/etc/magma/";


YAML::Node ConfigUtils::LoadServiceConfig(const std::string& service_name){
  const std::string filePath = CONFIG_DIR + service_name + ".yml";
  YAML::Node config = YAML::LoadFile(filePath);
  return config;
}

}
