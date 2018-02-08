/**
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */
#pragma once

#include <string>
#include "yaml-cpp/yaml.h"

namespace magma {

/**
 * ConfigUtils is a helper class to parse proc files for process information
 */
class ConfigUtils final {

  public:
    /*
     * Load service configuration from file.
     *
     * @return YAML::Node a Node representation of the file.
     */
    static YAML::Node LoadServiceConfig(const std::string& service_name);


  private:
    static const std::string CONFIG_DIR;

};

}
