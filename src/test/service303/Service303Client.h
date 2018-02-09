/**
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */
#ifndef SERVICE303_CLIENT_H
#define SERVICE303_CLIENT_H

#include <grpc++/grpc++.h>

#include <protos/service303.grpc.pb.h>

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using magma::Service303;
using magma::MetricsContainer;
using magma::ServiceInfo;

namespace magma {

/**
 * gRPC client for Service303
 */
class Service303Client {
  public:
    explicit Service303Client(const std::shared_ptr<Channel>& channel);

    /**
     * Get Service303 Info
     *
     * @param response: a pointer to the ServiceInfo object to populate
     * @return 0 on success, -1 on failure
     */
    int GetServiceInfo(ServiceInfo* response);

    /**
     * Get Metrics from server
     *
     * @param response: the MetricsContainer instance to populate
     * @return 0 on success, -1 on failure
     */
    int GetMetrics(MetricsContainer* response);

  private:
    std::shared_ptr<Service303::Stub> stub_;
};

} // namespace magma
#endif // SERVICE303_CLIENT_H
