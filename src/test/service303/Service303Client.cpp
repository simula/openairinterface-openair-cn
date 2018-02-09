/**
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

#include <protos/service303.grpc.pb.h>
#include <protos/metricsd.pb.h>
#include <protos/common.pb.h>

#include "Service303Client.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using magma::Service303;
using magma::Service303Client;
using magma::Void;
using magma::MetricsContainer;
using magma::ServiceInfo;

Service303Client::Service303Client(const std::shared_ptr<Channel>& channel)
  : stub_(Service303::NewStub(channel)) {}


int Service303Client::GetServiceInfo(ServiceInfo* response) {
  Void request;
  ClientContext context;
  Status status = stub_->GetServiceInfo(&context, request, response);
  if (!status.ok()) {
    std::cout << "GetServiceInfo fails with code " << status.error_code()
      << ", msg: " << status.error_message() << std::endl;
    return -1;
  }
  return 0;
}


int Service303Client::GetMetrics(MetricsContainer* response) {
  ClientContext context;
  Void request;
  Status status = stub_->GetMetrics(&context, request, response);
  if (!status.ok()) {
    std::cout << "GetMetrics fails with code " << status.error_code()
      << ", msg: " << status.error_message() << std::endl;
    return -1;
  }
  return 0;
}
