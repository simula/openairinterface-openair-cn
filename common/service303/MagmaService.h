/**
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */
#pragma once

#include <grpc++/grpc++.h>
#include <protos/service303.grpc.pb.h>
#include <chrono>

#include "MetricsRegistry.h"
#include "MetricsSingleton.h"

using grpc::ServerContext;
using grpc::Status;
using grpc::Server;
using magma::Service303;
using magma::ServiceInfo;
using magma::Void;
using magma::service303::MetricsSingleton;

namespace magma { namespace service303 {

/**
 * MagmaService provides the framework for all Magma services.
 * This class also implements the Service303 interface for external
 * entities to interact with the service.
 */
class MagmaService final : public Service303::Service {
  public:
    MagmaService(const std::string& name, const std::string& version);

    /**
     * Starts the gRPC Service with the service info
     */
    void Start();

    /**
     * Add an additional service to the grpc server before starting
     *
     * @param service: pointer to service to add
     */
    void AddServiceToServer(grpc::Service* service);

    /**
    * Stops the gRPC Service with the service info
    *
    */
    void Stop();

    /*
    * Returns the service info (name, version, state, etc.)
    *
    * @param context: the grpc Server context
    * @param request: void request param
    * @param response (out): the ServiceInfo response
    * @return grpc Status instance
    */
    Status GetServiceInfo(
        ServerContext* context,
        const Void* request,
        ServiceInfo* response) override;

    /*
    * Handles request to stop the service
    *
    * @param context: the grpc Server context
    * @param request: void request param
    * @param response (out): void response param
    * @return grpc Status instance
    */
    Status StopService(
        ServerContext* context,
        const Void* request,
        Void* response) override;

    /*
     * Collects timeseries samples from prometheus client interface on this
     * process
     *
     * @param context: the grpc Server context
     * @param request: void request param
     * @param response (out): container of all collected metrics
     * @return grpc Status instance
     */
     Status GetMetrics(
        ServerContext* context,
        const Void* request,
        MetricsContainer* response) override;

     /*
      * Simple setter function to set the new application health
      *
      * @param newState: the new application health you want to set
      *   One of: APP_UNKNOWN, APP_HEALTHY, APP_UNHEALTHY
      */
     void setApplicationHealth(ServiceInfo::ApplicationHealth newHealth);

  private:
    /*
     * Helper function to set the process_start_time_seconds in metricsd
     */
    void setMetricsStartTime();

    /*
     * Helper function to set all shared metrics among all services, like
     * uptime and memory usage
     */
    void setSharedMetrics();

    /*
     * Helper function to set the process_cpu_seconds_total in metrics
     */
    void setMetricsUptime();

    /*
     * Helper function to set process physical memory and virtual memory
     */
    void setMemoryUsage();

  private:
    const std::string name_;
    const std::string version_;
    const std::chrono::steady_clock::time_point start_time_;
    ServiceInfo::ApplicationHealth health_;
    std::unique_ptr<Server> server_;
    grpc::ServerBuilder builder_;
};

}} // namespace magma::service303
