/**
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */
#include <string>
#include <csignal>
#include <ctime>
#include <chrono>
#include <ratio>

#include <protos/service303.grpc.pb.h>
#include <protos/service303.pb.h>
#include <protos/common.pb.h>

#include "MagmaService.h"
#include "MetricsRegistry.h"
#include "MetricsSingleton.h"
#include "ProcFileUtils.h"
#include "ServiceRegistrySingleton.h"

using grpc::Channel;
using grpc::ServerContext;
using grpc::Status;
using grpc::ServerBuilder;
using grpc::InsecureServerCredentials;
using grpc::Server;
using magma::Service303;
using magma::ServiceInfo;
using magma::Void;
using magma::service303::MetricsSingleton;
using magma::service303::MagmaService;
using io::prometheus::client::MetricFamily;
using namespace std::chrono;

MagmaService::MagmaService(const std::string& name, const std::string& version)
    : name_(name), version_(version), health_(ServiceInfo::APP_UNKNOWN),
      start_time_(steady_clock::now()) {}

void MagmaService::AddServiceToServer(grpc::Service *service) {
  builder_.RegisterService(service);
}

void MagmaService::Start() {
    setMetricsStartTime();
    builder_.RegisterService(this);
    std::string service_addr = magma::ServiceRegistrySingleton::Instance()
      ->GetServiceAddrString(name_);
    builder_.AddListeningPort(service_addr,
                              grpc::InsecureServerCredentials());
    server_ = builder_.BuildAndStart();
    server_->Wait(); // Blocking call
}

void MagmaService::Stop() {
  server_->Shutdown();
}

Status MagmaService::GetServiceInfo(
    ServerContext* context, const Void* request, ServiceInfo* response) {
  response->set_name(name_);
  response->set_version(version_);
  response->set_state(ServiceInfo::ALIVE);
  response->set_health(health_);
  return Status::OK;
}

Status MagmaService::StopService(
    ServerContext* context, const Void* request, Void* response) {
  std::raise(SIGTERM);
  return Status::OK;
}

Status MagmaService::GetMetrics(
    ServerContext* context, const Void* request, MetricsContainer* response) {
  // Set all common metrics
  setSharedMetrics();

  MetricsSingleton& instance = MetricsSingleton::Instance();
  const std::vector<MetricFamily>& collected = instance.registry_->Collect();
  for (auto it = collected.begin(); it != collected.end(); it++) {
    MetricFamily* family = response->add_family();
    family->CopyFrom(*it);
  }
  return Status::OK;
}

void MagmaService::setSharedMetrics() {
  setMetricsUptime();
  setMemoryUsage();
}

void MagmaService::setApplicationHealth(
    ServiceInfo::ApplicationHealth newHealth) {
  health_ = newHealth;
}

void MagmaService::setMetricsStartTime() {
  va_list ap;
  // Use standard time to get start time
  MetricsSingleton::Instance().SetGauge("process_start_time_seconds",
    (double) std::time(nullptr), 0, ap);
}

void MagmaService::setMetricsUptime() {
  va_list ap;
  // Use monotonic time for uptime to avoid clock skew
  steady_clock::time_point t2 = steady_clock::now();
  duration<double> time_span = duration_cast<duration<double>>(
    t2 - start_time_);
  double uptime = time_span.count();
  MetricsSingleton::Instance().SetGauge("process_cpu_seconds_total", uptime, 0,
    ap);
}

void MagmaService::setMemoryUsage() {
  va_list ap;
  const ProcFileUtils::memory_info_t mem_info = ProcFileUtils::getMemoryInfo();
  MetricsSingleton::Instance().SetGauge("process_virtual_memory_bytes",
    mem_info.virtual_mem, 0, ap);
  MetricsSingleton::Instance().SetGauge("process_resident_memory_bytes",
    mem_info.physical_mem, 0, ap);
}
