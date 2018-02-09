#include <stdio.h>
#include <assert.h>
#include "service303.h"
#include "MagmaService.h"
#include "MetricsSingleton.h"

using magma::service303::MetricsSingleton;
using magma::service303::MagmaService;

static MagmaService* magma_service;

void start_service303_server(bstring name, bstring version) {
  char* name_c = bstr2cstr(name, (char) '?');
  char* version_c = bstr2cstr(version, (char) '?');
  magma_service = new MagmaService(name_c, version_c);
  magma_service->Start();
  free(name_c);
  free(version_c);
}

void stop_service303_server(void){
  magma_service->Stop();
  delete magma_service;
  magma_service = NULL;
}

void increment_counter(const char* name,
    double increment,
    size_t n_labels, ...) {
  va_list ap;
  va_start(ap, n_labels);
  MetricsSingleton::Instance().IncrementCounter(name, increment, n_labels, ap);
  va_end(ap);
}

void increment_gauge(const char* name,
    double increment,
    size_t n_labels, ...) {
  va_list ap;
  va_start(ap, n_labels);
  MetricsSingleton::Instance().IncrementGauge(name, increment, n_labels, ap);
  va_end(ap);
}

void decrement_gauge(const char* name,
    double decrement,
    size_t n_labels, ...) {
  va_list ap;
  va_start(ap, n_labels);
  MetricsSingleton::Instance().DecrementGauge(name, decrement, n_labels, ap);
  va_end(ap);
}

void set_gauge(const char* name,
    double value,
    size_t n_labels, ...) {
  va_list ap;
  va_start(ap, n_labels);
  MetricsSingleton::Instance().SetGauge(name, value, n_labels, ap);
  va_end(ap);
}

void observe_histogram(const char* name,
  double observation,
  size_t n_labels, ...) {
  va_list ap;
  va_start(ap, n_labels);
  MetricsSingleton::Instance().ObserveHistogram(name, observation, n_labels, ap);
  va_end(ap);
}

void service303_set_application_health(application_health_t health) {
  ServiceInfo::ApplicationHealth appHealthEnum;
  switch (health) {
    case APP_UNKNOWN : {
      appHealthEnum = ServiceInfo::APP_UNKNOWN;
      break;
    }
    case APP_HEALTHY : {
      appHealthEnum = ServiceInfo::APP_HEALTHY;
      break;
    }
    case APP_UNHEALTHY : {
      appHealthEnum = ServiceInfo::APP_UNHEALTHY;
      break;
    }
    default : {
      // invalid state
      assert(false);
    }
  }
  magma_service->setApplicationHealth(appHealthEnum);
}
