#include "service303.h"
#include <gtest/gtest.h>
#include "MetricsRegistry.h"
#include <prometheus/registry.h>


using io::prometheus::client::MetricFamily;
using prometheus::Registry;
using prometheus::BuildCounter;
using prometheus::detail::CounterBuilder;
using magma::service303::MetricsRegistry;
using ::testing::Test;

// Tests the MetricsRegistry properly initializes and retrieves metrics
TEST_F(Test, TestMetricsRegistry) {
  auto prometheus_registry = std::make_shared<Registry>();
  auto registry = MetricsRegistry<prometheus::Counter, CounterBuilder (&)()>(prometheus_registry, BuildCounter);
  EXPECT_EQ(registry.SizeFamilies(), 0);
  EXPECT_EQ(registry.SizeMetrics(), 0);

  // Create two new timeseries that will construct two families and metrics
  registry.Get("test", {});
  registry.Get("another", {{"key", "value"}});
  EXPECT_EQ(registry.SizeFamilies(), 2);
  EXPECT_EQ(registry.SizeMetrics(), 2);

  // This should retrieve the previously constructed family
  registry.Get("test", {});
  EXPECT_EQ(registry.SizeFamilies(), 2);
  EXPECT_EQ(registry.SizeMetrics(), 2);

  // Add new unique timeseries to an existing family
  registry.Get("test", {{"key","value1"}});
  registry.Get("test", {{"key","value2"}});
  EXPECT_EQ(registry.SizeFamilies(), 2);
  EXPECT_EQ(registry.SizeMetrics(), 4);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
