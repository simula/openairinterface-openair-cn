#include "ServiceRegistrySingleton.h"
#include <gtest/gtest.h>

using ::testing::Test;
using magma::ServiceRegistrySingleton;

// Tests the GetGrpcChannel
TEST(TestServiceRegistry, TestGetGrpcCloudChannelArgs) {
  auto args = ServiceRegistrySingleton::Instance()->GetCreateGrpcChannelArgs(
    "logger",
    "cloud");
  EXPECT_EQ(args.ip, "127.0.0.1");
  EXPECT_EQ(args.port, "8443");
  EXPECT_EQ(args.authority, "logger-controller.magma.test");

}


TEST(TestServiceRegistry, TestGetGrpcLocalChannelArgs) {
  auto args = ServiceRegistrySingleton::Instance()->GetCreateGrpcChannelArgs(
    "mobilityd",
    "local");
  EXPECT_EQ(args.ip, "127.0.0.1");
  EXPECT_EQ(args.port, "60051");
  EXPECT_EQ(args.authority, "mobilityd.local");
}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
