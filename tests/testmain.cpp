#include <gtest/gtest.h>
#include <string>
using namespace std;

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int status= RUN_ALL_TESTS();
  fprintf(stderr, "done\n");
  return status;
}

class MiscTest : public ::testing::Test {
protected:
  virtual void SetUp() {  }
};


TEST_F(MiscTest, placeholder) {
  
  ASSERT_TRUE(true);

}

extern bool UsbParseInterfaceInfo(std::string &info, std::string &vendorid, std::string &deviceid);

TEST_F(MiscTest, usb_info_parse) {
	std::string empty_info = "";
  std::string info1 = "\\??\\USB#VID_0782&PID_5512#325903820850385#{some guid}";
  std::string vendorid, deviceid;
  EXPECT_TRUE(UsbParseInterfaceInfo(empty_info, vendorid, deviceid));
  EXPECT_FALSE(UsbParseInterfaceInfo(info1, vendorid, deviceid));
  EXPECT_EQ("0782", vendorid);
  EXPECT_EQ("5512", deviceid);
}