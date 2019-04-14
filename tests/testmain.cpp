#include <gtest/gtest.h>
#include <string>
using namespace std;

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int status= RUN_ALL_TESTS();
  return status;
}

class MiscTest : public ::testing::Test {
protected:
  virtual void SetUp() {  }
};


TEST_F(MiscTest, placeholder) {
  
  ASSERT_TRUE(true);

}
