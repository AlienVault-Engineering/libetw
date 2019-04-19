#include <gtest/gtest.h>

#include <string>
#include <vector>

extern bool DnsExtractAddressesFromAnswer(const std::string answer, std::vector<std::string> &dest);

class DnsTest : public ::testing::Test {
protected:
	virtual void SetUp() {  }
};

std::string JOIN(std::vector<std::string> &a, char delim) {
	std::string s;
	for (std::string entry : a) {
		if (!s.empty()) { s += delim;  }
		s += entry;
	}
	return s;
}

TEST_F(DnsTest, simple) {
	std::vector<std::string> addrs;
	std::vector<std::string> answers = {
		"::1;::ffff:127.0.0.1;",
		"::ffff:107.20.240.232;::ffff:23.21.193.169;::ffff:184.72.104.138;",
		""
	};
	std::vector<std::string> answer_addrs = {
		"::1,127.0.0.1",
		"107.20.240.232,23.21.193.169,184.72.104.138",
		""
	};

	for (size_t i = 0; i < sizeof(answers); i++) {

		EXPECT_TRUE(DnsExtractAddressesFromAnswer(answers[i],addrs));
		EXPECT_EQ(answer_addrs[i], JOIN(addrs,','));
		addrs.clear();
	}

}
