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
		"",
		"type:  5 wd-prod-ss.trafficmanager.net;type:  5 wd-prod-ss-us-east-2-fe.eastus.cloudapp.azure.com;::ffff:40.117.150.237;",
		"type:  5 a-0001.a-afdentry.net.trafficmanager.net;type:  5 dual-a-0001.a-msedge.net;::ffff:13.107.21.200;::ffff:204.79.197.200;"
	};
	std::vector<std::string> answer_addrs = {
		"::1,127.0.0.1",
		"107.20.240.232,23.21.193.169,184.72.104.138",
		"",
		"40.117.150.237",
		"13.107.21.200,204.79.197.200"
	};

	for (size_t i = 0; i < answers.size(); i++) {

		EXPECT_TRUE(DnsExtractAddressesFromAnswer(answers[i],addrs));
		EXPECT_EQ(answer_addrs[i], JOIN(addrs,','));
		addrs.clear();
	}

}
