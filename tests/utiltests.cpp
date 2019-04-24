#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/etw/etw_utils.h"

class UtilTest : public ::testing::Test {
protected:
	virtual void SetUp() {  }
};


std::vector<std::string> cmdlines1 = {
	"\"C:\\Windows\\SystemApps\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\MicrosoftEdge.exe\" -ServerName:MicrosoftEdge.AppXdnhjhccw3zf0j06tkg3jtqr00qdm0khc.mca"
,"\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff - ForceV1"
,"build\\windows10\\osquery\\Release\\osqueryd.exe  --flagfile = \\temp\\osqueryd.flags --config_path = \\temp\\osqueryd.conf"
,"C:/Python27/python.exe C:/Users/Bob/somedir/osquery/tools/get_platform.py"
,"C:\\Program Files (x86)\\MSBuild\\14.0\\bin\\amd64\\MSBuild.exe / nologo / nodemode:1 / nodeReuse : true"
,"C:\\ProgramData\\chocolatey\\bin\\thrift.exe  --gen cpp --gen py : no_utf8strings C : / Users / Devo / av - agent - build - windows / osquery / osquery.thrift"
,"C:\\ProgramData\\chocolatey\\lib\\cmake.portable\\tools\\cmake-3.10.2-win64-x64\\bin\\cmake.exe - E cmake_echo_color --cyan --bold \"-- Building osqueryd: C:/Users/Devo/av-agent-build-windows/osquery/build/windows10/osquery/Release/osqueryd.exe\""
};

std::vector< std::string> paths1 = {
	"C:\\Windows\\SystemApps\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\MicrosoftEdge.exe"
	,"C:\\WINDOWS\\system32\\conhost.exe"
	,"build\\windows10\\osquery\\Release\\osqueryd.exe"
	,"C:/Python27/python.exe"
	,"C:\\Program Files (x86)\\MSBuild\\14.0\\bin\\amd64\\MSBuild.exe"
	,"C:\\ProgramData\\chocolatey\\bin\\thrift.exe"
	,"C:\\ProgramData\\chocolatey\\lib\\cmake.portable\\tools\\cmake-3.10.2-win64-x64\\bin\\cmake.exe"
};

TEST_F(UtilTest, simple) {
	for (int i = 0; i < cmdlines1.size(); i++) {
		std::string path;
		bool status = etw::ExtractCmdlinePath(cmdlines1[i], path);
		EXPECT_FALSE(status);
		EXPECT_EQ(paths1[i], path);
	}
}