#include "utils.h"

#include <codecvt>
#include <locale>

namespace etw {

bool ExtractCmdlinePath(const std::string &cmdline, std::string &path, std::string filenameHint) {
	if (cmdline.length() < 3) { return false; }

	// quoted path

	if (cmdline[0] == '"') {
		auto pos = cmdline.find('"', 1);
		if (pos == std::string::npos) { return true; }
		path = cmdline.substr(1, pos - 1);
		return false;
	}

	// some paths start with \??\

	size_t start = 0;
	if (cmdline.length() > 5 && cmdline[0] == '\\' && cmdline[1] == '?') {
		start = 4;
	}


	// should contain filenameHint

	if (!filenameHint.empty()) {
		auto pos = cmdline.find(filenameHint);
		if (pos != std::string::npos) {
			path = cmdline.substr(start, pos + filenameHint.size() - start);
			return false;
		}
	}

	// ideally paths with spaces are quoted, but not always

	auto pos = cmdline.find(' ');

	if (pos == std::string::npos) { return true; }

	// not quoted, but could have spaces
	auto last_pathsep_pos = cmdline.rfind('\\');
	if (last_pathsep_pos != std::string::npos) {
		auto last_space_pos = cmdline.find(' ',last_pathsep_pos);
		if (last_space_pos != std::string::npos) {
			pos = last_space_pos;
		}
	}

	path = cmdline.substr(start, pos - start);

	return false;
}


std::string guidToString(GUID guid) {
  char tmp[64];
  snprintf(tmp,sizeof(tmp),"%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", 
  guid.Data1, guid.Data2, guid.Data3, 
  guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
  guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
  return std::string(tmp);
}



static std::wstring_convert<
	std::codecvt_utf8_utf16<wchar_t, 0x10ffff, std::little_endian>>
	converter;

 std::wstring stringToWstring(const std::string& src) {
	std::wstring utf16le_str;
	try {
		utf16le_str = converter.from_bytes(src);
	}
	catch (std::exception /* e */) {
	}

	return utf16le_str;
}

 std::string wstringToString(const wchar_t* src) {
	if (src == nullptr) {
		return std::string("");
	}

	std::string utf8_str = converter.to_bytes(src);
	return utf8_str;
}

} // namespace etw
