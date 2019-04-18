#include "utils.h"

#include <codecvt>
#include <locale>

namespace etw {

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
