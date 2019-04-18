#pragma once

#include <string>
#include <windows.h>

namespace etw {

  std::string guidToString(GUID g);

  std::string wstringToString(LPCWSTR wstr);
}
