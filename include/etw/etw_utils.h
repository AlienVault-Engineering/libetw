#pragma once

#include <string>

namespace etw {
  bool ExtractCmdlinePath(const std::string &cmdline, std::string &path, std::string filenameHint="");
}
