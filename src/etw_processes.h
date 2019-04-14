#pragma once

#include <stdint.h>

#include "etw_userdata_reader.h"

struct Process_TypeGroup1_V2
{
	uint32_t UniqueProcessKey;
	uint32_t ProcessId;
	uint32_t ParentId;
	uint32_t SessionId;
	int32_t  ExitStatus;
	//object UserSID;
	//string ImageFileName;
	//string CommandLine;

};

struct Process_TypeGroup1_V3
{
	uint32_t UniqueProcessKey;
	uint32_t ProcessId;
	uint32_t ParentId;
	uint32_t SessionId;
	int32_t  ExitStatus;
	uint32_t DirectoryTableBase;
	//object UserSID;
	//string ImageFileName;
	//string CommandLine;

};

struct Process_TypeGroup1_V4
{
	uint64_t UniqueProcessKey;
	uint32_t ProcessId;
	uint32_t ParentId;
	uint32_t SessionId;
	int32_t ExitStatus;
	uint64_t DirectoryTableBase;
	uint32_t Flags;
	//uint8_t UserSIDVarlen[];
	//char zImageFileName[];
	//wchar_t zCommandLine[];
	//wchar_t PackageFullName[];
	//wchar_t ApplicationId[];
};

struct Process_TypeGroup1 {
	virtual uint64_t getUniqueProcessKey() = 0;
	virtual uint32_t getProcessId() = 0;
	virtual uint32_t getParentId() = 0;
	virtual uint32_t getSessionId() = 0;
	virtual int32_t  getExitStatus() = 0;
	virtual size_t   size() = 0;
};

/*
 * A C Macro to generate Version specific struct with
 * generic interface.
 */
#define PROCESS_TYPEGROUP1_WRAPPER(VER) \
struct Process_TypeGroup1_Wrapper_V##VER : public Process_TypeGroup1 \
{ \
  Process_TypeGroup1_Wrapper_V##VER(void *pUserData) : p_((Process_TypeGroup1_V##VER *)pUserData) { } \
  Process_TypeGroup1_V##VER *p_; \
  uint64_t getUniqueProcessKey() override { return p_->UniqueProcessKey; } \
  uint32_t getProcessId() override { return p_->ProcessId; }  \
  uint32_t getParentId() override { return p_->ParentId; }    \
  uint32_t getSessionId() override { return p_->SessionId; }  \
  int32_t getExitStatus() override { return p_->ExitStatus; } \
  size_t size() override { return sizeof(*p_); } \
};

// define wrapper for each known version

PROCESS_TYPEGROUP1_WRAPPER(2)
PROCESS_TYPEGROUP1_WRAPPER(3)
PROCESS_TYPEGROUP1_WRAPPER(4)

/**
 * @brief The application uses an instance of Wrapper to have
 *       version independent access to ETW struct.
 */
struct Process_TypeGroup1_Wrapper {
	Process_TypeGroup1_Wrapper(int version, void *pUserData, size_t userDataLen) : version_(version),
		v2(pUserData), v3(pUserData), v4(pUserData), p_(selectVersion(version)),
		varlenReader_((char *)pUserData, p_->size(), userDataLen) {
	}
	Process_TypeGroup1* get() {
		return p_;
	}
	/**
	 * @brief Reads variable length fields available in Process_TypeGroup1
	 *        structs.  The imageFileName and commandLine can be nullptr
	 *        to effectively skip without copying the value. Since varlen
	 *        fields have a specific order, it was decided to hide the
	 *        ETWVarlenReader access behind this function.
	 */
	bool readVarlenFields(PSID &psid, std::string *imageFileName, std::wstring *commandLine) {
		return varlenReader_.readSID(psid) || varlenReader_.readString(imageFileName) || varlenReader_.readWString(commandLine);
	}

protected:

	Process_TypeGroup1* selectVersion(int version) {
		switch (version) {
		case 4:
			return &v4;
		case 3:
			return &v3;
		default:
			return &v2;
		}
	}

	int version_;
	Process_TypeGroup1_Wrapper_V2 v2;
	Process_TypeGroup1_Wrapper_V3 v3;
	Process_TypeGroup1_Wrapper_V4 v4;
	Process_TypeGroup1 *p_;
	ETWVarlenReader varlenReader_;
};

