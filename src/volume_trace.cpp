
#include "etw_providers.h"

// Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <guiddef.h>
#include <sddl.h> // ConvertSidToStringSid
#include <wbemidl.h>
#include <wmistr.h>

#include <codecvt>
#include <locale>
#include <unordered_map>

#include "etw_userdata_reader.h"

#define DBG if (0)

class VolumeTraceSessionImpl : public ETWTraceSession {
 public:
  /*
   * constructor
   */
  VolumeTraceSessionImpl() : m_stopFlag(false), m_startTraceHandle(0L) {
	  logfile_ = fopen("\\temp\\pipedemo.log", "w");
  }

  virtual void Run();
  virtual void Stop() {
    m_stopFlag = true;
	if (pTraceProps_) {
		//ETWControlSession(EVENT_TRACE_CONTROL_STOP, pTraceProps_, m_startTraceHandle, (LPSTR)actualSessionName_.c_str());
	}

  }
  virtual void SetListener(SPETWVolumeListener listener)  {
    listener_ = listener;
  }


  bool Setup();
  void OnRecordEvent(PEVENT_RECORD pEvent);
  BOOL OnBuffer(PEVENT_TRACE_LOGFILE pBuffer);



 private:

  bool m_stopFlag;
  TRACEHANDLE m_startTraceHandle;
  ULONG64 m_tStart;
  SPETWVolumeListener listener_;
  PEVENT_TRACE_PROPERTIES pTraceProps_{ 0 };
  std::string actualSessionName_;
  FILE *logfile_;
};

static std::shared_ptr <VolumeTraceSessionImpl> gPipeTraceSession;

//---------------------------------------------------------------------
// Run()
// Will block until SetStopFlag is called, so this should be called from a
// dedicated thread.
//---------------------------------------------------------------------
void VolumeTraceSessionImpl::Run() {
  m_stopFlag = false;

  // Process Trace - blocks until BufferCallback returns FALSE, or

  ULONG status = ProcessTrace(&m_startTraceHandle, 1, 0, 0);
  if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
    //LOG(ERROR) << "ProcessTrace() failed with " << status;
    CloseTrace(m_startTraceHandle);
  }
}

DEFINE_GUID(/* e611b50f-cd88-4f74-8433-4835be8ce052 */
	MyGuid,
	0xe611b5EE,
	0xcd88,
	0x4f74,
	0x8E,
	0x33,
	0x4E,
	0x35,
	0xce,
	0x8c,
	0xe0,
	0x5E);
DEFINE_GUID(/* 6AD52B32-D609-4BE9-AE07-CE8DAE937E39 */
    IPCProviderGuid,
	0x6AD52B32,
    0xD609,
    0x4BE9,
    0xAE,
    0x07,
    0xCE,
    0x8D,
    0xAE,
    0x93,
    0x7E,
    0x39);

inline void ToULL(const FILETIME& ft, ULONGLONG& uft) {
  ULARGE_INTEGER uli;
  uli.LowPart = ft.dwLowDateTime;
  uli.HighPart = ft.dwHighDateTime;
  uft = uli.QuadPart;
}

inline void ToULL(const LARGE_INTEGER& uli, ULONGLONG& uft) {
  //	ULARGE_INTEGER uli;
  //	uli.LowPart = ft.dwLowDateTime;
  //	uli.HighPart = ft.dwHighDateTime;
  uft = uli.QuadPart;
}

struct RpcClientCallStart {
	GUID iterfaceUUID;
	int32_t procNum;
	int32_t protocol;
	// wstring NetworkAddress
	// wstring Endpoint
};

#define MIN(a,b) ((a) < (b) ? (a) : (b))

struct RpcPipeEventKey {
	uint32_t pid;
	uint8_t  is_server;
	char     pipe_name[27];
	RpcPipeEventKey() : pid(0), is_server(0) {
		memset(pipe_name, 0, sizeof(pipe_name));
	}
	RpcPipeEventKey(uint32_t _pid, bool _is_server, const std::string name) : pid(_pid), is_server(_is_server) {
		memset(pipe_name, 0, sizeof(pipe_name));
		strncpy(pipe_name, name.c_str(), MIN(name.size(), sizeof(pipe_name) - 1));
		pipe_name[sizeof(pipe_name) - 1] = 0;
	}
	
	bool operator==(const RpcPipeEventKey &other) const
	{
		return (pid == other.pid
			&& is_server == other.is_server
			&& strcmp(pipe_name, other.pipe_name) == 0);
	}
	/*
	std::size_t operator()(const RpcPipeEventKey& k) const noexcept
	{
		uint64_t* p = (uint64_t*)&pid;
		auto val = std::hash<uint64_t>()(*p++);
		val = (val ^ (std::hash<uint64_t>()(*p++) << 1)) >> 1;
		val = (val ^ (std::hash<uint64_t>()(*p++) << 1)) >> 1;
		val = (val ^ (std::hash<uint64_t>()(*p++) << 1));
		return val;
	}*/
};

namespace std
{
	template<> struct hash<RpcPipeEventKey>
	{
		typedef RpcPipeEventKey argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& s) const noexcept
		{
			uint64_t* p = (uint64_t*)&s.pid;
			auto val = std::hash<uint64_t>()(*p++);
			val = (val ^ (std::hash<uint64_t>()(*p++) << 1)) >> 1;
			val = (val ^ (std::hash<uint64_t>()(*p++) << 1)) >> 1;
			val = (val ^ (std::hash<uint64_t>()(*p++) << 1));
			return val;
		}
	};
}

struct RpcPipeEventInfo {
	RpcPipeEventKey key;
	uint64_t num;
	uint64_t numLast;
	RpcPipeEventInfo() : key(), num(0), numLast(0) {}
	RpcPipeEventInfo(RpcPipeEventKey k) : key(k), num(1), numLast(0) { }
};


static std::wstring_convert<
	std::codecvt_utf8_utf16<wchar_t, 0x10ffff, std::little_endian>>
	converter;

static std::wstring stringToWstring(const std::string& src) {
	std::wstring utf16le_str;
	try {
		utf16le_str = converter.from_bytes(src);
	}
	catch (std::exception /* e */) {
	}

	return utf16le_str;
}

static std::string wstringToString(const wchar_t* src) {
	if (src == nullptr) {
		return std::string("");
	}

	std::string utf8_str = converter.to_bytes(src);
	return utf8_str;
}


enum RPC_PROTO {
	RPC_PROTO_TCP=1,
	RPC_PROTO_NAMED_PIPE=2,
	RPC_PROTO_LRPC=3
};

//---------------------------------------------------------------------
// OnRecordEvent()
// Called from StaticEventRecordCallback(), which is called by
// ETW once ProcessEvent() is called.
//---------------------------------------------------------------------
void VolumeTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent) {
  DWORD status = ERROR_SUCCESS;
  HRESULT hr = S_OK;

  static std::unordered_map<RpcPipeEventKey, RpcPipeEventInfo> mapEvents;

  if (IsEqualGUID(pEvent->EventHeader.ProviderId, IPCProviderGuid)) {
	  auto &ed = pEvent->EventHeader.EventDescriptor;
//	  printf("V:%d %d id:%d opcode:%d\n", (int)ed.Version, pEvent->EventHeader.ProcessId, (int)ed.Id, (int)ed.Opcode);
	  
	  if (ed.Version != 1) {
		  DBG printf("unsupported version:%d\n", (int)ed.Version);
		  return;
	  }
	  if ((ed.Id == 6 || ed.Id == 5) && ed.Opcode == 1) {
		  bool isServerCall = (ed.Id == 6);
		  RpcClientCallStart *pData = (RpcClientCallStart*)pEvent->UserData;
		  if (pEvent->UserDataLength < sizeof(*pData)) {
			  DBG printf("invalid length\n");
			  return; // invalid
		  }
		  if (pData->protocol == RPC_PROTO_NAMED_PIPE) {
			  //GetUserPropLen(pEvent);
			  ETWVarlenReader reader((char*)pData, sizeof(*pData), pEvent->UserDataLength);
			  reader.readWString(); // network
			  std::wstring pipenameW;
			  reader.readWString(&pipenameW);
			  std::string pipename = wstringToString(pipenameW.c_str());

			  RpcPipeEventKey key(pEvent->EventHeader.ProcessId, isServerCall, pipename.c_str());
			  auto fit = mapEvents.find(key);
			  if (fit != mapEvents.end()) {
				  fit->second.num++;
			  }
			  else {
				  mapEvents[key] = RpcPipeEventInfo(key);
				  fprintf(logfile_, "NamedPipe %s pid:%lu protocol:%d pipe:'%s'\n", (isServerCall ? "SERVER" : "CLIENT"),
					  pEvent->EventHeader.ProcessId, pData->protocol, pipename.c_str());
				  fflush(logfile_);
			  }
/*
			  if (pipename.find("wkssvc") != std::string::npos) {

			  } else {//if (pipename.find("Peppa") != std::string::npos) {
				  printf("NamedPipe %s pid:%lu protocol:%d pipe:'%s'\n", (isServerCall ? "SERVER" : "CLIENT"),
					  pEvent->EventHeader.ProcessId, pData->protocol, pipename.c_str());
			  }*/
		  }
	  }
	  else if (ed.Opcode == 12 || ed.Opcode == 24 || ed.Opcode == 44 || ed.Opcode == 45) {
		  fprintf(logfile_,"got id:%d op:%d\n", ed.Id, ed.Opcode);
	  }
  }
  //else {
    // LOG(INFO) << "unexpected provider";
  //}
}

//---------------------------------------------------------------------
// Called from StaticEventBufferCallback(), which is called by
// ETW loop in ProcessSession().
//
// The only reason we implement this is to signal to ETW
// to terminate this session's ProcessSession() loop.
//---------------------------------------------------------------------
BOOL VolumeTraceSessionImpl::OnBuffer(PEVENT_TRACE_LOGFILE buf) {
  if (m_stopFlag)
    return FALSE; // I'm done. Stop sending and exit ProcessSession()

  /*
  // TODO: is EventsLost additive, or differential?
  if (buf->EventsLost > 0) {
          LOG(INFO) << " events_lost:" << buf->EventsLost;
  }*/

  return TRUE; // keep sending me events!
}

//---------------------------------------------------------------------
// Called from Setup()
//---------------------------------------------------------------------
static bool StartTraceSession(std::string &mySessionName,
	DWORD dwEnableFlags,
	TRACEHANDLE& traceSessionHandle,
	PEVENT_TRACE_PROPERTIES &petp
	) {
  size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (mySessionName.length() + 1) * sizeof(mySessionName[0]);

  petp = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);

  memset(petp, 0, sizeof(EVENT_TRACE_PROPERTIES));

  petp->Wnode.BufferSize = bufferSize;
  petp->LogFileNameOffset = 0;
  petp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  petp->Wnode.Guid = MyGuid;

  petp->Wnode.ClientContext = 1; // use QPC for timestamp resolution
  petp->Wnode.Flags = 0 | WNODE_FLAG_TRACED_GUID;

  petp->MinimumBuffers = 1;
  petp->FlushTimer = 1;
  petp->EnableFlags = dwEnableFlags ;

  petp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  // petp->LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE; // Windows 8+

  // Call StartTrace() to setup a realtime ETW context associated with Guid +
  // mySessionName
  // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364117(v=vs.85).aspx

  ULONG status = ::StartTrace(&traceSessionHandle, mySessionName.c_str(), petp);
  if (ERROR_ALREADY_EXISTS == status) {
	DBG fprintf(stderr, "ALREADY EXISTS!\n");
    // might not have flags / settings you want.
    return true;
  }
  else if (status != ERROR_SUCCESS) {
	  //LOG(ERROR) << "StartTraceW returned " << status;
	  DBG fprintf(stderr, "StartTrace returned %lu\n", status);
	  traceSessionHandle = 0L;
	  return false;
  }
  // } else {
  {
    // Enable Trace

	status = EnableTraceEx2(traceSessionHandle, &IPCProviderGuid,
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);

	if (status != ERROR_SUCCESS) {
      //LOG(ERROR) << "EnableTraceEx2 failed with status " << status;
	  DBG fprintf(stderr, "EnableTraceEx2 failed with status %lu\n", status);
	}
  }
  return true;
}

//---------------------------------------------------------------------
// Function wrapper to call our class OnRecordEvent()
//---------------------------------------------------------------------
static VOID WINAPI StaticRecordEventCallback(PEVENT_RECORD pEvent) {
  if (nullptr == gPipeTraceSession)
    return;
  return gPipeTraceSession->OnRecordEvent(pEvent);
}
/*
static VOID WINAPI StaticEventCallback(PEVENTMSG pEvent) {
	if (nullptr == gPipeTraceSession)
		return;
	printf("Event\n");
	return;
//	return gPipeTraceSession->OnRecordEvent(pEvent);
}
*/

//---------------------------------------------------------------------
// Function wrapper to call our class OnBuffer()
//---------------------------------------------------------------------
static BOOL WINAPI StaticBufferEventCallback(PEVENT_TRACE_LOGFILE buf) {
  if (nullptr == gPipeTraceSession)
    return FALSE;
  return gPipeTraceSession->OnBuffer(buf);
}

//---------------------------------------------------------------------
// Establish a session.
// Returns true on success, false otherwise.
//---------------------------------------------------------------------
bool VolumeTraceSessionImpl::Setup() {
  actualSessionName_ = "AV Microsoft-Windows-RPC";

  FILETIME ft;
  ::GetSystemTimeAsFileTime(&ft);
  ToULL(ft, m_tStart);

  ULONG status = StartTraceSession(
	  actualSessionName_, 0, this->m_startTraceHandle, pTraceProps_);

  if (status == false)
    return false;

  //ETWControlSession(EVENT_TRACE_CONTROL_FLUSH, pTraceProps_, m_startTraceHandle, (LPSTR)actualSessionName_.c_str());


  // Identify the log file from which you want to consume events
  // and the callbacks used to process the events and buffers.

  EVENT_TRACE_LOGFILE trace;
  TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
  ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
  trace.LoggerName = (LPSTR)actualSessionName_.c_str();
  trace.LogFileName = (LPSTR)NULL;

  // hook up our callback functions
//  trace.EventCallback = (PEVENT_CALLBACK)(StaticEventCallback);
  trace.EventRecordCallback =
      (PEVENT_RECORD_CALLBACK)(StaticRecordEventCallback);
  trace.BufferCallback =
      (PEVENT_TRACE_BUFFER_CALLBACK)(StaticBufferEventCallback);
  // trace.Context = this; // passes to EventRecordCallback, but only works in
  // Vista+

  trace.ProcessTraceMode =
      PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;

  // Open Trace

  this->m_startTraceHandle = OpenTrace(&trace);
  if (INVALID_PROCESSTRACE_HANDLE == this->m_startTraceHandle) {
    DWORD err = GetLastError();
	DBG fprintf(stderr, "OpenTrace() failed with err:%d\n", err);
    //LOG(ERROR) << "OpenTrace() failed with " << err;
    goto cleanup;
  }

  return true;

cleanup:
  CloseTrace(this->m_startTraceHandle);
  return false;
}
#include <memory>

SPETWTraceSession ETWVolumeTraceInstance(SPETWVolumeListener listener) {

  // TODO: check for existing session

  gPipeTraceSession = std::make_shared<VolumeTraceSessionImpl>();
  
  if (nullptr == gPipeTraceSession || gPipeTraceSession->Setup() == false) {
    //LOG(ERROR) << "KernelTraceSession Setup failed";
	return nullptr;
  }
  gPipeTraceSession->SetListener(listener);

  return std::static_pointer_cast<ETWTraceSession>(gPipeTraceSession);
}
