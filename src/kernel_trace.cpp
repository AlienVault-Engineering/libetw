
#include "etw_kernel_trace.h"

// Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include <WinSock2.h>
#include <evntcons.h>
#include <evntrace.h>
#include <guiddef.h>
#include <sddl.h> // ConvertSidToStringSid
#include <wbemidl.h>
#include <wmistr.h>

#include <codecvt>
#include <locale>
#include <string>
#include <vector>

#include "etw_processes.h"
#include "etw_network.h"
//#include "osquery/core/windows/wmi.h" // wstringToString

inline std::string SIDString(PSID psid) {
  std::string retval;
  LPTSTR cstr = nullptr;
  if (nullptr != psid && ConvertSidToStringSid(psid, &cstr)) {
    retval = cstr;
    LocalFree(cstr);
  }
  return retval;
}

// From ProcessHacker etwmon.c
ULONG ETWControlSession(
	_In_ ULONG ControlCode, PEVENT_TRACE_PROPERTIES pTraceProps, TRACEHANDLE sessionHandle, LPSTR loggerName
)
{
	// If we have a session handle, we use that instead of the logger name.

	pTraceProps->LogFileNameOffset = 0; // make sure it is 0, otherwise ControlTrace crashes

	return ControlTrace(
		sessionHandle,
		sessionHandle == 0 ? NULL : loggerName,
		pTraceProps,
		ControlCode
	);
}


class KernelTraceSessionImpl;

static SPKernelTraceSession gKernelTraceSession;

class KernelTraceSessionImpl : public KernelTraceSession {
 public:
  /*
   * constructor
   */
  KernelTraceSessionImpl() : m_stopFlag(false), m_startTraceHandle(0L) {}

  virtual void Run();
  virtual void Stop() {
    m_stopFlag = true;
	if (pTraceProps_) {
		ETWControlSession(EVENT_TRACE_CONTROL_STOP, pTraceProps_, m_startTraceHandle, (LPSTR)actualSessionName_.c_str());
	}

  }
  virtual void SetListener(SPETWProcessListener listener) override {
    processListener_ = listener;
  }
  virtual void SetListener(SPETWTcpListener listener) override {
    tcpListener_ = listener;
  }


  bool Setup();
  void OnRecordEvent(PEVENT_RECORD pEvent);
  BOOL OnBuffer(PEVENT_TRACE_LOGFILE pBuffer);



 private:
  void onProcessEvent(PEVENT_RECORD pEvent);
  void onTcpEvent(PEVENT_RECORD pEvent);

  bool m_stopFlag;
  TRACEHANDLE m_startTraceHandle;
  ULONG64 m_tStart;
  SPETWProcessListener processListener_;
  SPETWTcpListener tcpListener_;
  PEVENT_TRACE_PROPERTIES pTraceProps_{ 0 };
  std::string actualSessionName_;
};

//---------------------------------------------------------------------
// Run()
// Will block until SetStopFlag is called, so this should be called from a
// dedicated thread.
//---------------------------------------------------------------------
void KernelTraceSessionImpl::Run() {
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
            0xe611b50f,
            0xcd88,
            0x4f74,
            0x84,
            0x33,
            0x48,
            0x35,
            0xce,
            0x8c,
            0xe0,
            0x52);

DEFINE_GUID(/* 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c */
            ProcessProviderGuid,
            0x3d6fa8d0,
            0xfe05,
            0x11d0,
            0x9d,
            0xda,
            0x00,
            0xc0,
            0x4f,
            0xd7,
            0xba,
            0x7c);
DEFINE_GUID(/* 9A280AC0-C8E0-11D1-84E2-00C04FB998A2 */
            TcpProviderGuid,
            0x9A280AC0,
            0xc8e0,
            0x11d1,
            0x84,
            0xe2,
            0x00,
            0xc0,
            0x4f,
            0xB9,
            0x98,
            0xA2);

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


void KernelTraceSessionImpl::onProcessEvent(PEVENT_RECORD pEvent) {
  switch (pEvent->EventHeader.EventDescriptor.Opcode) {
  case EVENT_TRACE_TYPE_END: {
    Process_TypeGroup1_Wrapper wrapper(
        pEvent->EventHeader.EventDescriptor.Version,
        pEvent->UserData,
        pEvent->UserDataLength);
    Process_TypeGroup1* pProcess = wrapper.get();
    if (processListener_) {
      processListener_->onProcessEnd(pProcess->getUniqueProcessKey(), pProcess->getProcessId(), 
        pProcess->getParentId());
    }
    break;
  }
  case EVENT_TRACE_TYPE_START: {
    Process_TypeGroup1_Wrapper wrapper(
        pEvent->EventHeader.EventDescriptor.Version,
        pEvent->UserData,
        pEvent->UserDataLength);
    Process_TypeGroup1* pProcess = wrapper.get();
    std::string imageFileName;
    std::wstring commandLineW;
    std::string commandLine;
    PSID psid = nullptr;
    if (wrapper.readVarlenFields(psid, &imageFileName, &commandLineW)) {
      //LOG(INFO) << "unable to read a variable length field";
    } else {
      if (!commandLineW.empty()) {
        commandLine = wstringToString(commandLineW.c_str());
      }
      std::string usersid = SIDString(psid);
      if (processListener_) {
        processListener_->onProcessStart(pProcess->getUniqueProcessKey(), pProcess->getProcessId(), 
          pProcess->getParentId(), usersid, imageFileName, commandLine);
      }
    }

    break;
  }
  default:
    break;
  }
}


static inline void ipaddrstr(IN6_ADDR& addr, std::string& dest) {
  char tmp[INET6_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET6, &addr, tmp, INET6_ADDRSTRLEN);
  dest = tmp;
}

static inline void ipaddrstr(uint32_t addr, std::string& dest) {
  char tmp[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &addr, tmp, INET_ADDRSTRLEN);
  dest = tmp;
}

void KernelTraceSessionImpl::onTcpEvent(PEVENT_RECORD pEvent) {
  // currently only support V2 struct defs
  if (pEvent->EventHeader.EventDescriptor.Version != 2) {
    return;
  }
  switch (pEvent->EventHeader.EventDescriptor.Opcode) {
  case EVENT_TRACE_TYPE_ACCEPT:
  case EVENT_TRACE_TYPE_CONNECT: {
    bool isAccept = (pEvent->EventHeader.EventDescriptor.Opcode ==
                     (EVENT_TRACE_TYPE_ACCEPT));
    auto pData = (TcpIp_TypeGroup2_V2*)pEvent->UserData;
    std::string dstaddrstr;
    std::string srcaddrstr;
    ipaddrstr(pData->daddr, dstaddrstr);
    ipaddrstr(pData->saddr, srcaddrstr);
	if (tcpListener_) {
		tcpListener_->onTcpConnect(false, isAccept, pData->PID,
			srcaddrstr, ntohs(pData->sport),
			dstaddrstr, ntohs(pData->dport));
	}
    break;
  }
  case EVENT_TRACE_TYPE_ACCEPT + 16:
  case EVENT_TRACE_TYPE_CONNECT + 16: {
    bool isAccept = (pEvent->EventHeader.EventDescriptor.Opcode ==
                     (EVENT_TRACE_TYPE_ACCEPT + 16));
    auto pData = (TcpIp_TypeGroup4_V2*)pEvent->UserData;
    std::string dstaddrstr;
    std::string srcaddrstr;
    ipaddrstr(pData->daddr, dstaddrstr);
    ipaddrstr(pData->saddr, srcaddrstr);

    if (tcpListener_) {
      tcpListener_->onTcpConnect(true, isAccept, pData->PID,
		      srcaddrstr, ntohs(pData->sport),
		      dstaddrstr, ntohs(pData->dport));
    }
    break;
  }
  case EVENT_TRACE_TYPE_DISCONNECT:
  case EVENT_TRACE_TYPE_RECONNECT: {
    auto pData = (TcpIp_TypeGroup1_V2*)pEvent->UserData;
    break;
  }
  case EVENT_TRACE_TYPE_DISCONNECT + 16:
  case EVENT_TRACE_TYPE_RECONNECT + 16: {
    auto pData = (TcpIp_TypeGroup3_V2*)pEvent->UserData;
    break;
  }
  // case EVENT_TRACE_TYPE_RECEIVE:
  // case EVENT_TRACE_TYPE_SEND:
  default:
    break;
  }
  // LOG(INFO) << "NetTcpEvent " << pEvent->EventHeader.EventDescriptor.Opcode;
}


//---------------------------------------------------------------------
// OnRecordEvent()
// Called from StaticEventRecordCallback(), which is called by
// ETW once ProcessEvent() is called.
//---------------------------------------------------------------------
void KernelTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent) {
  DWORD status = ERROR_SUCCESS;
  HRESULT hr = S_OK;

  if ((pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) == 0) {
    return; // not a classic ETW message
  }
  /*
          // skip past events flood at startup
          ULONG64 ts;
          ToULL(pEvent->EventHeader.TimeStamp, ts);
          if (ts < m_tStart) {
                  return;
          }
          */

  if (IsEqualGUID(pEvent->EventHeader.ProviderId, ProcessProviderGuid)) {
    onProcessEvent(pEvent);
  }
  else if (IsEqualGUID(pEvent->EventHeader.ProviderId, TcpProviderGuid)) {
	  onTcpEvent(pEvent);
  } else {
    // LOG(INFO) << "unexpected provider";
  }
}

//---------------------------------------------------------------------
// Called from StaticEventBufferCallback(), which is called by
// ETW loop in ProcessSession().
//
// The only reason we implement this is to signal to ETW
// to terminate this session's ProcessSession() loop.
//---------------------------------------------------------------------
BOOL KernelTraceSessionImpl::OnBuffer(PEVENT_TRACE_LOGFILE buf) {
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
  //PEVENT_TRACE_PROPERTIES petp =      (PEVENT_TRACE_PROPERTIES)&vecEventTraceProps[0];

  memset(petp, 0, sizeof(EVENT_TRACE_PROPERTIES));

  petp->Wnode.BufferSize = bufferSize;
  petp->LogFileNameOffset = 0;
  petp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  if (true) { // WindowsVersion >= WINDOWS_8) {
    petp->Wnode.Guid = MyGuid;
  } else {
    petp->Wnode.Guid = SystemTraceControlGuid; // For kernel trace, have to use
                                               // this shared GUID
  }

  petp->Wnode.ClientContext = 1; // use QPC for timestamp resolution
  petp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;

  petp->MinimumBuffers = 1;
  petp->FlushTimer = 1;
  petp->EnableFlags = dwEnableFlags;

  petp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  // petp->LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE; // Windows 8+

  // Call StartTrace() to setup a realtime ETW context associated with Guid +
  // mySessionName
  // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364117(v=vs.85).aspx

  ULONG status = ::StartTrace(&traceSessionHandle, mySessionName.c_str(), petp);
  if (ERROR_ALREADY_EXISTS == status) {
    // might not have flags / settings you want.
    return true;
  } else if (status != ERROR_SUCCESS) {
    //LOG(ERROR) << "StartTraceW returned " << status;
    traceSessionHandle = 0L;
    return false;
  } else {
    // Enable Trace

    status = EnableTraceEx(&SystemTraceControlGuid,
                           NULL,
                           traceSessionHandle,
                           1,
                           0,
                           0x10,
                           0,
                           0,
                           NULL);
    //		status = EnableTraceEx2(traceSessionHandle, &SystemTraceControlGuid,
    //EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0,
    //NULL);

    // TODO: check status
    if (status != ERROR_SUCCESS) {
      //LOG(ERROR) << "EnableTraceEx2 failed with status " << status;
    }
  }
  return true;
}

//---------------------------------------------------------------------
// Function wrapper to call our class OnRecordEvent()
//---------------------------------------------------------------------
static VOID WINAPI StaticRecordEventCallback(PEVENT_RECORD pEvent) {
  if (0L == gKernelTraceSession)
    return;
  auto p = gKernelTraceSession.get();
  return ((KernelTraceSessionImpl*)p)->OnRecordEvent(pEvent);
}

//---------------------------------------------------------------------
// Function wrapper to call our class OnBuffer()
//---------------------------------------------------------------------
static BOOL WINAPI StaticBufferEventCallback(PEVENT_TRACE_LOGFILE buf) {
  if (nullptr == gKernelTraceSession)
    return FALSE;
  auto p = gKernelTraceSession.get();
  return ((KernelTraceSessionImpl*)p)->OnBuffer(buf);
}

//---------------------------------------------------------------------
// Establish a session.
// Returns true on success, false otherwise.
//---------------------------------------------------------------------
bool KernelTraceSessionImpl::Setup() {
  actualSessionName_ = KERNEL_LOGGER_NAME;

  FILETIME ft;
  ::GetSystemTimeAsFileTime(&ft);
  ToULL(ft, m_tStart);

  // This is where you wask for Process information, TCP, etc.  Look at
  // StartTraceW() docs.

  DWORD kernelTraceOptions = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_NETWORK_TCPIP 
	  | EVENT_TRACE_FLAG_FILE_IO;

  ULONG status = StartTraceSession(
	  actualSessionName_, kernelTraceOptions, this->m_startTraceHandle, pTraceProps_);

  if (status == false)
    return false;

  ETWControlSession(EVENT_TRACE_CONTROL_FLUSH, pTraceProps_, m_startTraceHandle, (LPSTR)actualSessionName_.c_str());


  // Identify the log file from which you want to consume events
  // and the callbacks used to process the events and buffers.

  EVENT_TRACE_LOGFILE trace;
  TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
  ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
  trace.LoggerName = (LPSTR)actualSessionName_.c_str();
  trace.LogFileName = (LPSTR)NULL;

  // hook up our callback functions

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
    //LOG(ERROR) << "OpenTrace() failed with " << err;
    goto cleanup;
  }

  return true;

cleanup:
  CloseTrace(this->m_startTraceHandle);
  return false;
}

//---------------------------------------------------------------------
// KernelTraceInstance()
// KernelTraceSession is a singleton.  Will return existing instance or
// create a new one before return.
//
// Returns NULL if setup failed, instance otherwise.
//---------------------------------------------------------------------
SPKernelTraceSession KernelTraceInstance() {
  if (gKernelTraceSession != 0L)
    return gKernelTraceSession;

  auto pobj = new KernelTraceSessionImpl();
  
  if (nullptr == pobj || pobj->Setup() == false) {
    //LOG(ERROR) << "KernelTraceSession Setup failed";
	if (pobj) {
		delete pobj;
	}
    return gKernelTraceSession;
  }

  gKernelTraceSession = std::shared_ptr<KernelTraceSession>(pobj);

  return gKernelTraceSession;
}
