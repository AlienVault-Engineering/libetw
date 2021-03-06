
#include <etw/etw_providers.h>

// Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include <WinSock2.h>
#include <evntcons.h>
#include <evntrace.h>
#include <guiddef.h>
#include <wbemidl.h>
#include <wmistr.h>

#include <string>
#include <vector>

#include "etw_session_base.h"
#include "etw_processes.h"
#include "etw_network.h"
//#include "osquery/core/windows/wmi.h" // wstringToString
#include "utils.h"

DEFINE_GUID(MyKernelGuid, 0xe611b50f, 0xcd88, 0x4f74,
	0x84, 0x33, 0x48, 0x35, 0xce, 0x8c, 0xe0, 0x52);

DEFINE_GUID(/* 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c */
	ProcessProviderGuid, 0x3d6fa8d0, 0xfe05, 0x11d0,
	0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c);

DEFINE_GUID(/* 9A280AC0-C8E0-11D1-84E2-00C04FB998A2 */
	TcpProviderGuid, 0x9A280AC0, 0xc8e0, 0x11d1,
	0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xB9, 0x98, 0xA2);



class KernelTraceSessionImpl;

static SPETWTraceSession gKernelTraceSession;

class KernelTraceSessionImpl : public ETWTraceSessionBase {
 public:
  /*
   * constructor
   */
  KernelTraceSessionImpl() : ETWTraceSessionBase(KERNEL_LOGGER_NAME /*"libetw.Kernel"*/, KERNEL_LOGGER_NAME ,SystemTraceControlGuid, MyKernelGuid) {
	  m_enableFlags = (EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_NETWORK_TCPIP);
	  m_traceLevel = 0;
	  m_doFlush = true;
  }

  virtual void SetListener(SPETWProcessListener listener)  {
    processListener_ = listener;
  }

  virtual void SetListener(SPETWTcpListener listener)  {
    tcpListener_ = listener;
  }

  void OnRecordEvent(PEVENT_RECORD pEvent);


 private:
  void onProcessEvent(PEVENT_RECORD pEvent);
  void onTcpEvent(PEVENT_RECORD pEvent);

  SPETWProcessListener processListener_;
  SPETWTcpListener tcpListener_;
};


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
        commandLine = etw::wstringToString(commandLineW.c_str());
      }
      if (processListener_) {
        processListener_->onProcessStart(pProcess->getUniqueProcessKey(), pProcess->getProcessId(), 
          pProcess->getParentId(), psid, imageFileName, commandLine);
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

static const uint32_t gIPv4LocalAddr = 0x0100007F;
static const in_addr6 gIPv6LocalAddr = {0,0,0,0, 0,0,0,0, 0,0,0,0 ,0,0,0,1};

#define EVENT_IPV6_DISCONNECT (EVENT_TRACE_TYPE_DISCONNECT+16)
#define EVENT_IPV6_RECONNECT (EVENT_TRACE_TYPE_RECONNECT+16)
#define EVENT_IPV6_CONNECT (EVENT_TRACE_TYPE_CONNECT+16)
#define EVENT_IPV6_ACCEPT (EVENT_TRACE_TYPE_ACCEPT+16)

inline bool ShouldSkipLocal(uint32_t flags, uint32_t srcaddr, uint32_t destaddr) {

	return (flags && ETWFlagTcpIgnoreLocal) &&
		(destaddr == srcaddr || destaddr == gIPv4LocalAddr);
}

inline bool ShouldSkipLocal(uint32_t flags, in6_addr srcaddr, in6_addr destaddr) {

	return (flags && ETWFlagTcpIgnoreLocal) &&
		(memcmp(&destaddr, &srcaddr, sizeof(in6_addr)) == 0
			|| memcmp(&destaddr, &gIPv6LocalAddr, sizeof(in6_addr)) == 0);
}

void KernelTraceSessionImpl::onTcpEvent(PEVENT_RECORD pEvent) {
  auto &ed = pEvent->EventHeader.EventDescriptor;

  // currently only support V2 struct defs
  if (ed.Version != 2) {
    return;
  }

  std::string dstaddrstr;
  std::string srcaddrstr;

  switch (ed.Opcode) {
  case EVENT_TRACE_TYPE_ACCEPT:
  case EVENT_TRACE_TYPE_CONNECT: {
    bool isAccept = (ed.Opcode == EVENT_TRACE_TYPE_ACCEPT);
    auto pData = (TcpIp_TypeGroup2_V2*)pEvent->UserData;

	if (ShouldSkipLocal(m_runtimeFlags, pData->saddr, pData->daddr)) {
		return;
	}

    ipaddrstr(pData->daddr, dstaddrstr);
    ipaddrstr(pData->saddr, srcaddrstr);
	if (tcpListener_) {
		tcpListener_->onTcpConnect(false, isAccept, pData->PID,
			srcaddrstr, ntohs(pData->sport),
			dstaddrstr, ntohs(pData->dport));
	}
    break;
  }
  case EVENT_IPV6_ACCEPT :
  case EVENT_IPV6_CONNECT: {
    bool isAccept = (ed.Opcode == EVENT_IPV6_ACCEPT);
    auto pData = (TcpIp_TypeGroup4_V2*)pEvent->UserData;

	if (ShouldSkipLocal(m_runtimeFlags, pData->saddr, pData->daddr)) {
		return;
	}

	ipaddrstr(pData->daddr, dstaddrstr);
    ipaddrstr(pData->saddr, srcaddrstr);

    if (tcpListener_) {
      tcpListener_->onTcpConnect(true, isAccept, pData->PID,
		      srcaddrstr, ntohs(pData->sport),
		      dstaddrstr, ntohs(pData->dport));
    }
    break;
  }
  case EVENT_TRACE_TYPE_RECONNECT: {
    auto pData = (TcpIp_TypeGroup1_V2*)pEvent->UserData;

	if (ShouldSkipLocal(m_runtimeFlags, pData->saddr, pData->daddr)) {
		return;
	}

	ipaddrstr(pData->daddr, dstaddrstr);
	ipaddrstr(pData->saddr, srcaddrstr);

	if (tcpListener_) {
		tcpListener_->onTcpReconnect(false, pData->PID,
			srcaddrstr, ntohs(pData->sport),
			dstaddrstr, ntohs(pData->dport));
	}
	break;
  }
  case EVENT_IPV6_RECONNECT: {
    auto pData = (TcpIp_TypeGroup3_V2*)pEvent->UserData;

	if (ShouldSkipLocal(m_runtimeFlags, pData->saddr, pData->daddr)) {
		return;
	}

	ipaddrstr(pData->daddr, dstaddrstr);
	ipaddrstr(pData->saddr, srcaddrstr);

	if (tcpListener_) {
		tcpListener_->onTcpReconnect(true, pData->PID,
			srcaddrstr, ntohs(pData->sport),
			dstaddrstr, ntohs(pData->dport));
	}

	break;
  }
  // WARNING: these are very frequent:
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
// KernelTraceInstance()
// KernelTraceSession is a singleton.  Will return existing instance or
// create a new one before return.
//
// Returns NULL if setup failed, instance otherwise.
//---------------------------------------------------------------------

SPETWTraceSession KernelTraceInstance(SPETWProcessListener procListener, SPETWTcpListener netListener, std::string &errmsgs) {
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

  pobj->SetListener(procListener);
  pobj->SetListener(netListener);
  errmsgs = pobj->m_errMsgs;

  gKernelTraceSession = std::shared_ptr<ETWTraceSession>(pobj);

  return gKernelTraceSession;
}
