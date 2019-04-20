
// Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include "etw_session_base.h"

#include <sddl.h> // ConvertSidToStringSid
#include <wbemidl.h>
#include <wmistr.h>

#include <codecvt>
#include <locale>
#include <unordered_map>

#include "etw_userdata_reader.h"
#include "utils.h"

#define DBG  if (0)

DEFINE_GUID(MyGuid, 0xe613b5E3, 0xcd88, 0x4f74,
	0x8E, 0x33, 0x4E, 0x35, 0xce, 0x8c, 0xe0, 0x5E);

DEFINE_GUID(/* 6AD52B32-D609-4BE9-AE07-CE8DAE937E39 */
	IPCProviderGuid,
	0x6AD52B32,	0xD609,	0x4BE9,	0xAE, 0x07,	0xCE, 0x8D, 0xAE, 0x93,	0x7E, 0x39);

// struct for EventId=5|6, OpCode=1

struct RpcClientCallStart {
	GUID iterfaceUUID;
	int32_t procNum;
	int32_t protocol;
	// wstring NetworkAddress
	// wstring Endpoint
};

#define MIN(a,b) ((a) < (b) ? (a) : (b))

// local structures to keep track of pipe access counts

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


class IPCTraceSessionImpl : public ETWTraceSessionBase {
 public:
  /*
   * constructor
   */
  IPCTraceSessionImpl() : ETWTraceSessionBase("libetw.IpcTrace", "Microsoft-Windows-RPC", IPCProviderGuid, MyGuid) {
	  m_doFlush = false;
  }

  virtual void SetListener(SPETWIPCListener listener)  {
    m_listener = listener;
  }


  virtual void OnRecordEvent(PEVENT_RECORD pEvent) override ;

 private:

  void reportChangedCounts();

  SPETWIPCListener m_listener;
  uint64_t m_lastReportTime{ 0L };
  std::unordered_map<RpcPipeEventKey, RpcPipeEventInfo> m_mapEvents;

};


enum RPC_PROTO {
	RPC_PROTO_TCP=1,
	RPC_PROTO_NAMED_PIPE=2,
	RPC_PROTO_LRPC=3
};

#define REPORT_INTERVAL_SEC 60

void IPCTraceSessionImpl::reportChangedCounts() {
  for (auto it = m_mapEvents.begin(); it != m_mapEvents.end(); ) {
	  auto &info = it->second;
	  auto diff = info.num - info.numLast;
	  if (diff > 0) {
		  if (m_listener) {
			  m_listener->onPipeAccess(info.key.pid, info.key.is_server != 0, info.key.pipe_name, diff);
		  }
		  info.numLast = info.num;
		  it++;
	  }
	  else {
		  m_mapEvents.erase(it++);
	  }
  }
}

//---------------------------------------------------------------------
// OnRecordEvent()
// Called from StaticEventRecordCallback(), which is called by
// ETW once ProcessEvent() is called.
//---------------------------------------------------------------------
void IPCTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent) {
  DWORD status = ERROR_SUCCESS;
  HRESULT hr = S_OK;

  if (IsEqualGUID(pEvent->EventHeader.ProviderId, IPCProviderGuid)) {
	  auto &ed = pEvent->EventHeader.EventDescriptor;

	  DBG printf("V:%d %d id:%d opcode:%d\n", (int)ed.Version, pEvent->EventHeader.ProcessId, (int)ed.Id, (int)ed.Opcode);
	  
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
			  std::string pipename = etw::wstringToString(pipenameW.c_str());

			  RpcPipeEventKey key(pEvent->EventHeader.ProcessId, isServerCall, pipename.c_str());
			  auto fit = m_mapEvents.find(key);
			  if (fit != m_mapEvents.end()) {
				  fit->second.num++;
				  // TODO: on interval, report count
				  auto nowSec = pEvent->EventHeader.TimeStamp.QuadPart / 10000000;
				  if ((nowSec - m_lastReportTime) > REPORT_INTERVAL_SEC) {
					  if (m_lastReportTime != 0L) {
						  reportChangedCounts();
					  }
					  m_lastReportTime = nowSec;
				  }

			  }
			  else {
				  m_mapEvents[key] = RpcPipeEventInfo(key);
				  if (m_listener) {
					  m_listener->onPipeAccess(pEvent->EventHeader.ProcessId, isServerCall, pipename, 1);
				  }
				  if (m_lastReportTime == 0) {
					  m_lastReportTime = pEvent->EventHeader.TimeStamp.QuadPart / 10000000;
				  }
			  }
		  }
	  }
  }
}



SPETWTraceSession ETWIPCTraceInstance(SPETWIPCListener listener, std::string &errmsgs) {

  auto traceSession = std::make_shared<IPCTraceSessionImpl>();
  
  if (nullptr == traceSession) {
	  return nullptr;
  }
  if (traceSession->Setup() == false) {
    errmsgs = traceSession->m_errMsgs;
	return nullptr;
  }
  traceSession->SetListener(listener);

  return std::static_pointer_cast<ETWTraceSession>(traceSession);
}
