// Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#include "etw_session_base.h"

#define DBG if (0)

DEFINE_GUID(
	MyGuid, 0xe611b544, 0xcd83, 0x4f74,
	0x84, 0x33, 0x44, 0x35, 0xc4, 0x8c, 0xe0, 0x11);

DEFINE_GUID(/* 1C95126E-7EEA-49A9-A3FE-A378B03DDB4D */
	DnsProviderGuid, 0x1C95126E,	0x7EEA,	0x49A9,
	0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D);


class DnsTraceSessionImpl : public ETWTraceSessionBase {
 public:
  /*
   * constructor
   */
  DnsTraceSessionImpl() : ETWTraceSessionBase("libetw.DnsTraceSess", "Microsoft-Windows-DNS-Client", DnsProviderGuid, MyGuid) {
  }

  virtual void SetListener(SPETWDNSListener listener)  {
    m_listener = listener;
  }

  void OnRecordEvent(PEVENT_RECORD pEvent) override ;

 private:
   uint64_t m_queryCount;
   uint64_t m_lastQueryCount;
   uint64_t m_lastTrackTime;
   SPETWDNSListener m_listener;
};


extern void PrintEventInfo(PEVENT_RECORD &pEvent);

static void split(const std::string& s, char seperator, std::vector<std::string> &output)
{
	std::string::size_type prev_pos = 0, pos = 0;

	while ((pos = s.find(seperator, pos)) != std::string::npos)
	{
		std::string substring(s.substr(prev_pos, pos - prev_pos));

		output.push_back(substring);

		prev_pos = ++pos;
	}

	output.push_back(s.substr(prev_pos, pos - prev_pos)); // Last word
}

struct Empty { };
#include "etw_userdata_reader.h"

//---------------------------------------------------------------------
// parse answer to extract ip addresses
//---------------------------------------------------------------------
bool DnsExtractAddressesFromAnswer(const std::string answer, std::vector<std::string> &dest) {
	int pos = -1;
	while ((pos+2) < answer.length()) {
		auto start = pos+1;
		size_t end = (int)answer.find(';',start);

		if (end == std::string::npos || (end - start) < 3) { break; }

		pos = (int)end;

		// skip entries like 'type:   5 some.cname.com'
		if (answer[start] == 't') {
			continue;
		}
		std::string addr = answer.substr(start, (pos - start));
		if (addr.find("::ffff:") != std::string::npos) {
			// ipv4
			addr = addr.substr(7);
		}
		dest.push_back(addr);
	}
}

//---------------------------------------------------------------------
// OnRecordEvent()
// Called from StaticEventRecordCallback(), which is called by
// ETW once ProcessEvent() is called.
//---------------------------------------------------------------------
void DnsTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent) {
  DWORD status = ERROR_SUCCESS;
  HRESULT hr = S_OK;

  if (true) { //IsEqualGUID(pEvent->EventHeader.ProviderId, DnsProviderGuid)) {

	  auto &ed = pEvent->EventHeader.EventDescriptor;
	  if (ed.Version == 0 && ed.Id == 3008) { // and 3020 , cache in 3018
		  m_queryCount++;
		  uint8_t *p = (uint8_t*)pEvent->UserData;

		  //printf("V:%d %d id:%d opcode:%d len:%d\n", (int)ed.Version, pEvent->EventHeader.ProcessId, (int)ed.Id, (int)ed.Opcode, (int)pEvent->UserDataLength);

		  ETWVarlenReader reader((char*)pEvent->UserData,0,pEvent->UserDataLength);
		  std::wstring queryNameW;
		  reader.readWString(&queryNameW);

		  // skip empty and localhost

		  if (queryNameW.empty() || queryNameW == L"localhost") return;

		  reader.addOffset(4 + 8 + 4); // type, options, status
		  std::wstring answerW;
		  reader.readWString(&answerW);

		  if (answerW.empty()) { return; }

		  std::string queryName = etw::wstringToString(queryNameW.c_str());
		  std::string answer = etw::wstringToString(answerW.c_str());

		  //printf("queryName:%s  answer:%s\n", queryName.c_str(), answer.c_str());
		  //PrintEventInfo(pEvent);
		  std::vector<std::string> addresses;
		  DnsExtractAddressesFromAnswer(answer, addresses);
		  
		  if (!addresses.empty() && m_listener) {
			  m_listener->onDnsAddress(queryName, addresses);
		  }
	  }
  }
}


#define KEYWORD_DNS_PACKET 0x0000080000000000L
#define KEYWORD_DNS_ADDRESS 0x0000080000000000L



SPETWTraceSession ETWDnsTraceInstance(SPETWDNSListener listener, std::string &errmsgs) {

  auto traceSession = std::make_shared<DnsTraceSessionImpl>();
  
  if (nullptr == traceSession || traceSession->Setup() == false) {
    //LOG(ERROR) << "KernelTraceSession Setup failed";
	return nullptr;
  }
  errmsgs = traceSession->m_errMsgs;
  traceSession->SetListener(listener);

  return std::static_pointer_cast<ETWTraceSession>(traceSession);
}
