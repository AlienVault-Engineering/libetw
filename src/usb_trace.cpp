
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

#define DBG //if (0)

DEFINE_GUID(MyGuid, 0xe671b575, 0xcd58, 0x4f74,
	0x87, 0x75, 0x47, 0x57, 0xc3, 0x8c, 0xe0, 0x51);

DEFINE_GUID(/* 7426A56B-E2D5-4B30-BDEF-B31815C1A74A */
	USBHubProviderGuid, 0x7426A56B, 0xE2D5, 0x4B30,
	0xBD, 0xEF, 0xB3, 0x18, 0x15, 0xC1, 0xA7, 0x4A);

DEFINE_GUID(/* AC52AD17-CC01-4F85-8DF5-4DCE4333C99B */
	USBHub3ProviderGuid, 0xAC52AD17, 0xCC01, 0x4F85,
	0x8D, 0xF5, 0x4D, 0xCE, 0x43, 0x33, 0xC9, 0x9B);

DEFINE_GUID(/* C88A4EF5-D048-4013-9408-E04B7DB2814A */
	USBPortProviderGuid, 0xC88A4EF5, 0xD048, 0x4013,
	0x94, 0x08, 0xE0, 0x4B, 0x7D, 0xB2, 0x81, 0x4A);

// gleaned from Message Analyzer
#define USB_KEYWORD_PNP 0x0010

class USBHubTraceSessionImpl : public ETWTraceSessionBase {
 public:
  /*
   * constructor
   */
	 USBHubTraceSessionImpl() : ETWTraceSessionBase("libetw.usbhub3", "Microsoft-Windows-USB-USBHUB3", USBHub3ProviderGuid, MyGuid) {
	 m_keywordMatchAny = USB_KEYWORD_PNP;
 }

  void SetListener(SPETWUSBHubListener listener)  {
    m_listener = listener;
  }


  void OnRecordEvent(PEVENT_RECORD pEvent) override;

 private:

	 SPETWUSBHubListener m_listener;
};

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


// "\??\USB#VID_0782&PID_5512#325903820850385#{some guid}"
bool UsbParseInterfaceInfo(std::string &info, std::string &vendorid, std::string &deviceid) {
	int pos = -1;
	int i = -1;
	while ((pos + 2) < info.length()) {
		i++;
		auto start = pos + 1;
		size_t end = (int)info.find('#', start);

		if (end == std::string::npos) { break; }

		pos = (int)end;

		if (i == 1) {
			// tmp will be like 'VID_0782&PID_5512'
			std::string tmp = info.substr(start, (pos - start));
			std::vector<std::string> parts;
			split(tmp, '&', parts);
			if (parts.size() != 2 || parts[0].size() < 6 || parts[1].size() < 6) {
				return true;
			}
			vendorid = parts[0].substr(4);
			deviceid = parts[1].substr(4);
			return false;
		}
	}

	return true;
}


//---------------------------------------------------------------------
// OnRecordEvent()
//---------------------------------------------------------------------
void USBHubTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent) {
  DWORD status = ERROR_SUCCESS;
  HRESULT hr = S_OK;

  if (true) { //IsEqualGUID(pEvent->EventHeader.ProviderId, USBPortProviderGuid)) {
	  auto &ed = pEvent->EventHeader.EventDescriptor;
	  if (ed.Version == 1 && ed.Id == 43 && ed.Opcode == 16) {
		  // usb device plugged in
		  ETWVarlenReader reader((char*)pEvent->UserData, 0, pEvent->UserDataLength);
		  reader.addOffset(8 + 8 + 4); // pHub, pPort, portnum
		  std::wstring typeW,infoW;
		  reader.readWString(&typeW);
		  reader.readWString(&infoW);
		  std::string devtype = etw::wstringToString(typeW.c_str());
		  std::string info = etw::wstringToString(infoW.c_str());
		  std::string vendorid, deviceid;
		  if (UsbParseInterfaceInfo(info, vendorid, deviceid)) {
			  // error parsing. TODO : log
		  }
		  else {
			  if (m_listener) {
				  m_listener->onUSBPlugged(devtype, vendorid, deviceid);
			  }
			  //fprintf(stderr, "USB plugged type:'%s'  ids:'%s'\n", devtype.c_str(), devids.c_str());
		  }
	  }
	  /*
	  else {
		  printf("V:%d %d id:%d opcode:%d keyword:0x%llx\n", (int)ed.Version, pEvent->EventHeader.ProcessId, (int)ed.Id, (int)ed.Opcode, ed.Keyword);
		  extern void PrintEventInfo(PEVENT_RECORD &pEvent);
		  PrintEventInfo(pEvent);
	  }*/
  }
}

SPETWTraceSession ETWUSBHubTraceInstance(SPETWUSBHubListener listener, std::string &errs) {
  auto traceSession = std::make_shared<USBHubTraceSessionImpl>();
  
  if (nullptr == traceSession) {
    return nullptr;
  }

  if (traceSession->Setup() == false) {
    errs = traceSession->m_errMsgs;
	return nullptr;
  }

  traceSession->SetListener(listener);

  return std::static_pointer_cast<ETWTraceSession>(traceSession);
}
