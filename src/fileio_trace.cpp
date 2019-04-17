
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

DEFINE_GUID(MyGuid, 0xe671b573, 0xcd88, 0x4f74,
	0x87, 0x73, 0x47, 0x75, 0xc3, 0x8c, 0xe0, 0x77);

DEFINE_GUID(/* D75D8303-6C21-4BDE-9C98-ECC6320F9291 */
	FileIOProviderGuid, 0xD75D8303, 0x6C21, 0x4BDE,
	0x7C, 0x98, 0xEC, 0xC6, 0x32, 0x0F, 0x92, 0x91);

class FileIOTraceSessionImpl : public ETWTraceSessionBase {
 public:
  /*
   * constructor
   */
  FileIOTraceSessionImpl() : ETWTraceSessionBase("libetw.FileIOTraceSess", FileIOProviderGuid, MyGuid) {
  }

  void SetListener(SPETWFileIOListener listener)  {
    listener_ = listener;
  }


  void OnRecordEvent(PEVENT_RECORD pEvent) override;

 private:

  SPETWFileIOListener listener_;
};


#define KEYWORD_CREATE_NAMED_PIPE 0x0000000000000002L


//---------------------------------------------------------------------
// OnRecordEvent()
// Called from StaticEventRecordCallback(), which is called by
// ETW once ProcessEvent() is called.
//---------------------------------------------------------------------
void FileIOTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent) {
  DWORD status = ERROR_SUCCESS;
  HRESULT hr = S_OK;

  if (IsEqualGUID(pEvent->EventHeader.ProviderId, FileIOProviderGuid)) {
	  auto &ed = pEvent->EventHeader.EventDescriptor;
	  printf("V:%d %d id:%d opcode:%d keyword:0x%llx\n", (int)ed.Version, pEvent->EventHeader.ProcessId, (int)ed.Id, (int)ed.Opcode, ed.Keyword);
  }
}

SPETWTraceSession ETWFileIOTraceInstance(SPETWFileIOListener listener, std::string &errs) {

  // TODO: check for existing session

  auto traceSession = std::make_shared<FileIOTraceSessionImpl>();
  
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
