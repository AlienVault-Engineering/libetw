
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


//#include "etw_userdata_reader.h"
#include "etw_session_base.h"

#define DBG if (0)

DEFINE_GUID(/* e611b50f-cd88-4f74-8433-4835be8ce052 */
	MyGuid, 0xe611b5EE, 0xcd88,0x4f74,
	0x8E, 0x33, 0x4E, 0x35, 0xce, 0x8c, 0xe0, 0x5E);

DEFINE_GUID(/* 058DD951-7604-414D-A5D6-A56D35367A46 */
	FileIO2ProviderGuid, 0x058DD951, 0x7604, 0x414D,
	0xA5, 0xD6, 0xA5, 0x6D, 0x35, 0x36, 0x7A, 0x46);

class VolumeTraceSessionImpl : public ETWTraceSessionBase {
 public:
  /*
   * constructor
   */
  VolumeTraceSessionImpl() : ETWTraceSessionBase("libetw.FileIO2","File Kernel Trace; Operation Set 2", FileIO2ProviderGuid, MyGuid) {
  }

  virtual void SetListener(SPETWVolumeListener listener)  {
    m_listener = listener;
  }

  void OnRecordEvent(PEVENT_RECORD pEvent);

 private:
	 SPETWVolumeListener m_listener;

};


//---------------------------------------------------------------------
// OnRecordEvent()
// Called from StaticEventRecordCallback(), which is called by
// ETW once ProcessEvent() is called.
//---------------------------------------------------------------------
void VolumeTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent) {
  DWORD status = ERROR_SUCCESS;
  HRESULT hr = S_OK;

  if (IsEqualGUID(pEvent->EventHeader.ProviderId, FileIO2ProviderGuid)) {
	  auto &ed = pEvent->EventHeader.EventDescriptor;
	  printf("V:%d %d id:%d opcode:%d\n", (int)ed.Version, pEvent->EventHeader.ProcessId, (int)ed.Id, (int)ed.Opcode);
	  
  }
}


SPETWTraceSession ETWVolumeTraceInstance(SPETWVolumeListener listener, std::string errmsgs) {

  // TODO: check for existing session

  auto spTraceSession = std::make_shared<VolumeTraceSessionImpl>();
  
  if (nullptr == spTraceSession || spTraceSession->Setup() == false) {
    //LOG(ERROR) << "KernelTraceSession Setup failed";
	return nullptr;
  }
  spTraceSession->SetListener(listener);
  errmsgs = spTraceSession->m_errMsgs;

  return std::static_pointer_cast<ETWTraceSession>(spTraceSession);
}
