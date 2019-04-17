#pragma once

#include <stdint.h>

#include <memory>
#include <string>


class ETWTraceSession
{
public:
	/*
	 * Run()
	 * Will block until Stop() is called, so this should be called from a dedicated thread.
	 */
	virtual void Run()=0;

	/**
	 * Sets a flag, so that next time ETW calls our internal BufferCallback() we will
	 * return FALSE.
	 */
	virtual void Stop()=0;

};
typedef std::shared_ptr<ETWTraceSession> SPETWTraceSession;

/*
 * IPC Trace notifies of named pipe access
 */
struct ETWIPCListener {
  virtual void onPipeAccess(uint32_t pid, bool isServer, std::string name, uint64_t num) = 0;
};
typedef std::shared_ptr<ETWIPCListener> SPETWIPCListener;

SPETWTraceSession ETWIPCTraceInstance(SPETWIPCListener listener, std::string &errmsgs);

/*
 * Volume Trace notifies on volume mount / unmount.
 */
struct ETWVolumeListener {
  virtual void onVolumeMounted(uint32_t pid, std::string path) = 0;
  virtual void onVolumeUnmounted(uint32_t pid, std::string path) = 0;
};
typedef std::shared_ptr<ETWVolumeListener> SPETWVolumeListener;

SPETWTraceSession ETWVolumeTraceInstance(SPETWVolumeListener listener, std::string &errmsgs);

/*
 * FileIO Listener notifies of NamedPipeCreate() calls
 */
struct ETWFileIOListener {
  virtual void onNamedPipeCreate(uint32_t pid, std::string name) = 0;
};
typedef std::shared_ptr<ETWFileIOListener> SPETWFileIOListener;

SPETWTraceSession ETWFileIOTraceInstance(SPETWFileIOListener listener, std::string &errmsgs);

