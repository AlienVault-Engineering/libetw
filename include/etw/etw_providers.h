#pragma once

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

struct ETWSessionInfo {
	std::string sessionName;
	std::string providerName;
	std::string providerGuid;
};

/*
 * Runtime flags
 * NOTE: provider defined flags should begin at bit 8.
 *
 * If session is running, setting ETWFlagDropAllEvents
 * will instruct provider to drop all events.  This is
 * useful for pausing all processing if application
 * determines system load is high.
 */
#define ETWFlagDropAllEvents (1<<0)

#define ETWFlagTcpIgnoreLocal (1<<8)

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

	/**
	 * Returns information about provider and session
	 */
	virtual ETWSessionInfo getSessionInfo() = 0;

	/**
	  * Application can use flags defined above, or for each
	  * provider to alter runtime behavior.
	  */
	virtual void setFlags(uint32_t flags) = 0;

	virtual uint32_t getFlags() = 0;

	virtual std::string getErrors() = 0;
};
typedef std::shared_ptr<ETWTraceSession> SPETWTraceSession;


struct ETWProcessListener {
	virtual void onProcessEnd(uint64_t uniqueId, uint32_t pid, uint32_t parentPid) = 0;
	virtual void onProcessStart(uint64_t uniqueId, uint32_t pid, uint32_t parentPid,
		void *pusersid, std::string filename, const std::string &commandLine) = 0;
};
typedef std::shared_ptr<ETWProcessListener> SPETWProcessListener;

struct ETWTcpListener {
	/*
	* Notifies of IPv4 and IPv6 TCP Connect and Accept.
	*/
	virtual void onTcpConnect(bool isV6, bool isAccept, uint32_t pid,
		std::string srcaddrstr, uint16_t srcport,
		std::string dstaddrstr, uint16_t dstport) = 0;

	/*
	* Notifies of IPv4 and IPv6 TCP Reconnect.
	* Such as connection failures.
	* Examples:
	* - ssh to system that does not have port 22 open or
	* service is down.
	* - browse to url of host that is not serving http(s) on that port.
	* - tcp port scan.
	*/
	virtual void onTcpReconnect(bool isV6, uint32_t pid,
		std::string srcaddrstr, uint16_t srcport,
		std::string dstaddrstr, uint16_t dstport) = 0;
};
typedef std::shared_ptr<ETWTcpListener> SPETWTcpListener;

SPETWTraceSession KernelTraceInstance(SPETWProcessListener procListener, SPETWTcpListener netListener, std::string &errmsgs);

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

/*
 * Windows-DNS-Client events
 */
struct ETWDNSListener {
	virtual void onDnsAddress(std::string hostname, std::vector<std::string> &addrs) = 0;
};
typedef std::shared_ptr<ETWDNSListener> SPETWDNSListener;

SPETWTraceSession ETWDnsTraceInstance(SPETWDNSListener listener, std::string &errmsgs);

/*
 * Microsoft-Windows-USB-USBHUB3 (PnP)
 */
struct ETWUSBHubListener {
	virtual void onUSBPlugged(std::string devtype, std::string vendorid, std::string deviceid) = 0;
};
typedef std::shared_ptr<ETWUSBHubListener> SPETWUSBHubListener;

SPETWTraceSession ETWUSBHubTraceInstance(SPETWUSBHubListener listener, std::string &errs);