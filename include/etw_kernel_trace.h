#ifndef _KERNEL_TRACE_H_
#define _KERNEL_TRACE_H_

#include <stdint.h>

#include <memory>
#include <string>

struct ETWProcessListener {
  virtual void onProcessEnd(uint64_t uniqueId, uint32_t pid, uint32_t parentPid) = 0;
  virtual void onProcessStart(uint64_t uniqueId, uint32_t pid, uint32_t parentPid,
		  std::string usersidstr, std::string filename, const std::string &commandLine) = 0;
};
typedef std::shared_ptr<ETWProcessListener> SPETWProcessListener;

struct ETWTcpListener {
  /*
   * Notifies of IPv4 and IPv6 TCP Connect and Accept.
   */
  virtual void onTcpConnect(bool isV6, bool isAccept, uint32_t pid,
     std::string srcaddrstr, uint16_t srcport,
     std::string dstaddrstr, uint16_t dstport) = 0;
};
typedef std::shared_ptr<ETWTcpListener> SPETWTcpListener;

class KernelTraceSession
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

	virtual void SetListener(SPETWProcessListener listener) = 0;
	virtual void SetListener(SPETWTcpListener listener) = 0;

};
typedef std::shared_ptr<KernelTraceSession> SPKernelTraceSession;

/**
 * KernelTraceSession is a singleton.  Will return existing instance or
 * create a new one before return.
 *
 * Returns NULL if setup failed, instance otherwise.
 */
SPKernelTraceSession KernelTraceInstance();


#endif // _KERNEL_TRACE_H_
