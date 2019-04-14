#include <etw_kernel_trace.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

class MyKernelTraceListener : public ETWProcessListener, public ETWTcpListener {
public:
	void onProcessEnd(uint64_t uniqueId, uint32_t pid, uint32_t parentPid) override {
		printf("ProcEND pid:%lu parentPid:%lu uuid:%llx\n", pid, parentPid, uniqueId);
	}
	void onProcessStart(uint64_t uniqueId, uint32_t pid, uint32_t parentPid,
		std::string usersidstr, std::string filename, const std::string &commandLine) override {
		printf("ProcNEW pid:%lu parentPid:%lu uuid:%llx user:%s file:%s cmdline:%s\n",
			pid, parentPid, uniqueId, usersidstr.c_str(),
			filename.c_str(), commandLine.c_str());
	}
	/*
	* Notifies of IPv4 and IPv6 TCP Connect and Accept.
	*/
	void onTcpConnect(bool isV6, bool isAccept, uint32_t pid,
		std::string srcaddrstr, uint16_t srcport,
		std::string dstaddrstr, uint16_t dstport) override {
		printf("TCP %d %s pid:%lu %s_%d -> %s_%d\n", (isV6 ? 6 : 4),
			(isAccept ? "Accept " : "Connect"), pid,
			srcaddrstr.c_str(), srcport,
			dstaddrstr.c_str(), dstport);
	}
};

//-------------------------------------------------------------------------
// Function for kernel trace thread.  It will call Run(), which
// calls ProcessTrace() Windows API call.
//-------------------------------------------------------------------------
static DWORD WINAPI KernelTraceThreadFunc(LPVOID lpParam)
{
	KernelTraceSession *kernelTraceSession = (KernelTraceSession*)lpParam;
	kernelTraceSession->Run();
	return 0;
}

int main(int argc, char *argv[])
{
	auto pListener = std::make_shared<MyKernelTraceListener>();
	SPKernelTraceSession spTrace = KernelTraceInstance();
//	auto pListener = std::shared_ptr<ETWProcessListener>(pListener);
	spTrace->SetListener(std::static_pointer_cast<ETWProcessListener>(pListener));
	spTrace->SetListener(std::static_pointer_cast<ETWTcpListener>(pListener));

	DWORD dwThreadIdKernel = 0;

	HANDLE kernelTraceThread = CreateThread(NULL, 0, KernelTraceThreadFunc, spTrace.get(), 0, &dwThreadIdKernel);

	printf("press a key to stop\n");
	getc(stdin);

	spTrace->Stop();

	// Give it a second...

	Sleep(1000);

	// Finally, terminate the threads

	TerminateThread(kernelTraceThread, 0);
}