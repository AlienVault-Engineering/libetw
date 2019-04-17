#include <etw_kernel_trace.h>
#include <etw_providers.h>
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

class MyPipeTraceListener : public ETWIPCListener {
	void onPipeAccess(uint32_t pid, bool isServer, std::string pipename, uint64_t num) override {
		fprintf(stdout, "NamedPipe %s pid:%lu pipe:'%s' num:%llu\n", (isServer ? "SERVER" : "CLIENT"),
			pid, pipename.c_str(), num);
	}
};

struct MyFileIOListener : ETWFileIOListener {
	void onNamedPipeCreate(uint32_t pid, std::string name) override {
		fprintf(stdout, "CreateNamedPipe pid:%lu name:%s\n", pid, name.c_str());
	}
};

//-------------------------------------------------------------------------
// Function for kernel trace thread.  It will call Run(), which
// calls ProcessTrace() Windows API call.
//-------------------------------------------------------------------------
static DWORD WINAPI KernelTraceThreadFunc(LPVOID lpParam)
{
	KernelTraceSession *pTraceSession = (KernelTraceSession*)lpParam;
	pTraceSession->Run();
	return 0;
}
static DWORD WINAPI TraceThreadFunc(LPVOID lpParam)
{
	ETWTraceSession *pTraceSession = (ETWTraceSession*)lpParam;
	pTraceSession->Run();
	return 0;
}

int main(int argc, char *argv[])
{
	SPKernelTraceSession spKernelTrace;
	HANDLE kernelTraceThread = 0;
	auto pListener = std::make_shared<MyKernelTraceListener>();
	SPETWTraceSession spPipeTrace, spDnsTrace, spFileIoTrace, spVolumeTrace;
	DWORD dwThreadIdPipes = 0;
	DWORD dwThreadIdKernel = 0;
	DWORD dwThreadIdDns = 0;
	DWORD dwThreadIdFile = 0;
	HANDLE pipeTraceThread = 0;
	HANDLE dnsTraceThread = 0;
	HANDLE fileioTraceThread = 0;

	std::string errmsgs;

	auto pPipeListener = std::make_shared<MyPipeTraceListener>();
	if (false) {
		errmsgs.clear();
		spKernelTrace = KernelTraceInstance();
		spKernelTrace->SetListener(std::static_pointer_cast<ETWProcessListener>(pListener));
		spKernelTrace->SetListener(std::static_pointer_cast<ETWTcpListener>(pListener));

		kernelTraceThread = CreateThread(NULL, 0, KernelTraceThreadFunc, spKernelTrace.get(), 0, &dwThreadIdKernel);

		if (!errmsgs.empty()) {
			fputs(errmsgs.c_str(), stderr);
		}
	}
	if (true) {
		errmsgs.clear();
		spPipeTrace = ETWIPCTraceInstance(std::static_pointer_cast<ETWIPCListener>(pPipeListener), errmsgs);
		if (spPipeTrace) {
			pipeTraceThread = CreateThread(NULL, 0, TraceThreadFunc, spPipeTrace.get(), 0, &dwThreadIdPipes);
		}
		if (!errmsgs.empty()) {
			fputs(errmsgs.c_str(), stderr);
		}
	}
	/*
	if (false) {
		spDnsTrace = ETWDnsTraceInstance();
		if (spDnsTrace) {
			dnsTraceThread = CreateThread(NULL, 0, TraceThreadFunc, spDnsTrace.get(), 0, &dwThreadIdDns);
		}
	}*/
	if (false) {
		errmsgs.clear();
		auto pFileIOListener = std::make_shared<MyFileIOListener>();
		spFileIoTrace = ETWFileIOTraceInstance(pFileIOListener, errmsgs);
		if (spFileIoTrace) {
			fileioTraceThread = CreateThread(NULL, 0, TraceThreadFunc, spFileIoTrace.get(), 0, &dwThreadIdFile);
		}
		if (!errmsgs.empty()) {
			fputs(errmsgs.c_str(), stderr);
		}
	}
	//printf("press a key to stop\n");
	//getc(stdin);
	while (true) {
		Sleep(1000);
	}

	if (spKernelTrace) {
		spKernelTrace->Stop();
	}

	// Give it a second...

	Sleep(1000);

	// Finally, terminate the threads

	if (spKernelTrace) {
		TerminateThread(kernelTraceThread, 0);
	}
}