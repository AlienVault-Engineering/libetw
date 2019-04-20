#include <etw/etw_providers.h>
#include <windows.h>
#include <stdio.h>

#include <vector>

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
			(isAccept ? "Accept" : "Connect"), pid,
			srcaddrstr.c_str(), srcport,
			dstaddrstr.c_str(), dstport);
	}
	void onTcpReconnect(bool isV6, uint32_t pid,
		std::string srcaddrstr, uint16_t srcport,
		std::string dstaddrstr, uint16_t dstport) override {
		printf("TCP %d %s pid:%lu %s_%d -> %s_%d\n", (isV6 ? 6 : 4),
			"RECONNECT", pid,
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

struct MyVolumeListener : public ETWVolumeListener{
	void onVolumeMounted(uint32_t pid, std::string path) {
		fprintf(stdout, "MOUNT pid:%lu path:%s\n", pid, path.c_str());

	}
	void onVolumeUnmounted(uint32_t pid, std::string path) {
		fprintf(stdout, "UNmount pid:%lu path:%s\n", pid, path.c_str());
	}
};

struct MyDNSListener : public ETWDNSListener {
	void onDnsAddress(std::string hostname, std::vector<std::string> &addrs) override {
		std::string s;
		for (std::string addr : addrs) {
			s += addr + ",";
		}
		fprintf(stdout, "DNS '%s' => %s\n", hostname.c_str(), s.c_str());
	}
};

struct MyUsbHubListener : public ETWUSBHubListener {
	void onUSBPlugged(std::string devtype, std::string vendorid, std::string deviceid) override {
		fprintf(stdout, "USB Plugged vendorid:%s deviceid:%s type:%s\n", vendorid.c_str(), deviceid.c_str(), devtype.c_str());
	}
};


static DWORD WINAPI TraceThreadFunc(LPVOID lpParam)
{
	ETWTraceSession *pTraceSession = (ETWTraceSession*)lpParam;
	pTraceSession->Run();
	return 0;
}

void printErrs(std::string &errmsgs)
{
	if (errmsgs.empty()) {
		return;
	}
	fputs(errmsgs.c_str(), stderr);
	errmsgs.clear();
}

struct TraceSessionThread {
	SPETWTraceSession session;
	HANDLE hThread;
	DWORD threadId;
};

static std::vector<TraceSessionThread> sessionThreads;

static void runTraceThread(SPETWTraceSession spTraceSession) {
	if (nullptr == spTraceSession) {
		fprintf(stderr, "null trace session\n");
		return;
	}
	// append new entry and link to it
	sessionThreads.push_back(TraceSessionThread());
	TraceSessionThread & entry = sessionThreads[sessionThreads.size() - 1];
	entry.session = spTraceSession;
	entry.hThread = CreateThread(NULL, 0, TraceThreadFunc, spTraceSession.get(), 0, &entry.threadId);
}

int main(int argc, char *argv[])
{
	auto pListener = std::make_shared<MyKernelTraceListener>();
	std::string errmsgs;

	if (true) {
		printf("Starting 'Kernel Trace'\n");
		auto spKernelTrace = KernelTraceInstance(std::static_pointer_cast<ETWProcessListener>(pListener),
			std::static_pointer_cast<ETWTcpListener>(pListener), errmsgs);

		spKernelTrace->setFlags(ETWFlagTcpIgnoreLocal);

		runTraceThread(spKernelTrace);
		printErrs(errmsgs);
	}
	if (false) {
		printf("Starting 'IPC Trace'\n");
		auto pPipeListener = std::make_shared<MyPipeTraceListener>();
		auto spPipeTrace = ETWIPCTraceInstance(std::static_pointer_cast<ETWIPCListener>(pPipeListener), errmsgs);
		runTraceThread(spPipeTrace);
		printErrs(errmsgs);
	}
	if (false) {
		printf("Starting 'DNS Client Trace'\n");
		auto listener = std::make_shared<MyDNSListener>();
		auto spTrace = ETWDnsTraceInstance(listener, errmsgs);
		runTraceThread(spTrace);
		printErrs(errmsgs);
	}
	if (false) {
		printf("Starting 'USB Hub Trace'\n");
		auto spTrace = ETWUSBHubTraceInstance(std::make_shared<MyUsbHubListener>(), errmsgs);
		runTraceThread(spTrace);
		printErrs(errmsgs);
	}
	/*
	if (false) {
		printf("Starting 'File Kernel Trace;Set 1'\n");
		auto pFileIOListener = std::make_shared<MyFileIOListener>();
		auto spFileIoTrace = ETWFileIOTraceInstance(pFileIOListener, errmsgs);
		runTraceThread(spFileIoTrace);
		printErrs(errmsgs);
	}
	if (false) {
		printf("Starting 'File Kernel Trace;Set 2'\n");
		auto listener = std::make_shared<MyVolumeListener>();
		auto spTrace = ETWVolumeTraceInstance(listener, errmsgs);
		runTraceThread(spTrace);
		printErrs(errmsgs);
	}*/

	printf("press a key to stop\n");
	getc(stdin);
	//while (true) {
	//	Sleep(1000);
	//}

	for (TraceSessionThread &entry : sessionThreads) {
		entry.session->Stop();
	}

	// Give it a second...

	Sleep(1000);

	// Finally, terminate the threads

	for (TraceSessionThread &entry : sessionThreads) {
		TerminateThread(entry.hThread, 0);
	}
}
