#pragma once

#include <vector>
#include <string>

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <guiddef.h>

#include "../include/etw_providers.h"
#include "utils.h"

class ETWTraceSessionBase : public ETWTraceSession
{
public:
	ETWTraceSessionBase(const std::string sessionName, const std::string providerName, const GUID &providerGuid, const GUID &myguid) : 
		m_actualSessionName(sessionName), m_providerName(providerName), m_providerGuid(providerGuid), m_myguid(myguid), m_errMsgs() { }
	~ETWTraceSessionBase() { }

	virtual void Stop() override {
		m_stopFlag = true;
		if (m_pTraceProps) {
			ETWControlSession(EVENT_TRACE_CONTROL_STOP, m_pTraceProps, m_startTraceHandle, (LPSTR)m_actualSessionName.c_str());
		}
	}
	//---------------------------------------------------------------------
	// Run()
	// Will block until SetStopFlag is called, so this should be called from a
	// dedicated thread.
	//---------------------------------------------------------------------
	virtual void Run() override {
		m_stopFlag = false;

		// Process Trace - blocks until BufferCallback returns FALSE, or

		ULONG status = ProcessTrace(&m_startTraceHandle, 1, 0, 0);

		if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
			m_errMsgs += m_actualSessionName + ":ProcessTrace() failed with " + std::to_string(status) + "\n";
			CloseTrace(m_startTraceHandle);
		}
	}

	ETWSessionInfo getSessionInfo() override {
		ETWSessionInfo info;
		info.sessionName = m_actualSessionName;
		info.providerName = m_providerName;
		info.providerGuid = etw::guidToString( m_providerGuid);
		return info;
	}

	//---------------------------------------------------------------------
	// Establish a session.
	// Returns true on success, false otherwise.
	//---------------------------------------------------------------------
	virtual bool Setup() {

		ULONG status = StartTraceSession(
			m_actualSessionName, m_enableFlags, m_startTraceHandle, m_pTraceProps);

		if (status == false)
			return false;

		if (m_doFlush) {
			ETWControlSession(EVENT_TRACE_CONTROL_FLUSH, m_pTraceProps, m_startTraceHandle, (LPSTR)m_actualSessionName.c_str());
		}

		// Identify the log file from which you want to consume events
		// and the callbacks used to process the events and buffers.

		EVENT_TRACE_LOGFILE trace;
		TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
		ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
		trace.LoggerName = (LPSTR)m_actualSessionName.c_str();
		trace.LogFileName = (LPSTR)NULL;

		// hook up our callback functions
		trace.EventRecordCallback =
			(PEVENT_RECORD_CALLBACK)(StaticRecordEventCallback);
		trace.BufferCallback =
			(PEVENT_TRACE_BUFFER_CALLBACK)(StaticBufferEventCallback);
		trace.Context = this; // only works in Vista+

		trace.ProcessTraceMode =
			PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;

		// Open Trace

		this->m_startTraceHandle = OpenTrace(&trace);
		if (INVALID_PROCESSTRACE_HANDLE == this->m_startTraceHandle) {
			DWORD err = GetLastError();
			m_errMsgs += m_actualSessionName + ":OpenTrace() failed with err:" + std::to_string(err) + "\n";
			goto cleanup;
		}

		return true;

	cleanup:
		CloseTrace(m_startTraceHandle);
		return false;
	}

	std::string m_errMsgs;

protected:
	virtual void OnRecordEvent(PEVENT_RECORD pEvent) = 0;

	bool m_stopFlag { false };
	std::string m_actualSessionName;
	std::string m_providerName;
	const GUID &m_providerGuid;
	const GUID &m_myguid;
	TRACEHANDLE m_startTraceHandle{ 0 };
	PEVENT_TRACE_PROPERTIES m_pTraceProps{ 0 };
	bool m_doFlush{ false };

	uint8_t m_traceLevel = TRACE_LEVEL_INFORMATION;
	DWORD m_enableFlags{ 0 };
	uint64_t m_keywordMatchAny{ 0 }, m_keywordMatchAll{ 0L };

	//---------------------------------------------------------------------
	// Called from Setup()
	//---------------------------------------------------------------------
	virtual bool StartTraceSession(std::string &mySessionName,
		DWORD dwEnableFlags,
		TRACEHANDLE& traceSessionHandle,
		PEVENT_TRACE_PROPERTIES &petp
	) {
		size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (mySessionName.length() + 1) * sizeof(mySessionName[0]);

		petp = (PEVENT_TRACE_PROPERTIES)malloc(bufferSize);

		memset(petp, 0, sizeof(EVENT_TRACE_PROPERTIES));

		petp->Wnode.BufferSize = bufferSize;
		petp->LogFileNameOffset = 0;
		petp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

		petp->Wnode.Guid = m_myguid;

		petp->Wnode.ClientContext = 1; // use QPC for timestamp resolution
		petp->Wnode.Flags = 0 | WNODE_FLAG_TRACED_GUID;

		petp->MinimumBuffers = 1;
		petp->FlushTimer = 1;
		petp->EnableFlags = dwEnableFlags;

		petp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		// petp->LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE; // Windows 8+

		// Call StartTrace() to setup a realtime ETW context associated with Guid +
		// mySessionName
		// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364117(v=vs.85).aspx

		ULONG status = ::StartTrace(&traceSessionHandle, mySessionName.c_str(), petp);
		if (ERROR_ALREADY_EXISTS == status) {
			//fprintf(stderr, "Trace session ALREADY EXISTS for sessionName + Guid\n");
			return true;
		}
		else if (status != ERROR_SUCCESS) {
			m_errMsgs += m_actualSessionName + ":StartTrace returned " + std::to_string(status) + "\n";
			traceSessionHandle = 0L;
			return false;
		}

		// Enable Trace
		status = EnableTraceEx2(traceSessionHandle, &m_providerGuid,
				EVENT_CONTROL_CODE_ENABLE_PROVIDER,
				m_traceLevel, m_keywordMatchAny, m_keywordMatchAll, 0, NULL);
	
		if (status != ERROR_SUCCESS) {
			m_errMsgs += m_actualSessionName + ":EnableTraceEx2 failed with status " + std::to_string(status) + "\n";
		}
		return true;
	}

	//---------------------------------------------------------------------
	// Function wrapper to call our class OnRecordEvent()
	//---------------------------------------------------------------------
	static VOID WINAPI StaticRecordEventCallback(PEVENT_RECORD pEvent) {
		if (nullptr == pEvent->UserContext) {
			// fputs("no UserContext\n", stderr);
			return;
		}
		auto pTraceSession = (ETWTraceSessionBase*)pEvent->UserContext;
		return pTraceSession->OnRecordEvent(pEvent);
	}

	//---------------------------------------------------------------------
	// Function wrapper to call our class OnBuffer()
	//---------------------------------------------------------------------
	static BOOL WINAPI StaticBufferEventCallback(PEVENT_TRACE_LOGFILE buf) {
		if (nullptr == buf->Context) {
			return FALSE;
		}
		auto pTraceSession = (ETWTraceSessionBase*)buf->Context;
		return pTraceSession->OnBuffer(buf);
	}

	//---------------------------------------------------------------------
	// Called from StaticEventBufferCallback(), which is called by
	// ETW loop in ProcessSession().
	//
	// The only reason we implement this is to signal to ETW
	// to terminate this session's ProcessSession() loop.
	//---------------------------------------------------------------------
	virtual BOOL OnBuffer(PEVENT_TRACE_LOGFILE buf) {
		if (m_stopFlag) {
			return FALSE; // I'm done. Stop sending and exit ProcessSession()
		}
		return TRUE; // keep sending me events!
	}

	// From ProcessHacker etwmon.c
	ULONG ETWControlSession(
		_In_ ULONG ControlCode, PEVENT_TRACE_PROPERTIES pTraceProps, TRACEHANDLE sessionHandle, LPSTR loggerName
	)
	{
		// If we have a session handle, we use that instead of the logger name.

		pTraceProps->LogFileNameOffset = 0; // make sure it is 0, otherwise ControlTrace crashes

		return ControlTrace(
			sessionHandle,
			sessionHandle == 0 ? NULL : loggerName,
			pTraceProps,
			ControlCode
		);
	}

};
