#pragma once

#include <stdint.h>
#include <windows.h>
#include <winsock2.h>
#include <Ws2tcpip.h> // IN6_ADDR

//[EventType{11, 13, 14, 16, 18}, EventTypeName{"RecvIPV4", "DisconnectIPV4", "RetransmitIPV4", "ReconnectIPV4", "TCPCopyIPV4"}]
struct TcpIp_TypeGroup1_V2
{
	uint32_t PID;
	uint32_t size;
	uint32_t daddr;
	uint32_t saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{ 12, 15 }, EventTypeName{ "ConnectIPV4", "AcceptIPV4" }]
struct TcpIp_TypeGroup2_V2
{
	uint32_t PID;
	uint32_t size;
	uint32_t daddr;
	uint32_t saddr;
	uint16_t dport;
	uint16_t sport;
	uint16_t mss;
	uint16_t sackopt;
	uint16_t tsopt;
	uint16_t wsopt;
	uint32_t rcvwin;
	int16_t rcvwinscale;
	int16_t sndwinscale;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{ 27, 29, 30, 32, 34 }, EventTypeName{ "RecvIPV6", "DisconnectIPV6", "RetransmitIPV6", "ReconnectIPV6", "TCPCopyIPV6" }]
struct TcpIp_TypeGroup3_V2
{
	uint32_t PID;
	uint32_t size;
	IN6_ADDR daddr;
	IN6_ADDR saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{28, 31}, EventTypeName{"ConnectIPV6", "AcceptIPV6"}]
struct TcpIp_TypeGroup4_V2
{
	uint32_t PID;
	uint32_t size;
	IN6_ADDR daddr;
	IN6_ADDR saddr;
	uint16_t dport;
	uint16_t sport;
	uint16_t mss;
	uint16_t sackopt;
	uint16_t tsopt;
	uint16_t wsopt;
	uint32_t rcvwin;
	int16_t rcvwinscale;
	int16_t sndwinscale;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{ 10 }, EventTypeName{ "SendIPV4" }]
struct TcpIp_SendIPV4_V2
{
	uint32_t PID;
	uint32_t size;
	uint32_t daddr;
	uint32_t saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t startime;
	uint32_t endtime;
	uint32_t seqnum;
	uint32_t connid;
};

//[EventType{ 26 }, EventTypeName{ "SendIPV6" }]
struct TcpIp_SendIPV6_V2
{
	uint32_t PID;
	uint32_t size;
	IN6_ADDR daddr;
	IN6_ADDR saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t startime;
	uint32_t endtime;
	uint32_t seqnum;
	uint32_t connid;
};



