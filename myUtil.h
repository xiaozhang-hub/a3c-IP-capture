// myUtil.h

#ifndef MYUTIL_H
#define MYUTIL_H

#include <fstream>
#include <string>
#include <sstream>
#include <sys/stat.h>  // 用于创建文件夹的头文件
#include <cstdint>
#include <arpa/inet.h> // 用于IP地址转换的头文件
#include <algorithm>   // 字符替换

#include <chrono>
#include <ctime>
#include <iomanip>

struct IPv4Header {
    uint8_t version_ihl; // 版本和首部长度
    uint16_t total_length;     // 总长度
    uint16_t identification;   // 标识
    uint16_t flags_fragment;   // 标志和片偏移
    uint8_t TTL;               // 存活时间
    uint8_t protocol;          // 协议
    uint16_t header_checksum;  // 头部校验和
    uint32_t source_ip;        // 源IP地址
    uint32_t dest_ip;          // 目标IP地址
};

struct TCPHeader {
    uint16_t source_port;      // 源端口
    uint16_t dest_port;        // 目的端口
    uint32_t sequence_number;  // 序列号
    uint32_t ack_number;       // 确认号
    uint16_t flags;            // 标志位（例如，SYN、ACK、FIN等）
    uint16_t window_size;      // 窗口大小
    uint16_t checksum;         // 校验和
    uint16_t urgent_pointer;   // 紧急指针
};

struct UDPHeader {
    uint16_t source_port;      // 源端口
    uint16_t dest_port;        // 目的端口
    uint16_t length;           // 数据包长度
    uint16_t checksum;         // 校验和
};

//pcap头部
struct pcap_hdr_s {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

//pcap记录首部
struct pcaprec_hdr_s {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

bool isIPv6Packet(const char* packet);
bool isInternalIP(uint32_t ip);

std::string getIPAndPort(char* packet, size_t packetSize);
std::string getIpv4Port(IPv4Header* ipv4Header, bool flag);

void newFile(std::ofstream& file, std::string folderPath, std::string label);
void write_pcap_hdr(std::ofstream& file);
void write_pcap_rec(std::ofstream& pcap_file, char* packet, size_t length);

#endif