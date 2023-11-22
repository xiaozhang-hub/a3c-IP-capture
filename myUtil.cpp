#include "myUtil.h"
using namespace std;

size_t pcap_record_size = 64;
long pcap_file_size = 2 * 1024 * 1024;

//控制源目地址切换
bool getSource = true;
bool getDest = false;

bool isIPv6Packet(const char* packet) {
    uint8_t ipVersion = (packet[0] >> 4) & 0x0F;
    return (ipVersion == 6);
}

bool isInternalIP(uint32_t ip) {
    if ((ip >= 0x0A000000 && ip <= 0x0AFFFFFF) ||  // 10.0.0.0 to 10.255.255.255
        (ip >= 0xAC100000 && ip <= 0xAC1FFFFF) ||  // 172.16.0.0 to 172.31.255.255
        (ip >= 0xC0A80000 && ip <= 0xC0A8FFFF)) {   // 192.168.0.0 to 192.168.255.255
        return true;
    } else {
        return false;
    }
    return true;
}

string getIPAndPort(char* packet, size_t packetSize) { 
    if (packetSize >= sizeof(IPv4Header)) {
        IPv4Header* ipv4Header = reinterpret_cast<IPv4Header*>(packet);
        uint32_t ipInt = ipv4Header->source_ip;
        string port;
        if(isInternalIP(ipInt)){
            port = getIpv4Port(ipv4Header, getSource);
        }else{
            ipInt = ipv4Header->dest_ip;
            if(isInternalIP(ipInt)){
                port = getIpv4Port(ipv4Header, getDest);
            }else{
                perror("Not internal IP.");
                uint32_t ipInt = 999999999; //无效ip，转换时返回空字符串
            }
        }
        // 转换为字符串形式
        struct in_addr ipAddress;
        ipAddress.s_addr = ipInt;
        char ipChar[INET_ADDRSTRLEN];  // INET_ADDRSTRLEN 是 IPv4 地址字符串的最大长度
        inet_ntop(AF_INET, &(ipAddress), ipChar, INET_ADDRSTRLEN);
        string IPaddr(ipChar);

        if(!IPaddr.empty() && !port.empty()){
            return IPaddr + ":" + port;
        }else{
            return "";
        }
    }else{
        perror("Invalid packet size." );
        return "";
    }
}

string getIpv4Port(IPv4Header* ipv4Header, bool flag){
    string port;
    uint8_t protocol = ipv4Header->protocol;
    int ipv4HeaderLength = (ipv4Header->version_ihl & 0x0F) * 4;

    if (protocol == 6) { // 6表示TCP协议
        TCPHeader* tcpHeader = reinterpret_cast<TCPHeader*>(ipv4Header + ipv4HeaderLength);
        uint16_t portInt = flag ? ntohs(tcpHeader->source_port) : ntohs(tcpHeader->dest_port);   // network to host short 网络字节序转化为主机字节序，如果相同，则不进行操作
        port = to_string(portInt);

    } else if (protocol == 17) { // 17表示UDP协议
        UDPHeader* udpHeader = reinterpret_cast<UDPHeader*>(ipv4Header + ipv4HeaderLength);
        uint16_t portInt = flag ? ntohs(udpHeader->source_port) : ntohs(udpHeader->dest_port);
        port = to_string(portInt);

    } else {
        perror("Unsupported protocol" );
    }
    return port;
}

void newFile(ofstream& file, string folderPath, string label){
    // 获取当前系统时间
    auto currentTime = chrono::system_clock::now();
    time_t time = chrono::system_clock::to_time_t(currentTime);
    tm localTime = *localtime(&time);
    stringstream ss;
    ss << put_time(&localTime, "%Y%m%d_%H%M%S");
    // 创建文件名
    string filename;
    replace(label.begin(), label.end(), ':', '.');
    filename = ss.str() + "__" + label + ".pcap";
    string filePath = folderPath + filename;

    // 打开文件流
    file.open(filePath, ios::binary);

    // 写入pcap头部
    if (file.is_open()) {
        write_pcap_hdr(file);
    } else {
        perror("无法打开文件进行写入");
    }
}

void write_pcap_hdr(ofstream& file) {
    // 创建pcap头部结构体并填充字段
    pcap_hdr_s pcap_hdr;
    pcap_hdr.magic_number = 0xa1b2c3d4;
    pcap_hdr.version_major = 2;
    pcap_hdr.version_minor = 4;
    pcap_hdr.thiszone = 0;
    pcap_hdr.sigfigs = 0;
    pcap_hdr.snaplen = pcap_record_size;
    pcap_hdr.network = 101;// 链路类型为纯IP报文
    // 将pcap头部写入文件
    file.write(reinterpret_cast<const char*>(&pcap_hdr), sizeof(pcap_hdr_s));
    file.flush();
}

void write_pcap_rec(ofstream& pcap_file, char* packet, size_t length) {
    // 获取当前时间戳
    auto now = chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = chrono::duration_cast<chrono::seconds>(duration);
    auto micros = chrono::duration_cast<chrono::microseconds>(duration - seconds);

    size_t plen = (length < pcap_record_size ? length : pcap_record_size);
    size_t rlen = sizeof(struct pcaprec_hdr_s) + plen;
    struct pcaprec_hdr_s pcap_rec;

    // 填充pcap记录头部结构体
    pcap_rec.ts_sec = static_cast<uint32_t>(seconds.count());
    pcap_rec.ts_usec = static_cast<uint32_t>(micros.count());
    pcap_rec.incl_len = static_cast<uint32_t>(plen);
    pcap_rec.orig_len = static_cast<uint32_t>(length);

    // 写入pcap记录头部
    pcap_file.write(reinterpret_cast<const char*>(&pcap_rec), sizeof(struct pcaprec_hdr_s));

    // 写入记录数据
    pcap_file.write(packet, plen);
}
