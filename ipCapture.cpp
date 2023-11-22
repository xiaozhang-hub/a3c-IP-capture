#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include <map>
#include "myUtil.h"

#ifdef __linux__
#include <net/if.h>
#include <linux/if_tun.h>
using namespace std;

#else

#error Sorry, you have to implement this part by yourself.

#endif

static int get_tunnel(char *port, char *secret)  //获取隧道
{
    // We use an IPv6 socket to cover both IPv4 and IPv6.
    cout<<"start get tunnel\n";
    int tunnel = socket(AF_INET6, SOCK_DGRAM, 0);
    int flag = 1;
    setsockopt(tunnel, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    setsockopt(tunnel, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

    // Accept packets received on any local address.
    sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(atoi(port));
    cout<<"start bind tunnel\n";

    // Call bind(2) in a loop since Linux does not have SO_REUSEPORT.
    while (bind(tunnel, (sockaddr *)&addr, sizeof(addr))) {  //将隧道与套接字绑定
        cout<<"bind failed\n";
        if (errno != EADDRINUSE) {
            return -1;
        }
        usleep(100000);
    }

    cout<<"start recv package\n";
    // Receive packets till the secret matches.  接收数据包，直到密钥匹配
    char packet[1024];
    socklen_t addrlen;
    do {
        addrlen = sizeof(addr);
        int n = recvfrom(tunnel, packet, sizeof(packet), 0,
                (sockaddr *)&addr, &addrlen);
        cout<<"get tunnel pack\n";
        
        if (n <= 0) {
            return -1;
        }
        packet[n] = 0;
    } while (packet[0] != 0 || strcmp(secret, &packet[1]));

    // Connect to the client as we only handle one client at a time.  隧道与客户端建立连接
    cout<<"start connect\n";
    connect(tunnel, (sockaddr *)&addr, addrlen);
    return tunnel;
}

static void build_parameters(char *parameters, int size, int argc, char **argv)
{
    // Well, for simplicity, we just concatenate them (almost) blindly.
    int offset = 0;
    for (int i = 4; i < argc; ++i) {
        char *parameter = argv[i];
        int length = strlen(parameter);
        char delimiter = ',';

        // If it looks like an option, prepend a space instead of a comma.
        if (length == 2 && parameter[0] == '-') {
            ++parameter;
            --length;
            delimiter = ' ';
        }

        // This is just a demo app, really.
        if (offset + length >= size) {
            puts("Parameters are too large");
            exit(1);
        }

        // Append the delimiter and the parameter.  附加分隔符和参数
        parameters[offset] = delimiter;
        memcpy(&parameters[offset + 1], parameter, length);
        offset += 1 + length;
    }

    // Fill the rest of the space with spaces.  用空格填充剩余的空间
    memset(&parameters[offset], ' ', size - offset);

    // Control messages always start with zero.  控制消息总是以“0”开头
    parameters[0] = 0;
}

//-----------------------------------------------------------------------------

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: %s <port> <secret> options...\n"
               "\n"
               "Options:\n"
               "  -m <MTU> for the maximum transmission unit\n"
               "\n"
               , argv[0]);
        exit(1);
    }

    // Parse the arguments and set the parameters.
    char parameters[1024];
    build_parameters(parameters, sizeof(parameters), argc, argv);

    // Wait for a tunnel.  等待隧道
    int tunnel;
    while ((tunnel = get_tunnel(argv[1], argv[2])) != -1) {
        // 获取时间戳
        time_t tt = time(NULL);
        char dir[64];
        strftime(dir, sizeof(dir), "%Y-%m-%d %H:%M:%S", localtime(&tt));
        cout << dir << "  " << argv[1] << ":隧道建立成功\n";
        fflush(stdout);

        // Put the tunnel into non-blocking mode.
        fcntl(tunnel, F_SETFL, O_NONBLOCK);  //非阻塞模式

        // Send the parameters several times in case of packet loss.  多次发送参数，以防丢包
        for (int i = 0; i < 3; ++i) {
            send(tunnel, parameters, sizeof(parameters), MSG_NOSIGNAL);
        }

        // Allocate the buffer for a single packet.  为单个数据包分配缓冲区
        char packet[32767];  //Packet header + packet data
        const int packet_hdl = 16;
        char* IPpacket = packet + packet_hdl;  //Packet data

        int timer = 0;
        int counter = 0; 

//********************************************************************************************************
        const map<string, string> ipTable;//ip:port形式
        map<string, string>::const_iterator it;
        
        //存储每个 IP 地址对应的文件流
        map<string, ofstream> ipToFileMap;
        string ipAndPort;
        
        // 构建文件夹路径
        const char* folderName = "pcapFile";
        if (mkdir(folderName, 0777) == -1) {
            // 如果文件夹已存在，这个错误会被忽略
            perror("创建文件夹失败");
        }
        string folderPath = string(folderName) + "/";
//********************************************************************************************************

        // We keep forwarding packets till something goes wrong.
        while (true) {
            // Assume that we did not make any progress in this iteration.
            bool idle = true;

            // Read the incoming packet from the tunnel.
            int length = recv(tunnel, packet, sizeof(packet), 0);
            if (length == 0) {
                break;
            }
            if (length > 0) {
                // Ignore control messages, which start with zero.
                if (packet[0] != 0) {

//********************************************************************************************************
                    if(!isIPv6Packet(IPpacket)){
                        ipAndPort = getIPAndPort(IPpacket, length - packet_hdl);

                        it = ipTable.find(ipAndPort);

                        if(it == ipTable.end()){
                            perror("No matching table entry.");

                        }else if(!ipAndPort.empty()){
                            ofstream& outputFile = ipToFileMap[it.second];
                            if (!outputFile.is_open()) {
                                newFile(outputFile, folderPath, it.second);
                            }
                            outputFile.write(packet, length);              
                        }

                        // if(!ipAndPort.empty()){
                        //     ofstream& outputFile = ipToFileMap[ipAndPort];
                        //     if (!outputFile.is_open()) {
                        //         newFile(outputFile, folderPath, ipAndPort);
                        //     } 
                        //     write_pcap_rec(outputFile, packet, length);                      
                        // }

                    }else{
                        cout << "IPv6 Packet." << endl;
                    }
//********************************************************************************************************
                }

                // There might be more incoming packets.
                idle = false;

            }

            // If we are idle or waiting for the network, sleep for a
            // fraction of time to avoid busy looping.
            if (idle) {
                usleep(100000);

                // Increase the timer. This is inaccurate but good enough,
                // since everything is operated in non-blocking mode.
                timer += 100;

                // We are receiving for a long time but not sending.
                // Can you figure out why we use a different value? :)
                if (timer > 16000) {
                    // Send empty control messages.
                    packet[0] = 0;
                    for (int i = 0; i < 3; ++i) {
                        send(tunnel, packet, 1, MSG_NOSIGNAL);
                    }

                    // Switch to sending.
                    timer = 1;
                    counter ++;
                }

                // 发送三次控制信息控制包未收到信息
                if (counter == 3) {
                    break;
                }
            }
        }
        // printf("%s: The tunnel is broken\n", argv[1]);
        close(tunnel);  //关闭隧道
//********************************************************************************************************
        for (auto& entry : ipToFileMap) {  //关闭文件流
            entry.second.close();
        }
//********************************************************************************************************
        // 获取时间戳
        tt = time(NULL);
        strftime(dir, sizeof(dir), "%Y-%m-%d %H:%M:%S", localtime(&tt));
        std::cout << dir << "  " << argv[1] << ":隧道关闭成功\n";
        fflush(stdout);
    }
    perror("Cannot create tunnels");
    exit(1);
}
