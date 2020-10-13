# NetSecExp-sniffing-and-spoofing
> Network Security Experiment: Packet Sniffing and Sppofing Lab
---
实验由`网络安全`课程布置, 来自[SeedProject](https://seedsecuritylabs.org/Labs_16.04/Networking/Sniffing_Spoofing/)

## 实验信息
- 难度：中等
- 类别：探索
- 环境：WSL2 kali GUN/Linux

## 参考资料
[Programming with pcap](http://www.tcpdump.org/pcap.htm)

[Programming with Libcap - Sniffing the network from our own applicaiton](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf) by Luis Martin Garcia.

## NBO(Network Byte Order)
对于单一的字节（a byte），大部分处理器以相同的顺序处理位元（bit），因此单字节的存放方法和传输方式一般相同。

对于多字节数据，如整数（32位机中一般占4字节），在不同的处理器的存放方式主要有两种。以内存中0x0A0B0C0D的存放方式为例：

**Big-Endian**
![Big-Endian](https://upload.wikimedia.org/wikipedia/commons/thumb/5/54/Big-Endian.svg/420px-Big-Endian.svg.png)

**Little-Endian**
![Little-Endian](https://upload.wikimedia.org/wikipedia/commons/thumb/e/ed/Little-Endian.svg/420px-Little-Endian.svg.png)

有些处理器体系是Little-Endian，有些是Big-Endian，还有的可以配置。

为了在互联网上可以统一标准的传输数据，定义了NBO

网络传输一般采用Big-Endian，。*IP协议*中定义Big-Endian为网络字节序。

Berkeley套接字定义了一组转换函数，用于无符号16和32bit整数在网络序和本机字节序之间的转换。`htonl`，`htons`用于本机序转换到网络序；`ntohl`，`ntohs`用于网络序转换到本机序。

因为x86是Little-Endian，所以在抓包时要进行处理：
1. 用转换函数`#include <arpa/inet.h>`
2. 在定义结构体时定义为`u_char`数组，单字节没有读取问题，然后注意整个数组的读取顺序

## 抓包流程
1. 初始化网络接口`Network Interface`
2. 设定`Fliter`
3. 抓包
4. 包处理
5. 关闭网络接口
6. 结束抓包

## `pcap_lookupdev is deprecated`
两个reference都使用`pcap_lookupdev`但是，它已经过时。

我们可以使用`pcap_findalldev`来代替
```c
pcap_if_t *devices, *temp;
int pcap_findalldev(pcap_if_t **devices, char *errbuf);
for (temp = devices; temp != NULL; temp = temp->next) 
    printf("Found Device %s\n", temp->name);
    
char *device = devices->name // 使用默认interface
```
- 参数1：指向pcap_if_t 数组的指针的地址，实际返回一个链表头
- 参数2：错误信息
- 返回值：-1代表失败， 其他组代表成功
