#include "buildpacket.cpp"
#include "Timer.cpp"
#include<string>
#include"tcp.h"
using namespace std;

#include <stdio.h>
#include <tchar.h>
#include <WinSock2.h>
#include <Windows.h>

#include <stdlib.h>
#include <iostream>
#include <string>
#define HAVE_REMOTE
#include <pcap.h>

#define PATHLEN 100
#define BUFFERSIZE 1000

int main(int argc, char *argv[])
{
	int c;//参数类型（源IP、目的IP、文件名）
	u_char *cp;//参数
	//libnet_t *l;
	//libnet_ptag_t t;
	char *filename;
	u_short filename_s;
	u_long src_ip, dst_ip;
	u_short src_prt, dst_prt;
	//char errbuf[LIBNET_ERRBUF_SIZE];
	FILE* file;//所创建的文件
	int filelength;
	char *payload;
	u_short payload_s;

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp and (src host *.*.*.*)";//自己定义ip地址
	struct bpf_program fcode;

	//src_ip = 0;
	//dst_ip = 0;
	src_prt = 8088;
	dst_prt = 0;

	Timer[] timers;
	timers = new Timer[x];

	for (i = 0; i<x; i++){
		timers[i] = new timer();
	}
	
	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %sn", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)n", d->description);
		else
			printf(" (No description available)n");
	}

	if (i == 0)
	{
		printf("nNo interfaces found! Make sure WinPcap is installed.n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("nInterface number out of range.n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name, // 设备名
		65535, // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式
		1000, // 读取超时时间
		NULL, // 远程机器验证
		errbuf // 错误缓冲池
		)) == NULL)
	{
		fprintf(stderr, "nUnable to open the adapter. %s is not supported by WinPcapn", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...n", d->description);


	/* 检查数据链路层，为了简单，只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "nThis program works only on Ethernet networks.n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("datalink:[%d]n", pcap_datalink(adhandle));
	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么假设一个C类的掩码 */
		netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "nUnable to compile the packet filter. Check the syntax.n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		int x;
		scanf("%d", &x);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "nError setting the filter.n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);



	/* 开始捕获 */
	int ret;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	
	int ACKn;
	int Seqn;
	
	while (1){

		/*接收第一次握手*/
		while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
		{
			if (ret == 0)
			{
				/* 超时时间到 */
				printf("time over!n");;
				continue;
			}
			//char buffer[20000];
			if (header->len > 0)
			{
				//printf("len:[%d]n", header->len);
				ip_header *ip = (ip_header *)(pkt_data + 14);
				tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
				if (ip->daddr == src_ip && SYN == 1 && tcp->dst_port == 8089){
					printf("recieve the handshake1 packet");
					ACKn=(tcp->seq);
					break;
				}
				else
					continue;
			}
		}

		/*发送第二次握手*/
		if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, null, 2, 200, Ackn+1) != 0){
			prtintf("Fail to send ack packet");
			exit(0);
		}

		/*接收第三次握手*/
		while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
		{
			if (ret == 0)
			{
				/* 超时时间到 */
				printf("time over!n");
				continue;
			}
			//char buffer[20000];
			if (header->len > 0)
			{
				//printf("len:[%d]n", header->len);
				ip_header *ip = (ip_header *)(pkt_data + 14);
				tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
				if (ip->daddr == src_ip && ACK == 1 && tcp->dst_port == 8088){
					printf("recieve the handshake1 packet");
					break;
				}
				else
					continue;
			}
		}

		/*接收客户端所请求文件的文件名*/
		while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
		{
			if (ret == 0)
			{
				/* 超时时间到 */
				printf("time over!n");
				continue;
			}
			char buffer[20000];
			if (header->len > 0)
			{
				ip_header *ip = (ip_header *)(pkt_data + 14);
				tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
				if (ip->daddr == src_ip && PSH == 1 && tcp->dst_port == 8088){
					printf("recieve the filename packet");
					char *data = (char *)tcp + (tcp->hlen) * 4;
					u_int datalen = ntohs(ip->tlen) - (ip->ver_ihl & 0xf) * 4 - (tcp->hlen) * 4;
					memcpy(buffer, data, datalen);
					file = fopen(buffer, r);
					ACKn=(tcp->seq);
					break;
				}
				else
					continue;
			}
		}

		/*查找文件，并获取文件大小*/
		fseek(file, 0, SEEK_END);
		filelength = ftell(file);
		sprintf(payload, "%d", filelength);

		Timer orgTime= new Timer();
		int orgT;
		
		/*将文件大小发送给客户端*/
		if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, payload, 5, 100, Ackn+datalen) != 0){
			prtintf("Fail to send filesize packet");
			exit(0);
		}
		
		orgTime.start();

		/*接收ACK*/
		while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
		{
			if (ret == 0)
			{
				/* 超时时间到 */
				printf("time over!n");
				continue;
			}
			if (header->len > 0)
			{
				ip_header *ip = (ip_header *)(pkt_data + 14);
				tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
				if (ip->daddr == src_ip && ACK == 1 && tcp->dst_port == 8088){
					printf("recieve the filelength packet");
					orgTime.stop();
					orgT = orgTime.Duration();
					break;
				}
				else
					continue;
			}
		}
		
		CWinThread *pReceive = AfxBeginThread((AFX_THREADPROC)Receive,
			&m_ctrW,
			THREAD_PRIORITY_NORMAL,
			0,
			CREATE_SUSPENDED);

		CWinThread *pSend = AfxBeginThread((AFX_THREADPROC)Send,
			&m_ctrD,
			THREAD_PRIORITY_NORMAL,
			0,
			CREATE_SUSPENDED);
		pReceive->ResumeThread();
		pSend->ResumeThread();


		CCriticalSection critical_section;
		int rate;

		int j = 0;//flag
		int packet_s;//数据包数量
		int packetn;//数据包序号
	
		packet_s = (filelength % 1000 == 0) ? filelength / 1000 : filelength / 1000 + 1;
		
		UINT Send()
		{
			for (i = 0; i<packet_s; i++){
				if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, payload, 5, 100, 100) != 0){
					prtintf("Fail to send filesize packet");
					exit(0);
				}
				timers[x].Start();
				critical_section.Lock();//锁定临界区
				sleep(rate);
				critical_section.Unlock();
			}
			return 0;
		}

		UINT Receive(LPVOID pParam)
		{
			while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
			{
				if (ret == 0)
				{
					/* 超时时间到 */
					printf("time over!n");
					continue;
				}
				if (header->len > 0)
				{
					ip_header *ip = (ip_header *)(pkt_data + 14);
					if (ip->saddr == dst_ip && ACK == 1){
						timers[x].Finish();
						duration = timers[x].Duration();
						critical_section.Lock();//锁定临界区
						rate = TFRC(duration);
						critical_section.Unlock();
					}
					else
						continue;
				}
			}//收到ACK			
			return 0;
		}

		//收到FIN+ACK
		while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
		{
			if (ret == 0)
			{
				/* 超时时间到 */
				printf("time over!n");
				continue;
			}
			//char buffer[20000];
			if (header->len > 0)
			{
				//printf("len:[%d]n", header->len);
				ip_header *ip = (ip_header *)(pkt_data + 14);
				if (ip->saddr == dst_ip && SYN == 1){
					printf("recieve the handshake2 packet");
					break;
				}
				else
					continue;
			}
		}

		if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, null, 3, 100, 100) != 0){
			prtintf("Fail to send ack packet");
			exit(0);
		}
		if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, null, 6, 100, 100) != 0){
			prtintf("Fail to send ack packet");
			exit(0);
		}
		while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
		{
			if (ret == 0)
			{
				/* 超时时间到 */
				printf("time over!n");
				continue;
			}
			//char buffer[20000];
			if (header->len > 0)
			{
				//printf("len:[%d]n", header->len);
				ip_header *ip = (ip_header *)(pkt_data + 14);
				if (ip->saddr == dst_ip && SYN == 1){
					printf("recieve the handshake2 packet");
					break;
				}
				else
					continue;
			}
		}//收到ACK
		fclose(file);
		printf("File trans is finished, communication is disconnected");

	}

	exit(0);
}
void
usage(char *name){
	fprintf(stderr,
		"usage: %s -s source_ip.source_port -d destination_ip.destination_port"
		" [-p payload]\n",
		name
		);
}

