#include "buildpacket.cpp"
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
	int c;//�������ͣ�ԴIP��Ŀ��IP���ļ�����
	u_char *cp;//����
	char *filename;
	u_short filename_s;
	u_long src_ip, dst_ip;
	u_short src_prt, dst_prt;
	//char errbuf[LIBNET_ERRBUF_SIZE];
	FILE* file;//���������ļ�
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
	char packet_filter[] = "tcp and (src host *.*.*.*)";//�Լ�����ip��ַ
	struct bpf_program fcode;

	src_ip = 0;
	dst_ip = 0;
	src_prt = 8088;
	dst_prt = 8089;

	while ((c=getopt(argc,argv,"d:s:p:"))!=EOF){
		switch (c){
		case 'd':
			if (!(cp = strchr(optarg, '.')))
			{
				usage(argv[0]);
			}
			*cp++ = 0;
			//dst_prt = (u_short)atoi(cp);
			if ((dst_ip = libnet_name2addr4(l, optarg, LIBNET_RESOLVE)) == -1)
			{
				fprintf(stderr, "Bad destination IP address: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case: 's':
			if (!(cp = strchr(optarg, '.')))
			{
				usage(argv[0]);
			}
			  *cp++ = 0;
			  //src_prt = (u_short)atoi(cp);
			  if ((src_ip = libnet_name2addr4(l, optarg, LIBNET_RESOLVE)) == -1)
			  {
				  fprintf(stderr, "Bad source IP address: %s\n", optarg);
				  exit(EXIT_FAILURE);
			  }
			  break;
		case: 'p' :
			filename = optarg;
			filename_s = strlen(filename);
			break;
		default:
			exit(EXIT_FAILURE);
		}
	}
	if (!src_ip || !src_prt || !dst_ip || !dst_prt)
	{
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* ��ȡ�����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %sn", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
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
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת��ѡ�е������� */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* ���豸 */
	if ((adhandle = pcap_open(d->name, // �豸��
		65535, // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS, // ����ģʽ
		1000, // ��ȡ��ʱʱ��
		NULL, // Զ�̻�����֤
		errbuf // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "nUnable to open the adapter. %s is not supported by WinPcapn", d->name);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...n", d->description);


	/* ���������·�㣬Ϊ�˼򵥣�ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "nThis program works only on Ethernet networks.n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("datalink:[%d]n", pcap_datalink(adhandle));
	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô����һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "nUnable to compile the packet filter. Check the syntax.n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		int x;
		scanf("%d", &x);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "nError setting the filter.n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);



	/* ��ʼ���� */
	int ret;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	int Seqn;
	int ACKn;

	//���͵�һ������
	if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, null, 1, 100, 0) != 0){
		prtintf("Fail to send handshake1 packet");
		exit(0);
	}

	printf("Waiting for the response for the handshake1");

	//�յ��ڶ�������
	while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (ret == 0)
		{
			/* ��ʱʱ�䵽 */
			printf("time over!n");
			continue;
		}
		if (header->len > 0)
		{
			ip_header *ip = (ip_header *)(pkt_data + 14);
			if (ip->saddr == dst_ip && SYN==1 && ACK==1 ){
				Seqn=(tcp->ack_seq);
				Ackn=(tcp->seq)
				printf("recieve the handshake2 packet");
				break;
			}
			else
				continue;
		}
	}

	//���͵���������
	if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, null, 3, Seqn, Ackn+1) != 0){
		prtintf("Fail to send ack packet");
		exit(0);
	}

	//������������ļ���
	if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, filename, 4, 100, 100) != 0){
		prtintf("Fail to send filename packet");
		exit(0);
	}

	printf("Waiting for the response for the filelength");

	//�յ������ļ������ACK
	while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (ret == 0)
		{
			/* ��ʱʱ�䵽 */
			printf("time over!n");
			continue;
		}
		char buffer[20000];
		if (header->len > 0)
		{
			ip_header *ip = (ip_header *)(pkt_data + 14);
			tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
			if (ip->saddr == dst_ip && tcp->ack==1){
				printf("recieve the filelength packet");
				char *data = (char *)tcp + (tcp->hlen) * 4;
				filelength = atoi(data);
				printf("the length of the data is &d", filelength);
				break;
			}
			else
				continue;
		}
	}
	
	if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, null, 3, Seqn, Ackn+1) != 0){
		prtintf("Fail to send ack packet");
		exit(0);
	}
	
	if ((file = fopen(filename, "wb")) == NULL)			//����һ�����ļ�
	{
		printf("File create error!");
		exit(1);
	}

	int j = 0;//flag
	int packet_s;//���ݰ�����
	int packetn;//���ݰ����
	
	packet_s = (filelength % 1000 == 0) ? filelength / 1000 : filelength / 1000 + 1;

	while (j != packet_s && (ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){
			if (ret == 0)
			{
				/* ��ʱʱ�䵽 */
				printf("time over!n");
				continue;
			}
			char buffer[10000];
			if (header->len > 0)
			{
				ip_header *ip = (ip_header *)(pkt_data + 14);
				tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
				if (ip->saddr == dst_ip && (tcp->psh == 1){
					printf("recieve the file data packet");
					char *data = (char *)tcp + (tcp->hlen) * 4;
					u_int datalen = ntohs(ip->tlen) - (ip->ver_ihl & 0xf) * 4 - (tcp->hlen) * 4;
					memcpy(buffer, data, datalen);
					packetn = tcp->(seq - 100) / 1000 + 1;
					fseek(file, (packetn-1)*1000, SEEK_SET);
					fwrite(buffer, sizeof(char), datalen, file);
					j++;
					if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, payload, 3, 0x01010101, (tcp->seq)+datalen) != 0){
						prtintf("Fail to send ack packet");
						exit(0);
					}
				}
				else
					continue;
			}		
	}

	fclose(file);

	//����FIN��
	if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, null, 6, 100, 100) != 0){
		prtintf("Fail to send fin packet");
		exit(0);
	}
	int finack=0;
	//recieve ACK
	//recieve FIN+ACK
	while (finack ! =2 && (ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (ret == 0)
		{
			/* ��ʱʱ�䵽 */
			printf("time over!n");
			continue;
		}
		char buffer[20000];
		if (header->len > 0)
		{
			//printf("len:[%d]n", header->len);
			ip_header *ip = (ip_header *)(pkt_data + 14);
			tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
			if (ip->saddr == dst_ip && (tcp->ack) == 1 && (tcp->fin) == 1){
				printf("recieve the filelength packet");
				finack++;
			}
			else if (ip->saddr == dst_ip && (tcp->ack) == 1 && (tcp->fin) == 0){
				printf("recieve the filelength packet");
				finack++;
			}
			else
				continue;
		}
	}

	//����ACK
	if (c = build_packet(src_ip, dst_ip, src_prt, dst_prt, null, 3, 100, 100) != 0){
		prtintf("Fail to send ack packet");
		exit(0);
	}

	printf("File trans is finished, communication is disconnected");
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

