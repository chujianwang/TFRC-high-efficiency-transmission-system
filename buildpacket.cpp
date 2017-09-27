#if (HAVE_CONFIG_H)
#include "..\headfiles\config.h"
#endif
#include "..\headfiles\libnet_test.h"
#ifdef _WIN32_
#include "..\headfiles\getopt.h"
#endif
#include<string>
#include "..\headfiles\libnet.lib"
using namespace std;

int build_packet(u_long src_ip, u_long dst_ip, u_short  src_prt, u_short dst_prt, char * payload,int type, int snumber, int acknumber){
	libnet_t *l;
	libnet_ptag_t t;
	char *payload;
	u_short payload_s;
	//u_long src_ip, dst_ip;
	u_short src_prt, dst_prt;
	char errbuf[LIBNET_ERRBUF_SIZE];

	printf("libnet 1.1 packet shaping: TCP + options[link]\n");
	l = libnet_init(
		LIBNET_LINK,
		NULL,
		errbuf
		);
	if (l == NULL)
	{
		fprintf(stderr, "libnet_init() failed:%s", errbuf);
		exit(EXIT_FAILURE);
	}

	t = libnet_build_tcp_option(
		"\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000",
		20,
		1,
		0);
		
	if (t == -1)
	{
		fprintf(stderr, "Can't build TCP options: %s\n", libnet_geterror(1));
		goto bad;
	}

	if (type == 1){//第一次握手
		t = libnet_build_tcp(
			src_prt,
			dst_prt,
			snumber,
			acknumber,
			TH_SYN,
			32767,//窗口大小
			0,//校验和
			10,//紧急指针
			LIBNET_TCP_H + 20 + payload_s,//数据包大小
			payload,
			payload_s,
			1,//libnet句柄
			0);//协议标记
	}
	else if (type == 2){//第二次握手
		t = libnet_build_tcp(
			src_prt,
			dst_prt,
			snumber,
			acknumber,
			TH_SYN | TH_ACK,
			32767,
			0,
			10,
			LIBNET_TCP_H + 20 + payload_s,
			payload
			payload_s,
			1,
			0);
	}
	else if (type == 3){//无负载的ACK
		t = libnet_build_tcp(
			src_prt,
			dst_prt,
			snumber,
			acknumber,
			TH_ACK,
			32767,
			0,
			10,
			LIBNET_TCP_H + 20 + payload_s,
			payload
			payload_s,
			1,
			0);
	}
	else if (type == 4){//有负载的数据包
		t = libnet_build_tcp(
			src_prt,
			dst_prt,
			snumber,
			acknumber,
			TH_PUSH,
			32767,
			0,
			10,
			LIBNET_TCP_H + 20 + payload_s,
			payload
			payload_s,
			1,
			0);
	}
	else if (type == 5){//有负载的ACK
		t = libnet_build_tcp(
			src_prt,
			dst_prt,
			snumber,
			acknumber,
			TH_ACK | TH_PUSH,
			32767,
			0,
			10,
			LIBNET_TCP_H + 20 + payload_s,
			payload
			payload_s,
			1,
			0);
	}
	else if (type == 6){//带FIN 与 ACK的数据包
		t = libnet_build_tcp(
			src_prt,
			dst_prt,
			snumber,
			acknumber,
			TH_FIN | TH_ACK,
			32767,
			0,
			10,
			LIBNET_TCP_H + 20 + payload_s,
			payload,
			payload_s,
			1,
			0);
	}

	if (t == -1){
		fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(1));
		goto bad;
	}
	t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H + 20 + payload_s,
		0,
		242,
		0,
		64,
		IPPROTO_TCP,
		0,
		src_ip,
		dst_ip,
		NULL,
		0,
		1,
		0);
	if (t == -1)
	{
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(1));
		goto bad;
	}
	t = libnet_build_ethernet(
		enet_dst,
		enet_src,
		ETHERTYPE_IP,
		NULL,
		0,
		1,
		0);
	if (t == -1)
	{
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(1));
		goto bad;
	}
	c = libnet_write(l);
	if (c == -1)
	{
		fprintf(stderr, "Write error : %s\n", libnet_geterror(1));
		goto bad;
	}
	else
	{
		fprintf(stderr, "Wrote %d byte TCP packet; check the wire.\n", c);
	}
	libnet_destroy(l);
	return 0;
bad:
	libnet_destroy(l);
	return -1;

}

#if defined(_WIN32_)
#include "..\headfiles\getopt.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif
