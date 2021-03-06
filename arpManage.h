#include <iostream>
#include <libnet.h>
#include <pcap.h>
#ifndef ARPMANAGE_H
#define ARPMANAGE_H

#endif // ARPMANAGE_H
#pragma once

struct arp_hdr{
    uint16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    uint16_t ar_pro;         /* format of protocol address */
    uint8_t  ar_hln;         /* length of hardware address */
    uint8_t  ar_pln;         /* length of protocol addres */
    uint16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

#define PACKETSIZE sizeof(struct libnet_ethernet_hdr)+sizeof(struct arp_hdr)
struct spoofingInfo{
    unsigned char pkt[PACKETSIZE];
    unsigned char broad_arr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    unsigned char null_arr[6] = {0x00,0x00,0x00,0x00,0x00,0x00 };
    unsigned char hostip[4];
    unsigned char hostmac[6];
    unsigned char senderip1[4];
    unsigned char targetip1[4];
    unsigned char senderip2[4];
    unsigned char targetip2[4];
    unsigned char sendermac1[6];
    unsigned char targetmac1[6];
    unsigned char sendermac2[6];
    unsigned char targetmac2[6];
};

struct pseudo_hdr{
    struct in_addr saddr;
    struct in_addr daddr;
    uint8_t reserve;
    uint8_t protocol;
    uint16_t len;
    struct libnet_tcp_hdr pse_tcp_hdr;
};

class arpManage{
public:
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res1;
    u_int length;
    struct libnet_ethernet_hdr* ep;
    struct arp_hdr* ap;
    struct libnet_ipv4_hdr* ip;
    u_char relayPacket[1500] = {0, };
    arpManage();
    ~arpManage();
    uint8_t sameCheck(uint8_t* source, uint8_t* destination);
    [[noreturn]] void infection(struct spoofingInfo ah);
};

