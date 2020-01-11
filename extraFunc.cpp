#include "extraFunc.h"
#include "arpManage.h"

void gethostinfo(char * argv, unsigned char* buf, int num){//1=ip,0=mac
    struct ifreq ifr;
    unsigned char* mac_p;
    unsigned char* ip_p;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", argv);
    switch(num){
    case 0:
        ioctl(fd, SIOCGIFHWADDR, &ifr);
        mac_p=reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
        memcpy(buf,mac_p,6);
        break;
    case 1:
        ioctl(fd, SIOCGIFADDR, &ifr);
        ip_p=reinterpret_cast<unsigned char*>(ifr.ifr_addr.sa_data+2);
        memcpy(buf,ip_p,4);
    }
    close(fd);
}

int GetIpArr(unsigned char* ip,char* argv){
    struct in_addr addr;
    int res1=inet_aton(argv,&addr);
    if(res1 == 0){
        printf("ip address Error !\n");
        return 1;
    }
    *ip=addr.s_addr&0x000000FF;
    *(ip+1)=(addr.s_addr&0x0000FF00)>>8;
    *(ip+2)=(addr.s_addr&0x00FF0000)>>16;
    *(ip+3)=(addr.s_addr&0xFF000000)>>24;
    return 0;
}

void SetAddArp(unsigned char* pkt, unsigned char* dmac, unsigned char* smac, unsigned char* sip, unsigned char* dmac2, unsigned char* dip){
    struct libnet_ethernet_hdr* eth_p=reinterpret_cast<struct libnet_ethernet_hdr*>(pkt);
    struct arp_hdr* arp_p=reinterpret_cast<struct arp_hdr*>(pkt+sizeof(struct libnet_ethernet_hdr));
    eth_p->ether_type=ntohs(0x0806);
    arp_p->ar_hrd=ntohs(0x0001);
    arp_p->ar_pro=ntohs(0x0800);
    arp_p->ar_hln=0x06;
    arp_p->ar_pln=0x04;
    memcpy(eth_p->ether_dhost,dmac,6);
    memcpy(eth_p->ether_shost,smac,6);
    memcpy(arp_p->sender_mac,smac,6);
    memcpy(arp_p->target_mac,dmac2,6);
    memcpy(arp_p->sender_ip,sip,4);
    memcpy(arp_p->target_ip,dip,4);
    if(*dmac == 0xff) arp_p->ar_op=ntohs(ARPOP_REQUEST);
    else arp_p->ar_op=ntohs(ARPOP_REPLY);
}

unsigned short checksum(unsigned short *buf, int len){
    unsigned long sum = 0;
    while(len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return static_cast<unsigned short>(~sum);
}
