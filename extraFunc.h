#ifndef EXTRAFUNC_H
#define EXTRAFUNC_H

#endif // EXTRAFUNC_H


void gethostinfo(char * argv, unsigned char* buf, int num);
int GetIpArr(unsigned char* ip,char* argv);
void SetBasicArp(unsigned char* pkt);
void SetAddArp(unsigned char* pkt, unsigned char* dmac, unsigned char* smac, unsigned char* sip, unsigned char* dmac2, unsigned char* dip);
unsigned short checksum(unsigned short *buf, int len);
