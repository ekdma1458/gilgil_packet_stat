#ifndef PCAP_STAT_H
#define PCAP_STAT_H
#include "stdafx.h"
#endif // PCAP_STAT_H

using namespace std;

class Mac;

#pragma pack(1)
struct ST_je_ip_header{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_ipv4_hdr ip_hdr;
};

struct ST_je_Rx_Tx{
    u_int32_t tx_c;
    u_int32_t tx_b;
    u_int32_t rx_c;
    u_int32_t rx_b;
};

void usage();
void countIp(const ST_je_ip_header* packet, map<u_int32_t, ST_je_Rx_Tx> *m, bpf_u_int32 size);
void printEndPoint(map<u_int32_t, ST_je_Rx_Tx> *m);
void countMac(const ST_je_ip_header* packet, map<Mac, ST_je_Rx_Tx> *m, bpf_u_int32 size);
void printEndPoint(map<Mac, ST_je_Rx_Tx> *m);
void countIpAtoB(const ST_je_ip_header* packet, map<pair<u_int32_t, u_int32_t>, ST_je_Rx_Tx> *m, bpf_u_int32 size);
void printEndPoint(map<pair<u_int32_t, u_int32_t>, ST_je_Rx_Tx> *m);
void countMacAtoB(const ST_je_ip_header* packet, map<pair<Mac, Mac>, ST_je_Rx_Tx> *m, bpf_u_int32 size);
void printEndPoint(map<pair<Mac, Mac>, ST_je_Rx_Tx> *m);
