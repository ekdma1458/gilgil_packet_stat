#include "stdafx.h"

void usage(){
    printf("syntax: pcap_stat <pcap file name>>\n");
    printf("sample: pcap_stat test.pcap");
}
void printEndPoint(map<u_int32_t, ST_je_Rx_Tx> *m){
    u_int count = 1;
    cout << "No  Key\t\t\ttx_c\ttx_b\t\trx_c\trx_b" << endl;
    for (auto it = m->begin(); it != m->end(); it++){
        u_int32_t ip = it->first;
        ip = htonl(ip);
        printf("%2d. ", count);
        count++;
        printf("%d.%d.%d.%d    \t", (ip & 0xff000000) >> 24  , (ip & 0x00ff0000) >> 16 , (ip & 0x0000ff00) >> 8 , ip & 0x000000ff);
        cout << it->second.tx_c << "\t" << it->second.tx_b << "\t\t" << it->second.rx_c << "\t" << it->second.rx_b << '\n';
    }
}
void printEndPoint(map<Mac, ST_je_Rx_Tx> *m){
    u_int count = 1;
    cout << "No  Key\t\t\ttx_c\ttx_b\t\trx_c\trx_b" << endl;
    for (auto it = m->begin(); it != m->end(); it++){
        printf("%2d. ", count);
        count++;
        Mac test = it->first;
        uint8_t* key = test.getEtherHost();
        printf("%02X:%02X:%02X:%02X:%02X:%02X\t", *key, *(key + 1), *(key + 2), *(key +3), *(key + 4), *(key + 5));
        cout << it->second.tx_c << "\t" << it->second.tx_b << "\t\t" << it->second.rx_c << "\t" << it->second.rx_b << '\n';
    }
}
void printEndPoint(map<pair<u_int32_t, u_int32_t>, ST_je_Rx_Tx> *m){
    u_int count = 1;
    cout << "No  A - B\t\t\t\tA to B_c\tA to B_b\tB to A_c\t       B to A_b" << endl;
    for (auto it = m->begin(); it != m->end(); it++){
        u_int32_t ip_src = it->first.first;
        u_int32_t ip_dst = it->first.second;
        ip_src = htonl(ip_src);
        ip_dst = htonl(ip_dst);
        printf("%2d. ", count);
        count++;
        printf("%d.%d.%d.%-3d - %d.%d.%d.%-5d\t",
               (ip_src & 0xff000000) >> 24  , (ip_src & 0x00ff0000) >> 16 , (ip_src & 0x0000ff00) >> 8 , ip_src & 0x000000ff
               ,(ip_dst & 0xff000000) >> 24  , (ip_dst & 0x00ff0000) >> 16 , (ip_dst & 0x0000ff00) >> 8 , ip_dst & 0x000000ff);
        cout << it->second.tx_c << "\t\t" << it->second.tx_b << "\t\t" << it->second.rx_c << "\t\t        " << it->second.rx_b << '\n';
    }
}
void printEndPoint(map<pair<Mac, Mac>, ST_je_Rx_Tx> *m){
    u_int count = 1;
    cout << "No  A - B\t\t\t\t\tA to B_c\tA to B_b\t\t    B to A_c\t      B to A_b" << endl;
    for (auto it = m->begin(); it != m->end(); it++){
        printf("%2d. ", count);
        count++;
        Mac test = it->first.first;
        uint8_t* key = test.getEtherHost();
        test = it->first.second;
        uint8_t* key2 = test.getEtherHost();
        printf("%02X:%02X:%02X:%02X:%02X:%02X - %02X:%02X:%02X:%02X:%02X:%02X\t",
               *key, *(key + 1), *(key + 2), *(key +3), *(key + 4), *(key + 5),
               *key2, *(key2 + 1), *(key2 + 2), *(key2 +3), *(key2 + 4), *(key2 + 5));

        cout << it->second.tx_c << "\t\t" << it->second.tx_b << "\t\t    " << it->second.rx_c << "\t\t      " << it->second.rx_b << '\n';
    }
}
void countIp(const ST_je_ip_header* packet, map<u_int32_t, ST_je_Rx_Tx> *m, bpf_u_int32 size){
    struct in_addr ip_src = packet->ip_hdr.ip_src;
    struct in_addr ip_dst = packet->ip_hdr.ip_dst;
    if( m->find(ip_src.s_addr) != m->end()){
        m->at(ip_src.s_addr).tx_c++;
        m->at(ip_src.s_addr).tx_b+=size;
    }else{
        ST_je_Rx_Tx rx_tx = {0, 0, 0, 0};
        rx_tx.tx_c++;
        rx_tx.tx_b+=size;
        m->insert(make_pair(ip_src.s_addr, rx_tx));
    }
    if( m->find(ip_dst.s_addr) != m->end()){
        m->at(ip_dst.s_addr).rx_c++;
        m->at(ip_dst.s_addr).rx_b+=size;
    }else{
        ST_je_Rx_Tx rx_tx = {0, 0, 0, 0};
        rx_tx.rx_c++;
        rx_tx.rx_b+=size;
        m->insert(make_pair(ip_dst.s_addr, rx_tx));
    }
}
void countMac(const ST_je_ip_header* packet, map<Mac, ST_je_Rx_Tx> *m, bpf_u_int32 size){
    Mac mac_src(packet->eth_hdr, 0);
    Mac mac_dst(packet->eth_hdr, 1);

    if( m->find(mac_src) != m->end()){
        m->at(mac_src).tx_c++;
        m->at(mac_src).tx_b+=size;
    }else{
        ST_je_Rx_Tx rx_tx = {0, 0, 0, 0};
        rx_tx.tx_c++;
        rx_tx.tx_b+=size;
        m->insert(make_pair(mac_src, rx_tx));
    }
    if( m->find(mac_dst) != m->end()){
        m->at(mac_dst).rx_c++;
        m->at(mac_dst).rx_b+=size;
    }else{
        ST_je_Rx_Tx rx_tx = {0, 0, 0, 0};
        rx_tx.rx_c++;
        rx_tx.rx_b+=size;
        m->insert(make_pair(mac_dst, rx_tx));
    }
}
void countIpAtoB(const ST_je_ip_header* packet, map<pair<u_int32_t, u_int32_t>, ST_je_Rx_Tx> *m, bpf_u_int32 size){
    struct in_addr ip_src = packet->ip_hdr.ip_src;
    struct in_addr ip_dst = packet->ip_hdr.ip_dst;

    if ((m->find(make_pair(ip_src.s_addr, ip_dst.s_addr)) != m->end()) || (m->find(make_pair(ip_dst.s_addr, ip_src.s_addr))) != m->end()){
        if(m->find(make_pair(ip_src.s_addr, ip_dst.s_addr)) != m->end()){
            m->at(make_pair(ip_src.s_addr, ip_dst.s_addr)).tx_c++;
            m->at(make_pair(ip_src.s_addr, ip_dst.s_addr)).tx_b+=size;
        } else{
            m->at(make_pair(ip_dst.s_addr, ip_src.s_addr)).rx_c++;
            m->at(make_pair(ip_dst.s_addr, ip_src.s_addr)).rx_b+=size;
        }
    } else{
        ST_je_Rx_Tx rx_tx = {0, 0, 0, 0};
        m->insert(make_pair(make_pair(ip_src.s_addr, ip_dst.s_addr), rx_tx));
        if ((m->find(make_pair(ip_src.s_addr, ip_dst.s_addr)) != m->end()) || (m->find(make_pair(ip_dst.s_addr, ip_src.s_addr))) != m->end()){
            if(m->find(make_pair(ip_src.s_addr, ip_dst.s_addr)) != m->end()){
                m->at(make_pair(ip_src.s_addr, ip_dst.s_addr)).tx_c++;
                m->at(make_pair(ip_src.s_addr, ip_dst.s_addr)).tx_b+=size;
            } else{
                m->at(make_pair(ip_dst.s_addr, ip_src.s_addr)).rx_c++;
                m->at(make_pair(ip_dst.s_addr, ip_src.s_addr)).rx_b+=size;
            }
        }
    }
}
void countMacAtoB(const ST_je_ip_header* packet, map<pair<Mac, Mac>, ST_je_Rx_Tx> *m, bpf_u_int32 size){
    Mac mac_src(packet->eth_hdr, 0);
    Mac mac_dst(packet->eth_hdr, 1);

    if ((m->find(make_pair(mac_src, mac_dst)) != m->end()) || (m->find(make_pair(mac_dst, mac_src))) != m->end()){
        if(m->find(make_pair(mac_src, mac_dst)) != m->end()){
            m->at(make_pair(mac_src, mac_dst)).tx_c++;
            m->at(make_pair(mac_src, mac_dst)).tx_b+=size;
        } else{
            m->at(make_pair(mac_dst, mac_src)).rx_c++;
            m->at(make_pair(mac_dst, mac_src)).rx_b+=size;
        }
    } else{
        ST_je_Rx_Tx rx_tx = {0, 0, 0, 0};
        m->insert(make_pair(make_pair(mac_src, mac_dst), rx_tx));
        if ((m->find(make_pair(mac_src, mac_dst)) != m->end()) || (m->find(make_pair(mac_dst, mac_src))) != m->end()){
            if(m->find(make_pair(mac_src, mac_dst)) != m->end()){
                m->at(make_pair(mac_src, mac_dst)).tx_c++;
                m->at(make_pair(mac_src, mac_dst)).tx_b+=size;
            } else{
                m->at(make_pair(mac_dst, mac_src)).rx_c++;
                m->at(make_pair(mac_dst, mac_src)).rx_b+=size;
            }
        }
    }
}
