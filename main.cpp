#include "stdafx.h"

int main(int argc, char *argv[])
{

    if (argc < 2) {
        usage();
        return -1;
    }

    char errbuffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handler = pcap_open_offline(argv[1], errbuffer);
    //you don't have file
    if (pcap_handler == nullptr) {
        fprintf(stderr, "%s", errbuffer);
        return -1;
    }
    map<u_int32_t, ST_je_Rx_Tx> ip;
    map<pair<u_int32_t, u_int32_t>, ST_je_Rx_Tx> ip_a_to_b;
    map<Mac, ST_je_Rx_Tx> mac;
    map<pair<Mac, Mac>, ST_je_Rx_Tx> mac_a_to_b;

    ST_je_ip_header* ip_header = reinterpret_cast<ST_je_ip_header*>(malloc(sizeof(ST_je_ip_header)));
    while (true) {
        //test_count
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap_handler, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        *ip_header = *(reinterpret_cast<ST_je_ip_header*>(const_cast<u_char*>(packet)));
        if (ip_header->eth_hdr.ether_type == 0x008){
            countIp(ip_header, &ip, header->caplen);
            countIpAtoB(ip_header, &ip_a_to_b, header->caplen);
        }
        countMac(ip_header, &mac, header->caplen);
        countMacAtoB(ip_header, &mac_a_to_b, header->caplen);
    }
    while (true){
        uint8_t num = 0;
        cout << "1. EndPoint (mac) " << endl;
        cout << "2. EndPoint (ip) " << endl;
        cout << "3. Conversation (mac) " << endl;
        cout << "4. Conversation (ip) " << endl;
        cout << "plz select num : ";
        cin >> num;

        system("clear");
        if (num == '1') printEndPoint(&mac);
        else if (num == '2') printEndPoint(&ip);
        else if (num == '3') printEndPoint(&mac_a_to_b);
        else if (num == '4') printEndPoint(&ip_a_to_b);
        else break;
        cout << endl;
    }
    free(ip_header);
    return 0;
}
