#include "stdafx.h"

Mac::Mac(struct libnet_ethernet_hdr a, bool check)
{
    if (!check){
        for (int i = 0; i <ETHER_ADDR_LEN; i++){
            ether_host[i] = a.ether_shost[i];
        }
    } else {
        for (int i = 0; i <ETHER_ADDR_LEN; i++){
            ether_host[i] = a.ether_dhost[i];
        }
    }
}
bool Mac::operator<(const Mac &other) const{
    u_int64_t check = 0;
    u_int64_t other_check =0;

    for(u_int8_t i = 0; i < ETHER_ADDR_LEN; i++){
        check += ether_host[i] << ((ETHER_ADDR_LEN - i) * 8);
        other_check += other.ether_host[i] << ((ETHER_ADDR_LEN - i) * 8);
    }

    return check < other_check;
}
uint8_t* Mac::getEtherHost(){
    return ether_host;
}
