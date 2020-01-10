#ifndef MAC_H
#define MAC_H
#include "stdafx.h"

class Mac
{
private:
    uint8_t ether_host[ETHER_ADDR_LEN];

public:
    Mac(struct libnet_ethernet_hdr, bool);
    bool operator<(const Mac& other) const;
    uint8_t* getEtherHost();
};

#endif // MAC_H
