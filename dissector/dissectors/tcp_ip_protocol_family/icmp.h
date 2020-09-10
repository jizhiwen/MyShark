#ifndef ICMP_H
#define ICMP_H

#include "../../protree/protree.h"
#include "../../dissres/dissectresutltframe.h"

#include "../../units/checksum2.h"

class Icmp
{
public:
    Icmp(ProTree *proTree,tcp_ip_protocol_family::DissectResultIcmp *dissectResultIcmp,void *reserves);
};

#endif // ICMP_H
