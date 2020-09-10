#include "icmp.h"


Icmp::Icmp(ProTree *proTree,tcp_ip_protocol_family::DissectResultIcmp *dissectResultIcmp,void *reserves)
{
    Q_UNUSED(reserves)

    // Summeruy
    qint32 start = dissectResultIcmp->GetDissectResultBase()->GetProtocolHeaderStartPositionByName("icmp");
    proTree->AddItem("icmp"
                     ,QString("Internet Control Message Protocol")
                     ,start
                     ,dissectResultIcmp->GetDissectResultBase()->GetProtocolHeaderEndPositionByName("icmp") - 1
                     ,ProTree::level::CURRENT);

    // Summery - Type
    proTree->AddNextLayerItem("icmp"
                              ,QString("Type : %1 (%2)")
                              .arg(dissectResultIcmp->GetType())
                              .arg(dissectResultIcmp->GetTypeMeaning())
                              ,&start
                              ,tcp_ip_protocol_family::DissectResultIcmp::ICMP_TYPE
                              ,true);

    // Summery - Code
    proTree->AddCurrentLayerItem("icmp"
                                 ,QString("Code: %1 (%2)")
                                 .arg(dissectResultIcmp->GetCode())
                                 .arg(dissectResultIcmp->GetCodeMeaning())
                                 ,&start
                                 ,tcp_ip_protocol_family::DissectResultIcmp::ICMP_CODE
                                 ,true);

    // Summery - Checksum
    proTree->AddCurrentLayerItem("tcmp"
                                 ,QString("Checksum: %1")
                                 .arg(dissectResultIcmp->GetChecksumStr())
                                 ,&start
                                 ,tcp_ip_protocol_family::DissectResultIcmp::ICMP_CHECKSUM
                                 ,true);
}
