#include "dissectresulticmp.h"

using namespace tcp_ip_protocol_family;

DissectResultIcmp::DissectResultIcmp(DissectResultBase *dissectResultBase,void *reserves)
        :DissectResult(dissectResultBase)
{
    Q_UNUSED(reserves)

    dissectResultBase->PushToProtocolList("icmp",ICMP_FIXED_LENGTH);

    this->header = (struct header_t*)dissectResultBase->GetProtocolHeaderStartPtrByName("icmp");

    dissectResultBase->SetSummery(QString("%1 (%2)")
                                  .arg(this->GetTypeMeaning())
                                  .arg(this->GetCodeMeaning())
                                  );
}

quint8 DissectResultIcmp::GetType(){
    return *this->header->type;
}

QString DissectResultIcmp::GetTypeMeaning(){
    return icmp_type_values.value(this->GetType());
}

quint8 DissectResultIcmp::GetCode(){
    return *this->header->code;
}

QString DissectResultIcmp::GetCodeMeaning(){
    return icmp_code_values.value(this->GetCode());
}

QString DissectResultIcmp::GetChecksumStr(){
    return Converter::ConvertQuint8ArrayToHexStr(this->header->checksum,ICMP_CHECKSUM);
}

QString DissectResultIcmp::GetInfoStr(){
    return Converter::ConvertQuint8ArrayToHexStr(this->header->info,ICMP_INFO,"","");
}
