#ifndef DISSECTRESULTICMP_H
#define DISSECTRESULTICMP_H

#include "arpa/inet.h"
#include "time.h"

#include "../../units/checksum2.h"

#include "../dissectresultbase.h"

#include "../dissectresult.h"

/*0                   1          |        2                   3
 *0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
 *type           |   Code        |     Checksum                  |
 *    取绝与ICMP类型                                              |
 *    数据部分（长度取决于ICPM类型）                                 |
 *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
 */

const QHash<qint32,QString> icmp_type_values =
{
    {3,"Destination unreachable"}
};

const QHash<qint32,QString> icmp_code_values =
{
    {3,"Port unreachable"}
};

namespace tcp_ip_protocol_family {

class DissectResultIcmp:public DissectResult
{
public:
    enum ICMP_FIELD_LENGTH{
        ICMP_TYPE = 1,
        ICMP_CODE = 1,
        ICMP_CHECKSUM = 2,
        ICMP_INFO = 4,

        ICMP_FIXED_LENGTH = 8
    };

    DissectResultIcmp(DissectResultBase *dissectResultBase,void *reserves);

    quint8 GetType();
    QString GetTypeMeaning();
    quint8 GetCode();
    QString GetCodeMeaning();
    QString GetChecksumStr();
    QString GetInfoStr();

private:
    struct header_t{
      quint8 type[ICMP_TYPE];
      quint8 code[ICMP_CODE];
      quint8 checksum[ICMP_CHECKSUM];
      quint8 info[ICMP_INFO];
    };

    struct header_t *header;
};

}

#endif // DISSECTRESULTICMP_H
