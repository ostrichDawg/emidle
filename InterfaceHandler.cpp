#include "InterfaceHandler.h"

void get_pkt(u_char* args, const pcap_pkthdr* header, const u_char* pkt_data)
{
    ((IPktProccesser*) args)->Proccess(pkt_data, header->len);
}

InterfaceHandler::InterfaceHandler(char *interfaceName, IPktProccesser *prcs)
{
    char error[PCAP_ERRBUF_SIZE];
    
    _adhandle = pcap_open(interfaceName, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, error);
    if(_adhandle == nullptr) 
        throw LPcapException(error);

    _prcs = prcs;
}

void InterfaceHandler::CaptureLoop()
{
    pcap_loop(_adhandle, 0, get_pkt, (u_char*) _prcs);
}