#include <iostream>
#include <WinSock2.h>

#define HAVE_REMOTE
#include <pcap.h>

int main(int argc, char** argv) 
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if( pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == PCAP_ERROR ) {
        std::cout << errbuf << '\n';
        return -1;
    }
    
    for(d = alldevs; d != nullptr; d = d->next) {
        std::cout << d->name;
        if(d->description) 
            std::cout << " (" << d->description << ")";
        std::cout << ";\n";
    }
        
    pcap_freealldevs(alldevs);

    return 0;
}