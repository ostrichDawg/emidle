#ifndef INTERFACEHANDLER_H_INCLUDE
#define INTERFACEHANDLER_H_INCLUDE


#include <WinSock2.h>
#define HAVE_REMOTE
#include <pcap.h>

#include "IPktProccesser.h"
#include "AppExceptions.h"

class InterfaceHandler {
private:
    pcap_t* _adhandle;
    IPktProccesser* _prcs;
public:
    InterfaceHandler(char* interfaceName, IPktProccesser* prcs);
 
    void CaptureLoop();
};


#endif // INTERFACEHANDLER_H_INCLUDE