#ifndef IPKTPROCCESSER_H
#define IPKTPROCCESSER_H

class IPktProccesser {
public:
    virtual void Proccess(const unsigned char* pkt, int pktSize) = 0; 
};

#endif // IPKTPROCCESSER_H