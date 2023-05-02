#ifndef APPEXCEPTIONS_H
#define APPEXCEPTIONS_H

#include <exception>
#include <string.h>

class LPcapException : public std::exception {
private:
    char error[256];
public:
    LPcapException(char* err_msg) {
        memcpy(error, err_msg, 256);
    }

    virtual const char* what() {
        return error;
    }
};

#endif // APPEXCEPTIONS_H