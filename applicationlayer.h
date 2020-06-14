#ifndef APPLICATIONLAYER_H
#define APPLICATIONLAYER_H

#include "lbpcap.h"

bool checkFTPproto(const u_char *packet, int len);

bool checkHTTPproto(const u_char *packet, int len);


#endif // APPLICATIONLAYER_H
