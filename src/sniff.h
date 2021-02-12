#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H
#include <pcap.h>

extern pcap_t *pcap_handle;
extern int verb;
void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

#endif
