#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

extern int threadflag;
extern unsigned char *pckt;

void dispatch(const struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);
void sig_handle (int sig);
void kill_threads();
void initialise();
void *threadpool (void* arg);

#endif
