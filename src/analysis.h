#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

extern int number_of_syn;
extern int number_of_arp;
extern int number_of_blacklist;
extern int ip_counter;
extern int packet_count;

int valueinarray(char *src, char **arr, int counter);

void free_array();

void no_mem();

void report();

void analyse(
              const unsigned char *packet,
              int verbose);
#endif
