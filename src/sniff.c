#ifndef __USE_BSD
#define __USE_BSD
#endif
#include "sniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include "dispatch.h"



pcap_t *pcap_handle; // Want to have this global so we can break the loop in our signal handling function
int verb; // Our global verbose variable

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){ 
	 // Dispatch packet for processing in dispatch()
	dispatch(header, packet, verb);
	
}


void sniff(char * interface, int verbose) {
  // Open network interface for packet capture
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  verb = verbose;
  if (signal(SIGINT, sig_handle) == SIG_ERR){
    printf("\nCan't catch SIGINT!\n");
		exit(0);
	}
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  initialise(); // Initialise our threads and stack for use
  pcap_loop(pcap_handle, 0, packet_handler, NULL); // Sends packets to packet_handler()
}


// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header * eth_header = (struct ether_header * ) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
