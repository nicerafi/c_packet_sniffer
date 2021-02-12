#include "analysis.h"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

// Constants used in analyse() //
#define SIZE_ETHERNET 14
#define ETHER_TYPE_IPv4 0x0800

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// Global Variables //
int number_of_syn = 0; // Counter for number of SYN bits
int number_of_arp = 0; // Counter for number of ARP responses
int number_of_blacklist = 0; // Counter for number of blacklist URL violations
int ip_counter = 0; // Counter of unique IPs
int packet_count = 0;
char **unique_ip; // Array of unique IPs

int valueinarray(char *val, char **arr, int counter) // searches through char array for a value
{
  int i;
  for (i = 0; i < counter; i++) {
    if (strcmp(val, arr[i]) == 0) // Compares the value we want to find and the value in that certain array index
      return 1;
  }
  return 0;
}

void free_array() { // Self explanatory, frees array to stop memory leaks
  int j;
  for (j = 0; j < ip_counter; j++) { // Free each pointer in the array
    free(unique_ip[j]);
  }
  free(unique_ip); // Free the top-level pointer
}

void no_mem() { // Method which runs if a memory allocation function fails to allocate memory
  printf("Cannot allocate memory, exiting program.");
  free_array();
  exit(0);
}

void analyse(const unsigned char *packet,int verbose) { 
  int i;
  char ip[16];
  // Lets access the Ethernet Header from our packet //
  struct ether_header * eth_header = (struct ether_header *) packet;
  if (ntohs(eth_header -> ether_type) == ETHERTYPE_ARP) { // If we have an ARP Packet
    // Access ARP Header which will be in the same location as an IP header //
    struct ether_arp * arp_hdr = (struct ether_arp *)(packet + SIZE_ETHERNET); 
    if (ntohs(arp_hdr -> arp_op) == 2) // We have an ARP response
    {
      // As we are incrementing a global variable we should mutex lock it //
      pthread_mutex_lock(&lock); 
      number_of_arp++;
      pthread_mutex_unlock(&lock);
    }
  } else if (ntohs(eth_header -> ether_type) == ETHER_TYPE_IPv4) { // We have a IP Header
    struct ip * ip_hdr = (struct ip *)(packet + SIZE_ETHERNET); // Access IP header
    struct tcphdr * tcp_hdr = (struct tcphdr *)(packet + SIZE_ETHERNET + ip_hdr -> ip_hl * 4); // Access TCP header
    // Massive if statement which checks whether the SYN bit is the only control bit in the TCP header which is 1 //
    if ((tcp_hdr -> syn == 1) & (tcp_hdr -> urg == 0) 
    & (tcp_hdr -> ack == 0) & (tcp_hdr -> psh == 0) 
    & (tcp_hdr -> rst == 0) & (tcp_hdr -> fin == 0)) {
      pthread_mutex_lock(&lock); 
      number_of_syn++; 
      pthread_mutex_unlock(&lock); 
      // As inet_ntoa() stores the string created in memory and can be overwritten we should store it in a variable //
      strcpy(ip, inet_ntoa(ip_hdr -> ip_src)); 
      if (ip_counter == 0) // First IP added to the array
      {
        pthread_mutex_lock(&lock);
        ip_counter++;
        pthread_mutex_unlock(&lock);
        unique_ip = malloc(ip_counter * sizeof(*unique_ip)); // Initiate the array
        if(unique_ip == NULL){no_mem();} // Check if we have actually allocated the memory for the array
        unique_ip[0] = malloc(16 * sizeof(char * )); //Allocate memory for the array index
        if(unique_ip[0] == NULL){no_mem();}
        strcpy(unique_ip[0], ip); // copy the current IP into our IP array
      } 
      else {
        if (valueinarray(ip, unique_ip, ip_counter) == 0) // Source IP is unique, add to array
        {
          pthread_mutex_lock(&lock);
          ip_counter++;
          pthread_mutex_unlock(&lock);
          // Rellocate memory in the array to accomodate for the new ip thats being added //
          unique_ip = realloc(unique_ip, (ip_counter) * sizeof(*unique_ip)); 
          if (unique_ip == NULL) {no_mem();}
          unique_ip[ip_counter - 1] = malloc(16 * sizeof(char * )); 
          if (unique_ip[ip_counter - 1] == NULL) {no_mem();}
          strcpy(unique_ip[ip_counter - 1], ip);
        }
      }
    }
    if (ntohs(tcp_hdr -> dest) == 80) // Packet sent to port 80
    {
      const unsigned char *payload = packet + ETH_HLEN + (ip_hdr -> ip_hl * 4) + (tcp_hdr -> doff * 4); // Access the payload of the header
      char *result = strstr((char *) payload, "Host:"); // Check if the payload contains the url as a substring
      if (result != NULL) { // strstr() returns NULL if it cannot find the substring
        if (strstr(result, "google.co.uk") != NULL) { // Now lets check if it contains the URL.
          pthread_mutex_lock(&lock);
          number_of_blacklist++;
          pthread_mutex_unlock(&lock);
        }
      }
    }
    // Debugging code, prints out packet information//
    if (0) // DONT USE VERBOSE MODE
    {
      printf("\n === ETHERNET HEADER ===");
      printf("\nSource MAC: ");
      for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header -> ether_shost[i]);
        if (i < 5) {
          printf(":");
        }
      }
      printf("\nDestination MAC: ");
      for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header -> ether_dhost[i]);
        if (i < 5) {
          printf(":");
        }
      }

      printf("\nType: %hu\n", ntohs(eth_header -> ether_type));
      printf("\n === IP HEADER ===");
      printf("\n Source IP: ");
      printf("%s", inet_ntoa(ip_hdr -> ip_src));
      printf("\n Destination IP: ");
      printf("%s", inet_ntoa(ip_hdr -> ip_dst));
      printf("\n Protocol: ");
      printf("%hu", ip_hdr -> ip_p);

      printf("\n === TCP HEADER ===");
      printf("\n Source Port: ");
      printf("%hu", ntohs(tcp_hdr -> source));
      printf("\n Destination Port: ");
      printf("%hu", ntohs(tcp_hdr -> dest));
    }
  }
  pthread_mutex_lock(&lock);
  packet_count++;
  pthread_mutex_unlock(&lock);
}