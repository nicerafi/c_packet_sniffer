#include "dispatch.h"
#include "analysis.h"
#include "queue.h"
#include "sniff.h"
#include <pthread.h>
#include <pcap.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

struct queue *packet_queue;
pthread_t threads[4];
int threadflag = 0;
unsigned char *pckt;

// mutex lock required for our shared queue //
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

void sig_handle(int sig)
{
  if (sig == SIGINT)
  {// If Ctrl^C is pressed
    threadflag++; // While loop in threadpool() will break
    kill_threads(); // Run function which will kill the program and write the report
    exit(EXIT_SUCCESS);  // Exit
  }
}

void kill_threads(){
  void *pointer;
  int i = 0;
  for (i = 0; i < 4; i++)
  { // Join our threads
    pthread_join(threads[i], &pointer);
  }
  pcap_breakloop(pcap_handle); // Break the loop so no more packets come in
  pcap_close(pcap_handle); // Close all pcap related stuff, frees it from memory
  //Print out the intrusion report//
  printf("\n Intrusion Detection Report: ");
  printf("\n %d Total Packets Sniffed", packet_count);
  printf("\n %d SYN Packets detected from %d different IPs (SYN Attack)", number_of_syn, ip_counter);
  printf("\n %d ARP responses (cache poisoning)", number_of_arp);
  printf("\n %d URL Blacklist violations \n", number_of_blacklist);
  //Free all the pointers//
  free_array();
  free(packet_queue);
  // exit(EXIT_SUCCESS);  
}

void initialise() // Initialise our queue and threads.
{
  packet_queue = create_queue();
  threadflag = 0;
  int i;
  printf("Making Threads\n");
  for (i = 0; i < 4; i++)
  {
    pthread_create(&threads[i], NULL, &threadpool, NULL);
  }
  printf("Threads Created!\n");
}

void *threadpool(void *arg) // Threading code
{
  unsigned char *pack;
  signal(SIGINT, sig_handle); // Checks for Ctrl^C signal
  while (!threadflag)
  { // While Ctrl^C Signal has not been inputted
    if (!is_empty(packet_queue))
    { // If the stack isn't empty
      // Dequeue the packet and analyse it //
      pack = dequeue(packet_queue);
      if (pack != NULL)
      { // Sanity check
        analyse(pack, verb);
        free(pack); // Free the pack variable after it's done being used.
      }
    }
  }
  return 0;
}

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose)
{
  if (packet != NULL) // Sanity check
  {
    /* As the packets are pointers, they are overwritten every time dispatch() is called
    so we store the packet data in a temp variable so they don't get overwritten. */
    pckt = malloc((sizeof(char) * header->len) + 1);
    if (pckt == NULL)
    { // Couldn't allocate memory
      exit(1);
    }
    // Copy the packet data in memory to our pckt variable //
    memcpy(pckt, packet, header->len + 1);
    pthread_mutex_lock(&queue_mutex);
    // Enqueue the packet //
    enqueue(packet_queue, pckt); 
    pthread_mutex_unlock(&queue_mutex);
  }
}
