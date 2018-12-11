/*
 * This project is a tool for TCP traffic analysis.
 *
 * Requirement: TCP trace file (Recommend using Wireshark for generation)
 * Author:      An Yameng
 * Repository:  https://github.com/imane0897/TCP-Traffic-Analysis
 */

#include "main.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int count = 0;

struct connection cList[MAX_NUM_CONNECTION];
struct built actual[MAX_NUM_CONNECTION];
struct built actual1[MAX_NUM_CONNECTION];
struct RTT slist[MAX_NUM_CONNECTION];
/*--------End of Variables--------*/

void print_report();
void dump_packets(const unsigned char *packet, struct timeval ts,
                  unsigned int capture_len);

/* Count the total number of connections and store it. */
void buildFilter(struct built *actual, struct connection *cList, int total) {
  /* Initialization of all the variables*/
  int j;
  int k;
  /* Checking all of the packets and collect the information. */
  for (j = 0; j < total; j++) {
    if (cList[j].is_set2 == 0) {
      strcpy(actual1[0].src, cList[j].src);
      strcpy(actual1[0].dst, cList[j].dst);
      actual1[0].src_port = cList[j].src_port;
      actual1[0].dst_port = cList[j].dst_port;
      cList[j].is_set2 = 1;
      count++;
    }
    k = 1;
    int i = j + 1;
    for (; i < total; i++) {
      if ((!strcmp(cList[i].src, actual1[0].src) &&
           !strcmp(cList[i].dst, actual1[0].dst) &&
           actual1[0].src_port == cList[i].src_port &&
           actual1[0].dst_port == cList[i].dst_port && cList[i].is_set2 == 0) ||
          (!strcmp(cList[i].src, actual1[0].dst) &&
           !strcmp(cList[i].dst, actual1[0].src) &&
           actual1[0].src_port == cList[i].dst_port &&
           actual1[0].dst_port == cList[i].src_port && cList[i].is_set2 == 0)) {
        cList[i].is_set2 = 1;
        strcpy(actual1[k].src, cList[i].src);
        strcpy(actual1[k].dst, cList[i].dst);
        actual1[k].src_port = cList[i].src_port;
        actual1[k].dst_port = cList[i].dst_port;
        k++;
      }
    }
  }
}

int main(int argc, char *argv[]) {
  /*
   * Load TCP trace file
   */
  if (argc != 2) {
    fprintf(stderr,
            "Error: This program need one parameter of TCP trace file path\n");
    exit(1);
  }

  pcap_t *pcap;
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap = pcap_open_offline(argv[1], errbuf);
  if (pcap == NULL) {
    fprintf(stderr, "Error reading pcap file: %s\n", errbuf);
    exit(1);
  }

  /*
   * 
   */
  const unsigned char *packet;
  struct pcap_pkthdr header;

  while ((packet = pcap_next(pcap, &header)) != NULL) {
    dump_packets(packet, header.ts, header.caplen);
  }

  buildFilter(actual, cList, total);
  print_report();

  return 0;
}

/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval timestamp) {
  static char timestamp_string_buf[256];

  sprintf(timestamp_string_buf, "%d.%06d", (int)timestamp.tv_sec,
          (int)timestamp.tv_usec);

  return timestamp_string_buf;
}

