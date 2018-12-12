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



void print_report();
void dump_packets(const unsigned char *packet, struct timeval ts,
                  unsigned int capture_len);


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
   * Process packets
   */
  const unsigned char *packet_content;
  struct pcap_pkthdr packet_header;

  while ((packet_content = pcap_next(pcap, &packet_header)) != NULL) {
    dump_packets(packet_content, packet_header.ts, packet_header.caplen);
  }

  print_report();

  return 0;
}
