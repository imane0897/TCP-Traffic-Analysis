/*
 * dump_packets.c
 *
 * This routine parses a packet, expecting Ethernet, IP, and TDP headers.
 */

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
#include "main.h"

void dump_packets(const unsigned char *packet, struct timeval ts,
                  unsigned int capture_len) {
  struct ip *ip;
  struct tcp_header *tcp;
  struct connection connect;

  unsigned int IP_header_length;
  unsigned int total_length = capture_len;

  /*
   * Check Ethernet Header
   */
  if (capture_len < sizeof(struct ether_header)) {
    parser_error("Ethernet header");
    return;
  }

  /*
   * Check IP Header
   */
  packet += sizeof(struct ether_header);
  capture_len -= sizeof(struct ether_header);

  if (capture_len < sizeof(struct ip)) {
    parser_error("IP header");
    return;
  }

  ip = (struct ip *)packet;
  IP_header_length = ip->ip_hl * 4;  // ip_hl is in 4-byte words

  if (capture_len < IP_header_length) {
    parser_error("IP header with options");
    return;
  }

  if (ip->ip_p != IPPROTO_TCP) {
    problem_pkt("non-TCP packet");
    return;
  }

  /*
   * Check TCP Header
   */
  packet += IP_header_length;
  capture_len -= IP_header_length;

  if (capture_len < sizeof(struct tcp_header)) {
    parser_error("TCP header");
    return;
  }

  /*
   * TCP info -> cList[]
   */
  tcp = (struct tcp_header *)packet;
  
  char *source = inet_ntoa(ip->ip_src);
  strcpy(connect.src, source);
  char *destination = inet_ntoa(ip->ip_dst);
  strcpy(connect.dst, destination);
  connect.port_src = ntohs(tcp->th_sport);
  connect.port_dst = ntohs(tcp->th_dport);
  strcpy(cList[total].src, connect.src);
  strcpy(cList[total].dst, connect.dst);
  cList[total].port_src = connect.port_src;
  cList[total].port_dst = connect.port_dst;
  cList[total].is_set = 0;
  cList[total].tflags = (unsigned int)tcp->th_flags;
  cList[total].length = capture_len - TH_OFF(tcp) * 4;
  cList[total].win = ntohs(tcp->th_win);
  cList[total].seq = ntohl(tcp->th_seq);
  cList[total].ack = ntohl(tcp->th_ack);

  static char timestamp_string_buf[256];

  sprintf(timestamp_string_buf, "%d.%06d", (int)ts.tv_sec, (int)ts.tv_usec);
  double tim = atof(timestamp_string_buf);
  cList[total].started = tim;
  total++;
}