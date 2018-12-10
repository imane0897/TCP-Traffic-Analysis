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
#include "dump_packets.h"

/* dump_tcp_packet()
 *
 * This routine parses a packet, expecting Ethernet, IP, and UDP headers.
 * It extracts the UDP source and destination port numbers along with the UDP
 * packet length by casting structs over a pointer that we move through
 * the packet.  We can do this sort of casting safely because libpcap
 * guarantees that the pointer will be aligned.
 *
 * The "ts" argument is the timestamp associated with the packet.
 *
 * Note that "capture_len" is the length of the packet *as captured by the
 * tracing program*, and thus might be less than the full length of the
 * packet.  However, the packet pointer only holds that much data, so
 * we have to be careful not to read beyond it.
 */
void dump_tcp_packet(const unsigned char *packet, struct timeval ts,
                     unsigned int capture_len) {
  /* Initialization if the variables. */
  struct ip *ip;
  struct tcp_header *tcp;
  struct connection connect;
  unsigned int IP_header_length;
  unsigned int total_length;

  total_length = capture_len;
  /* For simplicity, we assume Ethernet encapsulation. */
  if (capture_len < sizeof(struct ether_header)) {
    /* We didn't even capture a full Ethernet header, so we
     * can't analyze this any further.
     */
    too_short("Ethernet header");
    return;
  }

  /* Skip over the Ethernet header. */
  packet += sizeof(struct ether_header);
  capture_len -= sizeof(struct ether_header);

  if (capture_len < sizeof(struct ip)) { /* Didn't capture a full IP header */
    too_short("IP header");
    return;
  }

  ip = (struct ip *)packet;
  IP_header_length = ip->ip_hl * 4; /* ip_hl is in 4-byte words */

  if (capture_len < IP_header_length) { /* didn't capture the full IP header
                                           including options */
    too_short("IP header with options");
    return;
  }

  if (ip->ip_p != IPPROTO_TCP) {
    problem_pkt("non-TCP packet");
    return;
  }

  /* Skip over the IP header to get to the TCP header. */
  packet += IP_header_length;
  capture_len -= IP_header_length;

  if (capture_len < sizeof(struct tcp_header)) {
    too_short("TCP header");
    return;
  }

  tcp = (struct tcp_header *)packet;

  /* Get all the information from the tcp header and store it to the list ->
   * cList[]*/
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
  // printf("%u\n", cList[total].seq);
  // printf("%u\n", cList[total].ack);
  // printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
  /* Time thing. And store it to the tim variable. */
  static char timestamp_string_buf[256];

  sprintf(timestamp_string_buf, "%d.%06d", (int)ts.tv_sec, (int)ts.tv_usec);
  double tim = atof(timestamp_string_buf);
  cList[total].started = tim;
  total++;
}