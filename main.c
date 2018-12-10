/*
  This project is a tool for TCP traffic analysis.

  Requirement: TCP trace file (Recommend using Wireshark for generation)
  Author:      An Yameng
  Repository:  https://github.com/imane0897/TCP-Traffic-Analysis
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
/* We've included the UDP header struct for your ease of customization.
 * For your protocol, you might want to look at netinet/tcp.h for hints
 * on how to deal with single bits or fields that are smaller than a byte
 * in length.
 *
 * Per RFC 768, September, 1981.
 */
#define MAX_STR_LEN 200
#define MAX_NUM_CONNECTION 10000

/*
  TCP header
*/
typedef u_int tcp_seq;
struct tcp_header {
  u_short th_sport;  // source port
  u_short th_dport;  // destination port
  tcp_seq th_seq;    // sequence number
  tcp_seq th_ack;    // acknowledgement number
  u_char th_offx2;   // data offset, rsvd
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  u_short th_win;  // window
  u_short th_sum;  // checksum
  u_short th_urp;  // urgent pointer
};

/*
  The structure from the Lab
*/
struct connection {
  char src[MAX_STR_LEN];  // source ip
  char dst[MAX_STR_LEN];  // destination ip
  uint16_t port_src;      // source port number
  uint16_t port_dst;      // destination port number
  int tflags;
  int syn_count;  // flag count
  int fin_count;
  int rst_count;
  double started;
  struct timeval starting_time;
  struct timeval ending_time;
  double duration;
  int num_packet_src;  // number of packets sent out by source
  int num_packet_dst;  // number of packets sent out by destination
  int num_total_packets;
  int cur_data_len_src;  // num data bytes
  int cur_data_len_dst;  // num data bytes
  int cur_total_data_len;
  uint16_t win;
  uint16_t max_win_size;  // max window size
  uint16_t min_win_size;  // min window size
  double sum_win_size;
  int length;
  int seq;
  int ack;
  int is_set;
  int is_set2;
};


struct built {
  char src[MAX_STR_LEN];  // source ip
  char dst[MAX_STR_LEN];  // destination ip
  uint16_t port_src;      // source port number
  uint16_t port_dst;      // destination port number
  double started;
  double duration;
  int syn_count;  // flag count*/
  int fin_count;
  int rst_count;
  int length;
  uint16_t win;
  uint16_t max_win_size;  // max window size
  uint16_t min_win_size;  // min window size
  double sum_win_size;
  int is_set;
  int seq;
  int ack;
  int send;
};


struct RTT {
  double curr_time;
  int seq_num;
  int ack_num;
};


/*--------Global Variables--------*/
int print;
int connected;
int count = 0;
int total;
int counts;
int countf;
int countr;
int countEnd;
int minP = 1000;
int maxP;
int total_p;
double total_win;
double all_win;
double total_time;
double during;
double min_time = 1000.00;
double max_time;
double all_time;
int total_pack;
double Total_RTT;
double min_RTT = 1000.00;
double max_RTT;
int manys;

struct connection cList[MAX_NUM_CONNECTION];
struct built actual[MAX_NUM_CONNECTION];
struct built actual1[MAX_NUM_CONNECTION];
struct RTT slist[MAX_NUM_CONNECTION];
/*--------End of Variables--------*/

/* Some helper functions, which we define at the end of this file. */

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(const char *truncated_hdr);

/* dump_TCP_packet()
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
void dump_TCP_packet(const unsigned char *packet, struct timeval ts,
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
      actual1[0].port_src = cList[j].port_src;
      actual1[0].port_dst = cList[j].port_dst;
      cList[j].is_set2 = 1;
      count++;
    }
    k = 1;
    int i = j + 1;
    for (; i < total; i++) {
      if ((!strcmp(cList[i].src, actual1[0].src) &&
           !strcmp(cList[i].dst, actual1[0].dst) &&
           actual1[0].port_src == cList[i].port_src &&
           actual1[0].port_dst == cList[i].port_dst && cList[i].is_set2 == 0) ||
          (!strcmp(cList[i].src, actual1[0].dst) &&
           !strcmp(cList[i].dst, actual1[0].src) &&
           actual1[0].port_src == cList[i].port_dst &&
           actual1[0].port_dst == cList[i].port_src && cList[i].is_set2 == 0)) {
        cList[i].is_set2 = 1;
        strcpy(actual1[k].src, cList[i].src);
        strcpy(actual1[k].dst, cList[i].dst);
        actual1[k].port_src = cList[i].port_src;
        actual1[k].port_dst = cList[i].port_dst;
        k++;
      }
    }
  }
}

int checkConn(struct built *actual, struct connection *cList, struct timeval ts,
              int total, int print) {
  /* Initialization of all the variables*/
  struct connection checkAll;
  int sdata_len;
  int ddata_len;
  int j;
  int k;
  int nums;
  int num1;
  int k1;
  int k2;
  int constant;
  int only = 1;
  int many = 1;
  checkAll.num_packet_src = 0;
  checkAll.num_packet_dst = 0;

  /* Checking all of the packets and collect the information. */
  for (j = 0; j < total; j++) {
    only = 1;
    if (cList[j].is_set == 0) {
      print = 2;
      strcpy(actual[0].src, cList[j].src);
      strcpy(actual[0].dst, cList[j].dst);
      actual[0].port_src = cList[j].port_src;
      actual[0].port_dst = cList[j].port_dst;
      actual[0].length = cList[j].length;
      actual[0].win = cList[j].win;
      actual[0].started = cList[j].started;
      actual[0].seq = cList[j].seq;
      actual[0].ack = cList[j].ack;
      actual[0].send = actual[0].seq + actual[0].length;

      if (cList[j].tflags == 17 || cList[j].tflags == 1 ||
          cList[j].tflags == 25) {
        countf++;
      }
      if (cList[j].tflags == 2 || cList[j].tflags == 18) {
        counts++;
      }

      if (cList[j].tflags == 4 && only == 1) {
        countr++;
        only = 0;
        sdata_len = 0;
        ddata_len = 0;
        checkAll.num_packet_src = 0;
        checkAll.num_packet_dst = 0;
        counts = 0;
        countf = 0;
      }
      if ((cList[j].tflags == 4 && only == 1) ||
          (only == 1 && cList[j].tflags == 20)) {
        countr++;
        only = 0;
      }
      checkAll.num_packet_src++;
      cList[j].is_set = 1;
    }

    k = 1;
    int i = j + 1;
    for (; i < total; i++) {
      if ((!strcmp(cList[i].src, actual[0].src) &&
           !strcmp(cList[i].dst, actual[0].dst) &&
           actual[0].port_src == cList[i].port_src &&
           actual[0].port_dst == cList[i].port_dst && cList[i].is_set == 0) ||
          (!strcmp(cList[i].src, actual[0].dst) &&
           !strcmp(cList[i].dst, actual[0].src) &&
           actual[0].port_src == cList[i].port_dst &&
           actual[0].port_dst == cList[i].port_src && cList[i].is_set == 0)) {
        cList[i].is_set = 1;

        strcpy(actual[k].src, cList[i].src);
        strcpy(actual[k].dst, cList[i].dst);
        actual[k].port_src = cList[i].port_src;
        actual[k].port_dst = cList[i].port_dst;
        actual[k].length = cList[i].length;
        actual[k].win = cList[i].win;
        actual[k].started = cList[i].started;
        actual[k].seq = cList[i].seq;
        actual[k].ack = cList[i].ack;
        actual[k].send = actual[k].seq + actual[k].length;

        k++;
        if (cList[j].tflags == 4 && only == 1) {
          countr++;
          only = 0;
          sdata_len = 0;
          ddata_len = 0;
          checkAll.num_packet_src = 0;
          checkAll.num_packet_dst = 0;
          counts = 0;
          countf = 0;
          k = 0;
        }
        if ((cList[i].tflags == 4 && only == 1) ||
            (only == 1 && cList[i].tflags == 20)) {
          countr++;
          only = 0;
        }
        if (cList[i].tflags == 17 || cList[i].tflags == 1 ||
            cList[i].tflags == 25) {
          countf++;
        }
        if (cList[i].tflags == 2 || cList[i].tflags == 18) {
          counts++;
        }
      }
    }

    k2 = k1 = constant = num1 = nums = k;
    while (k > 0) {
      if (!strcmp(actual[k].src, actual[0].src) &&
          !strcmp(actual[k].dst, actual[0].dst) &&
          actual[0].port_src == actual[k].port_src &&
          actual[0].port_dst == actual[k].port_dst) {
        checkAll.num_packet_src++;
        sdata_len = sdata_len + actual[k].length;
      }
      if (!strcmp(actual[k].src, actual[0].dst) &&
          !strcmp(actual[k].dst, actual[0].src) &&
          actual[0].port_src == actual[k].port_dst &&
          actual[0].port_dst == actual[k].port_src) {
        checkAll.num_packet_dst++;
        ddata_len = ddata_len + actual[k].length;
      }
      k--;
    }

    /* Ckecking if the connecion is connected. */
    if ((counts == 1 && countf == 1) || (counts == 2 && countf == 1) ||
        (counts == 2 && countf == 2)) {
      connected++;
      print = 3;
    }
    /* Print all the data which is not connected. */
    if (print == 2) {
      printf("Connection %d:\n", many);
      printf("Source Address: %s\n", cList[j].src);
      printf("Destination address: %s\n", cList[j].dst);
      printf("Source Port: %d\n", cList[j].port_src);
      printf("Destination Port: %d\n", cList[j].port_dst);
      printf("Stats: S%dF%d\n", counts, countf);
      if (countf == 0) {
        countEnd++;
      }
      printf("END\n");
      printf("+++++++++++++++++++++++++++++\n");
      many++;
    }
    /* Print all the data which is not connected. */
    if (print == 3) {
      num1--;
      int numRTT;
      int numsRTT;
      for (numRTT = 0; numRTT < constant; numRTT++) {
        while (actual[numRTT].length == 0 && numRTT > 0) {
          numRTT++;
        }
        for (numsRTT = numRTT + 1; numsRTT < constant; numsRTT++) {
          if (actual[numRTT].send == actual[numsRTT].ack) {
            if (min_RTT > actual[numsRTT].started - actual[numRTT].started) {
              min_RTT = actual[numsRTT].started - actual[numRTT].started;
            }
            if (max_RTT < actual[numsRTT].started - actual[numRTT].started) {
              max_RTT = actual[numsRTT].started - actual[numRTT].started;
            }
            Total_RTT += actual[numsRTT].started - actual[numRTT].started;
            manys++;
            break;
          }
        }
      }

      nums--;
      while (nums >= 0) {
        if (actual[0].min_win_size > actual[nums].win) {
          actual[0].min_win_size = actual[nums].win;
        }
        if (actual[0].max_win_size < actual[nums].win) {
          actual[0].max_win_size = actual[nums].win;
        }
        total_win += actual[nums].win;
        nums--;
      }
      total_pack += constant;

      while (k1 > 0) {
        if (minP > constant) {
          minP = constant;
        }
        if (maxP < constant) {
          maxP = constant;
        }
        k1--;
      }
      total_p += constant;
      k2--;
      if (min_time > (actual[k2].started - actual[0].started)) {
        min_time = (actual[k2].started - actual[0].started);
      }
      if (max_time < (actual[k2].started - actual[0].started)) {
        max_time = (actual[k2].started - actual[0].started);
      }
      total_time += (actual[constant - 1].started - actual[0].started);

      /* Printing the whole data ...*/
      printf("Connection %d:\n", many);
      printf("Source Address: %s\n", cList[j].src);
      printf("Destination address: %s\n", cList[j].dst);
      printf("Source Port: %d\n", cList[j].port_src);
      printf("Destination Port: %d\n", cList[j].port_dst);
      if (countr % 2 == 0) {
        printf("Stats: S%dF%d\n", counts, countf);
      } else {
        printf("Stats: R\n");
        printf("Stats: S%dF%d\n", counts, countf);
      }
      printf("Start time: %f\n", actual[0].started - cList[0].started);
      printf("End Time: %f\n", actual[num1].started - cList[0].started);
      printf("Duration: %f\n", (actual[num1].started - cList[0].started) -
                                   (actual[0].started - cList[0].started));
      printf("Number of packets sent from Source to Destination: %d\n",
             checkAll.num_packet_src);
      printf("Number of packets sent from Destination to Source: %d\n",
             checkAll.num_packet_dst);
      printf("Total number of packets: %d\n",
             checkAll.num_packet_src + checkAll.num_packet_dst);
      printf("Number of data bytes sent from Source to Destination: %d\n",
             sdata_len);
      printf("Number of data bytes sent from Destination to Source: %d\n",
             ddata_len);
      printf("Total number of data bytes: %d\n", sdata_len + ddata_len);
      printf("END\n");
      printf("+++++++++++++++++++++++++++++\n");
      many++;
    }

    /* Reset all of the data into 0, and reset the only value. */
    only = 1;
    print = 0;
    sdata_len = 0;
    ddata_len = 0;
    checkAll.num_packet_src = 0;
    checkAll.num_packet_dst = 0;
    counts = 0;
    countf = 0;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  pcap_t *pcap;
  const unsigned char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;

  /* Skip over the program name. */
  argv++;
  argc--;

  /* We expect exactly one argument, the name of the file to dump. */
  if (argc != 1) {
    fprintf(stderr, "This program need one parameter of TCP trace file path\n");
    exit(1);
  }

  pcap = pcap_open_offline(argv[0], errbuf);
  if (pcap == NULL) {
    fprintf(stderr, "Error reading pcap file: %s\n", errbuf);
    exit(1);
  }

  /* Now just loop through extracting packets as long as we have
   * some to read.
   */

  while ((packet = pcap_next(pcap, &header)) != NULL) {
    dump_TCP_packet(packet, header.ts, header.caplen);
  }

  /* Printing out the whole data and generate the report.*/
  buildFilter(actual, cList, total);
  printf("\nTCP analysis output starting from here: \n\n");
  printf("A. Total number of connections: %d\n\n", count);
  printf("--------------------------------------------------------\n\n");

  printf("B. Connections' details: \n\n");
  checkConn(actual, cList, header.ts, total, print);
  printf("--------------------------------------------------------\n\n");
  printf("C. General\n\n");
  printf("Total number of complete TCP connections: %d\n", connected);
  printf("Number of reset TCP connections: %d\n", countr);
  printf(
      "Number of TCP connections that were still open when the trace capture "
      "ended: %d\n",
      countEnd);
  printf("--------------------------------------------------------\n\n");

  printf("D. Complete TCP connections:\n\n");
  printf("Minimum time durations: %f\n", min_time);
  printf("Mean time durations: %f\n", total_time / connected);
  printf("Maximum time durations: %f\n\n", max_time);
  printf("Minimum RTT values including both send/received: %.3f\n", min_RTT);
  printf("Mean RTT values including both send/received: %.3f\n",
         Total_RTT / manys);
  printf("Maximum RTT values including both send/received: %.3f\n\n", max_RTT);
  printf("Minimum number of packets including both send/received: %d\n", minP);
  printf("Mean number of packets including both send/received: %d\n",
         total_p / connected);
  printf("Maximum number of packets including both send/received: %d\n\n",
         maxP);
  printf("Minimum receive window sizes including both send/received: %d\n",
         actual[0].min_win_size);
  printf("Mean receive window sizes including both send/received: %f\n",
         total_win / total_pack);
  printf("Maximum receive window sizes including both send/received: %d\n\n",
         actual[0].max_win_size);
  printf("--------------------------------------------------------\n");

  return 0;
}

/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts) {
  static char timestamp_string_buf[256];

  sprintf(timestamp_string_buf, "%d.%06d", (int)ts.tv_sec, (int)ts.tv_usec);

  return timestamp_string_buf;
}

/* Check if there is problem and print.*/
void problem_pkt(const char *reason) { fprintf(stderr, "%s\n", reason); }

/* Check if there is problem and print.*/
void too_short(const char *truncated_hdr) {
  fprintf(stderr, "packet is truncated and lacks a full %s\n", truncated_hdr);
}