#ifndef MAIN_H_
#define MAIN_H_

#include <arpa/inet.h>
#include <pcap.h>
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

/* Some helper functions, which we define at the end of this file. */

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(const char *truncated_hdr);


extern struct connection cList[MAX_NUM_CONNECTION];
extern int total;

#endif  // MAIN_H_