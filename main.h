#ifndef MAIN_H_
#define MAIN_H_

#include <arpa/inet.h>
#include <pcap.h>
#include <sys/types.h>

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
struct tcp_packet {
  char src[MAX_STR_LEN];  // source ip
  char dst[MAX_STR_LEN];  // destination ip
  uint16_t src_port;      // source port number
  uint16_t dst_port;      // destination port number
  int th_flags;
  int syn_count;  // flag count
  int fin_count;
  int rst_count;
  double started;
  struct timeval starting_time;
  struct timeval ending_time;
  double duration;
  int src_num_packet;  // number of packets sent out by source
  int dst_num_packet;  // number of packets sent out by destination
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
  int check;
  int flag;
};


extern int all_conn_counter;

extern struct tcp_packet tcp_packets[MAX_NUM_CONNECTION];

#endif  // MAIN_H_