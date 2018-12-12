#ifndef PRINT_REPORT_H_
#define PRINT_REPORT_H_

#include <arpa/inet.h>

#define MAX_STR_LEN 200
#define MAX_NUM_CONNECTION 10000

struct connection {
  char src[MAX_STR_LEN];  // source ip
  char dst[MAX_STR_LEN];  // destination ip
  uint16_t src_port;      // source port number
  uint16_t dst_port;      // destination port number
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

#endif