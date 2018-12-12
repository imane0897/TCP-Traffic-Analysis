/*
 * print_report.c
 *
 * Print connection info report as required
 */
#include "print_report.h"
#include <string.h>
#include "main.h"

int all_conn_counter;
int round_counter;
int complete_tcp_counter;
int reset_tcp_counter;
int open_tcp_counter;
int min_packet = 1000;
int max_packet;
int total_packets;
double total_win;
double total_time;
double min_time = 1000.00;
double max_time;
double total_rtt;
double min_rtt = 1000.00;
double max_rtt;
struct tcp_packet tcp_packets[MAX_NUM_CONNECTION];
struct connection tcp_conn[MAX_NUM_CONNECTION];

int count_tcp();
int traverse_packets(struct tcp_packet *tcp_packets, int all_conn_counter);

void print_report() {
  printf(
      "\n========================Starting from here======================== "
      "\n\n");
  /*
   ******   A   *******
   */
  printf("A. Total number of TCP connections: %d\n\n", count_tcp());
  /*
   ******   B   *******
   */
  printf("B. Connections' details: \n\n");
  traverse_packets(tcp_packets, all_conn_counter);
  /*
   ******   C   *******
   */
  printf("C. General\n\n");
  printf("Total number of complete TCP tcp_conn: %d\n", complete_tcp_counter);
  printf("Number of reset TCP tcp_conn: %d\n", reset_tcp_counter);
  printf(
      "Number of TCP tcp_conn that were still open when the trace capture "
      "ended: %d\n\n",
      open_tcp_counter);
  /*
   ******   D   *******
   */
  printf("D. Complete TCP tcp_conn:\n\n");
  printf("Minimum time durations: %f\n", min_time);
  printf("Mean time durations: %f\n", total_time / complete_tcp_counter);
  printf("Maximum time durations: %f\n\n", max_time);
  printf("Minimum RTT values including both send/received: %.3f\n", min_rtt);
  printf("Mean RTT values including both send/received: %.3f\n",
         total_rtt / round_counter);
  printf("Maximum RTT values including both send/received: %.3f\n\n", max_rtt);
  printf("Minimum number of packets including both send/received: %d\n",
         min_packet);
  printf("Mean number of packets including both send/received: %d\n",
         total_packets / complete_tcp_counter);
  printf("Maximum number of packets including both send/received: %d\n\n",
         max_packet);
  printf("Minimum receive window sizes including both send/received: %d\n",
         tcp_conn[0].min_win_size);
  printf("Mean receive window sizes including both send/received: %f\n",
         total_win / total_packets);
  printf("Maximum receive window sizes including both send/received: %d\n\n",
         tcp_conn[0].max_win_size);
  printf(
      "\n================================END================================ "
      "\n\n");
}

int traverse_packets(struct tcp_packet *tcp_packets, int all_conn_counter) {
  int i, j, k;
  int counts, countf;
  int k1, k2, nums, num1;
  int print_flag, reset_flag, cur_max_index, tcp_index = 1;
  int src_data_len, dst_data_len;

  struct tcp_packet temp;

  for (j = 0; j < all_conn_counter; j++) {
    reset_flag = 1;
    print_flag = 0;
    src_data_len = 0;
    dst_data_len = 0;
    temp.src_num_packet = 0;
    temp.dst_num_packet = 0;
    counts = 0;
    countf = 0;

    if (tcp_packets[j].check == 0) {
      print_flag = 2;
      strcpy(tcp_conn[0].src, tcp_packets[j].src);
      strcpy(tcp_conn[0].dst, tcp_packets[j].dst);
      tcp_conn[0].src_port = tcp_packets[j].src_port;
      tcp_conn[0].dst_port = tcp_packets[j].dst_port;
      tcp_conn[0].length = tcp_packets[j].length;
      tcp_conn[0].win = tcp_packets[j].win;
      tcp_conn[0].started = tcp_packets[j].started;
      tcp_conn[0].seq = tcp_packets[j].seq;
      tcp_conn[0].ack = tcp_packets[j].ack;
      tcp_conn[0].send = tcp_conn[0].seq + tcp_conn[0].length;

      if (tcp_packets[j].th_flags == 17 || tcp_packets[j].th_flags == 1 ||
          tcp_packets[j].th_flags == 25) {
        countf++;
      }

      if (tcp_packets[j].th_flags == 2 || tcp_packets[j].th_flags == 18) {
        counts++;
      }

      if (tcp_packets[j].th_flags == 4 && reset_flag == 1) {
        reset_tcp_counter++;
        reset_flag = 0;
        src_data_len = 0;
        dst_data_len = 0;
        temp.src_num_packet = 0;
        temp.dst_num_packet = 0;
        counts = 0;
        countf = 0;
      }

      if (reset_flag == 1 && tcp_packets[j].th_flags == 20) {
        reset_tcp_counter++;
        reset_flag = 0;
      }

      temp.src_num_packet++;
      tcp_packets[j].check = 1;
    }

    for (k = 1, i = j + 1; i < all_conn_counter; i++) {
      if ((!strcmp(tcp_packets[i].src, tcp_conn[0].src) &&
           !strcmp(tcp_packets[i].dst, tcp_conn[0].dst) &&
           tcp_conn[0].src_port == tcp_packets[i].src_port &&
           tcp_conn[0].dst_port == tcp_packets[i].dst_port &&
           tcp_packets[i].check == 0) ||
          (!strcmp(tcp_packets[i].src, tcp_conn[0].dst) &&
           !strcmp(tcp_packets[i].dst, tcp_conn[0].src) &&
           tcp_conn[0].src_port == tcp_packets[i].dst_port &&
           tcp_conn[0].dst_port == tcp_packets[i].src_port &&
           tcp_packets[i].check == 0)) {
        tcp_packets[i].check = 1;

        strcpy(tcp_conn[k].src, tcp_packets[i].src);
        strcpy(tcp_conn[k].dst, tcp_packets[i].dst);
        tcp_conn[k].src_port = tcp_packets[i].src_port;
        tcp_conn[k].dst_port = tcp_packets[i].dst_port;
        tcp_conn[k].length = tcp_packets[i].length;
        tcp_conn[k].win = tcp_packets[i].win;
        tcp_conn[k].started = tcp_packets[i].started;
        tcp_conn[k].seq = tcp_packets[i].seq;
        tcp_conn[k].ack = tcp_packets[i].ack;
        tcp_conn[k].send = tcp_conn[k].seq + tcp_conn[k].length;

        k++;

        if (tcp_packets[j].th_flags == 4 && reset_flag == 1) {
          reset_tcp_counter++;
          reset_flag = 0;
          src_data_len = 0;
          dst_data_len = 0;
          temp.src_num_packet = 0;
          temp.dst_num_packet = 0;
          counts = 0;
          countf = 0;
          k = 0;
        }
        if ((tcp_packets[i].th_flags == 4 && reset_flag == 1) ||
            (reset_flag == 1 && tcp_packets[i].th_flags == 20)) {
          reset_tcp_counter++;
          reset_flag = 0;
        }
        if (tcp_packets[i].th_flags == 17 || tcp_packets[i].th_flags == 1 ||
            tcp_packets[i].th_flags == 25) {
          countf++;
        }
        if (tcp_packets[i].th_flags == 2 || tcp_packets[i].th_flags == 18) {
          counts++;
        }
      }
    }

    k2 = k1 = cur_max_index = num1 = nums = k;
    while (k > 0) {
      if (!strcmp(tcp_conn[k].src, tcp_conn[0].src) &&
          !strcmp(tcp_conn[k].dst, tcp_conn[0].dst) &&
          tcp_conn[0].src_port == tcp_conn[k].src_port &&
          tcp_conn[0].dst_port == tcp_conn[k].dst_port) {
        temp.src_num_packet++;
        src_data_len = src_data_len + tcp_conn[k].length;
      }
      if (!strcmp(tcp_conn[k].src, tcp_conn[0].dst) &&
          !strcmp(tcp_conn[k].dst, tcp_conn[0].src) &&
          tcp_conn[0].src_port == tcp_conn[k].dst_port &&
          tcp_conn[0].dst_port == tcp_conn[k].src_port) {
        temp.dst_num_packet++;
        dst_data_len = dst_data_len + tcp_conn[k].length;
      }
      k--;
    }

    // Ckecking if the connecion is complete connections
    if ((counts == 1 && countf == 1) || (counts == 2 && countf == 1) ||
        (counts == 2 && countf == 2)) {
      complete_tcp_counter++;
      print_flag = 3;
    }

    // Print not complete tcp connection
    if (print_flag == 2) {
      printf("Connection %d:\n", tcp_index++);
      printf("Source Address: %s\n", tcp_packets[j].src);
      printf("Destination address: %s\n", tcp_packets[j].dst);
      printf("Source Port: %d\n", tcp_packets[j].src_port);
      printf("Destination Port: %d\n", tcp_packets[j].dst_port);
      printf("Status: OPEN\n");
      if (countf == 0) {
        open_tcp_counter++;
      }
      printf("-----------------------------------\n");
    }

    // Print complete TCP connection
    if (print_flag == 3) {
      num1--;
      int index_s, index_d;
      for (index_s = 0; index_s < cur_max_index; index_s++) {
        while (tcp_conn[index_s].length == 0 && index_s > 0) {
          index_s++;
        }
        for (index_d = index_s + 1; index_d < cur_max_index; index_d++) {
          if (tcp_conn[index_s].send == tcp_conn[index_d].ack) {
            if (min_rtt >
                tcp_conn[index_d].started - tcp_conn[index_s].started) {
              min_rtt = tcp_conn[index_d].started - tcp_conn[index_s].started;
            }
            if (max_rtt <
                tcp_conn[index_d].started - tcp_conn[index_s].started) {
              max_rtt = tcp_conn[index_d].started - tcp_conn[index_s].started;
            }
            total_rtt += tcp_conn[index_d].started - tcp_conn[index_s].started;
            round_counter++;
            break;
          }
        }
      }

      nums--;
      while (nums >= 0) {
        if (tcp_conn[0].min_win_size > tcp_conn[nums].win) {
          tcp_conn[0].min_win_size = tcp_conn[nums].win;
        }
        if (tcp_conn[0].max_win_size < tcp_conn[nums].win) {
          tcp_conn[0].max_win_size = tcp_conn[nums].win;
        }
        total_win += tcp_conn[nums].win;
        nums--;
      }

      for (; k1 > 0; k1--) {
        min_packet = min_packet < cur_max_index ? min_packet : cur_max_index;
        max_packet = max_packet > cur_max_index ? max_packet : cur_max_index;
      }

      total_packets += cur_max_index;
      k2 -= 1;
      if (min_time > (tcp_conn[k2].started - tcp_conn[0].started)) {
        min_time = (tcp_conn[k2].started - tcp_conn[0].started);
      }
      if (max_time < (tcp_conn[k2].started - tcp_conn[0].started)) {
        max_time = (tcp_conn[k2].started - tcp_conn[0].started);
      }
      total_time += (tcp_conn[cur_max_index - 1].started - tcp_conn[0].started);

      printf("Connection %d:\n", tcp_index++);
      printf("Source Address: %s\n", tcp_packets[j].src);
      printf("Destination address: %s\n", tcp_packets[j].dst);
      printf("Source Port: %d\n", tcp_packets[j].src_port);
      printf("Destination Port: %d\n", tcp_packets[j].dst_port);
      if (reset_tcp_counter % 2 == 0) {
        printf("Status: COMPLETE\n");
      } else {
        printf("Status: RESET COMPLETE\n");
      }
      printf("Start time: %f\n", tcp_conn[0].started - tcp_packets[0].started);
      printf("End Time: %f\n", tcp_conn[num1].started - tcp_packets[0].started);
      printf("Duration: %f\n",
             (tcp_conn[num1].started - tcp_packets[0].started) -
                 (tcp_conn[0].started - tcp_packets[0].started));
      printf("Number of packets sent from Source to Destination: %d\n",
             temp.src_num_packet);
      printf("Number of packets sent from Destination to Source: %d\n",
             temp.dst_num_packet);
      printf("Total number of packets: %d\n",
             temp.src_num_packet + temp.dst_num_packet);
      printf("Number of data bytes sent from Source to Destination: %d\n",
             src_data_len);
      printf("Number of data bytes sent from Destination to Source: %d\n",
             dst_data_len);
      printf("Total number of data bytes: %d\n", src_data_len + dst_data_len);
      printf("-----------------------------------\n");
    }
  }
  printf("\n");
  return 0;
}

int count_tcp() {
  int counter = 0;
  struct connection temp;

  for (int j = 0; j < all_conn_counter; j++) {
    if (tcp_packets[j].flag == 0) {
      strcpy(temp.src, tcp_packets[j].src);
      strcpy(temp.dst, tcp_packets[j].dst);
      temp.src_port = tcp_packets[j].src_port;
      temp.dst_port = tcp_packets[j].dst_port;
      tcp_packets[j].flag = 1;
      counter++;
    }

    for (int i = j + 1; i < all_conn_counter; i++) {
      // if not dependent connection
      // connections with the same src&dts address and port are viewed as the
      // same connections
      if ((!strcmp(tcp_packets[i].src, temp.src) &&
           !strcmp(tcp_packets[i].dst, temp.dst) &&
           temp.src_port == tcp_packets[i].src_port &&
           temp.dst_port == tcp_packets[i].dst_port &&
           tcp_packets[i].flag == 0) ||
          (!strcmp(tcp_packets[i].src, temp.dst) &&
           !strcmp(tcp_packets[i].dst, temp.src) &&
           temp.src_port == tcp_packets[i].dst_port &&
           temp.dst_port == tcp_packets[i].src_port &&
           tcp_packets[i].flag == 0)) {
        tcp_packets[i].flag = 1;
      }
    }
  }

  return counter;
}