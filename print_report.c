/*
 * print_report.c
 *
 * Print connection info report as required
 */
#include "print_report.h"
#include <string.h>
#include "main.h"


int complete_tcp_counter;
int all_conn_counter;
int counts;
int countf;
int reset_tcp_counter;
int open_tcp_counter;
int min_packet = 1000;
int max_packet;
int total_p;
double total_win;
double all_win;
double total_time;
double during;
double min_time = 1000.00;
double max_time;
double all_time;
int total_pack;
double total_rtt;
double min_rtt = 1000.00;
double max_rtt;
int manys;
int count = 0;
struct tcp_packet tcp_packets[MAX_NUM_CONNECTION];
struct connection a[MAX_NUM_CONNECTION];



int count_tcp();
int checkConn(struct tcp_packet *tcp_packets, int all_conn_counter);


void print_report() {
  printf(
      "\n========================Starting from here======================== "
      "\n\n");
  /*
   ******   A   *******
   */
  printf("A. Total number of TCP connections: %d\n\n", count_tcp());
  printf("--------------------------------------------------------\n\n");
  /*
   ******   B   *******
   */
  printf("B. Connections' details: \n\n");
  checkConn(tcp_packets, all_conn_counter);
  printf("--------------------------------------------------------\n\n");
  /*
   ******   C   *******
   */
  printf("C. General\n\n");
  printf("Total number of complete TCP connections: %d\n",
         complete_tcp_counter);
  printf("Number of reset TCP connections: %d\n", reset_tcp_counter);
  printf(
      "Number of TCP connections that were still open when the trace capture "
      "ended: %d\n",
      open_tcp_counter);
  printf("--------------------------------------------------------\n\n");
  /*
   ******   D   *******
   */
  printf("D. Complete TCP connections:\n\n");
  printf("Minimum time durations: %f\n", min_time);
  printf("Mean time durations: %f\n", total_time / complete_tcp_counter);
  printf("Maximum time durations: %f\n\n", max_time);
  printf("Minimum RTT values including both send/received: %.3f\n", min_rtt);
  printf("Mean RTT values including both send/received: %.3f\n",
         total_rtt / manys);
  printf("Maximum RTT values including both send/received: %.3f\n\n", max_rtt);
  printf("Minimum number of packets including both send/received: %d\n",
         min_packet);
  printf("Mean number of packets including both send/received: %d\n",
         total_p / complete_tcp_counter);
  printf("Maximum number of packets including both send/received: %d\n\n",
         max_packet);
  printf("Minimum receive window sizes including both send/received: %d\n",
         a[0].min_win_size);
  printf("Mean receive window sizes including both send/received: %f\n",
         total_win / total_pack);
  printf("Maximum receive window sizes including both send/received: %d\n\n",
         a[0].max_win_size);
  printf(
      "\n================================END================================ "
      "\n\n");
}

int checkConn(struct tcp_packet *tcp_packets, int all_conn_counter) {
  int j;
  int k;
  int nums;
  int num1;
  int k1;
  int k2;
  int constant;
  int tcp_index = 1;
  int print;
  int only;
  int src_data_len;
  int dst_data_len;

  struct tcp_packet checkAll;

  for (j = 0; j < all_conn_counter; j++) {
    only = 1;
    print = 0;
    src_data_len = 0;
    dst_data_len = 0;
    checkAll.src_num_packet = 0;
    checkAll.dst_num_packet = 0;
    counts = 0;
    countf = 0;

    if (tcp_packets[j].check == 0) {
      print = 2;
      strcpy(a[0].src, tcp_packets[j].src);
      strcpy(a[0].dst, tcp_packets[j].dst);
      a[0].src_port = tcp_packets[j].src_port;
      a[0].dst_port = tcp_packets[j].dst_port;
      a[0].length = tcp_packets[j].length;
      a[0].win = tcp_packets[j].win;
      a[0].started = tcp_packets[j].started;
      a[0].seq = tcp_packets[j].seq;
      a[0].ack = tcp_packets[j].ack;
      a[0].send = a[0].seq + a[0].length;

      if (tcp_packets[j].th_flags == 17 || tcp_packets[j].th_flags == 1 ||
          tcp_packets[j].th_flags == 25) {
        countf++;
      }

      if (tcp_packets[j].th_flags == 2 || tcp_packets[j].th_flags == 18) {
        counts++;
      }

      if (tcp_packets[j].th_flags == 4 && only == 1) {
        reset_tcp_counter++;
        only = 0;
        src_data_len = 0;
        dst_data_len = 0;
        checkAll.src_num_packet = 0;
        checkAll.dst_num_packet = 0;
        counts = 0;
        countf = 0;
      }

      if (only == 1 && tcp_packets[j].th_flags == 20) {
        reset_tcp_counter++;
        only = 0;
      }

      checkAll.src_num_packet++;
      tcp_packets[j].check = 1;
    }

    k = 1;
    int i = j + 1;
    for (; i < all_conn_counter; i++) {
      if ((!strcmp(tcp_packets[i].src, a[0].src) &&
           !strcmp(tcp_packets[i].dst, a[0].dst) &&
           a[0].src_port == tcp_packets[i].src_port &&
           a[0].dst_port == tcp_packets[i].dst_port &&
           tcp_packets[i].check == 0) ||
          (!strcmp(tcp_packets[i].src, a[0].dst) &&
           !strcmp(tcp_packets[i].dst, a[0].src) &&
           a[0].src_port == tcp_packets[i].dst_port &&
           a[0].dst_port == tcp_packets[i].src_port &&
           tcp_packets[i].check == 0)) {
        tcp_packets[i].check = 1;

        strcpy(a[k].src, tcp_packets[i].src);
        strcpy(a[k].dst, tcp_packets[i].dst);
        a[k].src_port = tcp_packets[i].src_port;
        a[k].dst_port = tcp_packets[i].dst_port;
        a[k].length = tcp_packets[i].length;
        a[k].win = tcp_packets[i].win;
        a[k].started = tcp_packets[i].started;
        a[k].seq = tcp_packets[i].seq;
        a[k].ack = tcp_packets[i].ack;
        a[k].send = a[k].seq + a[k].length;

        k++;
        if (tcp_packets[j].th_flags == 4 && only == 1) {
          reset_tcp_counter++;
          only = 0;
          src_data_len = 0;
          dst_data_len = 0;
          checkAll.src_num_packet = 0;
          checkAll.dst_num_packet = 0;
          counts = 0;
          countf = 0;
          k = 0;
        }
        if ((tcp_packets[i].th_flags == 4 && only == 1) ||
            (only == 1 && tcp_packets[i].th_flags == 20)) {
          reset_tcp_counter++;
          only = 0;
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

    k2 = k1 = constant = num1 = nums = k;
    while (k > 0) {
      if (!strcmp(a[k].src, a[0].src) && !strcmp(a[k].dst, a[0].dst) &&
          a[0].src_port == a[k].src_port && a[0].dst_port == a[k].dst_port) {
        checkAll.src_num_packet++;
        src_data_len = src_data_len + a[k].length;
      }
      if (!strcmp(a[k].src, a[0].dst) && !strcmp(a[k].dst, a[0].src) &&
          a[0].src_port == a[k].dst_port && a[0].dst_port == a[k].src_port) {
        checkAll.dst_num_packet++;
        dst_data_len = dst_data_len + a[k].length;
      }
      k--;
    }

    /* Ckecking if the connecion is complete_tcp_counter. */
    if ((counts == 1 && countf == 1) || (counts == 2 && countf == 1) ||
        (counts == 2 && countf == 2)) {
      complete_tcp_counter++;
      print = 3;
    }
    /* Print all the data which is not complete tcp connection */
    if (print == 2) {
      printf("Connection %d:\n", tcp_index++);
      printf("Source Address: %s\n", tcp_packets[j].src);
      printf("Destination address: %s\n", tcp_packets[j].dst);
      printf("Source Port: %d\n", tcp_packets[j].src_port);
      printf("Destination Port: %d\n", tcp_packets[j].dst_port);
      printf("Status: S%dF%d\n", counts, countf);
      if (countf == 0) {
        open_tcp_counter++;
      }
      printf("+++++++++++++++++++++++++++++\n");
    }
    /* Print all the data which is complete TCP connection */
    if (print == 3) {
      num1--;
      int numRTT;
      int numsRTT;
      for (numRTT = 0; numRTT < constant; numRTT++) {
        while (a[numRTT].length == 0 && numRTT > 0) {
          numRTT++;
        }
        for (numsRTT = numRTT + 1; numsRTT < constant; numsRTT++) {
          if (a[numRTT].send == a[numsRTT].ack) {
            if (min_rtt > a[numsRTT].started - a[numRTT].started) {
              min_rtt = a[numsRTT].started - a[numRTT].started;
            }
            if (max_rtt < a[numsRTT].started - a[numRTT].started) {
              max_rtt = a[numsRTT].started - a[numRTT].started;
            }
            total_rtt += a[numsRTT].started - a[numRTT].started;
            manys++;
            break;
          }
        }
      }

      nums--;
      while (nums >= 0) {
        if (a[0].min_win_size > a[nums].win) {
          a[0].min_win_size = a[nums].win;
        }
        if (a[0].max_win_size < a[nums].win) {
          a[0].max_win_size = a[nums].win;
        }
        total_win += a[nums].win;
        nums--;
      }
      total_pack += constant;

      while (k1 > 0) {
        if (min_packet > constant) {
          min_packet = constant;
        }
        if (max_packet < constant) {
          max_packet = constant;
        }
        k1--;
      }
      total_p += constant;
      k2--;
      if (min_time > (a[k2].started - a[0].started)) {
        min_time = (a[k2].started - a[0].started);
      }
      if (max_time < (a[k2].started - a[0].started)) {
        max_time = (a[k2].started - a[0].started);
      }
      total_time += (a[constant - 1].started - a[0].started);

      /* Printing the whole data ...*/
      printf("Connection %d:\n", tcp_index++);
      printf("Source Address: %s\n", tcp_packets[j].src);
      printf("Destination address: %s\n", tcp_packets[j].dst);
      printf("Source Port: %d\n", tcp_packets[j].src_port);
      printf("Destination Port: %d\n", tcp_packets[j].dst_port);
      if (reset_tcp_counter % 2 == 0) {
        printf("Status: S%dF%d\n", counts, countf);
      } else {
        printf("Status: R\n");
        printf("Status: S%dF%d\n", counts, countf);
      }
      printf("Start time: %f\n", a[0].started - tcp_packets[0].started);
      printf("End Time: %f\n", a[num1].started - tcp_packets[0].started);
      printf("Duration: %f\n", (a[num1].started - tcp_packets[0].started) -
                                   (a[0].started - tcp_packets[0].started));
      printf("Number of packets sent from Source to Destination: %d\n",
             checkAll.src_num_packet);
      printf("Number of packets sent from Destination to Source: %d\n",
             checkAll.dst_num_packet);
      printf("Total number of packets: %d\n",
             checkAll.src_num_packet + checkAll.dst_num_packet);
      printf("Number of data bytes sent from Source to Destination: %d\n",
             src_data_len);
      printf("Number of data bytes sent from Destination to Source: %d\n",
             dst_data_len);
      printf("Total number of data bytes: %d\n", src_data_len + dst_data_len);
      printf("+++++++++++++++++++++++++++++\n");
    }
  }

  return 0;
}

int count_tcp() {
  int i, j, k;
  int counter = 0;
  struct connection temp[MAX_NUM_CONNECTION];
  for (j = 0; j < all_conn_counter; j++) {
    if (tcp_packets[j].flag == 0) {
      strcpy(temp[0].src, tcp_packets[j].src);
      strcpy(temp[0].dst, tcp_packets[j].dst);
      temp[0].src_port = tcp_packets[j].src_port;
      temp[0].dst_port = tcp_packets[j].dst_port;
      tcp_packets[j].flag = 1;
      counter++;
    }

    for (k = 0, i = j + 1; i < all_conn_counter; i++) {
      if ((!strcmp(tcp_packets[i].src, temp[0].src) &&
           !strcmp(tcp_packets[i].dst, temp[0].dst) &&
           temp[0].src_port == tcp_packets[i].src_port &&
           temp[0].dst_port == tcp_packets[i].dst_port &&
           tcp_packets[i].flag == 0) ||
          (!strcmp(tcp_packets[i].src, temp[0].dst) &&
           !strcmp(tcp_packets[i].dst, temp[0].src) &&
           temp[0].src_port == tcp_packets[i].dst_port &&
           temp[0].dst_port == tcp_packets[i].src_port &&
           tcp_packets[i].flag == 0)) {
        tcp_packets[i].flag = 1;
        strcpy(temp[k].src, tcp_packets[i].src);
        strcpy(temp[k].dst, tcp_packets[i].dst);
        temp[k].src_port = tcp_packets[i].src_port;
        temp[k].dst_port = tcp_packets[i].dst_port;
        k++;
      }
    }
  }

  return counter;
}