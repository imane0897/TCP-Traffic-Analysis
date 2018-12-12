/*
 * print_report.c
 *
 * Print connection info report as required
 */
#include <string.h>
#include "main.h"

int print;
int connected;
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
int count = 0;
struct connection cList[MAX_NUM_CONNECTION];
struct built actual[MAX_NUM_CONNECTION];

int checkConn(struct connection *cList, int total, int print);

void print_report() {
  printf("\nTCP analysis output starting from here: \n\n");
  /*
   ******   A   *******
   */
  printf("A. Total number of TCP connections: %d\n\n", count);
  printf("--------------------------------------------------------\n\n");
  /*
   ******   B   *******
   */
  printf("B. Connections' details: \n\n");
  checkConn(cList, total, print);
  printf("--------------------------------------------------------\n\n");
  /*
   ******   C   *******
   */
  printf("C. General\n\n");
  printf("Total number of complete TCP connections: %d\n", connected);
  printf("Number of reset TCP connections: %d\n", countr);
  printf(
      "Number of TCP connections that were still open when the trace capture "
      "ended: %d\n",
      countEnd);
  printf("--------------------------------------------------------\n\n");
  /*
   ******   D   *******
   */
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
}

int checkConn(struct connection *cList, int total, int print) {
  int src_data_len;
  int dst_data_len;
  int j;
  int k;
  int nums;
  int num1;
  int k1;
  int k2;
  int constant;
  int only = 1;
  int many = 1;

  struct connection checkAll;

  checkAll.src_num_packet = 0;
  checkAll.dst_num_packet = 0;

  for (j = 0; j < total; j++) {
    only = 1;
    if (cList[j].is_set == 0) {
      print = 2;
      strcpy(actual[0].src, cList[j].src);
      strcpy(actual[0].dst, cList[j].dst);
      actual[0].src_port = cList[j].src_port;
      actual[0].dst_port = cList[j].dst_port;
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
        src_data_len = 0;
        dst_data_len = 0;
        checkAll.src_num_packet = 0;
        checkAll.dst_num_packet = 0;
        counts = 0;
        countf = 0;
      }
      if ((cList[j].tflags == 4 && only == 1) ||
          (only == 1 && cList[j].tflags == 20)) {
        countr++;
        only = 0;
      }
      checkAll.src_num_packet++;
      cList[j].is_set = 1;
    }

    k = 1;
    int i = j + 1;
    for (; i < total; i++) {
      if ((!strcmp(cList[i].src, actual[0].src) &&
           !strcmp(cList[i].dst, actual[0].dst) &&
           actual[0].src_port == cList[i].src_port &&
           actual[0].dst_port == cList[i].dst_port && cList[i].is_set == 0) ||
          (!strcmp(cList[i].src, actual[0].dst) &&
           !strcmp(cList[i].dst, actual[0].src) &&
           actual[0].src_port == cList[i].dst_port &&
           actual[0].dst_port == cList[i].src_port && cList[i].is_set == 0)) {
        cList[i].is_set = 1;

        strcpy(actual[k].src, cList[i].src);
        strcpy(actual[k].dst, cList[i].dst);
        actual[k].src_port = cList[i].src_port;
        actual[k].dst_port = cList[i].dst_port;
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
          src_data_len = 0;
          dst_data_len = 0;
          checkAll.src_num_packet = 0;
          checkAll.dst_num_packet = 0;
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
          actual[0].src_port == actual[k].src_port &&
          actual[0].dst_port == actual[k].dst_port) {
        checkAll.src_num_packet++;
        src_data_len = src_data_len + actual[k].length;
      }
      if (!strcmp(actual[k].src, actual[0].dst) &&
          !strcmp(actual[k].dst, actual[0].src) &&
          actual[0].src_port == actual[k].dst_port &&
          actual[0].dst_port == actual[k].src_port) {
        checkAll.dst_num_packet++;
        dst_data_len = dst_data_len + actual[k].length;
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
      printf("Source Port: %d\n", cList[j].src_port);
      printf("Destination Port: %d\n", cList[j].dst_port);
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
      printf("Source Port: %d\n", cList[j].src_port);
      printf("Destination Port: %d\n", cList[j].dst_port);
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
      printf("END\n");
      printf("+++++++++++++++++++++++++++++\n");
      many++;
    }

    /* Reset all of the data into 0, and reset the only value. */
    only = 1;
    print = 0;
    src_data_len = 0;
    dst_data_len = 0;
    checkAll.src_num_packet = 0;
    checkAll.dst_num_packet = 0;
    counts = 0;
    countf = 0;
  }

  return 0;
}
