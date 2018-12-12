#A Tool for TCP Traffic Analysis

## Usage

```bash
// Requirements: gcc & pcap
// Test environment: macOS 10.14.1 Apple LLVM version 10.0.0 (clang-1000.10.44.4)
$ cd TCP\ Traffic\ Analysis/
$ make
$ ./analyser TCP_TRACE_FILE
```

## Related

#### TCP protocol

TCP is connection-oriented and works at the transport layer. It  provides reliable, ordered, and error-checked delivery of a stream of octets (bytes) between applications running on hosts communicating via an IP network. 

#### TCP segment structure

![image-20181212105355431](https://ws3.sinaimg.cn/large/006tNbRwly1fy3rwggv59j32da0nwn35.jpg)

TCP accepts data from a data stream, divides it into chunks, and adds a TCP header creating a TCP segment. The TCP segment is then encapsulated into an IP datagram with IP header, further into Ethernet frame with Ethernet header, and exchanged with peers.

#### RTT

For a segment, RTT is the amount of time between when the segment is sent (passed to IP), and when an ACK for the segment is received.

## Implementation

1. Load and parse TCP trace file, store TCP connection info in struct array.

2. ```c
   void dump_packets(const unsigned char *packet, struct timeval ts,
                     unsigned int capture_len) {
     struct ip *ip_ptr;
     struct tcp_header *tcp_ptr;
   
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
   
     ip_ptr = (struct ip *)packet;
     IP_header_length = ip_ptr->ip_hl * 4;  // ip_hl is in 4-byte words
   
     if (capture_len < IP_header_length) {
       parser_error("IP header with options");
       return;
     }
   
     if (ip_ptr->ip_p != IPPROTO_TCP) {
       // problem_pkt("This packet is not a TCP packet");
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
      * TCP info -> tcp_packets[]
      */
     tcp_ptr = (struct tcp_header *)packet;
     strcpy(tcp_packets[all_conn_counter].src, inet_ntoa(ip_ptr->ip_src));
     strcpy(tcp_packets[all_conn_counter].dst, inet_ntoa(ip_ptr->ip_dst));
     tcp_packets[all_conn_counter].src_port = ntohs(tcp_ptr->th_sport);
     tcp_packets[all_conn_counter].dst_port = ntohs(tcp_ptr->th_dport);
     tcp_packets[all_conn_counter].check = 0;
     tcp_packets[all_conn_counter].th_flags = (unsigned int)tcp_ptr->th_flags;
     tcp_packets[all_conn_counter].length = capture_len - TH_OFF(tcp_ptr) * 4;
     tcp_packets[all_conn_counter].win = ntohs(tcp_ptr->th_win);
     tcp_packets[all_conn_counter].seq = ntohl(tcp_ptr->th_seq);
     tcp_packets[all_conn_counter].ack = ntohl(tcp_ptr->th_ack);
   
     static char timestamp_string_buf[256];
     sprintf(timestamp_string_buf, "%d.%06d", (int)ts.tv_sec, (int)ts.tv_usec);
     tcp_packets[all_conn_counter].started = atof(timestamp_string_buf);
     all_con
   ```

3. Process TCP packets

   - Count total number of TCP connections

   ```c
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
   ```
    - Traverse TCP
   ```c
   
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
   
     return 0;
   }
   ```

4. Print result

5. ```c
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
   ```


## Example

![image-20181212160000517](https://ws4.sinaimg.cn/large/006tNbRwly1fy40qvwy1jj311o0u0qfe.jpg)

![image-20181212153604288](https://ws4.sinaimg.cn/large/006tNbRwly1fy401zb7h6j311o0u04bp.jpg)

![image-20181212153323120](/Users/aym/Library/Application Support/typora-user-images/image-20181212153344353.png)

## References

[1] https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/tcp.h.html

[2] https://en.wikipedia.org/wiki/Transmission_Control_Protocol

[3] Kurose J F, Ross K W. Computer networking: a top-down approach: international edition[M]. Pearson Higher Ed, 2013.