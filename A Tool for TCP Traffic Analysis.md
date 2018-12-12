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

2. Process TCP packets

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
    - reset TCP
    - still open TCP
    - complete TCP
3. Print result

## Example

![image-20181212160000517](https://ws4.sinaimg.cn/large/006tNbRwly1fy40qvwy1jj311o0u0qfe.jpg)

![image-20181212153604288](https://ws4.sinaimg.cn/large/006tNbRwly1fy401zb7h6j311o0u04bp.jpg)

![image-20181212153323120](/Users/aym/Library/Application Support/typora-user-images/image-20181212153344353.png)

## References

[1] https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/tcp.h.html

[2] https://en.wikipedia.org/wiki/Transmission_Control_Protocol

[3] Kurose J F, Ross K W. Computer networking: a top-down approach: international edition[M]. Pearson Higher Ed, 2013.