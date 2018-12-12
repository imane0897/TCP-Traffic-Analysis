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

   ```c
   void func() {
     int i, j, k;
     struct connection temp[MAX_NUM_CONNECTION];
     for (j = 0; j < all_conn_counter; j++) {
       if (tcp_packets[j].flag == 0) {
         strcpy(temp[0].src, tcp_packets[j].src);
         strcpy(temp[0].dst, tcp_packets[j].dst);
         temp[0].src_port = tcp_packets[j].src_port;
         temp[0].dst_port = tcp_packets[j].dst_port;
         tcp_packets[j].flag = 1;
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
   }
   ```

3. Print result

## Example



## References

[1] https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/tcp.h.html

[2] https://en.wikipedia.org/wiki/Transmission_Control_Protocol