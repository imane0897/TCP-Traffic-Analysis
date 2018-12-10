#ifndef DUMP_TCP_PACKET_H_
#define DUMP_TCP_PACKET_H_

void dump_packets(const unsigned char *packet, struct timeval ts,
                     unsigned int capture_len);

#endif