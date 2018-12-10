make: main.c dump_tcp_packet.c
	gcc -o analyser main.c dump_tcp_packet.c -lpcap -I.

clean:
	rm analyser