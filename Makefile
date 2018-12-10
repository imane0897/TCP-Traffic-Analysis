make: main.c dump_packets.c
	gcc -o analyser main.c dump_packets.c -lpcap -I.

clean:
	rm analyser