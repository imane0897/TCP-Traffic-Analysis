make: main.c dump_packets.c print_report.c
	gcc -o analyser main.c dump_packets.c print_report.c -lpcap -I.

clean:
	rm analyser