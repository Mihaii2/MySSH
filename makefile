all:
	gcc server.c -o server
	gcc client.c -o client
	gcc test.c -o test
clean:
	rm server client test