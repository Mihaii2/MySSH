all:
	gcc server.c -o server -ljansson
	gcc client.c -o client
clean:
	rm server client test