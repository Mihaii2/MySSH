all:
	gcc server.c common_functions.c -o server -ljansson
	gcc client.c common_functions.c -o client
clean:
	rm server client test