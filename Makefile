OBJS=obj/main.o obj/help_functions.o obj/icmp_client.o obj/icmp_server.o
HEADERS=src/main.h src/help_functions.h src/icmp_client.h src/icmp_server.h
CC=g++
CFLAGS= -std=c++17 -Wall -Wextra -pedantic -lpcap -Wno-unused-variable -Wno-unused-parameter -lcrypto -lssl -O3
BINARY=secret

obj/%.o: src/%.cpp $(HEADERS)
	@mkdir -p obj
	$(CC) -c $< -o $@ $(CFLAGS)


$(BINARY): $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS)


all: $(BINARY)

zip:
	tar -cvf xzdrav00.tar ./src/* Makefile manual.pdf secret.1

clean:
	rm -rf obj/
	rm -f $(BINARY)
	rm -rf xzdrav00.tar

