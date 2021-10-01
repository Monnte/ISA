OBJS=obj/main.o 
HEADERS=src/main.h
CC=g++
CFLAGS=-Wall -Wextra -pedantic -lpcap -Wno-unused-variable -Wno-unused-parameter -lcrypto -lssl
BINARY=secret

obj/%.o: src/%.cpp $(HEADERS)
	@mkdir -p obj
	$(CC) -c $< -o $@ $(CFLAGS)


$(BINARY): $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS)


all: $(BINARY)

clean:
	rm -rf obj/
	rm -f $(BINARY)

