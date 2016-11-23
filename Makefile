CC=clang-3.8
OBJECTS=main.o

all: build

build: $(OBJECTS)
	$(CC) -Wall -Wextra -Werror -pedantic \
		-I/usr/include/bcc/compat \
		$(OBJECTS) -o chownsnoop \
		-lbcc

.phony: clean

clean:
	rm -vf chownsnoop
	rm -vf *.o
