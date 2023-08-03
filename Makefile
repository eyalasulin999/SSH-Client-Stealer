CC = gcc
FLAGS = -fPIC -shared -ldl -D_GNU_SOURCE
TARGET = stealer.so

SRCS = src/stealer.c
OBJS = $(SRCS:.c=.o)

stealer: $(SRCS)
	$(CC) $(FLAGS) -o $(TARGET) $(SRCS)
	rm -f $(OBJS)