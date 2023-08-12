CC = gcc
FLAGS = -fPIC -shared -ldl -D_GNU_SOURCE -DLOG_USE_COLOR
TARGET = stealer.so

SRCS = src/stealer.c src/logger/log.c
OBJS = $(SRCS:.c=.o)

stealer: $(SRCS)
	$(CC) $(FLAGS) -o $(TARGET) $(SRCS)
	rm -f $(OBJS)