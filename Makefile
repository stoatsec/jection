TARGET = jection
BUILD_DIR = build

CC = gcc
#CFLAGS = -g

SRCS = \
    parsing/parser.c \
    process/trace.c \
    proxy/proxy.c \
    utils.c \
    inject.c \
    jection.c

OBJS = $(SRCS:.c=.o)

all: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	find . -type f -name "*.o" -delete

.PHONY: all clean
all: $(BUILD_DIR)/$(TARGET)
