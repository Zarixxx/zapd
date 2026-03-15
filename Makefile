CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Isrc $(shell pkg-config --cflags openssl 2>/dev/null)
LDFLAGS = -lpthread $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")
TARGET  = zapd
SRCS    = src/main.c src/ui.c src/scanner.c src/pinger.c src/whois.c src/virustotal.c
OBJS    = $(SRCS:.c=.o)

all: check-openssl $(TARGET)

check-openssl:
	@pkg-config --exists openssl 2>/dev/null || \
	(echo "" && \
	 echo "  [!] OpenSSL not found. Install it with:" && \
	 echo "      sudo pacman -S openssl" && \
	 echo "" && exit 1)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "  Build successful → ./$(TARGET)"
	@echo ""

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/$(TARGET)
	sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "  Installed → /usr/local/bin/$(TARGET)"

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all check-openssl install uninstall clean
