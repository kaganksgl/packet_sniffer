# Build the packet sniffer used by the desktop GUI.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
# Applied on top of CFLAGS: stack protector, fortified libc calls, full RELRO, PIE.
HARDEN   = -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Wformat-security -fPIE
HARDEN_LD = -pie -Wl,-z,relro,-z,now
BIN      = sniffer
SRC      = packet_sniffer.c

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(HARDEN) -o $@ $< $(LDFLAGS) $(HARDEN_LD)

# Allow raw-socket capture without running the whole program as root.
# Needs a one-time authentication prompt.
setcap: $(BIN)
	pkexec setcap cap_net_raw,cap_net_admin+ep $(CURDIR)/$(BIN)

clean:
	rm -f $(BIN)

.PHONY: all setcap clean
