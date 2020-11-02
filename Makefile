CC = clang
INCPATHS = -I/usr/local/opt/openssl@1.1/include
CFLAGS = -g -Wall -O3 $(INCPATHS) -march=native
LDLIBS = -lgmp -lssl -lcrypto
LDPATH = -L/usr/local/opt/openssl@1.1/lib
BUILD = build


SRC = main.c crypto.c ore.c 
OBJPATHS = $(patsubst %.c,$(BUILD)/%.o, $(SRC))


all: $(BUILD) $(OBJPATHS) main


$(BUILD):
	mkdir -p $(BUILD)


$(BUILD)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


main:$(OBJPATHS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDPATH) $(LDLIBS)

clean:
	rm -rf $(BUILD) *~
	rm main