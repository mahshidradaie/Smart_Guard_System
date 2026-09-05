CC = gcc
CFLAGS = -Wall -pthread -lssl -lcrypto -lcurl -lsqlite3 -lmosquitto

TARGET = webserver
SRC = server.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(CFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
