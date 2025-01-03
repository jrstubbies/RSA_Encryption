CC := g++
TARGET := secure_client
SRC := secure_client.cpp


# Detect the operating system
ifeq ($(OS),Windows_NT)
	# Windows
# 	TARGET := $(TARGET)
	CFLAGS := -c -std=c++11 -Wall -O2 -fconserve-space $(SRC) 
    LFLAGS := -lws2_32 
    EXTENSION = .exe
	CLEANUP := del
	CLEANUP_OBJS := del *.o
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Darwin)
		# macOS
		EXTENSION = .out
		CFLAGS := -c -std=c++11 -Wall 
		LFLAGS := 
		CLEANUP := rm -f
		CLEANUP_OBJS := rm -f *.o
	else ifeq ($(UNAME_S),Linux)
		# Linux

		EXTENSION = .out
		CFLAGS := -c -std=c++11 -Wall 
		LFLAGS := 
		CLEANUP := rm -f
		CLEANUP_OBJS := rm -f *.o
	endif
endif




$(TARGET)$(EXTENSION)	:  $(TARGET).o 
	$(CC)  $(SRC) $(LFLAGS) -o $(TARGET)$(EXTENSION)
			
$(TARGET).o	 : 	$(SRC) 
	$(CC) $(CFLAGS) $(SRC) 

clean:
	$(CLEANUP) $(TARGET)
	$(CLEANUP_OBJS)
