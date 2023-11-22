CC = g++
TARGET = ipCapture
LIB_SOURCES = myUtil.cpp
MAIN_SOURCE = ipCapture.cpp
HEADERS = myUtil.h
OBJECTS = $(LIB_SOURCES:.cpp=.o)
CFLAGS = -Wall

all: $(TARGET)

$(TARGET): $(OBJECTS) $(MAIN_SOURCE)
	$(CC) $(CFLAGS) $(OBJECTS) $(MAIN_SOURCE) -o $(TARGET)

%.o: %.cpp $(HEADERS)
	$(CC) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)
