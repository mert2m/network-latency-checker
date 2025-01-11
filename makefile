CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
BUILD_TYPE ?= release

ifeq ($(BUILD_TYPE),debug)
CXXFLAGS += -g -O0
else
CXXFLAGS += -O2
endif

INCLUDES = -isystem /opt/homebrew/Cellar/libssh/0.11.1/include \
          -I/opt/homebrew/opt/openssl@3/include \
          -I/opt/homebrew/include \
          -I/opt/homebrew/include/nlohmann
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib \
          -L/opt/homebrew/lib
LIBS = -lssl -lcrypto -lssh -lcurl

TARGET = app
SRCS = app.cpp
BUILD_DIR = build
OBJS = $(addprefix $(BUILD_DIR)/, $(SRCS:.cpp=.o))

.DEFAULT_GOAL := $(TARGET)

$(BUILD_DIR)/%.o: %.cpp
	mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

.PHONY: clean
clean:
	rm -rf $(TARGET) $(BUILD_DIR)
