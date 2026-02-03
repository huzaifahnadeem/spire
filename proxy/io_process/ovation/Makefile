# If you want to link the io_process binary to a different spire codebase, you can do that by overriding the spire path variable `SPIRE_DIR`. If you want to use a different binary name, then there is `BINARY_NAME` variable for that as well. For example, when running `make`, you can do something like: make SPIRE_DIR=../../../../spire_something BINARY_NAME=io_process_something

SPIRE_DIR  = ../../../

BINARY_NAME = io_proc_ovation

CC            = gcc
CXX           = g++
CFLAGS        += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
CXXFLAGS      += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
LINK          = g++
LFLAGS        = -m64 -Wl,-O1

TARGET        = $(BINARY_NAME)

PRIME_DIR  = $(SPIRE_DIR)/prime
SPINES_DIR  = $(SPIRE_DIR)/spines

LIBS_LIST          = -lpthread \
				$(PRIME_DIR)/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
				$(SPINES_DIR)/libspines/libspines.a \
				$(PRIME_DIR)/stdutil/lib/libstdutil.a \
				$(PRIME_DIR)/libspread-util/lib/libspread-util.a -lrt -ldl -lcrypto \

SOURCES_LIST       = \
		io_process.cpp \
        $(SPIRE_DIR)/common/scada_packets.c \
        $(SPIRE_DIR)/common/net_wrapper.c \
        $(SPIRE_DIR)/common/openssl_rsa.c \
        $(SPIRE_DIR)/common/tc_wrapper.c \
        $(SPIRE_DIR)/common/itrc.c \
		$(SPIRE_DIR)/common/key_value.c \
		$(SPIRE_DIR)/config/cJSON.c \
		$(SPIRE_DIR)/config/config_helpers.c \

OBJECTS_LIST       = \
		$(BINARY_NAME).o \
        $(SPIRE_DIR)/common/scada_packets.o \
        $(SPIRE_DIR)/common/net_wrapper.o \
        $(SPIRE_DIR)/common/openssl_rsa.o \
        $(SPIRE_DIR)/common/tc_wrapper.o \
        $(SPIRE_DIR)/common/itrc.o \
		$(SPIRE_DIR)/common/key_value.o \
		$(SPIRE_DIR)/config/cJSON.o \
		$(SPIRE_DIR)/config/config_helpers.o \

HEADERS_LIST       = \
		$(SPIRE_DIR)/common/net_wrapper.h \
		$(SPIRE_DIR)/common/openssl_rsa.h \
		$(SPIRE_DIR)/common/tc_wrapper.h \
		$(SPIRE_DIR)/common/scada_packets.h \
		$(SPIRE_DIR)/common/def.h \
        $(SPIRE_DIR)/common/itrc.h \
		$(SPIRE_DIR)/common/key_value.h \
		$(SPIRE_DIR)/config/config_helpers.h \
		$(SPIRE_DIR)/config/cJSON.h \

INCLUDE_PATH       = -I. \
				-I$(SPIRE_DIR)/. \
				-I$(PRIME_DIR)/stdutil/include \

.SUFFIXES: .o .c .cpp .cc .cxx .C

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCLUDE_PATH) -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INCLUDE_PATH) -o "$@" "$<"


all: $(TARGET)

$(TARGET):  $(OBJECTS_LIST)
	$(LINK) $(LDFLAGS) $(LFLAGS) -o $(TARGET) $(OBJECTS_LIST) $(LIBS_LIST) -I/usr/include/modbus -lmodbus

clean: 
	rm -rf $(OBJECTS_LIST)
	rm -rf $(TARGET)

$(BINARY_NAME).o: io_proc_ovation.cpp $(HEADERS_LIST)
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCLUDE_PATH) -o $(BINARY_NAME).o io_proc_ovation.cpp

testprog_ovation_demo: testprog_ovation_demo.cpp
	g++ testprog_ovation_demo.cpp -o testprog_ovation_demo -I/usr/include/modbus -lmodbus
