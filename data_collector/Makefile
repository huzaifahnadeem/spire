CC            = gcc
CXX           = g++
CFLAGS        += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
CXXFLAGS      += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
PRIME         = ../prime
SPINES        = ../spines
SPIRE         = ..
INCPATH       = -I. -I$(PRIME)/stdutil/include \
				-I$(SPINES)/libspines/ -I$(SPIRE)/common -I$(PRIME)/libspread-util/include
LINK          = g++
LFLAGS        = -m64 -Wl,-O1
LIBS          = $(SUBLIBS) -lpthread \
					$(PRIME)/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
					$(SPINES)/libspines/libspines.a $(PRIME)/stdutil/lib/libstdutil.a \
					$(PRIME)/libspread-util/lib/libspread-util.a -lrt -ldl -lcrypto

SOURCES       = data_collector.cpp \
		$(SPIRE)/common/scada_packets.c \
        $(SPIRE)/common/net_wrapper.c \
        $(SPIRE)/common/openssl_rsa.c \
        $(SPIRE)/common/tc_wrapper.c \
        $(SPIRE)/common/itrc.c \
		$(SPIRE)/common/key_value.c \
		$(SPIRE)/config/cJSON.c \
		$(SPIRE)/config/config_helpers.c 

OBJECTS       = data_collector.o \
		$(SPIRE)/common/scada_packets.o \
        $(SPIRE)/common/net_wrapper.o \
        $(SPIRE)/common/openssl_rsa.o \
        $(SPIRE)/common/tc_wrapper.o \
        $(SPIRE)/common/itrc.o \
		$(SPIRE)/common/key_value.o \
		$(SPIRE)/config/cJSON.o \
		$(SPIRE)/config/config_helpers.o

TARGET        = data_collector

HEADERS       = \
		$(SPIRE)/common/net_wrapper.h \
		$(SPIRE)/common/openssl_rsa.h \
		$(SPIRE)/common/tc_wrapper.h \
		$(SPIRE)/common/scada_packets.h \
		$(SPIRE)/common/def.h \
        $(SPIRE)/common/itrc.h \
		$(SPIRE)/common/key_value.h \
		$(SPIRE)/config/config_helpers.h \
		$(SPIRE)/config/cJSON.h

.SUFFIXES: .o .c .cpp .cc .cxx .C

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INCPATH) -o "$@" "$<"

all: $(TARGET)

$(TARGET):  $(OBJECTS)  
	$(LINK) $(LDFLAGS) $(LFLAGS) -o $(TARGET) $(OBJECTS) $(OBJCOMP) $(LIBS)

clean: 
	rm -rf $(OBJECTS)
	rm -rf $(TARGET)

data_collector.o: data_collector.cpp $(HEADERS)
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o data_collector.o data_collector.cpp
