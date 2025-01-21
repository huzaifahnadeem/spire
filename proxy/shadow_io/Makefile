# can override when running make like: make SHADOW_SPIRE=/path/to/shadow 

SHADOW_SPIRE  = ../../../../shadow-spire

CC            = gcc
CXX           = g++
CFLAGS        += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
CXXFLAGS      += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
LINK          = g++
LFLAGS        = -m64 -Wl,-O1

TARGET        = shadow_io

SHADOW_PRIME  = $(SHADOW_SPIRE)/prime
SHADOW_SPINES  = $(SHADOW_SPIRE)/spines

SHADOW_LIBS          = -lpthread \
				$(SHADOW_PRIME)/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
				$(SHADOW_SPINES)/libspines/libspines.a \
				$(SHADOW_PRIME)/stdutil/lib/libstdutil.a \
				$(SHADOW_PRIME)/libspread-util/lib/libspread-util.a -lrt -ldl -lcrypto \

SHADOW_SOURCES       = \
		shadow_io.cpp \
        $(SHADOW_SPIRE)/common/scada_packets.c \
        $(SHADOW_SPIRE)/common/net_wrapper.c \
        $(SHADOW_SPIRE)/common/openssl_rsa.c \
        $(SHADOW_SPIRE)/common/tc_wrapper.c \
        $(SHADOW_SPIRE)/common/itrc.c \
		$(SHADOW_SPIRE)/common/key_value.c \
		$(SHADOW_SPIRE)/config/cJSON.c \
		$(SHADOW_SPIRE)/config/config_helpers.c \

SHADOW_OBJECTS       = \
		shadow_io.o \
        $(SHADOW_SPIRE)/common/scada_packets.o \
        $(SHADOW_SPIRE)/common/net_wrapper.o \
        $(SHADOW_SPIRE)/common/openssl_rsa.o \
        $(SHADOW_SPIRE)/common/tc_wrapper.o \
        $(SHADOW_SPIRE)/common/itrc.o \
		$(SHADOW_SPIRE)/common/key_value.o \
		$(SHADOW_SPIRE)/config/cJSON.o \
		$(SHADOW_SPIRE)/config/config_helpers.o \

SHADOW_HEADERS       = \
		$(SHADOW_SPIRE)/common/net_wrapper.h \
		$(SHADOW_SPIRE)/common/openssl_rsa.h \
		$(SHADOW_SPIRE)/common/tc_wrapper.h \
		$(SHADOW_SPIRE)/common/scada_packets.h \
		$(SHADOW_SPIRE)/common/def.h \
        $(SHADOW_SPIRE)/common/itrc.h \
		$(SHADOW_SPIRE)/common/key_value.h \
		$(SHADOW_SPIRE)/config/config_helpers.h \
		$(SHADOW_SPIRE)/config/cJSON.h \

SHADOW_INCPATH       = -I. \
				-I$(SHADOW_SPIRE)/.. \
				-I$(SHADOW_PRIME)/stdutil/include \

.SUFFIXES: .o .c .cpp .cc .cxx .C

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(SHADOW_INCPATH) -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(SHADOW_INCPATH) -o "$@" "$<"


all: $(TARGET)

$(TARGET):  $(SHADOW_OBJECTS)
	$(LINK) $(LDFLAGS) $(LFLAGS) -o $(TARGET) $(SHADOW_OBJECTS) $(SHADOW_LIBS)

clean: 
	rm -rf $(SHADOW_OBJECTS)
	rm -rf $(TARGET)

shadow_io.o: shadow_io.cpp $(SHADOW_HEADERS)
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(SHADOW_INCPATH) -o shadow_io.o shadow_io.cpp
