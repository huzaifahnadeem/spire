CC            = gcc
CXX           = g++
CFLAGS        += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
CXXFLAGS      += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
PRIME         = ../../prime
SPINES        = ../../spines
SPIRE         = ../..
INCPATH       = -I. \
				-I$(SPIRE) \
				-I$(PRIME)/stdutil/include \

LINK          = g++
LFLAGS        = -m64 -Wl,-O1
LIBS          = $(SUBLIBS) -lpthread \
				$(PRIME)/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
				$(SPINES)/libspines/libspines.a \
				$(PRIME)/stdutil/lib/libstdutil.a \
				$(PRIME)/libspread-util/lib/libspread-util.a -lrt -ldl -lcrypto \

TARGET        = proxy
SOURCES       = \
		proxy.cpp \
        $(SPIRE)/common/scada_packets.c \
        $(SPIRE)/common/net_wrapper.c \
        $(SPIRE)/common/openssl_rsa.c \
        $(SPIRE)/common/tc_wrapper.c \
        $(SPIRE)/common/itrc.c \
		$(SPIRE)/common/key_value.c \
		$(SPIRE)/config/cJSON.c \
		$(SPIRE)/config/config_helpers.c \

OBJECTS       = \
		proxy.o \
        $(SPIRE)/common/scada_packets.o \
        $(SPIRE)/common/net_wrapper.o \
        $(SPIRE)/common/openssl_rsa.o \
        $(SPIRE)/common/tc_wrapper.o \
        $(SPIRE)/common/itrc.o \
		$(SPIRE)/common/key_value.o \
		$(SPIRE)/config/cJSON.o \
		$(SPIRE)/config/config_helpers.o \

HEADERS       = $(SPIRE)/common/net_wrapper.h \
		$(SPIRE)/common/openssl_rsa.h \
		$(SPIRE)/common/tc_wrapper.h \
		$(SPIRE)/common/scada_packets.h \
		$(SPIRE)/common/def.h \
        $(SPIRE)/common/itrc.h \
		$(SPIRE)/common/key_value.h \
		$(SPIRE)/config/config_helpers.h \
		$(SPIRE)/config/cJSON.h \

.SUFFIXES: .o .c .cpp .cc .cxx .C

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INCPATH) -o "$@" "$<"


all: $(TARGET) shadow_io

shadow_io:
	$(MAKE) -C ./shadow_io/

$(TARGET):  $(OBJECTS)
	$(LINK) $(LDFLAGS) $(LFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean: 
	rm -rf $(OBJECTS)
	rm -rf $(TARGET)

proxy.o: proxy.cpp $(HEADERS)
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o proxy.o proxy.cpp
