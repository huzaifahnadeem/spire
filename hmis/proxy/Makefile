CC            = gcc
CXX           = g++
CFLAGS        += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
CXXFLAGS      += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
PRIME         = ../../prime
SPINES        = ../../spines
SPIRE         = ../..
INCPATH       = -I. -I$(PRIME)/stdutil/include \
				-I$(SPINES)/libspines/ -I$(SPIRE)/common -I$(PRIME)/libspread-util/include
LINK          = g++
LFLAGS        = -m64 -Wl,-O1
LIBS          = $(SUBLIBS) -lpthread \
					$(PRIME)/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
					$(SPINES)/libspines/libspines.a $(PRIME)/stdutil/lib/libstdutil.a \
					$(PRIME)/libspread-util/lib/libspread-util.a -lrt -ldl -lcrypto

TARGET        = proxy
SOURCES       = proxy.cpp \
        $(SPIRE)/common/scada_packets.c \
        $(SPIRE)/common/net_wrapper.c \
        $(SPIRE)/common/openssl_rsa.c \
        $(SPIRE)/common/tc_wrapper.c \
        $(SPIRE)/common/itrc.c \
		$(SPIRE)/common/key_value.c \
		$(SPIRE)/config/cJSON.c \
		$(SPIRE)/config/config_helpers.c 
OBJECTS       = proxy.o \
        $(SPIRE)/common/scada_packets.o \
        $(SPIRE)/common/net_wrapper.o \
        $(SPIRE)/common/openssl_rsa.o \
        $(SPIRE)/common/tc_wrapper.o \
        $(SPIRE)/common/itrc.o \
		$(SPIRE)/common/key_value.o \
		$(SPIRE)/config/cJSON.o \
		$(SPIRE)/config/config_helpers.o

HEADERS       = $(SPIRE)/common/net_wrapper.h \
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

proxy.o: proxy.cpp $(HEADERS)
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o proxy.o proxy.cpp

# mask1.o: mask1.cpp $(HEADERS)
# 	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o mask1.o mask1.cpp














# SHADOW_SPIRE	= ../../../shadow-spire
# SHADOW_PRIME	= $(SHADOW_SPIRE)/prime
# SHADOW_SPINES	= $(SHADOW_SPIRE)/spines

# CC            = gcc
# CXX           = g++
# CFLAGS        += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
# CXXFLAGS      += -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
# PRIME         = ../../prime
# SPINES        = ../../spines
# SPIRE         = ../..
# INCPATH       = -I. -I$(PRIME)/stdutil/include \
# 				-I$(SPINES)/libspines/ -I$(SPIRE)/common -I$(PRIME)/libspread-util/include \
# 				-I$(SHADOW_SPIRE) \
# 				-I$(SHADOW_SPIRE)/hmis/proxy/ -I$(SHADOW_PRIME)/stdutil/include \
# 				-I$(SHADOW_SPINES)/libspines/ -I$(SHADOW_SPIRE)/common -I$(SHADOW_PRIME)/libspread-util/include \

# LINK          = g++
# LFLAGS        = -m64 -Wl,-O1
# LIBS          = $(SUBLIBS) -lpthread \
# 					$(PRIME)/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
# 					$(SPINES)/libspines/libspines.a $(PRIME)/stdutil/lib/libstdutil.a \
# 					$(PRIME)/libspread-util/lib/libspread-util.a -lrt -ldl -lcrypto

# TARGET        = proxy

# # shadow:

# SHADOW_SOURCES       = $(SHADOW_SPIRE)/hmis/proxy/proxy.cpp \
#         $(SHADOW_SPIRE)/common/scada_packets.c \
#         $(SHADOW_SPIRE)/common/net_wrapper.c \
#         $(SHADOW_SPIRE)/common/openssl_rsa.c \
#         $(SHADOW_SPIRE)/common/tc_wrapper.c \
#         $(SHADOW_SPIRE)/common/itrc.c \
# 		$(SHADOW_SPIRE)/common/key_value.c \
# 		$(SHADOW_SPIRE)/config/cJSON.c \
# 		$(SHADOW_SPIRE)/config/config_helpers.c 
# SHADOW_OBJECTS       = $(SHADOW_SPIRE)/hmis/proxy/proxy.o \
#         $(SHADOW_SPIRE)/common/scada_packets.o \
#         $(SHADOW_SPIRE)/common/net_wrapper.o \
#         $(SHADOW_SPIRE)/common/openssl_rsa.o \
#         $(SHADOW_SPIRE)/common/tc_wrapper.o \
#         $(SHADOW_SPIRE)/common/itrc.o \
# 		$(SHADOW_SPIRE)/common/key_value.o \
# 		$(SHADOW_SPIRE)/config/cJSON.o \
# 		$(SHADOW_SPIRE)/config/config_helpers.o

# SHADOW_HEADERS       = $(SHADOW_SPIRE)/common/net_wrapper.h \
# 		$(SHADOW_SPIRE)/common/openssl_rsa.h \
# 		$(SHADOW_SPIRE)/common/tc_wrapper.h \
# 		$(SHADOW_SPIRE)/common/scada_packets.h \
# 		$(SHADOW_SPIRE)/common/def.h \
#         $(SHADOW_SPIRE)/common/itrc.h \
# 		$(SHADOW_SPIRE)/common/key_value.h \
# 		$(SHADOW_SPIRE)/config/config_helpers.h \
# 		$(SHADOW_SPIRE)/config/cJSON.h








# SOURCES       = proxy.cpp shadow_ns_fns.cpp \
#         $(SPIRE)/common/scada_packets.c \
#         $(SPIRE)/common/net_wrapper.c \
#         $(SPIRE)/common/openssl_rsa.c \
#         $(SPIRE)/common/tc_wrapper.c \
#         $(SPIRE)/common/itrc.c \
# 		$(SPIRE)/common/key_value.c \
# 		$(SPIRE)/config/cJSON.c \
# 		$(SPIRE)/config/config_helpers.c \
# 		$(SHADOW_SOURCES)

# OBJECTS       = proxy.o shadow_ns_fns.o\
#         $(SPIRE)/common/scada_packets.o \
#         $(SPIRE)/common/net_wrapper.o \
#         $(SPIRE)/common/openssl_rsa.o \
#         $(SPIRE)/common/tc_wrapper.o \
#         $(SPIRE)/common/itrc.o \
# 		$(SPIRE)/common/key_value.o \
# 		$(SPIRE)/config/cJSON.o \
# 		$(SPIRE)/config/config_helpers.o \
# 		$(SHADOW_OBJECTS)

# HEADERS       = $(SPIRE)/common/net_wrapper.h \
# 		$(SPIRE)/common/openssl_rsa.h \
# 		$(SPIRE)/common/tc_wrapper.h \
# 		$(SPIRE)/common/scada_packets.h \
# 		$(SPIRE)/common/def.h \
#         $(SPIRE)/common/itrc.h \
# 		$(SPIRE)/common/key_value.h \
# 		$(SPIRE)/config/config_helpers.h \
# 		$(SPIRE)/config/cJSON.h \
# 		$(SHADOW_HEADERS)



# # shadow:

# SHADOW_SOURCES       = $(SHADOW_SPIRE)/hmis/proxy/proxy.cpp \
#         $(SHADOW_SPIRE)/common/scada_packets.c \
#         $(SHADOW_SPIRE)/common/net_wrapper.c \
#         $(SHADOW_SPIRE)/common/openssl_rsa.c \
#         $(SHADOW_SPIRE)/common/tc_wrapper.c \
#         $(SHADOW_SPIRE)/common/itrc.c \
# 		$(SHADOW_SPIRE)/common/key_value.c \
# 		$(SHADOW_SPIRE)/config/cJSON.c \
# 		$(SHADOW_SPIRE)/config/config_helpers.c 
# SHADOW_OBJECTS       = $(SHADOW_SPIRE)/hmis/proxy/proxy.o \
#         $(SHADOW_SPIRE)/common/scada_packets.o \
#         $(SHADOW_SPIRE)/common/net_wrapper.o \
#         $(SHADOW_SPIRE)/common/openssl_rsa.o \
#         $(SHADOW_SPIRE)/common/tc_wrapper.o \
#         $(SHADOW_SPIRE)/common/itrc.o \
# 		$(SHADOW_SPIRE)/common/key_value.o \
# 		$(SHADOW_SPIRE)/config/cJSON.o \
# 		$(SHADOW_SPIRE)/config/config_helpers.o

# SHADOW_HEADERS       = $(SHADOW_SPIRE)/common/net_wrapper.h \
# 		$(SHADOW_SPIRE)/common/openssl_rsa.h \
# 		$(SHADOW_SPIRE)/common/tc_wrapper.h \
# 		$(SHADOW_SPIRE)/common/scada_packets.h \
# 		$(SHADOW_SPIRE)/common/def.h \
#         $(SHADOW_SPIRE)/common/itrc.h \
# 		$(SHADOW_SPIRE)/common/key_value.h \
# 		$(SHADOW_SPIRE)/config/config_helpers.h \
# 		$(SHADOW_SPIRE)/config/cJSON.h




# .SUFFIXES: .o .c .cpp .cc .cxx .C

# .cpp.o:
# 	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o "$@" "$<"

# .c.o:
# 	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INCPATH) -o "$@" "$<"

# all: $(TARGET)

# $(TARGET):  $(OBJECTS)  
# 	$(LINK) $(LDFLAGS) $(LFLAGS) -o $(TARGET) $(OBJECTS) $(OBJCOMP) $(LIBS)

# clean: 
# 	rm -rf $(OBJECTS)
# 	rm -rf $(TARGET)

# proxy.o: proxy.cpp $(HEADERS)
# 	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o proxy.o proxy.cpp

