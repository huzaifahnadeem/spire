CC            = gcc
CXX           = g++
LINK          = g++
CXXFLAGS      += -std=c++17 -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)

SPIRE         = ../
SPINES        = $(SPIRE)/spines
INCPATH       = -I. \
				-I$(SPIRE) \

LIBS          = $(SUBLIBS) -lpthread \
				$(SPINES)/libspines/libspines.a \


TARGET        = switcher

SOURCES       = \
		switcher.cpp \
		$(SPIRE)/common/net_wrapper.c \

OBJECTS       = \
		switcher.o \
		$(SPIRE)/common/net_wrapper.o \

HEADERS       = \
		switcher.h \
		$(SPIRE)/common/net_wrapper.h \

.SUFFIXES: .o .c .cpp .cc .cxx .C

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INCPATH) -o "$@" "$<"

all: $(TARGET) 

$(TARGET):  $(OBJECTS)
	$(LINK) $(LDFLAGS) $(LFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean: 
	rm -rf $(OBJECTS)
	rm -rf $(TARGET)

switcher.o: switcher.cpp $(HEADERS)
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $(INCPATH) -o switcher.o switcher.cpp