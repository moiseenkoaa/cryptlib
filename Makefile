
include ../Makefile.inc

OBJECTS_DIR = ./

HEADERS = 
SOURCES = stdafx.cpp \
	    exp5.cpp \
	    Gost_BS_MAA.cpp \
	    Kuznechik_MAA.cpp \
	    main.cpp \
	    longint2.cpp \
	    RSA.cpp \
	    AntiRobotCaptcha.cpp \
	    ntlm.cpp \
	    li_64.nasm \
	    li_32_64.nasm \
	    sha256/sha224-256.cpp \
	    sha256/sha384-512.cpp \
	    sha256/sha.cpp \
	    sha256/usha.cpp \
	    sha256/hmac.cpp \
	    sha256/sha_iface.cpp

OBJECTS = stdafx.o \
	    exp5.o \
	    Gost_BS_MAA.o \
	    Kuznechik_MAA.o \
	    main.o \
	    longint2.o \
	    RSA.o \
	    AntiRobotCaptcha.o \
	    ntlm.o \
	    li_64.o \
	    li_32_64.o \
	    sha256/sha224-256.o \
	    sha256/sha384-512.o \
	    sha256/sha.o \
	    sha256/usha.o \
	    sha256/hmac.o \
	    sha256/sha_iface.o
	    

DESTDIR  = 
TARGET   = CryptLib.a

#first: all

all: Makefile $(TARGET)

../ToolsLib/ToolsLib.a: ../ToolsLib/
	$(MAKE) -C ../ToolsLib

#li_64.o: li_64.nasm
#	nasm -f elf64 -g -F dwarf li_64.nasm

#li_32_64.o: li_32_64.nasm
#	nasm -f elf64 -g -F dwarf li_32_64.nasm

#	nasm -f elf64 -g -F dwarf li_64.nasm -l hello.lst

$(TARGET):  $(OBJECTS) ../ToolsLib/ToolsLib.a
	$(AR) $(TARGET) $(OBJECTS)
	ls -l *.a

install:  

uninstall:  
