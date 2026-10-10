TARGET = rea_psp_fixture
OBJS = main.o probe.o
BUILD_PRX = 0
CFLAGS = -O0 -g -G0 -fno-inline -fno-builtin
ASFLAGS = -g
PSPSDK := $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak
