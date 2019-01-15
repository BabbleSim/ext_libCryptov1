################################################################################
#
#      Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
#
#            Global configuration Makefile. Included everywhere.
#
################################################################################

# EDIT HERE:
CC:=gcc
CPPFLAGS:=#HACK missing var
TARGET_ARCH:=#HACK missing var
CFLAGS:=-O2 -std=c99 -Wall -Wextra -D_ISOC99_SOURCE -MMD -I../lib/include/ -I../lib/source/ -I../tests/include/ -m32 -g#HACK: build as 32bit and with O2 and debug info
vpath %.c ../lib/source/
ENABLE_TESTS=false#HACK:No need for tests when built as a library
ARFLAGS=cr#HACK: default was vr = verbose, and warn if it did not exist

# override MinGW built-in recipe
%.o: %.c
	@$(COMPILE.c) $(OUTPUT_OPTION) $< #HACK: be silent

#HACK: removed DOTEXE part (no windows support here)
# DO NOT EDIT AFTER THIS POINT:
ifeq ($(ENABLE_TESTS), true)
CFLAGS += -DENABLE_TESTS
else
CFLAGS += -DDISABLE_TESTS
endif

export CC
export CFLAGS
export VPATH
export ENABLE_TESTS

################################################################################
