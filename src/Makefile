# Copyright 2017-2018 Oticon A/S
# SPDX-License-Identifier: Apache-2.0

# makefile for building and running a quick test the library

SRCS:=blecrypt.c
OBJS:=${SRCS:.c=.o}
TEST_SRCS:=blecrypt_unittest.c
TEST_EXE:=./blecrypt_unittest
INCLUDES:=-I../include/

LIBS:=	../libcrypto.a \
	-ldl

CC:=gcc
WARNINGS:=-Wall -pedantic
CFLAGS:= ${WARNINGS} -std=c99 -m32

all: compile

compile: ${OBJS}

%.o: %.c
	@${CC} ${CFLAGS} ${INCLUDES} -c $< -o $@

test: ${TEST_SRCS} ${OBJS}
	@${CC} ${CFLAGS} ${TEST_SRCS} ${OBJS} ${LIBS} -o ${TEST_EXE}
	@-${TEST_EXE}
	@-rm -f ${TEST_EXE}

clean:
	@-rm -f ${TEST_EXE} ${OBJS}

install:
