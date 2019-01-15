# Copyright 2018 Oticon A/S
# SPDX-License-Identifier: Apache-2.0

BSIM_BASE_PATH?=$(abspath ../ )
include ${BSIM_BASE_PATH}/common/pre.make.inc

SRCS:=src/blecrypt.c
LIB_NAME:=libCryptov1
A_LIBS:=$(COMPONENT_OUTPUT_DIR)/tinycrypt/lib/libtinycrypt.a
SO_LIBS:=
DEBUG:=-g
OPT:=-O2
ARCH:=-m32
WARNINGS:=-Wall -pedantic
COVERAGE:=
CFLAGS:=${ARCH} ${DEBUG} ${OPT} ${WARNINGS} -MMD -MP -std=c99 -fPIC -Itinycrypt/lib/include
LDFLAGS:=${ARCH} ${COVERAGE}
CPPFLAGS:=

include ${BSIM_BASE_PATH}/common/make.lib_so.inc

$(COMPONENT_OUTPUT_DIR)/tinycrypt/lib/libtinycrypt.a: always_run_this_target
	@cd tinycrypt && $(MAKE) #SO=linux DOTEXE= LDFLAGS=${LDFLAGS} LOADLIBES= LDLIBS=
