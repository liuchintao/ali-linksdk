ifneq ($(COMPILE),)
    AIOT_CC := $(COMPILE)
else
	AIOT_CC := gcc
endif

LIB_NAME := libnopoll
WORK_PATH := "components/remote-access/src/nopoll"

ifeq ($(OS),Windows_NT)
    uname_S := Windows
else
    uname_S := $(shell uname -s)
endif

ifeq ($(uname_S), Windows)
    SHARE_LIB   := $(LIB_NAME).dll
    CFLAGS  := -I./include -Wl,--add-stdcall-alias
    STATIC_LIB   := $(LIB_NAME).lib
endif
ifeq ($(uname_S), Linux)
    SHARE_LIB   := $(LIB_NAME).so
    CFLAGS  := -fPIC -I./include -O0 -g
    STATIC_LIB := $(LIB_NAME).a
else
    SHARE_LIB   := $(LIB_NAME).so
    CFLAGS  := -fPIC -I./include -O0 -g
    STATIC_LIB := $(LIB_NAME).a
endif

SHARED_FLAG := -shared

DIR_SRC := ./library
DIR_OBJ := ./library
DIR_LIB := .

SRC := $(wildcard ${DIR_SRC}/*.c)
OBJ := $(patsubst %.c, ${DIR_OBJ}/%.o, $(notdir ${SRC}))

all: $(OBJ) shared 

$(DIR_SRC)/%.o:$(DIR_SRC)/%.c
	@echo ": Compiling $(WORK_PATH)/$< ..."
	@$(AIOT_CC)  -o $@ -c $< $(CFLAGS)
shared:$(OBJ)
	@echo ": Compiling $(WORK_PATH)/$(SHARE_LIB)"
	@$(AIOT_CC) -o $(DIR_LIB)/$(SHARE_LIB) $(OBJ) $(CFLAGS) $(SHARED_FLAG)
clean:
	@rm -rf $(DIR_OBJ)/*.o $(DIR_LIB)/*.so
