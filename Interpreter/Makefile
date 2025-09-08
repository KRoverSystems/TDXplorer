DYNINST_PATH	:= /home/neo/smu/KRover/dyninst/install
DYNINST_INC_PATH		:= ${DYNINST_PATH}/include
DYNINST_LIB_PATH		:= ${DYNINST_PATH}/lib

Z3_PATH	:= /home/neo/smu/KRover/z3/z3-solver/z3
Z3_INC_PATH		:= ${Z3_PATH}/include
Z3_LIB_PATH		:= ${Z3_PATH}

INC_PATH := -I${DYNINST_INC_PATH}
INC_PATH += -I${Z3_INC_PATH}

SEAM_MGR_INC_PATH := ../Monitor/include

API_INC := -I${SEAM_MGR_INC_PATH}
INC_PATH += -I${SEAM_MGR_INC_PATH}

LIB_PATH := -L${DYNINST_LIB_PATH}
LIB_PATH += -L${Z3_LIB_PATH}

C		:= gcc
CFLAGS	:= -fPIC -c
CC		:= g++
CPPFLAGS	:=-fPIC -c -std=c++11 
LDFLAGS= '-Wl,--rpath=${DYNINST_LIB_PATH}:${Z3_PATH}'
DEP = -lz3 -lparseAPI -linstructionAPI -lsymtabAPI -ldynDwarf -lelf -ldynElf -lcommon -lsymLite 

ifeq (${DEBUG}, 1)
	CPPFLAGS	+= -O3 -g -ggdb3  -DDEBUG
else
	CPPFLAGS	+= -O3
endif

CPPS	:= centralhub.cpp VMState.cpp CPUState.cpp MemState.cpp thinctrl.cpp symexec.cpp oprand.cpp Expr.cpp EFlagsManager.cpp Z3Handler.cpp SymList.cpp pageManager.cpp HistoryTree.cpp Analyze.cpp AnaCtrl.cpp interpreterWrapper.cpp 
OBJS	:= $(patsubst %.cpp,%.o,${CPPS})

all: libinterpreter.so

$(OBJS):%.o:%.cpp
	$(CC) $(CPPFLAGS) $(INC_PATH) $^ -o $@

interpreterAPI.o: interpreterAPI.c
	$(C) $(CFLAGS) $(API_INC) -o $@ $^

libinterpreter.so: ${OBJS} interpreterAPI.o 
	$(CC) --shared -fPIC $^ -o $@ $(LIB_PATH) $(LDFLAGS) $(DEP) -std=c++11

clean:
	rm -rf ${OBJS} interpreterAPI.o
