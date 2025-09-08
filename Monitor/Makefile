CC = gcc
CFLAGS = -Wall -Wextra -O2
CFLAGS2 = -O2 -fno-stack-protector

SEAM_MANAGER_DIR := seamManager
SEAM_MANAGER_SRC = $(wildcard $(SEAM_MANAGER_DIR)/*.c)

NP_LOADER_DIR := npLoader
NP_LOADER_SRC = $(wildcard $(NP_LOADER_DIR)/*.c)

SEAM_AGENT_DIR := seamAgent
BUILD_DIR := build
INC_DIR := include

INTERPRETER_DIR := ../Interpreter

seam_manager: $(SEAM_MANAGER_SRC) $(NP_LOADER_SRC) $(BUILD_DIR)/payload.o $(INTERPRETER_DIR)/libinterpreter.so
	$(CC) $(CFLAGS2) -I $(INC_DIR) $^ -o $@

$(BUILD_DIR)/payload.o: $(SEAM_AGENT_DIR)/payload.ld $(BUILD_DIR)/seam_agent.img.o
	$(LD) -T $< -o $@

$(BUILD_DIR)/seam_agent.o: $(SEAM_AGENT_DIR)/seam_agent.c
	$(CC) $(CFLAGS) -I $(INC_DIR) -m64 -ffreestanding -fno-pic -c -o $@ $^

$(BUILD_DIR)/seam_agent.img: $(BUILD_DIR)/seam_agent.o
	$(LD) -T $(SEAM_AGENT_DIR)/agent.ld $^ -o $@

$(BUILD_DIR)/seam_agent.img.o: $(BUILD_DIR)/seam_agent.img
	$(LD) -b binary -r $^ -o $@

.PHONY: clean
TO_CLEAN = $(wildcard $(BUILD_DIR)/*)
clean:
	$(RM) seam_manager $(TO_CLEAN)
