rm data/agent/agent.objdmp
objdump -d data/agent/agent.o > data/agent/agent.objdmp
echo "o dumped to agent.objdmp"
objdump -d --no-show-raw-insn data/agent/agent.o | grep cr | awk '{print $1}' | tr -d ':' > data/agent/cr_ins.address
