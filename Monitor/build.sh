make clean; make
cp build/payload.o data/agent/agent.o
echo "copied agent.o"
./data/agent/get_cr_ins_address.sh
