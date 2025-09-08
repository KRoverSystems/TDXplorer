objdump -d --no-show-raw-insn pseamldr.so \
    | grep -v ">:" \
    | grep -v -e '^[[:space:]]*$' \
    | grep -v "pseamldr.so" \
    | grep -v "Disassembly" \
    | sed -e 's/^[ \t]*//' > pseamldr.so.objdump
objdump -d pseamldr.so > pseamldr.so.objdump_full

