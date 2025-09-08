#!/bin/bash
nm libtdx_unstripped.so | grep tdx_seamcall_entry_point > libtdx-seamentry.address
nm libtdx_unstripped.so | grep tdx_tdexit_entry_point > libtdx-tdexit-entry.address
nm libtdx_unstripped.so | grep ippsAES_GCMDecrypt > libtdx-ippcrypto.start.address
nm libtdx_unstripped.so | grep tdh_mem_page_aug > libtdx-tdh_mem_page_aug.address
nm libtdx_unstripped.so | grep tdh_mem_page_aug > libtdx-tdh_mem_page_aug.address
nm libtdx_unstripped.so | grep tdh_mem_sept_add > libtdx-tdh_mem_sept_add.address
nm libtdx_unstripped.so | grep tdh_servtd_bind > libtdx-ttdh_servtd_bind.address
nm libtdx_unstripped.so | grep tdg_mem_page_attr_rd > libtdx-tdg_mem_page_attr_rd.address
objdump -d libtdx_unstripped.so > libtdx_unstripped.so.objdump
objdump -d --no-show-raw-insn libtdx.so \
    | grep -v ">:" \
    | grep -v -e '^[[:space:]]*$' \
    | grep -v "libtdx.so" \
    | grep -v "Disassembly" \
    | sed -e 's/^[ \t]*//' > libtdx.so.objdump

cat libtdx.so.objdump | grep -A1 'stac ' | grep 'mov' > libtdx-khole-edit-write.ins

file="libtdx_unstripped.so.objdump"
out_seamret="libtdx-seamret.address"
out_vmresume="libtdx-vmresume.address"
out_vmlaunch="libtdx-vmlaunch.address"

# Empty the output files
> "$out_seamret"
> "$out_vmresume"
> "$out_vmlaunch"

# 1. Find 66 0f 01 followed by cd 0f (seamret)
grep -n -E "66 0f 01" "$file" | while IFS=: read -r lineno line; do
    nextline=$((lineno+1))
    if sed -n "${nextline}p" "$file" | grep -q -E "cd 0f"; then
        echo "$line" | awk '{print $1}' | tr -d ':' >> "$out_seamret"
    fi
done

# 2. Find 0f 01 c3 (vmresume)
grep -E "0f 01 c3" "$file" | awk '{print $1}' | tr -d ':' >> "$out_vmresume"

# 3. Find 0f 01 c2 (vmlaunch)
grep -E "0f 01 c2" "$file" | awk '{print $1}' | tr -d ':' >> "$out_vmlaunch"

zip -r ziplibtdx.zip libtdx*