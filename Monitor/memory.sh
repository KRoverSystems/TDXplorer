#!/bin/bash

binary=./seam_manager
$binary &  # Start seam_manager in the background
pid=$!

start_time=$(date +%s.%N)  # Record precise start time
echo "Tracking memory usage for PID $pid"

# Write CSV header
echo "Time(s),RSS(KB),VSZ(KB)" > mem_usage_seam_manager.csv
# Add initial row with zeros
echo "0,0,0" >> mem_usage_seam_manager.csv

last_elapsed=0

while kill -0 $pid 2>/dev/null; do
    rss=$(awk '/VmRSS/ {print $2}' /proc/$pid/status)
    vsz=$(awk '/VmSize/ {print $2}' /proc/$pid/status)

    now=$(date +%s.%N)
    # Calculate elapsed time since start (in seconds, with fractions)
    elapsed=$(echo "$now - $start_time" | bc)

    # Write row only if none of the fields are empty
    echo "$elapsed,$rss,$vsz" | awk -F',' 'NF==3 && $1 != "" && $2 != "" && $3 != ""' >> mem_usage_seam_manager.csv

    last_elapsed=$elapsed
    sleep 0.000001
done

# Add final row (last_elapsed + 0.0001,0,0)
final_elapsed=$(echo "$last_elapsed + 0.0001" | bc)
echo "$final_elapsed,0,0" >> mem_usage_seam_manager.csv

echo "Process ended."
