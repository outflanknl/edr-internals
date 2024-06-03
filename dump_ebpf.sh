#!/bin/bash

OUTPUT_DIR="ebpf_dumps"
mkdir -p "$OUTPUT_DIR"

dump_prog() {
    local prog_id=$1
    local dir=$2

    echo "Dumping program ID $prog_id"
    bpftool prog show id $prog_id > "$dir/prog_$prog_id.txt"
    bpftool prog dump xlated id $prog_id > "$dir/prog_${prog_id}_xlated.txt"
    bpftool prog dump jit id $prog_id > "$dir/prog_${prog_id}_jit.txt"
}

dump_map() {
    local map_id=$1
    local dir=$2

    echo "Dumping map ID $map_id"
    bpftool map show id $map_id > "$dir/map_$map_id.txt"
    bpftool map dump id $map_id > "$dir/map_${map_id}_dump.txt"
}

prog_ids=$(bpftool prog list | awk '/^[0-9]+:/ {print $1}' | tr -d ':')
for prog_id in $prog_ids; do
    prog_dir="$OUTPUT_DIR/prog_$prog_id"
    mkdir -p "$prog_dir"
    dump_prog $prog_id "$prog_dir"

    map_ids=$(bpftool prog show id $prog_id | awk '/map_ids/ {print $8}' | tr ',' '\n')
    for map_id in $map_ids; do
        map_dir="$OUTPUT_DIR/prog_${prog_id}_map_$map_id"
        mkdir -p "$map_dir"
        dump_map $map_id "$map_dir"
    done
done

echo "All eBPF programs and maps have been dumped to $OUTPUT_DIR."
