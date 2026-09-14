#!/bin/bash
set -ex
mount -t proc none /proc
mount -t sysfs none /sys

mkdir /tmp/exp_ro
mount -t 9p exp /tmp/exp_ro

mkdir /tmp/exp
chown user:user /tmp/exp
chmod a+rx /tmp/exp

cp /tmp/exp_ro/* tmp/exp/
chmod a+rx /tmp/exp/*

# Set-up lo interface so that it's coherent with the live instance.
ifconfig lo 127.0.0.1 netmask 255.0.0.0 up

# Test-branch-only tracing in the same pinned COS guest as the repro action.
TRACE_ROOT=/sys/kernel/tracing
mkdir -p "$TRACE_ROOT"
mount -t tracefs tracefs "$TRACE_ROOT" || true
if [[ -e "$TRACE_ROOT/kprobe_events" ]]; then
    echo 0 > "$TRACE_ROOT/tracing_on"
    echo 8192 > "$TRACE_ROOT/buffer_size_kb" || true
    if echo 'p:slub_discard discard_slab cache=$arg1:x64 slab=$arg2:x64' >> "$TRACE_ROOT/kprobe_events"; then
        echo 1 > "$TRACE_ROOT/events/kprobes/slub_discard/enable"
        echo 'COS-TRACE discard probe ready'
    fi
    if echo 'r:pte_alloc pte_alloc_one page=$retval:x64' >> "$TRACE_ROOT/kprobe_events"; then
        echo 1 > "$TRACE_ROOT/events/kprobes/pte_alloc/enable"
        echo 'COS-TRACE PTE probe ready'
    fi
    echo 1 > "$TRACE_ROOT/tracing_on"
fi

CMD="/tmp/exp/exploit"
if [[ " $* " == *" kaslr_leak=1 "* ]]; then
    KASLR_BASE=`head -n 1 /proc/kallsyms | cut -d " " -f1`
    CMD="$CMD $KASLR_BASE"
fi

echo "running exploit, cmd='$CMD', ::EXPLOIT OUTPUT FROM HERE::"
su user -c "$CMD" || true
if [[ -e "$TRACE_ROOT/trace" ]]; then
    echo 0 > "$TRACE_ROOT/tracing_on"
    awk '
        /slub_discard:/ {
            discarded++
            cache = ""; slab = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^cache=/) { split($i, parts, "="); cache = parts[2] }
                if ($i ~ /^slab=/) { split($i, parts, "="); slab = parts[2] }
            }
            if (slab != "") freed[slab] = cache
        }
        /pte_alloc:/ {
            allocated++
            page = ""
            for (i = 1; i <= NF; i++)
                if ($i ~ /^page=/) { split($i, parts, "="); page = parts[2] }
            if (page != "" && page != "0x0" && (page in freed)) {
                reused++
                print "COS-TRACE reused slab cache=" freed[page] " page=" page
            }
        }
        END { print "COS-TRACE totals discarded=" discarded + 0 " pte=" allocated + 0 " reuse=" reused + 0 }
    ' "$TRACE_ROOT/trace" || true
    grep -E 'slub_discard:|pte_alloc:' "$TRACE_ROOT/trace" | tail -n 100 || true
fi
