#!/bin/bash
# End-to-end demo inside container:
# 1) baseline non-root chrt -> EPERM
# 2) start loader, register target tgid via bpftool
# 3) non-root chrt -> success (syscall return overridden)
set +e
cd /work/pocs/ch14-sched-fifo
useradd -M t14 2>/dev/null
echo "=== baseline: non-root chrt -f 50 ==="
su t14 -c 'chrt -f 50 $$; echo baseline_ret=$?'

echo ""
echo "=== loading BPF impersonator ==="
./build/ch14-sched-fifo >/tmp/imp.log 2>&1 &
L=$!
sleep 1

# Pre-start a victim that just sleeps, grab its pid
su t14 -c 'sleep 8 & echo $! > /tmp/victim.pid; wait' &
VP=$!
sleep 0.5
VICTIM=$(cat /tmp/victim.pid)
echo "victim pid=$VICTIM"

# register in map
MAP=$(bpftool map show 2>/dev/null | awk '/target_tgids/ {print $1}' | tr -d ':' | head -1)
echo "map_id=$MAP"
# little-endian 4 bytes
H=$(printf '%02x %02x %02x %02x' $((VICTIM & 0xff)) $(((VICTIM>>8)&0xff)) $(((VICTIM>>16)&0xff)) $(((VICTIM>>24)&0xff)))
bpftool map update id $MAP key hex $H value hex 01 00 00 00

echo ""
echo "=== now t14 calls chrt against the registered victim ==="
su t14 -c "chrt -f 50 $VICTIM; echo override_ret=\$?"

sleep 1
kill $L $VP 2>/dev/null
wait 2>/dev/null
echo ""
echo "=== ringbuf output from loader ==="
cat /tmp/imp.log
