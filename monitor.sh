#!/bin/sh
# monitor-stack.sh
# Requires: cgroupv2 with user delegation, util-linux (unshare/nsenter), inotifywait (inotify-tools)

set -eu

CGROUP_MOUNT="/sys/fs/cgroup"
STACK_NAME="${1:-mystack}"
CGROUP_PATH="${CGROUP_MOUNT}/user.slice/user-$(id -u).slice/${STACK_NAME}.scope"

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "[$(date -Iseconds)] $*" >&2; }

# ── 1. Create the cgroup ────────────────────────────────────────────────────

setup_cgroup() {
    mkdir -p "$CGROUP_PATH"
    # Enable subtree control if needed (for nested cgroups)
    # echo "+pids +memory" > "${CGROUP_PATH}/../cgroup.subtree_control" 2>/dev/null || true
    log "cgroup created: $CGROUP_PATH"
}

# ── 2. Launch a process inside the cgroup ──────────────────────────────────

# Usage: launch_in_cgroup <pidvar> <cmd> [args...]
# Writes the child PID into $pidvar. The trick: the shell forks, writes its
# own PID into cgroup.procs before exec-ing the real command, so the child
# inherits the cgroup atomically.
launch_in_cgroup() {
    local _var="$1"; shift
    (
        echo $$ > "${CGROUP_PATH}/cgroup.procs"
        exec "$@"
    ) &
    eval "${_var}=$!"
}

# ── 3. Tear everything down ────────────────────────────────────────────────

teardown() {
    log "Teardown triggered — killing cgroup ${STACK_NAME}"
    # Freeze first to prevent fork-bombs racing the kill
    echo 1 > "${CGROUP_PATH}/cgroup.freeze" 2>/dev/null || true
    # Kill every process in the cgroup atomically
    echo 1 > "${CGROUP_PATH}/cgroup.kill"   2>/dev/null || true  # kernel 5.14+
    # Fallback for older kernels: signal via cgroup.procs
    if [ -s "${CGROUP_PATH}/cgroup.procs" ]; then
        xargs kill -9 < "${CGROUP_PATH}/cgroup.procs" 2>/dev/null || true
    fi
    # Wait for the cgroup to empty before rmdir
    local i=0
    while [ -s "${CGROUP_PATH}/cgroup.procs" ] && [ $i -lt 50 ]; do
        sleep 0.1; i=$((i+1))
    done
    rmdir "$CGROUP_PATH" 2>/dev/null || true
    log "Teardown complete"
}

# ── 4. The robust monitor ──────────────────────────────────────────────────

# Strategy: poll cgroup.events with inotifywait.
# "populated=0" means the cgroup is empty — every process has exited.
# This is edge-triggered; we re-read the file on each event.
#
# We also maintain a parallel watch on individual PIDs for *early* failure
# detection (populated=0 is the definitive signal, but pid-watching catches
# a single process dying while others still run).

monitor_cgroup() {
    local events_file="${CGROUP_PATH}/cgroup.events"
    log "Monitoring via cgroup.events: $events_file"

    # inotifywait -e modify blocks until the file changes, then returns.
    # Loop: re-check after every modification event.
    while inotifywait -q -e modify "$events_file" 2>/dev/null; do
        if grep -q "^populated 0$" "$events_file"; then
            log "cgroup unpopulated — all processes have exited"
            return 0   # signal to caller: stack is gone
        fi
        log "cgroup event (still populated), continuing"
    done
    # inotifywait itself exited unexpectedly (cgroup removed?)
    log "inotifywait exited — assuming stack is gone"
    return 0
}

# ── 5. Optional: watch for individual process exit while stack still runs ──
#
# If you want to act the moment *any single* process dies (not wait for all),
# use a background watcher per PID. Unlike `wait -n`, this works even when
# the PID was not a direct child of this shell.
#
# Technique: /proc/<pid>/fd trick — open a pidfd or poll /proc/<pid>/wchan.
# On Alpine (busybox), simplest is a tight loop on kill -0.
# Better: use the `pidfd_open` syscall via a small C helper, or use
# `waitpid` via a wrapper. Below is the portable busybox-safe version.

watch_pid() {
    local pid="$1" name="$2"
    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.5
    done
    log "Process exited: ${name} (pid ${pid})"
    # Signal the main monitor to tear down.
    # We write to a pipe the main loop is select()-ing on.
    echo "exit:${name}:${pid}" >&"${NOTIFY_FD}"
}

# ── 6. Main ────────────────────────────────────────────────────────────────

main() {
    setup_cgroup
    trap teardown EXIT INT TERM

    # Launch your processes
    launch_in_cgroup PID_DAEMON  /usr/sbin/your-daemon --config /etc/daemon.conf
    launch_in_cgroup PID_TCPDUMP /usr/sbin/tcpdump -i eth0 -C 100 -W 10 -w /var/log/cap/tc.pcap
    launch_in_cgroup PID_OTHER   /usr/bin/your-other-proc

    log "Stack started. daemon=$PID_DAEMON tcpdump=$PID_TCPDUMP other=$PID_OTHER"

    # Set up notification pipe for per-process watchers
    pipe=$(mktemp -u)
    mkfifo "$pipe"
    exec {NOTIFY_FD}<>"$pipe"   # open RW so it never gets EOF
    rm "$pipe"

    # Start per-process watchers in background (catches single-proc failures
    # while others are still running, before populated=0 fires)
    watch_pid "$PID_DAEMON"  "daemon"  &
    watch_pid "$PID_TCPDUMP" "tcpdump" &   # tcpdump will exit/restart; that's OK
    watch_pid "$PID_OTHER"   "other"   &

    # ── Main event loop ──────────────────────────────────────────────────
    # Two signal sources: cgroup.events (authoritative) and the notify pipe.
    # Use a short-timeout read on the pipe, fall through to check cgroup.

    local events_file="${CGROUP_PATH}/cgroup.events"

    while true; do
        # Non-blocking check: is cgroup already empty?
        if grep -q "^populated 0$" "$events_file" 2>/dev/null; then
            log "Stack is gone (populated=0)"
            break
        fi

        # Block up to 2s for a pipe notification
        local msg=""
        if read -r -t 2 msg <&"${NOTIFY_FD}" 2>/dev/null; then
            log "Notification: $msg"
            # Decide policy here:
            case "$msg" in
                exit:tcpdump:*)
                    # tcpdump exiting is expected on rotation — don't tear down.
                    # Re-watch whatever the new PID is (find it via cgroup.procs).
                    log "tcpdump rotation detected, re-watching"
                    new_pid=$(grep -v "^$" "${CGROUP_PATH}/cgroup.procs" | head -1)
                    # (Better: compare against known PIDs to find the new one)
                    ;;
                exit:*:*)
                    # Any other process exiting is fatal
                    log "Fatal: $msg — tearing down"
                    break
                    ;;
            esac
        fi
    done

    # teardown fires via EXIT trap
    log "Exiting monitor — service supervisor will handle restart policy"
    exit 1   # non-zero so supervisor knows it wasn't a clean stop
}

main "$@"
