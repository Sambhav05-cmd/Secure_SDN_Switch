# SDN Secure Switch — Snort + OpenFlow Auto-Blocking

A containerised SDN lab that automatically blocks attackers at the switch level using Snort IDS + OpenFlow.

## Architecture

```
Snort (host)
    ↓  writes alerts to /var/log/snort/alert
block-agent (container)
    ↓  tails alert file, writes "BLOCK <ip>" to named pipe /tmp/block_pipe
os-ken-ctrl (container)
    ↓  reads pipe, installs OFPFlowMod DROP via OpenFlow
OVS switch (container)
    ↓  drops all packets from attacker at wire speed (priority=200)
```
┌─────────────────────────────────────────────────────────┐
│                        HOST                             │
│   Snort ──► /var/log/snort/alert                        │
│   snort0 (mirror interface) ◄── OVS mirror              │
└─────────────────────────────────────────────────────────┘
│ bind mount
┌────────▼────────────────────────────────────────────────┐
│                   Docker Network (sdn-net)               │
│                                                          │
│  ┌─────────────┐    pipe    ┌──────────────┐            │
│  │ block-agent │ ─────────► │ os-ken-ctrl  │            │
│  └─────────────┘  /tmp/     │ (OpenFlow)   │            │
│                   block_pipe└──────┬───────┘            │
│                                    │ OF1.3              │
│  ┌─────────────────────────────────▼──────────────┐     │
│  │              OVS Switch (br0)                   │     │
│  │  veth1-br  veth2-br  veth3-br  veth4-br        │     │
│  └────┬────────────┬───────────┬──────────┬────────┘     │
│       │            │           │          │              │
│   node1        node2       node3      attacker          │
│  10.0.0.1    10.0.0.2    10.0.0.3    10.0.0.4          │
└─────────────────────────────────────────────────────────┘

## Flow Priority Ladder

| Priority | Rule        | Installed by  |
|----------|-------------|---------------|
| 200      | DROP src IP | block-agent   |
| 1        | FORWARD     | os-ken-ctrl   |
| 0        | Table-miss → Controller | os-ken-ctrl |

## Prerequisites

```bash
# Install dependencies on host
sudo apt-get install -y snort iproute2 docker.io docker-compose-plugin

# Verify
snort --version
docker --version
```

## Setup & Run

### 1. Clone the repo

```bash
git clone <your-repo-url>
cd sdn-project
```

### 2. Copy attacker folder from original project (if not present)

```bash
# If attacker/ directory is missing
cp -r ../attacker ./attacker
```

### 3. Run the lab

```bash
sudo bash run.sh
```

This will:
- Start all Docker containers (controller, OVS switch, nodes, attacker, block-agent)
- Wire all nodes via veth pairs into OVS
- Create a snort mirror port on OVS (snort0)
- Start Snort on the host listening on snort0
- Run a ping test to confirm the dataplane works

Expected at the end:
[✔] Ping successful! SDN dataplane is working.
[✔] Setup complete.

### 4. Run the attack

```bash
# In a separate terminal, watch block-agent in real time
docker logs -f block-agent

# Then in another terminal, run the attack
sudo bash attack.sh
```

## Verification

### Step 1 — Confirm Snort fired alerts

```bash
sudo cat /var/log/snort/alert
```

Expected output:
04/06-01:34:51.865582  [] [1:1000001:2] ICMP Flood Detected [] [Priority: 0] {ICMP} 10.0.0.4 -> 10.0.0.1
04/06-01:35:07.491663  [] [1:1000003:2] SSH Brute Force Detected [] [TCP} 10.0.0.4:2540 -> 10.0.0.1:22
...

### Step 2 — Confirm block-agent detected and acted

```bash
docker logs block-agent | grep -E "ALERT|BLOCKING|PIPE_SENT"
```

Expected output:
[INFO]    ALERT      10.0.0.4         Port Scan Detected
[WARNING] BLOCKING   10.0.0.4         reason: Port Scan Detected
[INFO]    PIPE_SENT  BLOCK 10.0.0.4

### Step 3 — Confirm controller installed the DROP flow

```bash
docker logs os-ken-ctrl | grep -i "blocker"
```

Expected output:
[blocker] Installing DROP for 10.0.0.4 on all switches
[blocker] DROP flow installed on dpid=0x... for 10.0.0.4

### Step 4 — Confirm DROP rule is in the OVS flow table (ground truth)

```bash
docker exec ovs-switch ovs-ofctl -O OpenFlow13 dump-flows br0
```

Expected output:
priority=200,ip,nw_src=10.0.0.4 actions=drop    ← attacker blocked
priority=0 actions=CONTROLLER:65535              ← table-miss

### Step 5 — Confirm packet counter is increasing (OVS actively dropping)

```bash
# Run twice, a few seconds apart — n_packets should increase
docker exec ovs-switch ovs-ofctl -O OpenFlow13 dump-flows br0 | grep "nw_src=10.0.0.4"
```

Expected:
cookie=0x0, duration=73s, n_packets=1113, n_bytes=82341, priority=200,ip,nw_src=10.0.0.4 actions=drop

### Step 6 — Confirm attacker is silently dropped (no response)

```bash
docker exec attacker ping -c 3 10.0.0.1
# Expected: 100% packet loss, no response (not "unreachable" — just silence)
```

### Step 7 — Confirm legitimate traffic still works

```bash
docker exec node1 ping -c 3 10.0.0.2
# Expected: success — only attacker is blocked, not the whole network
```

## Snort Rules (snort/local.rules)

| SID     | Rule                  | Threshold               |
|---------|-----------------------|-------------------------|
| 1000001 | ICMP Flood            | 10 packets/sec          |
| 1000002 | Port Scan             | 20 SYN packets / 3 sec  |
| 1000003 | SSH Brute Force       | 5 connections / 60 sec  |
| 1000004 | UDP Flood             | 50 packets/sec          |
| 1000005 | NULL Scan             | 5 packets / 3 sec       |
| 1000006 | FIN Scan              | 5 packets / 3 sec       |
| 1000007 | Xmas Scan             | 5 packets / 3 sec       |

## Configuration

Edit environment variables in `docker-compose.yml` under the `block-agent` service:

| Variable               | Default                  | Description                          |
|------------------------|--------------------------|--------------------------------------|
| `SNORT_ALERT_FILE`     | `/var/log/snort/alert`   | Path to Snort alert file             |
| `BLOCK_TIMEOUT_SECONDS`| `0`                      | 0 = permanent, >0 = auto-unblock     |
| `WHITELIST_IPS`        | (empty)                  | Comma-separated IPs to never block   |

Example — auto-unblock after 5 minutes:
```yaml
environment:
  BLOCK_TIMEOUT_SECONDS: "300"
  WHITELIST_IPS: "10.0.0.1,10.0.0.2"
```

## Teardown

```bash
# Stop everything
docker compose down

# Stop Snort on host
sudo pkill -f 'snort -i snort0'

# Clean up veth interfaces
for iface in snort0 snort-br veth1 veth2 veth3 veth1-br veth2-br veth3-br veth4 veth4-br; do
    sudo ip link del "$iface" 2>/dev/null || true
done
```

## Useful Commands

```bash
# Live Snort alerts
sudo tail -f /var/log/snort/alert

# Live block-agent activity
docker logs -f block-agent

# Watch flow table in real time
watch -n 1 "docker exec ovs-switch ovs-ofctl -O OpenFlow13 dump-flows br0"

# Check OVS mirror is working
docker exec ovs-switch ovs-vsctl list mirror

# Verify traffic is being mirrored to snort0
sudo tcpdump -i snort0 -c 20

# Controller logs
docker logs -f os-ken-ctrl
```
