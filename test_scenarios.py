
import time
from test_forensics import query_forensics

# Scenario 1: Specific time range + NAT IP
f1 = {
    "start_time": "2026-09-08 17:30:00",
    "end_time": "2026-09-08 17:40:00",
    "nat_src_ip": "203.0.113.103",
    "protocol": "TCP",
    "limit": 5
}
t0 = time.time()
r1 = query_forensics(f1)
print(f"Scenario 1 (Time + NAT IP + TCP): total = {r1['total_count']}, time = {r1['query_time_ms']}ms, count = {r1['returned_count']}")
for row in r1['rows'][:2]:
    print("  ", row)

# Scenario 2: Subscriber IP
f2 = {
    "src_ip": "100.66.255.108",
    "start_time": "2026-09-09 14:00:00",
    "end_time": "2026-09-09 14:35:00",
    "limit": 5
}
r2 = query_forensics(f2)
print(f"Scenario 2 (Subscriber IP + Time): total = {r2['total_count']}, time = {r2['query_time_ms']}ms, count = {r2['returned_count']}")

# Scenario 3: Destination port 443 + Router
f3 = {
    "dst_port": 443,
    "router_ip": "203.0.113.1",
    "start_time": "2026-09-09 14:30:00",
    "end_time": "2026-09-09 14:35:00",
    "limit": 5
}
r3 = query_forensics(f3)
print(f"Scenario 3 (Dst Port + Router + Time): total = {r3['total_count']}, time = {r3['query_time_ms']}ms, count = {r3['returned_count']}")
