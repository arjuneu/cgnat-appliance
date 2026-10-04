
import clickhouse_connect

client = clickhouse_connect.get_client(host='127.0.0.1', port=8123, database='nat_logs')
res = client.query("SELECT router_ip, count() FROM nat_logs.translations WHERE timestamp >= now() - INTERVAL 1 HOUR GROUP BY router_ip")
print("Active routers last hour:")
for r in res.result_rows:
    print(" ", r)

res_all = client.query("SELECT DISTINCT router_ip FROM nat_logs.translations LIMIT 20")
print("Distinct routers all-time:")
for r in res_all.result_rows:
    print(" ", r)
