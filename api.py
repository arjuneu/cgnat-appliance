import os

import time

import logging

from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, Response, Header, Query

from fastapi.middleware.cors import CORSMiddleware

from fastapi.staticfiles import StaticFiles

from fastapi.responses import HTMLResponse, FileResponse, Response

from pydantic import BaseModel, Field

from typing import Optional, Dict, Any, List

import config

from auth import (
    user_manager, 
    create_access_token, 
    get_current_user, 
    get_optional_user, 
    require_admin, 
    require_operator
)



logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

logger = logging.getLogger("api")



app = FastAPI(title="NAT AI Network Intelligence Assistant", version="1.3.0")





app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)



if os.path.exists("/opt/nat-ai-agent/static"):

    app.mount("/static", StaticFiles(directory="/opt/nat-ai-agent/static"), name="static")



class LoginRequest(BaseModel):

    username: str

    password: str



class ChangePasswordRequest(BaseModel):

    current_password: str

    new_password: str



class CreateUserRequest(BaseModel):

    username: str

    password: str

    role: Optional[str] = "operator"



class UpdateUserRoleRequest(BaseModel):
    role: str

class ResetPasswordRequest(BaseModel):

    new_password: str



class ChatRequest(BaseModel):

    query: str



class ForensicExportRequest(BaseModel):

    start_time: Optional[str] = None

    end_time: Optional[str] = None

    nat_src_ip: Optional[str] = None

    nat_src_port: Optional[int] = None

    src_ip: Optional[str] = None

    src_port: Optional[int] = None

    dst_ip: Optional[str] = None

    dst_port: Optional[int] = None

    protocol: Optional[str] = None

    router_ip: Optional[str] = None

    timezone: Optional[str] = "Asia/Kathmandu"

    limit: Optional[int] = 5000

    format: Optional[str] = "xlsx"

    with_radius: Optional[bool] = False

    enriched: Optional[bool] = False



collector = None

enricher = None

detector = None

engine = None

brain = None



@app.get("/", response_class=HTMLResponse)

def get_index():

    index_path = "/opt/nat-ai-agent/templates/index.html"

    if os.path.exists(index_path):

        with open(index_path, "r", encoding="utf-8") as f:

            return HTMLResponse(content=f.read(), media_type="text/html; charset=utf-8")

    return HTMLResponse(content="<h1>NAT AI Agent Running</h1>", media_type="text/html; charset=utf-8")



@app.get("/download/{filename}")

def download_file(filename: str, user_payload: Dict[str, Any] = Depends(get_current_user)):

    file_path = os.path.join("/opt/nat-ai-agent/downloads", filename)

    if os.path.exists(file_path):

        return FileResponse(

            path=file_path,

            filename=filename,

            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        )

    raise HTTPException(status_code=404, detail="File not found")



# --- AUTH & USER MANAGEMENT ---



@app.post("/api/v1/auth/login")

def login(req: LoginRequest):

    user = user_manager.authenticate(req.username, req.password)

    if user:

        token = create_access_token(user["username"], user["role"])

        return {

            "status": "success", 

            "token": token,

            "access_token": token,

            "username": user["username"],

            "role": user["role"]

        }

    raise HTTPException(status_code=401, detail="Invalid username or password")



@app.get("/api/v1/auth/me")

def get_me(user: Dict[str, Any] = Depends(get_current_user)):

    user_detail = user_manager.get_user(user["username"])

    if not user_detail:

        return {"status": "authenticated", "username": user["username"], "role": user.get("role", "operator")}

    return {

        "status": "authenticated", 

        "username": user_detail["username"], 

        "role": user_detail["role"],

        "created_at": user_detail.get("created_at"),

        "last_login": user_detail.get("last_login")

    }



@app.post("/api/v1/auth/change-password")

def change_password(req: ChangePasswordRequest, user: Dict[str, Any] = Depends(get_current_user)):

    try:

        user_manager.change_password(user["username"], req.current_password, req.new_password)

        return {"status": "success", "message": "Password updated successfully"}

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e))

    except Exception:

        raise HTTPException(status_code=500, detail="Failed to update password")



@app.get("/api/v1/users")

def get_users(admin: Dict[str, Any] = Depends(require_admin)):

    return {"status": "success", "users": user_manager.list_users()}



@app.post("/api/v1/users")

def create_new_user(req: CreateUserRequest, admin: Dict[str, Any] = Depends(require_admin)):

    try:

        new_user = user_manager.create_user(req.username, req.password, req.role or "operator")

        return {"status": "success", "user": new_user, "message": f"User '{req.username}' created successfully"}

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:

        raise HTTPException(status_code=500, detail="Failed to create user")



@app.put("/api/v1/users/{username}/reset-password")

def admin_reset_pwd(username: str, req: ResetPasswordRequest, admin: Dict[str, Any] = Depends(require_admin)):

    try:

        user_manager.admin_reset_password(username, req.new_password)

        return {"status": "success", "message": f"Password reset for user '{username}'"}

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e))

    except Exception:

        raise HTTPException(status_code=500, detail="Failed to reset password")



@app.put("/api/v1/users/{username}/role")
def update_user_role(username: str, req: UpdateUserRoleRequest, admin: Dict[str, Any] = Depends(require_admin)):
    try:
        user_manager.update_user_role(username, req.role, admin["username"])
        return {"status": "success", "message": f"Role updated to '{req.role}' for user '{username}'"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to update user role")

@app.delete("/api/v1/users/{username}")

def delete_user_account(username: str, admin: Dict[str, Any] = Depends(require_admin)):

    try:

        user_manager.delete_user(username, admin["username"])

        return {"status": "success", "message": f"User '{username}' deleted successfully"}

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e))

    except Exception:

        raise HTTPException(status_code=500, detail="Failed to delete user")



# --- TELEMETRY & FORENSICS ---



@app.post("/api/v1/chat")

def chat(req: ChatRequest, user: Dict[str, Any] = Depends(get_current_user)):

    if not brain:

        raise HTTPException(status_code=503, detail="AI Brain initializing")

    response_md = brain.process_message(req.query)

    return {"query": req.query, "response": response_md}



@app.get("/api/v1/summary")

def get_summary(user_payload: Optional[Dict[str, Any]] = Depends(get_optional_user)):

    if not engine:

        raise HTTPException(status_code=503, detail="Agent initializing")

    return engine.generate_executive_summary()



@app.get("/api/v1/telemetry")

def get_telemetry(

    minutes: Optional[int] = Query(None, ge=1, le=4320),

    start_time: Optional[str] = Query(None),

    end_time: Optional[str] = Query(None),

    user_payload: Optional[Dict[str, Any]] = Depends(get_optional_user)

):

    if not collector:

        raise HTTPException(status_code=503, detail="Metrics Collector initializing")

    mins = minutes if minutes is not None else (None if start_time and end_time else 5)

    return collector.get_full_telemetry(minutes=mins, start_time=start_time, end_time=end_time)



@app.get("/api/v1/server-health")

def get_server_health(

    minutes: Optional[int] = Query(None, ge=1, le=4320),

    start_time: Optional[str] = Query(None),

    end_time: Optional[str] = Query(None),

    user_payload: Optional[Dict[str, Any]] = Depends(get_optional_user)

):

    if not collector:

        raise HTTPException(status_code=503, detail="Metrics Collector initializing")

    mins = minutes if minutes is not None else (None if start_time and end_time else 5)

    return collector.get_full_telemetry(minutes=mins, start_time=start_time, end_time=end_time)



@app.get("/api/v1/export/routers")

def get_routers(user_payload: Optional[Dict[str, Any]] = Depends(get_optional_user)):

    if not collector:

        active_ips = [r.get("ip") for r in router_registry.list_routers() if r.get("ip")] if router_registry else []
        return {"routers": active_ips or ["192.0.2.1"]}

    return {"routers": collector.get_active_routers()}



@app.post("/api/v1/export/preview")

def preview_forensics(req: ForensicExportRequest, user_payload: Dict[str, Any] = Depends(get_current_user)):

    if not collector:

        raise HTTPException(status_code=503, detail="Collector initializing")

    

    filters = req.dict()

    limit = req.limit or 20

    with_radius = bool(req.with_radius)

    preview_data = collector.query_forensics(filters, limit=min(limit, 100), with_radius=with_radius)

    return {

        "status": "success",

        "data": preview_data

    }



@app.post("/api/v1/export/download")

def download_forensics_post(req: ForensicExportRequest, user_payload: Dict[str, Any] = Depends(get_current_user)):

    if not collector:

        raise HTTPException(status_code=503, detail="Collector initializing")

    

    filters = req.dict()

    limit = min(req.limit or 10000, 100000)

    fmt = req.format or "xlsx"

    enriched = bool(req.enriched)

    

    file_bytes = collector.export_forensic_records(filters, limit=limit, fmt=fmt, enriched=enriched)

    ts_now = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    

    if enriched:

        filename = f"NTA_Lawful_Interception_Report_{ts_now}.xlsx"

    else:

        filename = f"NAT_Forensic_Export_{ts_now}.xlsx"

    media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        

    return Response(

        content=file_bytes,

        media_type=media_type,

        headers={

            "Content-Disposition": f'attachment; filename="{filename}"',

            "Access-Control-Expose-Headers": "Content-Disposition"

        }

    )



class SubscriberEnrichRequest(BaseModel):

    subscribers: List[str]



@app.post("/api/v1/subscribers/enrich-radius")

def enrich_subscribers_endpoint(req: SubscriberEnrichRequest, user_payload: Dict[str, Any] = Depends(get_current_user)):

    try:

        from radius_client import radius_client

        from concurrent.futures import ThreadPoolExecutor

        results = {}

        now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lookup_list = [ip.strip() for ip in req.subscribers if ip and ip.strip()]

        

        with ThreadPoolExecutor(max_workers=10) as executor:

            def lookup(ip):

                data = radius_client.lookup_subscriber(ip, now_ts)

                return ip, data

            

            for ip, data in executor.map(lookup, lookup_list):

                if data:

                    cust = data.get("customer") or {}

                    sess = data.get("session") or {}

                    results[ip] = {

                        "username": cust.get("pppoe_username") or sess.get("username") or "N/A",

                        "name": cust.get("name") or "N/A",

                        "account_type": cust.get("account_type") or "Personal",

                        "contact": (cust.get("contact") or {}).get("primary") or "",

                        "address": cust.get("address") or ""

                    }

                else:

                    results[ip] = {"username": "N/A", "name": "N/A", "account_type": "N/A", "contact": "", "address": ""}

        return {"status": "ok", "data": results}

    except Exception as e:

        logger.error(f"Error enriching subscribers with RADIUS: {e}")

        return {"status": "error", "message": str(e), "data": {}}



@app.get("/api/v1/export/download")

def download_forensics_get(

    start_time: Optional[str] = Query(None),

    end_time: Optional[str] = Query(None),

    nat_src_ip: Optional[str] = Query(None),

    nat_src_port: Optional[int] = Query(None),

    src_ip: Optional[str] = Query(None),

    src_port: Optional[int] = Query(None),

    dst_ip: Optional[str] = Query(None),

    dst_port: Optional[int] = Query(None),

    protocol: Optional[str] = Query(None),

    router_ip: Optional[str] = Query(None),

    limit: Optional[int] = Query(10000),

    format: Optional[str] = Query("xlsx"),

    user_payload: Dict[str, Any] = Depends(get_current_user),

    enriched: Optional[bool] = Query(False)

):

    if not collector:

        raise HTTPException(status_code=503, detail="Collector initializing")

        

    filters = {

        "start_time": start_time,

        "end_time": end_time,

        "nat_src_ip": nat_src_ip,

        "nat_src_port": nat_src_port,

        "src_ip": src_ip,

        "src_port": src_port,

        "dst_ip": dst_ip,

        "dst_port": dst_port,

        "protocol": protocol,

        "router_ip": router_ip

    }

    fmt = format or "xlsx"

    max_limit = min(limit or 10000, 100000)

    

    file_bytes = collector.export_forensic_records(filters, limit=max_limit, fmt=fmt, enriched=bool(enriched))

    ts_now = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    

    if enriched:

        filename = f"NTA_Lawful_Interception_Report_{ts_now}.xlsx"

    else:

        filename = f"NAT_Forensic_Export_{ts_now}.xlsx"

    media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

        

    return Response(

        content=file_bytes,

        media_type=media_type,

        headers={

            "Content-Disposition": f'attachment; filename="{filename}"',

            "Access-Control-Expose-Headers": "Content-Disposition"

        }

    )



@app.get("/api/v1/health")

def health():

    return {"status": "ok", "service": "nat-ai-agent"}



# -------------------------------------------------------------



# -------------------------------------------------------------

# MikroTik Threat & Scanner Sync Endpoints

# -------------------------------------------------------------

try:

    import mikrotik_sync

except ImportError:

    mikrotik_sync = None



@app.get("/api/v1/threats/scanners")

def get_threat_scanners(

    minutes: Optional[int] = Query(15),

    min_ports: Optional[int] = Query(None),

    max_subscribers: Optional[int] = Query(None),

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not mikrotik_sync:

        raise HTTPException(status_code=500, detail="MikroTik sync module not available")

    try:

        cfg = mikrotik_sync.get_threat_config()

        candidates, subnet_groups = mikrotik_sync.find_scanner_and_flood_candidates(

            minutes=minutes, 

            min_ports=min_ports, 

            max_subscribers=max_subscribers

        )

        existing_items = mikrotik_sync.get_mikrotik_address_list()

        existing_addrs = {item["address"]: item for item in existing_items if "address" in item}

        

        for c in candidates:

            c["is_blocked_in_mikrotik"] = c["dst_ip"] in existing_addrs

            

        return {

            "status": "ok",

            "minutes": minutes,

            "sync_state": cfg,

            "min_ports_threshold": min_ports if min_ports is not None else cfg["min_ports"],

            "max_subscribers_threshold": max_subscribers if max_subscribers is not None else cfg["max_subscribers"],

            "flood_min_flows_threshold": cfg.get("flood_min_flows", 10000),

            "total_candidates": len(candidates),

            "candidates": candidates,

            "mikrotik_active_count": len(existing_items),

            "mikrotik_ip": mikrotik_sync.MIKROTIK_IP,

            "address_list": mikrotik_sync.ADDRESS_LIST_NAME

        }

    except Exception as e:

        logger.error(f"Error fetching threat scanners: {e}")

        raise HTTPException(status_code=500, detail=str(e))



@app.get("/api/v1/threats/sync/status")

def get_mikrotik_sync_status(

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not mikrotik_sync:

        raise HTTPException(status_code=500, detail="MikroTik sync module not available")

    cfg = mikrotik_sync.get_threat_config()

    return {

        "status": "ok",

        "sync_state": cfg,

        "min_ports_threshold": cfg["min_ports"],

        "max_subscribers_threshold": cfg["max_subscribers"],

        "flood_min_flows_threshold": cfg.get("flood_min_flows", 10000),

        "mikrotik_ip": mikrotik_sync.MIKROTIK_IP,

        "address_list": mikrotik_sync.ADDRESS_LIST_NAME

    }



class ThreatConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    enforcement_scope: Optional[str] = None

    subnet_min_hosts: Optional[int] = None

    subnet_min_ports: Optional[int] = None

    subnet_min_flows: Optional[int] = None

    min_ports: Optional[int] = None

    flood_min_flows: Optional[int] = None

    max_subscribers: Optional[int] = None

    private_ip_flow_threshold: Optional[int] = None

    private_ip_target_threshold: Optional[int] = None

    private_ip_port_threshold: Optional[int] = None

    port_exhaustion_threshold: Optional[int] = None

    destination_spike_flows: Optional[int] = None



@app.get("/api/v1/threats/config")

def get_threat_config_endpoint(

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not mikrotik_sync:

        raise HTTPException(status_code=500, detail="MikroTik sync module not available")

    return {

        "status": "ok",

        "config": mikrotik_sync.get_threat_config()

    }



@app.post("/api/v1/threats/config")

def update_threat_config_endpoint(

    req: ThreatConfigRequest,

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not mikrotik_sync:

        raise HTTPException(status_code=500, detail="MikroTik sync module not available")

    username = user_payload.get("username", "admin")

    updated_state = mikrotik_sync.set_threat_config(
        enabled=req.enabled,
        enforcement_scope=req.enforcement_scope,

        subnet_min_hosts=req.subnet_min_hosts,

        subnet_min_ports=req.subnet_min_ports,

        subnet_min_flows=req.subnet_min_flows,

        min_ports=req.min_ports,

        flood_min_flows=req.flood_min_flows,

        max_subscribers=req.max_subscribers,

        private_ip_flow_threshold=req.private_ip_flow_threshold,

        private_ip_target_threshold=req.private_ip_target_threshold,

        private_ip_port_threshold=req.private_ip_port_threshold,

        port_exhaustion_threshold=req.port_exhaustion_threshold,

        destination_spike_flows=req.destination_spike_flows,

        updated_by=username

    )

    logger.info(f"Threat configuration updated by {username}: {updated_state}")

    return {

        "status": "ok",

        "message": "Threat detection parameters successfully updated",

        "config": updated_state

    }



class AuditPruneRequest(BaseModel):

    dry_run: Optional[bool] = False

    min_ports: Optional[int] = None

    max_subscribers: Optional[int] = None



@app.post("/api/v1/threats/audit-prune")

def audit_and_prune_endpoint(

    req: AuditPruneRequest,

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not mikrotik_sync:

        raise HTTPException(status_code=500, detail="MikroTik sync module not available")

    try:

        report = mikrotik_sync.audit_and_prune_mikrotik(

            address_list=mikrotik_sync.ADDRESS_LIST_NAME,

            min_ports=req.min_ports,

            max_subscribers=req.max_subscribers,

            dry_run=bool(req.dry_run)

        )

        return report

    except Exception as e:

        logger.error(f"Error during audit & prune: {e}")

        raise HTTPException(status_code=500, detail=str(e))



class ToggleSyncRequest(BaseModel):

    enabled: bool



@app.post("/api/v1/threats/sync/toggle")
def toggle_mikrotik_sync(
    req: ToggleSyncRequest,
    user_payload: Dict[str, Any] = Depends(require_operator)
):
    username = user_payload.get("username", "operator")
    new_state = {}
    if threat_shield_engine:
        new_state = threat_shield_engine.set_threat_config({"enabled": req.enabled}, updated_by=username)
    if mikrotik_sync:
        try:
            new_state = mikrotik_sync.set_sync_state(req.enabled, updated_by=username)
        except Exception:
            pass

    action_str = "RESUMED (Active)" if req.enabled else "STOPPED (Paused)"
    logger.info(f"Threat Shield AI reasoning & router sync toggled to {action_str} by user {username}")

    return {
        "status": "ok",
        "enabled": req.enabled,
        "message": f"Threat Shield AI reasoning & address-list/prefix-list sync {action_str}",
        "sync_state": new_state
    }



try:

    import daily_threat_sync

except ImportError:

    daily_threat_sync = None



@app.post("/api/v1/threats/sync")

def trigger_mikrotik_sync(

    minutes: Optional[int] = Query(15),

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not mikrotik_sync:

        raise HTTPException(status_code=500, detail="MikroTik sync module not available")

    try:

        res = mikrotik_sync.sync_all(dry_run=False, minutes=minutes)

        return res

    except Exception as e:

        logger.error(f"Error during MikroTik sync: {e}")

        raise HTTPException(status_code=500, detail=str(e))



@app.post("/api/v1/threats/sync/daily")

def trigger_daily_threat_sync(

    hours: Optional[int] = Query(24),

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not daily_threat_sync:

        raise HTTPException(status_code=500, detail="Daily threat sync module not available")

    try:

        res = daily_threat_sync.run_daily_sync(dry_run=False, hours=hours)

        return res

    except Exception as e:

        logger.error(f"Error during daily threat sync: {e}")

        raise HTTPException(status_code=500, detail=str(e))



@app.get("/api/v1/threats/mikrotik-list")

def get_mikrotik_list_endpoint(

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not mikrotik_sync:

        raise HTTPException(status_code=500, detail="MikroTik sync module not available")

    try:

        items = mikrotik_sync.get_mikrotik_address_list()

        return {

            "status": "ok",

            "mikrotik_ip": mikrotik_sync.MIKROTIK_IP,

            "address_list": mikrotik_sync.ADDRESS_LIST_NAME,

            "total_entries": len(items),

            "entries": items,

            "sync_state": mikrotik_sync.get_threat_config()

        }

    except Exception as e:

        logger.error(f"Error fetching MikroTik address-list: {e}")

        raise HTTPException(status_code=500, detail=str(e))



class AddMikrotikAddressRequest(BaseModel):
    address: str
    comment: Optional[str] = "Manual entry"
    router_id: Optional[str] = "all"
    list_name: Optional[str] = None
    timeout: Optional[str] = None

@app.post("/api/v1/threats/mikrotik-list/add")
def add_mikrotik_address(
    req: AddMikrotikAddressRequest,
    user_payload: Dict[str, Any] = Depends(get_current_user)
):
    if not mikrotik_sync:
        raise HTTPException(status_code=500, detail="MikroTik sync module not available")
    target_list = req.list_name or mikrotik_sync.ADDRESS_LIST_NAME
    success, msg = mikrotik_sync.add_to_mikrotik(req.address, req.comment or "Manual entry", list_name=target_list)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "ok", "message": msg, "address": req.address}

class RemoveMikrotikAddressRequest(BaseModel):
    address: str
    router_id: Optional[str] = "all"
    list_name: Optional[str] = None



@app.post("/api/v1/threats/mikrotik-list/remove")

def remove_mikrotik_address(

    req: RemoveMikrotikAddressRequest,

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not mikrotik_sync:

        raise HTTPException(status_code=500, detail="MikroTik sync module not available")

    success, msg = mikrotik_sync.remove_from_mikrotik(req.address)

    if not success:

        raise HTTPException(status_code=400, detail=msg)

    return {"status": "ok", "message": msg, "address": req.address}



# --- MULTI-VENDOR ROUTER & FLEET MANAGEMENT (MIKROTIK / JUNIPER) ---



try:

    from router_registry import router_registry

    import threat_shield_engine

except ImportError:

    router_registry = None

    threat_shield_engine = None



class AddRouterRequest(BaseModel):
    router_id: Optional[str] = None
    name: Optional[str] = None
    vendor: Optional[str] = "mikrotik"
    ip: Optional[str] = None
    router_ip: Optional[str] = None
    port: Optional[int] = 22
    user: Optional[str] = None
    username: Optional[str] = "natlog"
    password: Optional[str] = None
    address_list: Optional[str] = "scanner"
    supported_lists: Optional[Any] = None
    role: Optional[str] = "cgnat"
    sync_enabled: Optional[bool] = True
    description: Optional[str] = ""

class UpdateRouterRequest(BaseModel):
    name: Optional[str] = None
    vendor: Optional[str] = None
    ip: Optional[str] = None
    router_ip: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    address_list: Optional[str] = None
    supported_lists: Optional[Any] = None
    role: Optional[str] = None
    sync_enabled: Optional[bool] = None
    description: Optional[str] = ""
class UpdateRouterRequest(BaseModel):

    name: Optional[str] = None

    vendor: Optional[str] = None

    ip: Optional[str] = None

    port: Optional[int] = None

    user: Optional[str] = None

    password: Optional[str] = None

    address_list: Optional[str] = None

    sync_enabled: Optional[bool] = None

    description: Optional[str] = None



@app.get("/api/v1/routers")

def list_routers(user_payload: Dict[str, Any] = Depends(get_current_user)):

    if not router_registry:

        raise HTTPException(status_code=500, detail="Router registry unavailable")

    return {"status": "ok", "routers": router_registry.list_routers(mask_passwords=True)}



@app.get("/api/v1/routers/discovered")

def get_discovered_ingress_routers(user_payload: Dict[str, Any] = Depends(get_current_user)):

    if not router_registry:

        raise HTTPException(status_code=500, detail="Router registry unavailable")

    registered_ips = {r.get("ip") for r in router_registry.list_routers(mask_passwords=True)}

    

    discovered = []

    try:

        if collector and collector.client:

            res = collector.client.query("""

                SELECT 

                    router_ip, 

                    count() AS total_flows_24h, 

                    min(timestamp) AS first_seen, 

                    max(timestamp) AS last_seen

                FROM nat_logs.translations

                WHERE timestamp >= now() - INTERVAL 24 HOUR

                  AND router_ip != '' AND router_ip != '0.0.0.0' AND router_ip != 'UNKNOWN'

                GROUP BY router_ip

                ORDER BY total_flows_24h DESC

            """)

            for row in res.result_rows:

                r_ip = str(row[0])

                flows = int(row[1])

                first_s = str(row[2])

                last_s = str(row[3])

                is_reg = r_ip in registered_ips

                discovered.append({

                    "ip": r_ip,

                    "flow_count_24h": flows,

                    "first_seen": first_s,

                    "last_seen": last_s,

                    "is_registered": is_reg

                })

    except Exception as e:

        logger.warning(f"Could not query discovered routers: {e}")

        

    return {

        "status": "ok",

        "discovered_routers": discovered,

        "unregistered_count": sum(1 for d in discovered if not d["is_registered"])

    }



@app.post("/api/v1/routers")

def add_router_endpoint(req: AddRouterRequest, user_payload: Dict[str, Any] = Depends(require_operator)):

    if not router_registry:

        raise HTTPException(status_code=500, detail="Router registry unavailable")

    data = req.dict(exclude_unset=True)

    ok, msg = router_registry.add_router(data)

    if not ok:

        raise HTTPException(status_code=400, detail=msg)

    return {"status": "ok", "message": msg}



@app.put("/api/v1/routers/{router_id}")

def update_router_endpoint(router_id: str, req: UpdateRouterRequest, user_payload: Dict[str, Any] = Depends(require_operator)):

    if not router_registry:

        raise HTTPException(status_code=500, detail="Router registry unavailable")

    data = req.dict(exclude_unset=True)

    ok, msg = router_registry.update_router(router_id, data)

    if not ok:

        raise HTTPException(status_code=400, detail=msg)

    return {"status": "ok", "message": msg}



@app.delete("/api/v1/routers/{router_id}")

def delete_router_endpoint(router_id: str, user_payload: Dict[str, Any] = Depends(require_operator)):

    if not router_registry:

        raise HTTPException(status_code=500, detail="Router registry unavailable")

    ok, msg = router_registry.delete_router(router_id)

    if not ok:

        raise HTTPException(status_code=400, detail=msg)

    return {"status": "ok", "message": msg}



@app.post("/api/v1/routers/{router_id}/test")

def test_router_endpoint(router_id: str, user_payload: Dict[str, Any] = Depends(require_operator)):

    if not router_registry:

        raise HTTPException(status_code=500, detail="Router registry unavailable")

    adapter = router_registry.get_adapter(router_id)

    if not adapter:

        raise HTTPException(status_code=404, detail=f"Router '{router_id}' not found")

    ok, msg, info = adapter.test_connection()

    return {"status": "ok" if ok else "error", "connected": ok, "message": msg, "info": info}



# --- RADIUS SUBSCRIBER LOOKUP TEST ---



class RadiusTestRequest(BaseModel):

    ip: str

    timestamp: Optional[str] = None



@app.post("/api/v1/radius/test")

def test_radius_lookup(req: RadiusTestRequest, user_payload: Dict[str, Any] = Depends(require_admin)):

    try:

        from radius_client import RadiusClient

        rc = RadiusClient()

        ts = req.timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        res = rc.lookup_subscriber(req.ip, ts)

        return {

            "status": "ok",

            "ip": req.ip,

            "timestamp": ts,

            "api_url": rc.api_url,

            "auth_type": rc.auth_type,

            "result": res

        }

    except Exception as e:

        logger.error(f"Error testing RADIUS: {e}")

        raise HTTPException(status_code=500, detail=str(e))



# --- MULTI-VENDOR THREAT FLEET ENDPOINTS ---



@app.get("/api/v1/threats/fleet-list")

def get_fleet_threat_list(

    router_id: Optional[str] = Query("all"),

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not threat_shield_engine:

        raise HTTPException(status_code=500, detail="Threat engine unavailable")

    entries = threat_shield_engine.threat_engine.get_fleet_threat_lists(router_id=router_id)

    return {

        "status": "ok",

        "router_filter": router_id,

        "total_entries": len(entries),

        "entries": entries,

        "sync_state": threat_shield_engine.get_threat_config()

    }



@app.post("/api/v1/threats/fleet-sync")

def trigger_fleet_sync(

    router_id: Optional[str] = Query("all"),

    minutes: Optional[int] = Query(15),

    user_payload: Dict[str, Any] = Depends(get_current_user)

):

    if not threat_shield_engine:

        raise HTTPException(status_code=500, detail="Threat engine unavailable")

    res = threat_shield_engine.threat_engine.sync_fleet(minutes=minutes, dry_run=False, router_id=router_id)

    return res



@app.post("/api/v1/threats/fleet-add")
def add_fleet_threat_endpoint(
    req: AddMikrotikAddressRequest,
    router_id: Optional[str] = Query("all"),
    user_payload: Dict[str, Any] = Depends(get_current_user)
):
    if not threat_shield_engine:
        raise HTTPException(status_code=500, detail="Threat engine unavailable")
    
    target_router = req.router_id if (req.router_id and req.router_id != "all") else router_id
    ok, msg = threat_shield_engine.threat_engine.add_threat_to_fleet(
        req.address, 
        req.comment or "Manual fleet entry", 
        router_id=target_router,
        list_name=req.list_name,
        timeout=req.timeout
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    try:
        from ai_threat_classifier import add_targets_to_local_cache
        add_targets_to_local_cache([{
            "target": req.address,
            "threat_type": "MANUAL_BLOCK",
            "rationale": f"Manual block on {target_router} (list: {req.list_name or 'default'})"
        }], updated_by=f"operator_{user_payload.get('sub', 'admin')}")
    except Exception:
        pass

    return {"status": "ok", "message": msg, "address": req.address, "router_id": target_router, "list_name": req.list_name}

@app.post("/api/v1/threats/fleet-remove")
def remove_fleet_threat_endpoint(
    req: RemoveMikrotikAddressRequest,
    router_id: Optional[str] = Query("all"),
    user_payload: Dict[str, Any] = Depends(get_current_user)
):
    if not threat_shield_engine:
        raise HTTPException(status_code=500, detail="Threat engine unavailable")
    
    target_router = req.router_id if (req.router_id and req.router_id != "all") else router_id
    ok, msg = threat_shield_engine.threat_engine.remove_threat_from_fleet(
        req.address, 
        router_id=target_router,
        list_name=req.list_name
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    try:
        from ai_threat_classifier import remove_target_from_local_cache
        remove_target_from_local_cache(req.address)
    except Exception:
        pass

    return {"status": "ok", "message": msg, "address": req.address, "router_id": target_router}

# --- CONFIG VAULT & APPLIANCE SETTINGS (ADMIN ONLY) ---



try:

    from config_vault import ConfigVault

    _vault = ConfigVault()

except Exception:

    _vault = None



@app.get("/api/v1/vault/config")

def get_vault_config(user_payload: Dict[str, Any] = Depends(require_admin)):

    if not _vault:

        raise HTTPException(status_code=500, detail="Config vault module unavailable")

    return {

        "status": "ok",

        "key_path": _vault.key_path,

        "vault_path": _vault.vault_path,

        "config": _vault.get_all_masked()

    }



class VaultUpdateRequest(BaseModel):

    key: str

    value: str



@app.post("/api/v1/vault/update")

def update_vault_key(req: VaultUpdateRequest, user_payload: Dict[str, Any] = Depends(require_admin)):

    if not _vault:

        raise HTTPException(status_code=500, detail="Config vault module unavailable")

    k = req.key.strip()

    v = req.value.strip()

    if not k:

        raise HTTPException(status_code=400, detail="Key name cannot be empty")

    

    _vault.set(k, v)

    logger.info(f"Vault key '{k}' updated by admin {user_payload.get('username', 'admin')}")

    return {

        "status": "ok",

        "message": f"Parameter '{k}' safely encrypted and updated in appliance vault.",

        "key": k,

        "masked_value": ConfigVault.mask_value(k, v)

    }









# =====================================================================
# AI KEY VAULT & REAL-TIME AI THREAT CLASSIFIER API ENDPOINTS
# =====================================================================
import os
import json
import time

try:
    from ai_key_vault import key_vault
except ImportError:
    key_vault = None

class AddAIKeyRequest(BaseModel):
    name: str = ""
    key: str

class UpdateAIKeyRequest(BaseModel):
    name: Optional[str] = None
    direction: Optional[str] = None # 'up' or 'down'

class ReorderAIKeysRequest(BaseModel):
    ordered_ids: List[str]

class TestAIKeyRequest(BaseModel):
    key_id: Optional[str] = None
    raw_key: Optional[str] = None

@app.get("/api/v1/ai/keys")
def get_ai_keys(admin: Dict[str, Any] = Depends(require_admin)):
    if not key_vault:
        raise HTTPException(status_code=500, detail="AI Key Vault not available")
    return {"status": "ok", "keys": key_vault.get_keys(masked=True)}

@app.post("/api/v1/ai/keys")
def add_ai_key(req: AddAIKeyRequest, admin: Dict[str, Any] = Depends(require_admin)):
    if not key_vault:
        raise HTTPException(status_code=500, detail="AI Key Vault not available")
    raw = req.key.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Key cannot be empty")
    entry = key_vault.add_key(req.name, raw)
    return {"status": "ok", "message": "Key added to encrypted vault", "key_id": entry["id"]}

@app.put("/api/v1/ai/keys/{key_id}")
def update_ai_key(key_id: str, req: UpdateAIKeyRequest, admin: Dict[str, Any] = Depends(require_admin)):
    if not key_vault:
        raise HTTPException(status_code=500, detail="AI Key Vault not available")
    
    if req.name is not None:
        if not key_vault.rename_key(key_id, req.name):
            raise HTTPException(status_code=404, detail="Key not found")
        return {"status": "ok", "message": "Key renamed successfully"}
    
    if req.direction in ["up", "down"]:
        if not key_vault.move_key(key_id, req.direction):
            raise HTTPException(status_code=400, detail="Cannot move key in that direction")
        return {"status": "ok", "message": f"Key moved {req.direction}"}
        
    raise HTTPException(status_code=400, detail="No valid update field provided")

@app.put("/api/v1/ai/keys/reorder")
def reorder_ai_keys(req: ReorderAIKeysRequest, admin: Dict[str, Any] = Depends(require_admin)):
    if not key_vault:
        raise HTTPException(status_code=500, detail="AI Key Vault not available")
    key_vault.reorder_keys(req.ordered_ids)
    return {"status": "ok", "message": "Keys reordered successfully"}

@app.delete("/api/v1/ai/keys/{key_id}")
def delete_ai_key(key_id: str, admin: Dict[str, Any] = Depends(require_admin)):
    if not key_vault:
        raise HTTPException(status_code=500, detail="AI Key Vault not available")
    if not key_vault.delete_key(key_id):
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "ok", "message": "Key removed from vault"}

@app.post("/api/v1/ai/keys/test")
def test_ai_key(req: TestAIKeyRequest, admin: Dict[str, Any] = Depends(require_admin)):
    if not key_vault:
        raise HTTPException(status_code=500, detail="AI Key Vault not available")
    
    raw = req.raw_key
    if not raw and req.key_id:
        for k in key_vault._read_vault():
            if k.get("id") == req.key_id:
                raw = k.get("key")
                break
    
    if not raw:
        raise HTTPException(status_code=400, detail="No key token provided or found")
    
    success, msg = key_vault.test_key(raw)
    return {"success": success, "message": msg}

@app.get("/api/v1/threats/ai-feed")
def get_ai_threat_feed(user_payload: Dict[str, Any] = Depends(get_current_user)):
    feed_path = "/opt/nat-ai-agent/data/latest_ai_threats.json"
    if not os.path.exists(feed_path):
        # Return fallback empty structure
        return {
            "status": "ok",
            "data": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_window_hours": 0.25,
                "account_used": "Pending First Scan",
                "total_evaluated": 0,
                "blocked_count": 0,
                "verdicts": []
            }
        }
    try:
        with open(feed_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {"status": "ok", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read AI threat feed: {str(e)}")

@app.post("/api/v1/threats/sync/daily")
def trigger_daily_ai_sync(hours: float = 24.0, user_payload: Dict[str, Any] = Depends(require_operator)):
    try:
        import subprocess
        res = subprocess.run(
            ["/opt/nat-ai-agent/venv/bin/python3", "/opt/nat-ai-agent/ai_threat_classifier.py", str(hours)],
            capture_output=True,
            text=True,
            timeout=120
        )
        return {
            "status": "ok",
            "message": "AI Threat Classification completed",
            "stdout": res.stdout[-300:],
            "stderr": res.stderr[-300:] if res.stderr else ""
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Scan execution error: {str(e)}")


# =====================================================================
# SYSTEM MANAGEMENT: DISCORD & BULK VAULT CONFIG ENDPOINTS
# =====================================================================

class TestDiscordRequest(BaseModel):
    webhook_url: Optional[str] = None

@app.post("/api/v1/discord/test")
def test_discord_webhook(req: TestDiscordRequest, user_payload: Dict[str, Any] = Depends(require_operator)):
    url = req.webhook_url
    if not url and _vault:
        url = _vault.get("DISCORD_WEBHOOK_URL", "")
    if not url:
        url = DISCORD_WEBHOOK_URL
    if not url:
        raise HTTPException(status_code=400, detail="No Discord Webhook URL provided or configured")
    
    payload = {
        "embeds": [{
            "title": "🔔 CGNAT Appliance Test Notification",
            "description": "Discord Webhook connection verified successfully from CGNAT Appliance System Management.",
            "color": 3066993,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }]
    }
    try:
        import requests
        r = requests.post(url, json=payload, timeout=8)
        if r.status_code in [200, 204]:
            return {"status": "ok", "message": "Test notification sent successfully to Discord!"}
        return {"status": "error", "message": f"Discord returned HTTP {r.status_code}: {r.text[:100]}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reach Discord: {str(e)}")

class BulkVaultUpdateRequest(BaseModel):
    settings: Dict[str, Any]

@app.post("/api/v1/vault/bulk-update")
def bulk_update_vault(req: BulkVaultUpdateRequest, user_payload: Dict[str, Any] = Depends(require_operator)):
    if not _vault:
        raise HTTPException(status_code=500, detail="Config vault module unavailable")
    
    is_admin = (user_payload.get("role") == "admin")
    saved_count = 0
    radius_updated = False
    
    for k, v in req.settings.items():
        k_clean = k.strip()
        v_clean = str(v).strip()
        if v_clean == "" or v_clean.startswith("****"):
            continue
            
        # Role-based restriction: Only admin can modify RADIUS or other core secrets
        if "RADIUS" in k_clean and not is_admin:
            raise HTTPException(status_code=403, detail="Only administrators can configure RADIUS settings.")
            
        if not is_admin and not (k_clean.startswith("DISCORD_") or k_clean.startswith("ROUTER_PASS_")):
            raise HTTPException(status_code=403, detail=f"Permission denied to modify setting '{k_clean}'. Admin role required.")
            
        _vault.set(k_clean, v_clean)
        saved_count += 1
        if "RADIUS" in k_clean:
            radius_updated = True
            
    if radius_updated and is_admin:
        try:
            from radius_client import radius_client
            radius_client.reload_config()
            radius_client.cache.clear()
            logger.info("RADIUS client reloaded and cache invalidated following vault settings update.")
        except Exception as ex:
            logger.warning(f"Could not auto-reload radius client: {ex}")
            
    return {
        "status": "ok",
        "message": f"Successfully updated {saved_count} configuration parameters in encrypted appliance vault.",
        "saved_count": saved_count
    }
