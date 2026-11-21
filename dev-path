from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import json
import asyncio
import secrets
import os
from datetime import datetime

from models.topology import NetworkTopology
from models.path import PacketPath
from parsers.cisco_parser import CiscoParser
from parsers.juniper_parser import JuniperParser
from engine.topology_builder import TopologyBuilder
from engine.path_finder import PathFinder
from engine.impact_analyzer import ImpactAnalyzer

app = FastAPI(
    title="Network Path Analyzer API",
    description="API for network topology analysis and path simulation",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()
# Configure credentials through environment variables. Never commit secrets.
ADMIN_USERNAME = os.getenv("NETWORK_ANALYZER_USERNAME")
ADMIN_PASSWORD = os.getenv("NETWORK_ANALYZER_PASSWORD")

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication credentials are not configured on the server.",
        )
    is_correct_username = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    is_correct_password = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

topology_builder = TopologyBuilder()
current_topology: Optional[NetworkTopology] = None
path_finder: Optional[PathFinder] = None
impact_analyzer: Optional[ImpactAnalyzer] = None

class PathRequest(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str = "ip"
    source_port: Optional[int] = None
    destination_port: Optional[int] = None

class ImpactAnalysisRequest(BaseModel):
    device_name: str
    config_diff: str
    test_flows: List[Dict[str, str]]

class DeviceConfig(BaseModel):
    hostname: str
    device_type: str
    config_content: str

@app.get("/")
async def root():
    return {"message": "Network Path Analyzer API", "version": "1.0.0"}

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "topology_loaded": current_topology is not None,
        "device_count": len(current_topology.devices) if current_topology else 0
    }

@app.post("/api/v1/ingest")
async def ingest_configurations(configs: List[DeviceConfig]):
    """Ingest device configurations and build topology"""
    global current_topology, path_finder, impact_analyzer
    try:
        topology_builder = TopologyBuilder()
        for config in configs:
            if config.device_type.lower().startswith('cisco'):
                parser = CiscoParser(config.config_content, config.hostname)
            elif config.device_type.lower().startswith('juniper'):
                parser = JuniperParser(config.config_content, config.hostname)
            else:
                raise HTTPException(status_code=400, detail=f"Unsupported device type: {config.device_type}")
            device = parser.parse()
            topology_builder.add_device(device)
        current_topology = topology_builder.build_topology()
        path_finder = PathFinder(current_topology)
        impact_analyzer = ImpactAnalyzer(current_topology)
        validation = topology_builder.validate_topology()
        return {
            "status": "success",
            "message": f"Successfully ingested {len(configs)} device configurations",
            "topology_stats": {
                "devices": len(current_topology.devices),
                "links": len(current_topology.links),
                "validation": validation
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest configurations: {str(e)}")

@app.post("/api/v1/ingest/upload")
async def upload_configurations(files: List[UploadFile] = File(...), username: str = Depends(authenticate)):
    """Upload configuration files"""
    try:
        configs = []
        for file in files:
            content = await file.read()
            config_text = content.decode('utf-8')
            device_type = "cisco_ios"
            if "juniper" in file.filename.lower() or "srx" in file.filename.lower():
                device_type = "juniper_srx"
            hostname = file.filename.split('.')[0]
            configs.append(DeviceConfig(hostname=hostname, device_type=device_type, config_content=config_text))
        return await ingest_configurations(configs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload configurations: {str(e)}")

@app.get("/api/v1/topology")
async def get_topology(username: str = Depends(authenticate)):
    """Get network topology"""
    if not current_topology:
        raise HTTPException(status_code=404, detail="No topology loaded. Please ingest configurations first.")
    return {
        "topology": current_topology.to_dict(),
        "stats": {"devices": len(current_topology.devices), "links": len(current_topology.links)}
    }

@app.get("/api/v1/devices")
async def get_devices():
    """Get all devices in the topology"""
    if not current_topology:
        raise HTTPException(status_code=404, detail="No topology loaded")
    devices = []
    for name, device in current_topology.devices.items():
        devices.append({
            "hostname": device.hostname,
            "device_type": device.device_type,
            "management_ip": device.management_ip,
            "interface_count": len(device.interfaces),
            "route_count": len(device.routes),
            "bgp_neighbors": len(device.bgp_neighbors),
            "ospf_neighbors": len(device.ospf_neighbors)
        })
    return {"devices": devices}

@app.get("/api/v1/devices/{device_name}")
async def get_device_details(device_name: str):
    """Get detailed information about a specific device"""
    if not current_topology:
        raise HTTPException(status_code=404, detail="No topology loaded")
    device = current_topology.get_device(device_name)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_name} not found")
    return {"device": device.dict()}

@app.post("/api/v1/path")
async def calculate_path(request: PathRequest, username: str = Depends(authenticate)):
    """Calculate packet path between source and destination"""
    if not path_finder:
        raise HTTPException(status_code=404, detail="No topology loaded. Please ingest configurations first.")
    try:
        path = path_finder.find_path(request.source_ip, request.destination_ip, request.protocol, request.source_port, request.destination_port)
        return {"path": path.dict(), "summary": path.to_summary()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate path: {str(e)}")

@app.post("/api/v1/impact")
async def analyze_impact(request: ImpactAnalysisRequest, username: str = Depends(authenticate)):
    """Analyze impact of configuration changes"""
    if not impact_analyzer:
        raise HTTPException(status_code=404, detail="No topology loaded. Please ingest configurations first.")
    try:
        analysis = impact_analyzer.analyze_config_change(request.device_name, request.config_diff, request.test_flows)
        return {"analysis": analysis}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze impact: {str(e)}")

@app.get("/api/v1/links")
async def get_links():
    """Get all links in the topology"""
    if not current_topology:
        raise HTTPException(status_code=404, detail="No topology loaded")
    links = []
    for link in current_topology.links:
        links.append({
            "id": link.link_id,
            "source": {"device": link.source_device, "interface": link.source_interface},
            "target": {"device": link.target_device, "interface": link.target_interface},
            "type": link.link_type, "cost": link.cost, "bandwidth": link.bandwidth, "delay": link.delay
        })
    return {"links": links}

@app.get("/api/v1/graph")
async def get_graph_data():
    """Get topology data formatted for graph visualization"""
    if not current_topology:
        raise HTTPException(status_code=404, detail="No topology loaded")
    nodes = []
    for name, device in current_topology.devices.items():
        nodes.append({
            "id": name, "label": device.hostname, "type": device.device_type,
            "management_ip": device.management_ip, "interface_count": len(device.interfaces),
            "route_count": len(device.routes)
        })
    edges = []
    for link in current_topology.links:
        edges.append({
            "id": link.link_id, "source": link.source_device, "target": link.target_device,
            "label": f"{link.source_interface} - {link.target_interface}", "type": link.link_type,
            "cost": link.cost, "bandwidth": link.bandwidth
        })
    return {"nodes": nodes, "edges": edges}

@app.post("/api/v1/paths/batch")
async def calculate_batch_paths(requests: List[PathRequest]):
    """Calculate multiple paths in batch"""
    if not path_finder:
        raise HTTPException(status_code=404, detail="No topology loaded")
    results = []
    for request in requests:
        try:
            path = path_finder.find_path(request.source_ip, request.destination_ip, request.protocol, request.source_port, request.destination_port)
            results.append({"request": request.dict(), "path": path.dict(), "summary": path.to_summary()})
        except Exception as e:
            results.append({"request": request.dict(), "error": str(e)})
    return {"results": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
