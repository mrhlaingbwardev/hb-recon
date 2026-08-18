import os
import shutil
import platform
import logging

IS_WINDOWS = platform.system() == 'Windows'

def find_tool(tool_name: str) -> str:
    """Find tool in PATH, ~/go/bin, or /usr/bin"""
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path
    
    go_path = os.path.expanduser(f"~/go/bin/{tool_name}")
    if os.path.exists(go_path):
        return go_path
    
    usr_path = f"/usr/bin/{tool_name}"
    if os.path.exists(usr_path):
        return usr_path
    
    return tool_name

class Config:
    TIMEOUT_SECONDS = 300
    KATANA_DEPTH = 3
    KATANA_CONCURRENCY = 15
    
    # Tool Paths
    SUBFINDER = find_tool("subfinder")
    HTTPX = find_tool("httpx") or find_tool("httpx-toolkit")
    KATANA = find_tool("katana")
    GF = find_tool("gf")
    WHATWEB = find_tool("whatweb")

def setup_logging(debug: bool = False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )
