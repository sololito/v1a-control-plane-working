#!/usr/bin/env python3
"""Startup script for the ODIVORA Home Connectivity server."""
import os
import socket
from app.config import get_settings

settings = get_settings()


def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        # Create a socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def main():
    local_ip = get_local_ip()
    host = os.getenv("HOST", settings.host)
    port = int(os.getenv("PORT", settings.port))
    
    print(f"ODIVORA Home Connectivity Server")
    print(f"Local: http://127.0.0.1:{port}")
    print(f"Network: http://{local_ip}:{port}")
    print(f"Docs: http://{local_ip}:{port}/docs")
    print(f"Health: http://{local_ip}:{port}/health")
    print("\nPress Ctrl+C to stop\n")
    
    import uvicorn
    uvicorn.run("app.main:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    main()
