#!/usr/bin/env python3
"""SentriX — AI-Driven SOC Platform — Entry Point"""
import uvicorn
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("=" * 60)
    print("  SentriX — AI-Driven SOC Platform")
    print("  Applied Science Private University")
    print("=" * 60)
    print("  Starting server on http://localhost:8000")
    print("  API Docs: http://localhost:8000/docs")
    print("  Default Login: admin / admin123")
    print("=" * 60)

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
