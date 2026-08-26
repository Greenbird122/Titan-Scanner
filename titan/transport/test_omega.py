#!/usr/bin/env python3
"""Quick test — run this in WSL directly, not through freebuff.

Usage:
    cd ~/titan-lab
    source venv/bin/activate
    python titan/transport/test_omega.py
"""

import asyncio
import sys
import os

# Add titan-lab to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


async def test_transports():
    from titan.transport import TransportRegistry, AttackRequest
    from titan.transport.base import RequestMethod

    print("=" * 60)
    print("  TITAN OMEGA — Transport Layer Test")
    print("=" * 60)

    # 1. Load all available transports
    registry = TransportRegistry()
    await registry.auto_register()
    print(f"\n[1] Available transports: {registry.available}")

    # 2. Test HTTP transport
    http = registry.get("http")
    if http:
        print("\n[2] Testing HTTP transport...")
        resp = await http.send(AttackRequest(
            url="https://httpbin.org/get",
            method=RequestMethod.GET,
        ))
        print(f"    Status: {resp.status}")
        print(f"    Body length: {len(resp.body)} bytes")
        print(f"    Elapsed: {resp.elapsed:.2f}s")
        print(f"    [OK] HTTP works!" if resp.ok else "    [FAIL] HTTP failed!")
    else:
        print("\n[2] HTTP transport not available ❌")

    # 3. Test Tor transport
    tor = registry.get("tor")
    if tor:
        print("\n[3] Testing Tor transport...")
        resp = await tor.send(AttackRequest(
            url="https://check.torproject.org/api/ip",
            method=RequestMethod.GET,
        ))
        print(f"    Status: {resp.status}")
        if resp.ok:
            import json
            data = json.loads(resp.body)
            print(f"    IsTor: {data.get('IsTor')}")
            print(f"    IP: {data.get('IP')}")
            print(f"    [OK] Tor works!")
        else:
            print(f"    Error: {resp.error}")
            print(f"    ❌ Tor failed!")
    else:
        print("\n[3] Tor transport not available (is tor running?)")

    # 4. Test .onion resolution (without actually connecting)
    print("\n[4] Testing .onion URL handling...")
    from titan.transport.base import TargetDescriptor, TransportProtocol
    target = TargetDescriptor(url="http://example.onion/api/test")
    print(f"    Host: {target.host}")
    print(f"    Protocol: {target.protocol}")
    print(f"    Is .onion: {'onion' in target.host}")
    print(f"    [OK] .onion parsing works!")

    print("\n" + "=" * 60)
    print("  TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_transports())
