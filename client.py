"""
PyRedis Test Client
Comprehensive test runner for verification of:
- Standard In-Memory operations (Strings, Hashes, Counters)
- Geospatial mapping and spherical Haversine distance computations
- Granular Access Control Lists (ACL creation, authentication, permission denials)
"""

import socket
import time
from typing import Optional


class RedisTestClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 6379):
        self.host = host
        self.port = port

    def execute(self, command: str, verbose: bool = True) -> str:
        """Connects, encodes a command to RESP format, sends, and prints output."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))

        parts = command.split()
        resp = f"*{len(parts)}\r\n"
        for part in parts:
            resp += f"${len(part)}\r\n{part}\r\n"

        s.sendall(resp.encode("utf-8"))
        response = s.recv(4096).decode("utf-8", errors="replace").strip()
        s.close()

        if verbose:
            print(f"> {command}")
            print(f"  Response: {response}\n")
        return response


def run_test_suite():
    client = RedisTestClient()

    print("==================================================")
    print("   STAGE 1: STRINGS, TTL & HASHTABLES")
    print("==================================================")
    client.execute("PING")
    client.execute("SET company Google EX 10")
    client.execute("GET company")
    client.execute("TTL company")
    client.execute("INCR page_visits")
    client.execute("INCR page_visits")
    client.execute("HSET profile:101 username dev_alice")
    client.execute("HSET profile:101 role SeniorArchitect")
    client.execute("HGETALL profile:101")

    print("==================================================")
    print("   STAGE 2: GEOSPATIAL INDEXING (HAVERSINE)")
    print("==================================================")
    # Adding coordinates: GEOADD key longitude latitude member
    client.execute("GEOADD cities 13.361389 38.115556 Palermo 15.087269 37.502669 Catania")
    
    # Calculate distance in meters, kilometers, and miles
    print("[Testing Haversine Spherical Distance]")
    client.execute("GEODIST cities Palermo Catania m")
    client.execute("GEODIST cities Palermo Catania km")
    client.execute("GEODIST cities Palermo Catania mi")
    client.execute("GEOPOS cities Palermo Catania NonExistentCity")

    print("==================================================")
    print("   STAGE 3: ACCESS CONTROL LISTS (ACL) & AUTH")
    print("==================================================")
    # Check default identity
    client.execute("ACL WHOAMI")

    # Provision a restricted user: only GET and PING allowed, password = secret
    print("[Creating restricted user 'analyst' with password 'secret']")
    client.execute("ACL SETUSER analyst on >secret -@all +GET +PING")
    client.execute("ACL GETUSER analyst")

    # Connect an interactive socket session to test authentication and access
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 6379))

    def send_raw(sock, cmd_str):
        p = cmd_str.split()
        b = f"*{len(p)}\r\n" + "".join(f"${len(x)}\r\n{x}\r\n" for x in p)
        sock.sendall(b.encode("utf-8"))
        res = sock.recv(1024).decode("utf-8").strip()
        print(f"(Session) > {cmd_str} -> {res}")
        return res

    print("\n[Interactive Session: Authentication Flow]")
    send_raw(s, "ACL WHOAMI")
    send_raw(s, "AUTH analyst secret")
    send_raw(s, "ACL WHOAMI")

    print("\n[Interactive Session: Testing Whitelisted Command]")
    send_raw(s, "GET company")

    print("\n[Interactive Session: Testing Permission Rejection (NOPERM)]")
    send_raw(s, "SET illegal_key bad_payload")  # Must return NOPERM error
    send_raw(s, "DEL company")                  # Must return NOPERM error

    s.close()
    print("\n==================================================")
    print("   TEST SUITE EXECUTION COMPLETED")
    print("==================================================")


if __name__ == "__main__":
    run_test_suite()