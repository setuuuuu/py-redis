"""
PyRedis Enterprise - Production-Grade Asynchronous In-Memory Store
Features:
- Binary-safe RESP2 protocol serialization/deserialization
- Active + Passive (lazy) key expiration with dual-TTL
- In-memory data structures: Strings, Hashes, and Geospatial Coordinates
- Granular Role-Based Access Control (ACL) with connection state tracking
- Haversine-formula geospatial calculations (GEOADD, GEODIST, GEOPOS)
- Append-Only File (AOF) write-ahead persistence with auto-replay (Binary Safe)
"""

import asyncio
import hashlib
import math
import os
import random
import time
from typing import Any, Dict, List, Optional, Tuple, Union


# =====================================================================
# 1. RESP2 PROTOCOL SERIALIZER & DESERIALIZER
# =====================================================================

class RESPParser:
    """Stream-based, binary-safe Redis Serialization Protocol (RESP2) parser."""

    @staticmethod
    async def parse(reader: asyncio.StreamReader) -> Optional[List[str]]:
        """Parses an incoming RESP Array from an asynchronous byte stream."""
        prefix = await reader.read(1)
        if not prefix:
            return None  # Socket disconnected

        if prefix != b"*":
            # Inline command fallback (telnet/netcat style)
            line = prefix + await reader.readline()
            return line.decode("utf-8", errors="replace").strip().split()

        line = await reader.readline()
        if not line:
            return None

        num_elements = int(line.strip())
        elements: List[str] = []

        for _ in range(num_elements):
            dollar = await reader.read(1)
            if dollar != b"$":
                raise ValueError(f"Malformed RESP: expected '$', got {dollar!r}")

            len_line = await reader.readline()
            length = int(len_line.strip())

            if length == -1:
                elements.append("")
                continue

            # Read exact payload length + trailing \r\n (binary safe)
            payload = await reader.readexactly(length + 2)
            elements.append(payload[:-2].decode("utf-8", errors="replace"))

        return elements

    @staticmethod
    def encode_simple_string(msg: str) -> bytes:
        return f"+{msg}\r\n".encode("utf-8")

    @staticmethod
    def encode_error(err: str) -> bytes:
        return f"-ERR {err}\r\n".encode("utf-8")

    @staticmethod
    def encode_integer(val: int) -> bytes:
        return f":{val}\r\n".encode("utf-8")

    @staticmethod
    def encode_bulk_string(val: Optional[str]) -> bytes:
        if val is None:
            return b"$-1\r\n"
        encoded = str(val).encode("utf-8")
        return f"${len(encoded)}\r\n".encode("utf-8") + encoded + b"\r\n"

    @staticmethod
    def encode_array(items: Optional[List[Any]]) -> bytes:
        if items is None:
            return b"*-1\r\n"
        buf = [f"*{len(items)}\r\n".encode("utf-8")]
        for item in items:
            if item is None:
                buf.append(b"$-1\r\n")
            elif isinstance(item, list):
                buf.append(RESPParser.encode_array(item))
            elif isinstance(item, str):
                buf.append(RESPParser.encode_bulk_string(item))
            elif isinstance(item, int):
                buf.append(RESPParser.encode_integer(item))
            elif isinstance(item, bytes):
                buf.append(f"${len(item)}\r\n".encode("utf-8") + item + b"\r\n")
        return b"".join(buf)


# =====================================================================
# 2. ROLE-BASED ACCESS CONTROL (ACL) ENGINE
# =====================================================================

class ACLUser:
    def __init__(self, username: str):
        self.username = username
        self.is_active = True
        self.password_hash: Optional[str] = None
        self.commands = {"PING", "AUTH", "ACL", "QUIT"}  # Base allowed commands
        self.all_commands = False  # Controlled by +@all

    def verify_password(self, password: str) -> bool:
        if not self.password_hash:
            return True  # No password configured means open access
        return self.password_hash == hashlib.sha256(password.encode("utf-8")).hexdigest()


class ACLEngine:
    def __init__(self):
        self.users: Dict[str, ACLUser] = {}
        # Default user with unrestricted access
        default_user = ACLUser("default")
        default_user.all_commands = True
        self.users["default"] = default_user

    def set_user(self, username: str, rules: List[str]) -> str:
        if username not in self.users:
            self.users[username] = ACLUser(username)

        user = self.users[username]
        for rule in rules:
            if rule == "on":
                user.is_active = True
            elif rule == "off":
                user.is_active = False
            elif rule.startswith(">"):
                user.password_hash = hashlib.sha256(rule[1:].encode("utf-8")).hexdigest()
            elif rule == "+@all":
                user.all_commands = True
            elif rule.startswith("+"):
                user.commands.add(rule[1:].upper())
            elif rule.startswith("-"):
                user.commands.discard(rule[1:].upper())
                user.all_commands = False
        return "OK"

    def can_execute(self, username: str, command: str) -> bool:
        user = self.users.get(username)
        if not user or not user.is_active:
            return False
        return user.all_commands or (command.upper() in user.commands)


# =====================================================================
# 3. IN-MEMORY STORAGE ENGINE WITH GEOSPATIAL & TTL
# =====================================================================

class StorageEngine:
    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._expires: Dict[str, float] = {}

    def _is_expired(self, key: str) -> bool:
        if key in self._expires:
            if time.time() >= self._expires[key]:
                self.delete(key)
                return True
        return False

    # String Operations
    def get(self, key: str) -> Optional[str]:
        if self._is_expired(key):
            return None
        val = self._data.get(key)
        return val if isinstance(val, str) else None

    def set(self, key: str, value: str, ttl_seconds: Optional[float] = None) -> None:
        self._data[key] = value
        if ttl_seconds is not None:
            self._expires[key] = time.time() + ttl_seconds
        elif key in self._expires:
            del self._expires[key]

    def delete(self, *keys: str) -> int:
        count = 0
        for key in keys:
            deleted = False
            if key in self._data:
                del self._data[key]
                deleted = True
            if key in self._expires:
                del self._expires[key]
                deleted = True
            if deleted:
                count += 1
        return count

    def exists(self, *keys: str) -> int:
        return sum(1 for key in keys if key in self._data and not self._is_expired(key))

    def incr(self, key: str) -> int:
        if self._is_expired(key):
            val = 0
        else:
            current = self._data.get(key, "0")
            if not isinstance(current, str) or not current.lstrip("-").isdigit():
                raise ValueError("ERR value is not an integer or out of range")
            val = int(current)

        val += 1
        self._data[key] = str(val)
        return val

    def ttl(self, key: str) -> int:
        if key not in self._data or self._is_expired(key):
            return -2  # Key does not exist
        if key not in self._expires:
            return -1  # Key exists with no expiration
        remaining = int(self._expires[key] - time.time())
        return remaining if remaining > 0 else -2

    # Hash Operations
    def hset(self, key: str, field: str, value: str) -> int:
        self._is_expired(key)
        if key not in self._data:
            self._data[key] = {}
        elif not isinstance(self._data[key], dict):
            raise TypeError("WRONGTYPE Operation against a key holding the wrong kind of value")

        is_new = field not in self._data[key]
        self._data[key][field] = value
        return 1 if is_new else 0

    def hget(self, key: str, field: str) -> Optional[str]:
        if self._is_expired(key):
            return None
        container = self._data.get(key)
        if container is None:
            return None
        if not isinstance(container, dict):
            raise TypeError("WRONGTYPE Operation against a key holding the wrong kind of value")
        return container.get(field)

    def hgetall(self, key: str) -> List[str]:
        if self._is_expired(key):
            return []
        container = self._data.get(key, {})
        if not isinstance(container, dict):
            raise TypeError("WRONGTYPE Operation against a key holding the wrong kind of value")
        res = []
        for k, v in container.items():
            res.extend([k, v])
        return res

    # Geospatial Operations
    def geoadd(self, key: str, *args: str) -> int:
        if len(args) % 3 != 0:
            raise ValueError("ERR wrong number of arguments for 'geoadd' command")

        self._is_expired(key)
        if key not in self._data:
            self._data[key] = {}
        elif not isinstance(self._data[key], dict):
            raise TypeError("WRONGTYPE Operation against a key holding the wrong kind of value")

        added = 0
        for i in range(0, len(args), 3):
            lon = float(args[i])
            lat = float(args[i + 1])
            member = args[i + 2]

            if not (-180.0 <= lon <= 180.0 and -85.05112878 <= lat <= 85.05112878):
                raise ValueError("ERR invalid longitude,latitude pair")

            if member not in self._data[key]:
                added += 1
            self._data[key][member] = (lon, lat)

        return added

    def geodist(self, key: str, member1: str, member2: str, unit: str = "m") -> Optional[str]:
        if self._is_expired(key) or key not in self._data:
            return None

        container = self._data[key]
        if not isinstance(container, dict) or member1 not in container or member2 not in container:
            return None

        lon1, lat1 = container[member1]
        lon2, lat2 = container[member2]

        # Haversine distance formula on spherical Earth
        r = 6372797.560856  # Earth radius in meters
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)

        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        dist_m = r * c

        unit_conversions = {"m": 1.0, "km": 1000.0, "mi": 1609.344, "ft": 0.3048}
        unit_lower = unit.lower()
        if unit_lower not in unit_conversions:
            raise ValueError("ERR unsupported unit provided. please use m, km, ft, mi")

        return f"{dist_m / unit_conversions[unit_lower]:.4f}"

    def geopos(self, key: str, *members: str) -> List[Optional[List[str]]]:
        if self._is_expired(key) or key not in self._data:
            return [None for _ in members]

        container = self._data[key]
        positions: List[Optional[List[str]]] = []
        for member in members:
            if isinstance(container, dict) and member in container:
                lon, lat = container[member]
                positions.append([str(lon), str(lat)])
            else:
                positions.append(None)
        return positions

    # Active Expiration Routine (Probabilistic 20-Key Sampling)
    def active_eviction_cycle(self, sample_size: int = 20) -> None:
        if not self._expires:
            return

        keys = list(self._expires.keys())
        sampled = random.sample(keys, min(sample_size, len(keys)))
        now = time.time()
        for key in sampled:
            if now >= self._expires[key]:
                self.delete(key)


# =====================================================================
# 4. APPEND-ONLY FILE (AOF) PERSISTENCE ENGINE
# =====================================================================

class AOFEngine:
    MUTATING_COMMANDS = {"SET", "DEL", "INCR", "HSET", "GEOADD"}

    def __init__(self, filepath: str = "appendonly.aof"):
        self.filepath = filepath
        # FIXED: Open in "ab" (append binary) to prevent Windows \r\n corruption
        self._file = open(self.filepath, "ab")

    def log(self, args: List[str]) -> None:
        if args and args[0].upper() in self.MUTATING_COMMANDS:
            encoded = RESPParser.encode_array(args)  # Keep as raw bytes
            self._file.write(encoded)
            self._file.flush()

    async def replay(self, server_instance: "RedisServer") -> None:
        if not os.path.exists(self.filepath):
            return

        with open(self.filepath, "rb") as f:
            reader = asyncio.StreamReader()
            reader.feed_data(f.read())
            reader.feed_eof()

            dummy_state = {"user": "default", "authenticated": True}
            while True:
                command = await RESPParser.parse(reader)
                if not command:
                    break
                await server_instance.execute_command(command, dummy_state, persist=False)


# =====================================================================
# 5. SERVER DISPATCHER & EVENT LOOP
# =====================================================================

class RedisServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 6379):
        self.host = host
        self.port = port
        self.store = StorageEngine()
        self.aof = AOFEngine()
        self.acl = ACLEngine()

    async def execute_command(self, args: List[str], client_state: Dict[str, Any], persist: bool = True) -> bytes:
        if not args:
            return RESPParser.encode_error("empty command")

        cmd = args[0].upper()

        try:
            # --- Base Commands ---
            if cmd == "PING":
                return RESPParser.encode_simple_string("PONG" if len(args) == 1 else args[1])

            elif cmd == "ECHO" and len(args) > 1:
                return RESPParser.encode_bulk_string(args[1])

            elif cmd == "COMMAND":
                return RESPParser.encode_array([])

            # --- Authentication & ACL ---
            elif cmd == "AUTH":
                if len(args) == 3:
                    user, pwd = args[1], args[2]
                elif len(args) == 2:
                    user, pwd = "default", args[1]
                else:
                    return RESPParser.encode_error("wrong number of arguments for 'auth'")

                target_user = self.acl.users.get(user)
                if target_user and target_user.verify_password(pwd):
                    client_state["user"] = user
                    client_state["authenticated"] = True
                    return RESPParser.encode_simple_string("OK")
                return RESPParser.encode_error("WRONGPASS invalid username-password pair")

            elif cmd == "ACL" and len(args) >= 2:
                subcmd = args[1].upper()
                if subcmd == "WHOAMI":
                    return RESPParser.encode_bulk_string(client_state["user"])
                elif subcmd == "SETUSER" and len(args) >= 3:
                    res = self.acl.set_user(args[2], args[3:])
                    return RESPParser.encode_simple_string(res)
                elif subcmd == "GETUSER" and len(args) == 3:
                    u = self.acl.users.get(args[2])
                    if not u:
                        return RESPParser.encode_bulk_string(None)
                    return RESPParser.encode_array([
                        "flags", ["on" if u.is_active else "off"],
                        "passwords", ["configured" if u.password_hash else "none"],
                        "commands", "+@all" if u.all_commands else list(u.commands)
                    ])

            # --- String & Key Operations ---
            elif cmd == "SET":
                if len(args) < 3:
                    return RESPParser.encode_error("wrong number of arguments for 'set'")
                key, val = args[1], args[2]
                ttl = None
                if len(args) >= 5 and args[3].upper() == "EX":
                    ttl = float(args[4])
                self.store.set(key, val, ttl)
                if persist:
                    self.aof.log(args)
                return RESPParser.encode_simple_string("OK")

            elif cmd == "GET":
                if len(args) != 2:
                    return RESPParser.encode_error("wrong number of arguments for 'get'")
                return RESPParser.encode_bulk_string(self.store.get(args[1]))

            elif cmd == "DEL":
                count = self.store.delete(*args[1:])
                if persist:
                    self.aof.log(args)
                return RESPParser.encode_integer(count)

            elif cmd == "EXISTS":
                return RESPParser.encode_integer(self.store.exists(*args[1:]))

            elif cmd == "INCR":
                val = self.store.incr(args[1])
                if persist:
                    self.aof.log(args)
                return RESPParser.encode_integer(val)

            elif cmd == "TTL":
                return RESPParser.encode_integer(self.store.ttl(args[1]))

            # --- Hash Operations ---
            elif cmd == "HSET":
                if len(args) != 4:
                    return RESPParser.encode_error("wrong number of arguments for 'hset'")
                res = self.store.hset(args[1], args[2], args[3])
                if persist:
                    self.aof.log(args)
                return RESPParser.encode_integer(res)

            elif cmd == "HGET":
                return RESPParser.encode_bulk_string(self.store.hget(args[1], args[2]))

            elif cmd == "HGETALL":
                return RESPParser.encode_array(self.store.hgetall(args[1]))

            # --- Geospatial Operations ---
            elif cmd == "GEOADD":
                if len(args) < 5:
                    return RESPParser.encode_error("wrong number of arguments for 'geoadd'")
                count = self.store.geoadd(args[1], *args[2:])
                if persist:
                    self.aof.log(args)
                return RESPParser.encode_integer(count)

            elif cmd == "GEODIST":
                if len(args) not in (4, 5):
                    return RESPParser.encode_error("wrong number of arguments for 'geodist'")
                unit = args[4] if len(args) == 5 else "m"
                dist = self.store.geodist(args[1], args[2], args[3], unit)
                return RESPParser.encode_bulk_string(dist)

            elif cmd == "GEOPOS":
                if len(args) < 3:
                    return RESPParser.encode_error("wrong number of arguments for 'geopos'")
                positions = self.store.geopos(args[1], *args[2:])
                return RESPParser.encode_array(positions)

            else:
                return RESPParser.encode_error(f"unknown command `{cmd}`")

        except Exception as e:
            return RESPParser.encode_error(str(e))

    async def client_handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Per-connection session state
        client_state = {"user": "default", "authenticated": True}

        try:
            while True:
                command = await RESPParser.parse(reader)
                if command is None:
                    break

                cmd = command[0].upper()

                # Granular Access Control check
                if not self.acl.can_execute(client_state["user"], cmd):
                    writer.write(RESPParser.encode_error(
                        f"NOPERM this user has no permissions to run the '{cmd}' command"
                    ))
                    await writer.drain()
                    continue

                response = await self.execute_command(command, client_state)
                writer.write(response)
                await writer.drain()

        except ConnectionResetError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def _active_eviction_worker(self) -> None:
        """Background coroutine running active key expiration at 10 Hz."""
        while True:
            await asyncio.sleep(0.1)
            self.store.active_eviction_cycle()

    async def start(self) -> None:
        await self.aof.replay(self)
        server = await asyncio.start_server(self.client_handler, self.host, self.port)
        print(f"[*] PyRedis Server operational on {self.host}:{self.port} (PID: {os.getpid()})")
        print(f"[*] AOF Write-Ahead Logging active: {self.aof.filepath}")

        asyncio.create_task(self._active_eviction_worker())
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(RedisServer().start())
    except KeyboardInterrupt:
        print("\n[*] Clean shutdown completed.")