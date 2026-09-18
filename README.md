# PyRedis: Asynchronous In-Memory Datastore

An asynchronous, single-threaded Redis clone built entirely from scratch in Python. It implements the binary-safe RESP2 protocol and handles concurrent TCP connections via Python's `asyncio` event loop.

##  Features

* **RESP2 Protocol Parser:** Stream-based, binary-safe serializer/deserializer handling arrays, bulk strings, and integers natively.
* **Dual-Eviction Memory Management:** Implements both passive (lazy) key expiration on read, and an active probabilistic background sampling loop (10 Hz) to eliminate memory leaks.
* **Geospatial Indexing:** Calculates spherical distances between coordinates (in m, km, mi, ft) using the Haversine trigonometric formula.
* **Role-Based Access Control (ACL):** Stateful connection tracking enabling granular command whitelisting and secure password hashing.
* **Write-Ahead Logging (AOF):** Guarantees state durability across server crashes by serializing mutating commands to an Append-Only File with automatic cold-boot replay.

##  Quick Start

**Zero dependencies required.** PyRedis uses only Python's standard library.

1. **Start the Server:**
   ```bash
   python redis_server.py
