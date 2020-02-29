# SENG Server Prototype

A Docker container for easier setup is currently missing.
OpenSSL 1.0.2g is required for compilation and will have to be added as submodule.

Use:
seng_ossl_double_tunnel_server <listen_port> (currently 12345)

Experimental demo with Sqlite3 database for access checks and Enclave Subnet
definitions:
seng_ossl_double_tunnel_server -d ../demo_sqlite3.db 12345

Create the demo database for instance via:
sqlite3 demo_sqlite3.db < seng_db_creator.sql
