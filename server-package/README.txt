Ghidra Bridge -- Server Deployment Package
==========================================

This package runs on the same machine as your Ghidra Server.
Java (JDK 17+) and a Ghidra installation are required on the server.

Quick start (Linux / macOS)
---------------------------
1. Copy this directory to the Ghidra server machine.
2. Set GHIDRA_HOME to your Ghidra installation:
     export GHIDRA_HOME=/path/to/ghidra_12.x_PUBLIC
3. Start the bridge:
     ./start-bridge.sh
   The bridge listens on port 13200 by default.  Use --port N to change it.

Quick start (Windows)
---------------------
1. Copy this directory to the Ghidra server machine.
2. Set GHIDRA_HOME in the environment or edit start-bridge.bat.
3. Run start-bridge.bat.

Firewall
--------
Allow TCP port 13200 inbound from your Binary Ninja client machine(s).
The bridge has no built-in authentication -- restrict access at the
firewall level to trusted hosts only.

Binary Ninja settings
---------------------
In BN: Settings -> Ghidra -> Bridge Mode  -> set to "remote"
        Settings -> Ghidra -> Bridge Port  -> set to match port above (default: 13200)
The bridge host is always the same as the Ghidra Server host entered
in the Connect dialog -- no separate host configuration needed.

Running as a Windows service
----------------------------
Use NSSM (https://nssm.cc) or Task Scheduler to run start-bridge.bat at startup.
Example with NSSM:
  nssm install GhidraBridge "C:\path\to\server-package\start-bridge.bat"
  nssm set GhidraBridge AppEnvironmentExtra GHIDRA_HOME=C:\path\to\ghidra
  nssm start GhidraBridge
