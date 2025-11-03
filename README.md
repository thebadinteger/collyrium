<h1 align="center">collyrium - 🌐RTSP and Web authentication bruteforce tool</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="Python"/>
  <img src="https://img.shields.io/github/license/dansiup44/collyrium" alt="License"/>
  <img src="https://img.shields.io/badge/dependencies-requests-green" alt="Deps"/>
</p>

<h1>About:</h1>

collyrium Is a tool for bruteforcing login credentials of RTSP and Web interfaces of IP cameras and other devices.

<h1>Features:</h1>

- Multithreading
- Port and dictionary configuration
- Credential bruteforcing for RTSP and Web Auth (Basic, Digest, Bearer)

<h1>Installation:</h1>

```bash
git clone https://github.com/dansiup44/collyrium.git
cd collyrium
pip install -r requirements.txt
```

<h1>Usage:</h1>

```bash
python collyrium.py -i [input] -o [out] -t [threads]
```
`-i [Path to the input file (Supports IP/Ranges/CIDR)]`

`-o [Path to the output file (Can be written in existing files)`

`-t [Threads number (Default=128)]`

Output format: `[Type] login:password@ip:port`

<h1>Credits:</h1>

Made by dansiup44 [GPL v3.0 License]
