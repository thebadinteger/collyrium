<h1 align="center">collyrium - 🌐IP Cameras Web authentication bruteforce tool</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="Python"/>
  <img src="https://img.shields.io/github/license/dansiup44/collyrium" alt="License"/>
  <img src="https://img.shields.io/badge/dependencies-requests-green" alt="Deps"/>
</p>

<h1>About:</h1>

<h3>collyrium Is a tool for bruteforcing login credentials for Web interfaces of IP cameras</h4>

<h1>Features:</h1>

- Multithreading
- Port and dictionary configuration
- Credential bruteforcing for Web Auth (Basic, Digest)
- Snapshots saving
- Multiplatform

<h1>Installation:</h1>

```bash
git clone https://github.com/dansiup44/collyrium.git
cd collyrium
pip install -r requirements.txt
```

<h1>Configuration:</h1>

Configs are used in the following format:

```
string
string
string
```

- Logins: `config/login.cfg`
- Passwords: `config/pass.cfg`
- Ports: `config/ports.cfg`

<h1>Usage:</h1>

```bash
python collyrium.py -i [input] -o [output] -t [threads]
```
`-i [Path to the input file (Supports IP/IP:Port/Ranges/CIDR)]`

`-o [Path to the output folder (Can be written in existing files)]`

`-t [Threads number (Default=512)]`

`-? [Help]`

Output format: `login:password@ip:port`

<h1>Credits:</h1>

Made by dansiup44 [GPL v3.0 License]
