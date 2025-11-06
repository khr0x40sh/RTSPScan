#!/usr/bin/env python3
"""
rtsp_audit_multi_streams.py

Scan a CIDR for RTSP streams, try multiple stream paths per host,
support credential lists, early-stop per host on first success,
save screenshots, and log to CSV/JSON.
"""
import argparse
import ipaddress
import socket
import concurrent.futures
import cv2
import csv
import os
import json
import time
from datetime import datetime
from PIL import Image
import platform
import socket as pysocket
import numpy as np
import rtspsocket
from parsenmap import parse_nmap_xml, expand_to_job_list

# ----------------------------
# Utility helpers
# ----------------------------
def save_screenshot(frame, out_path, resize=None):
    if frame is None:
        return False
    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    img = Image.fromarray(rgb)
    if resize:
        img = img.resize(resize, Image.LANCZOS)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    img.save(out_path)
    return True

def parse_resize(s):
    if not s:
        return None
    try:
        w, h = s.lower().split("x")
        return (int(w), int(h))
    except Exception:
        raise argparse.ArgumentTypeError("Resize must be WIDTHxHEIGHT, e.g. 640x360")

def load_list(path):
    """Load a text file into a list of lines (skip empty)."""
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

# ----------------------------
# Core RTSP check
# ----------------------------
def check_rtsp_stream(ip, port=554, timeout=3, screenshot_dir=None,
                      resize=None, frame_attempts=3, delay_between=1.0,
                      stream_name="", skip_describe=False, grab_options=False, username=None, password=None, ):
    """
    Attempt to open RTSP (with optional credentials), read up to frame_attempts frames,
    and optionally save a screenshot.
    Returns dict with keys: ip, status, screenshot, user, pass, stream.
    Status values: "open", "open_but_no_frame", "auth_failed", "closed"
    """
    # normalize stream_name -> ensure either empty or starts with '/'
    if stream_name and not stream_name.startswith("/"):
        stream_name = "/" + stream_name

    # build auth part if credentials provided
    auth = ""
    if username or password:
        auth = f"{username or ''}:{password or ''}@"

    rtsp_url = f"rtsp://{auth}{ip}:{port}{stream_name}"

    status = ""

    # quick port check
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            pass
    except Exception:
        status = "closed"
        return {"ip": str(ip), "port": str(port), "status": status, "screenshot": None, "user": username, "pass": password, "stream": stream_name}

    # --- Phase 1: DESCRIBE handshake ---
    if not skip_describe:
        desc = rtspsocket.rtsp_describe(ip, port, stream_name, username, password, timeout)
        if "RTSP/1.0 401" in desc:
            return {"ip": str(ip), "port": str(port), "status": "auth_required", "screenshot": None, "user": username, "pass": password, "stream": stream_name}
        elif "RTSP/1.0 200" not in desc:
            return {"ip": str(ip), "port": str(port), "status": "no_response", "screenshot": None, "user": username, "pass": password, "stream": stream_name}

    if grab_options:
        resp = rtspsocket.rtsp_options(ip, port, timeout)
        print(f"[!] {ip}:{port} - Server advertises the following OPTIONS:\n\n{resp}\n")

    # Optional PUBLISH test (requires flag), needs work
    #if check_publish:
    #    pub = rtspsocket.rtsp_publish_check(ip, port, stream_name, username, password, timeout)
    #    if "200" in pub:
    #        print(f"[!] {ip} allows RTSP PUBLISH to {stream_name}")
    #        status = "publish;"

    cap = cv2.VideoCapture(rtsp_url)
    if not cap.isOpened():
        status += "auth_failed"
        return {"ip": str(ip), "port": str(port), "status": status, "screenshot": None, "user": username, "pass": password, "stream": stream_name}

    frame = None
    for attempt in range(frame_attempts):
        ret, f = cap.read()
        if ret and f is not None:
            frame = f
            break
        time.sleep(delay_between)
    cap.release()

    if frame is not None:
        screenshot_path = None
        if screenshot_dir:
            filename = f"{str(ip).replace(':','_')}_{stream_name.strip('/').replace('/','_') or 'root'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            screenshot_path = os.path.join(screenshot_dir, filename)
            try:
                save_screenshot(frame, screenshot_path, resize=resize)
            except Exception as e:
                screenshot_path = f"ERROR: {e}"
        status +="open"
        return {"ip": str(ip), "port": str(port), "status": status, "screenshot": screenshot_path, "user": username, "pass": password, "stream": stream_name}
    else:
        status += "open_but_no_frame"
        return {"ip": str(ip), "port": str(port), "status": "open_but_no_frame", "screenshot": None, "user": username, "pass": password, "stream": stream_name}

# ----------------------------
# Per-host scanning
# ----------------------------
def scan_host(job, args, users, passes, stream_paths):
    """
    Handle one host sequentially:
      - iterate stream_paths (in order)
      - for each stream, if credential lists present try (user x pass) sequentially
      - if no creds, just test unauthenticated once for that stream
      - early-stop per host when any attempt returns status "open"
    Returns a list of result dicts (one entry per attempt made).
    """
    results = []

    # iterate streams
    for stream in stream_paths:
        # if no credential lists => just try unauthenticated once for this stream
        if not users or not passes:
            res = check_rtsp_stream(job["ip"], job["port"], args.timeout, args.screenshot_dir,
                                    args.screenshot_resize, args.frame_attempts, args.frame_delay,
                                    stream, args.skip_describe, args.grab_options)
            results.append(res)
            if res["status"] == "open":
                return results  # early stop across streams
            # otherwise continue to next stream
            continue

        # have credential lists -> try combos sequentially for this stream
        for user in users:
            for pw in passes:
                res = check_rtsp_stream(job["ip"], job["port"], args.timeout, args.screenshot_dir,
                                        args.screenshot_resize, args.frame_attempts, args.frame_delay,
                                        stream, args.skip_describe, args.grab_options, user, pw)
                results.append(res)
                if res["status"] == "open":
                    return results  # early stop per host on first success
                # throttle between auth attempts if requested
                if args.auth_delay and args.auth_delay > 0:
                    time.sleep(args.auth_delay)
        # after trying all creds for this stream, continue to next stream
    return results

# ----------------------------
# Main
# ----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Scan CIDR for RTSP streams. Try multiple stream paths per host; credential lists supported; early-stop on first success per host."
    )
    parser.add_argument("--cidr", default=None, help="CIDR (e.g., 192.168.1.0/24) or IP. Cannot be used with --nmap-xml.")
    parser.add_argument("--nmap-xml", default=None, help="Read in RTSP targets from nmap xml file. Cannot be used with --port or --cidr.")
    parser.add_argument("--port", type=int, default=554, help="RTSP port (default 554). Cannot be used with --nmap-xml.")
    parser.add_argument("--timeout", type=int, default=3, help="Socket timeout seconds (default 3)")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent host threads (default 20)")
    parser.add_argument("--output", default=None, help="CSV output filename")
    parser.add_argument("--json", default=None, help="JSON output filename")
    parser.add_argument("--screenshot-dir", default=None, help="Directory to save screenshots (optional)")
    parser.add_argument("--screenshot-resize", type=parse_resize, default=None,
                        help="Resize screenshots to WIDTHxHEIGHT (e.g. 640x360)")
    parser.add_argument("--frame-attempts", type=int, default=3,
                        help="Attempts to read frame before marking open_but_no_frame (default 3)")
    parser.add_argument("--frame-delay", type=float, default=1.0,
                        help="Delay between frame read attempts (default 1.0)")
    # stream options
    parser.add_argument("--stream-name", action="append", default=[],
                        help="RTSP stream path (e.g. /live.sdp). Can be specified multiple times.")
    parser.add_argument("--stream-list", default=None,
                        help="File with stream paths (one per line). Paths may include leading / or not.")
    # credential options
    parser.add_argument("--userlist", default=None, help="File with usernames (one per line)")
    parser.add_argument("--passlist", default=None, help="File with passwords (one per line)")
    parser.add_argument("-U", "--User", default=None, help="Username (Cannot be used with --userlist)")
    parser.add_argument("-P", "--Password", default=None, help="Password (Cannot be used with --passlist)")
    parser.add_argument("--auth-delay", type=float, default=0.0,
                        help="Delay between credential attempts per host in seconds (default 0.0)")
    parser.add_argument(
        "--skip-describe",
        action="store_true",
        help="Skip the initial RTSP DESCRIBE test (default: perform it)"
    )
    #parser.add_argument(
    #    "--check-publish",
    #    action="store_true",
    #    help="Attempt RTSP PUBLISH to test for writable streams"
    #)
    parser.add_argument(
        "--grab-options",
        action="store_true",
        help="Grab RTSP options banner."
    )

    args = parser.parse_args()
    network = None

    if args.cidr and args.nmap_xml:
        print(f"[-] Cannot use both CIDR and NMAP XML Parser. Check your syntax and try again.")
        return
    elif args.cidr is None and args.nmap_xml is None:
        print(f"[-] Specify either a CIDR (--cidr 192.168.0.0/24) or NMAP XML file to parse (--nmap-xml nmaprtspscan.xml). Check your syntax and try again.")
        return

    if args.nmap_xml:
        parsed = parse_nmap_xml(args.nmap_xml)
        jobs = expand_to_job_list(parsed, prefer_rtsp_only=True, default_ports=[args.port, 8554, 554])
        # jobs is list of dicts {ip, port, hostname, service, product}
    else:
        # fallback to CIDR expansion
        # CIDR validation
        try:
            network = ipaddress.ip_network(args.cidr, strict=False)
        except ValueError as e:
            print(f"Invalid CIDR: {e}")
            return
        jobs = [{"ip": str(ip), "port": args.port, "hostname": None} for ip in network.hosts()]

    # load users/passes/stream paths
    if args.User is not None:
        users = [args.User]
    else:
        users = load_list(args.userlist)
    if args.Password is not None:
        passes = [args.Password]
    else:
        passes = load_list(args.passlist)

    # compose stream path list (file first, then any --stream-name args)
    stream_paths = []
    if args.stream_list:
        stream_paths.extend(load_list(args.stream_list))
    if args.stream_name:
        # args.stream_name may contain duplicates; keep provided order
        stream_paths.extend(args.stream_name)
    # default to root (empty) if no stream paths provided
    if not stream_paths:
        stream_paths = [""]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = args.output or f"rtsp_scan_{timestamp}.csv"
    json_file = args.json or f"rtsp_scan_{timestamp}.json"
    os.makedirs(os.path.dirname(csv_file) or ".", exist_ok=True)
    if args.screenshot_dir:
        os.makedirs(args.screenshot_dir, exist_ok=True)

    # scanner metadata
    host_meta = {
        "scanner_hostname": platform.node(),
        "scanner_local_ip": None,
        "scanner_os": platform.platform(),
        "python_version": platform.python_version()
    }
    try:
        host_meta["scanner_local_ip"] = pysocket.gethostbyname(pysocket.gethostname())
    except Exception:
        host_meta["scanner_local_ip"] = None

    if args.nmap_xml:
        print(f"Scanning hosts/services found in {args.nmap_xml} ...")
    else:
        print(f"Scanning {args.cidr} (port {args.port}) ...")
    print(f"Streams to try (in order): {stream_paths}")
    if users and passes:
        print(f"Using credential lists: {len(users)} users × {len(passes)} passwords (early stop per host)")
    elif users or passes: # I may change this so you can supply just a username...
        print("⚠️ Both userlist and passlist should be supplied for credential scanning.")
    else:
        print("No credentials supplied (testing unauthenticated access only).")
    print(f"Frame attempts: {args.frame_attempts}, Frame delay: {args.frame_delay}s, Auth delay: {args.auth_delay}s")
    print("")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_host, job, args, users, passes, stream_paths): job for job in jobs}

        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                host_results = future.result()
                for res in host_results:
                    res_record = {
                        "ip": res.get("ip"),
                        "port": res.get("port"),
                        "status": res.get("status"),
                        "timestamp": datetime.now().isoformat(),
                        "user": res.get("user"),
                        "pass": res.get("pass"),
                        "stream": res.get("stream"),
                        "screenshot": res.get("screenshot")
                    }
                    results.append(res_record)
                    s = res_record["status"]
                    u, p, st = res_record.get("user"), res_record.get("pass"), res_record.get("stream")
                    output = ""
                    if "open_but_no_frame" in s:
                        output = f"⚠️ {ip} - open but no frame [{u}:{p}] stream='{st}'"
                    elif "open" in s:
                        output = f"✅ {ip} - OPEN [{u}:{p}] stream='{st}' ({res_record.get('screenshot')})"
                    elif "auth_failed" in s:
                        output = f"🔒 {ip} - auth failed [{u}:{p}] stream='{st}'"
                    elif "closed" in s:
                        output = f"❌ {ip} - closed"
                    elif "no_response" in s:
                        output = f"❌ {ip} - TCP {args.port} open, but no response."
                    elif "auth_required" in s:
                        output = f"❌ {ip} - DESCRIBE failed using [{u}:{p}]"
                    if "publish" in s:
                        output += " - MAY ALLOW PUBLISH (write)!!!"
                    print(output)
            except Exception as e:
                print(f"Error scanning {ip}: {e}")

    # Write CSV
    with open(csv_file, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["IP Address", "Status", "Timestamp", "Username", "Password", "Stream", "Screenshot"])
        for r in results:
            w.writerow([r["ip"], r["status"], r["timestamp"], r.get("user"), r.get("pass"), r.get("stream"), r.get("screenshot")])

    # Write JSON
    with open(json_file, "w") as f:
        json.dump({
            "scan_time": datetime.now().isoformat(),
            "cidr": args.cidr,
            "port": args.port,
            "stream_paths": stream_paths,
            "frame_attempts": args.frame_attempts,
            "frame_delay": args.frame_delay,
            "auth_delay": args.auth_delay,
            "early_stop_per_host": True,
            "scanner": host_meta,
            "results": results
        }, f, indent=2)

    print("\nScan complete.")
    print(f"Results entries: {len(results)}")
    print(f"Saved CSV: {csv_file}")
    print(f"Saved JSON: {json_file}")
    if args.screenshot_dir:
        print(f"Screenshots: {args.screenshot_dir}")

if __name__ == "__main__":
    main()
