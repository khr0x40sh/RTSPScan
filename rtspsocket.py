import socket
import base64

def rtsp_send_request(ip, port, request, timeout=3):
    try:
        s = socket.create_connection((str(ip), port), timeout=timeout)
        s.sendall(request.encode("utf-8"))
        response = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        return response
    except Exception as e:
        return f"ERROR: {e}"

def rtsp_describe(ip, port=554, stream_path="/", user=None, password=None, timeout=3):
    if not stream_path.startswith("/"):
        stream_path = "/" + stream_path
    url = f"rtsp://{ip}:{port}{stream_path}"
    cseq = 1
    headers = [
        f"DESCRIBE {url} RTSP/1.0",
        f"CSeq: {cseq}",
        "Accept: application/sdp",
    ]
    if user and password:
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers.append(f"Authorization: Basic {auth}")
    headers.append("\r\n")

    request = "\r\n".join(headers)
    return rtsp_send_request(ip, port, request, timeout)

def rtsp_publish_check(ip, port=554, stream_path="/", user=None, password=None, timeout=3):
    if not stream_path.startswith("/"):
        stream_path = "/" + stream_path
    url = f"rtsp://{ip}:{port}{stream_path}"
    cseq = 1
    headers = [
        f"ANNOUNCE {url} RTSP/1.0",
        f"CSeq: {cseq}",
        "Content-Type: application/sdp",
        "Content-Length: 0",
    ]
    if user and password:
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers.append(f"Authorization: Basic {auth}")
    headers.append("\r\n")

    request = "\r\n".join(headers)
    return rtsp_send_request(ip, port, request, timeout)
