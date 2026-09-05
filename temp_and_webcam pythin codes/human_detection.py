import cv2
import time
from datetime import datetime
import socket
import requests
import urllib3
import threading
from ultralytics import YOLO

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- SECURITY SETTINGS ---
SECRET_KEY = b"1234567890123456" 
aesgcm = AESGCM(SECRET_KEY)

# Suppress SSL warnings because we are using a custom server.crt
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- NETWORK SETTINGS ---
VM_IP = "192.168.118.130"
VIDEO_UDP_PORT = 8891  
PERSON_UDP_PORT = 8890  

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

model = YOLO('yolov8n.pt')
cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)

if not cap.isOpened():
    print("\n[FATAL ERROR] Cannot access the webcam!")
    exit()

prev_frame_time = 0
STUDENT_ID = "401101749" 

frame_counter = 0
cached_boxes = []
person_count = 0
last_printed_count = -1
is_overheating = False


def fetch_telemetry_loop():
    global is_overheating
    
    # Force Python to bypass proxies and immediately drop the connection when done
    proxies = { "http": None, "https": None }
    headers = { "Connection": "close" }
    
    while True:
        try:
            url = f"https://{VM_IP}:8443/API/V1/TELEMETRY"
            # Increased timeout and added the close header to prevent server traffic jams
            resp = requests.get(url, verify=False, timeout=5.0, proxies=proxies, headers=headers)
            data = resp.json()
            server_temp = data.get("cpu_temp", 0.0)
            
            if server_temp >= 75.0 and not is_overheating:
                is_overheating = True
                print(f"[THERMAL ALERT] Ubuntu is overheating ({server_temp} C)! Python dropping FPS.")
            elif server_temp <= 70.0 and is_overheating:
                is_overheating = False
                print(f"[THERMAL RECOVERY] Ubuntu cooled down ({server_temp} C). Python restoring FPS.")
                
        except Exception as e:
            # print(f"[DEBUG] Connection Blocked: {e}")
            pass
        
        # Wait 3 seconds between checks to give the C server time to breathe
        time.sleep(3) 

# Launch the thermal checker in the background
threading.Thread(target=fetch_telemetry_loop, daemon=True).start()

print("\nStarting SECURE Smart Guard Human Detection with Asynchronous Thermal Sync...")
print("Press 'q' in the video window to quit.")

while True:
    total_frames = 0
    correct_detections = 0
    ret, frame = cap.read()
    if not ret:
        break

    frame = cv2.resize(frame, (640, 480))
    frame_counter += 1

    if is_overheating:
        time.sleep(0.15) 

    if frame_counter % 2 == 0:
        results = model(frame, classes=[0], conf=0.75, verbose=False, imgsz=320)
        
        cached_boxes = []
        for r in results:
            for box in r.boxes:
                x1, y1, x2, y2 = map(int, box.xyxy[0])
                cached_boxes.append((x1, y1, x2, y2))
        
        person_count = len(cached_boxes)
    if person_count > 0 and last_printed_count == 0:
        print(f"🕒 [LATENCY START] Person entered frame at: {time.time():.3f}")

    # --- 1. SECURE PERSON COUNT TRANSMISSION ---
    count_bytes = str(person_count).encode()
    nonce_p = os.urandom(12)
    encrypted_count = aesgcm.encrypt(nonce_p, count_bytes, associated_data=None)
    payload_p = nonce_p + encrypted_count
    udp_sock.sendto(payload_p, (VM_IP, PERSON_UDP_PORT))
    
    if person_count != last_printed_count:
        last_printed_count = person_count

    for (x1, y1, x2, y2) in cached_boxes:
        cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)

    # Calculate Real FPS
    new_frame_time = time.time()
    if new_frame_time - prev_frame_time > 0:
        fps = 1 / (new_frame_time - prev_frame_time)
    else:
        fps = 0
    prev_frame_time = new_frame_time

    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    fps_color = (0, 0, 255) if is_overheating else (0, 255, 0)
    
    cv2.putText(frame, f"People Count: {person_count}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
    cv2.putText(frame, f"Student ID: {STUDENT_ID}", (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
    cv2.putText(frame, f"Time: {current_datetime}", (10, 90), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 0), 2)
    cv2.putText(frame, f"FPS: {int(fps)}", (10, 120), cv2.FONT_HERSHEY_SIMPLEX, 0.7, fps_color, 2)
    
    if is_overheating:
        cv2.putText(frame, "THERMAL THROTTLING ACTIVE", (10, 150), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)

    cv2.imshow("Smart Guard - Human Detection", frame)

    # --- 2. SECURE VIDEO TRANSMISSION (Optimized for Network) ---
    network_frame = cv2.resize(frame, (320, 480)) 
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 65] 
    result, encoded_image = cv2.imencode('.jpg', network_frame, encode_param)

    if result:
        try:
            frame_bytes = encoded_image.tobytes()
            
            nonce_v = os.urandom(12)
            encrypted_vid = aesgcm.encrypt(nonce_v, frame_bytes, associated_data=None)
            payload_v = nonce_v + encrypted_vid
            
            udp_sock.sendto(payload_v, (VM_IP, VIDEO_UDP_PORT))
        except Exception as e:
            print(f"[DEBUG] Video Frame Dropped (Too Large): {e}")

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()