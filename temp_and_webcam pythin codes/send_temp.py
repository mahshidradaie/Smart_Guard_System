import socket
import time
import wmi

VM_IP = "192.168.118.130"
UDP_PORT = 8892
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("Connecting to Windows Hardware Sensors...")

try:
    w = wmi.WMI(namespace="root\\OpenHardwareMonitor")
except Exception as e:
    print("ERROR: Could not connect to sensors.")
    print("Please make sure Open Hardware Monitor is running as Administrator!")
    exit()

print(f"Success! Sending REAL live host temperature to {VM_IP}:{UDP_PORT}...")

try:
    while True:
        temperature = None
        
        hardware_infos = w.Sensor()
        
        for sensor in hardware_infos:
            if sensor.SensorType == 'Temperature' and 'CPU' in sensor.Name:
                temperature = sensor.Value
                break # Grab the first CPU temp sensor found
        
        if temperature is not None:
        
            temp_string = f"{temperature:.1f}"
            sock.sendto(temp_string.encode(), (VM_IP, UDP_PORT))
            print(f"Transmitting Real CPU Temp: {temp_string}°C")
        else:
            print("Could not find a valid CPU temperature sensor.")
        
 
        time.sleep(2)

except KeyboardInterrupt:
    print("\nStopped sending telemetry.")
    sock.close()