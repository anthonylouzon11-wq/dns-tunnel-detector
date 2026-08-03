# DNS Tunneling Detector

Real-time DNS anomaly detection using entropy analysis and beaconing interval detection.

## Run
`ash
sudo python3 dns_tunnel_detector.py
``n
## Detection Logic
- High entropy (>4.0) = encoded data
- Long queries (>50 chars) = data exfiltration
- Beaconing intervals = C2 communication
