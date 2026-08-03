# dns_tunnel_detector.py
from scapy.all import sniff, DNSQR
import math, datetime, collections

def entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log(p) / math.log(2) for p in prob) if prob else 0

query_log = collections.defaultdict(list)

def dns_callback(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode().rstrip('.')
        domain = '.'.join(qname.split('.')[-2:])
        length = len(qname)
        ent = entropy(qname)
        now = datetime.datetime.now()
        
        score = 0
        if length > 50: score += 1
        if ent > 4.0: score += 1
        
        query_log[domain].append(now)
        if len(query_log[domain]) > 10:
            times = query_log[domain][-10:]
            intervals = [(times[i]-times[i-1]).seconds for i in range(1,len(times))]
            if len(set(intervals)) <= 3 and len(intervals) >= 5:
                score += 2
        
        if score >= 2:
            print(f"[ALERT] {now.strftime('%H:%M:%S')} | {qname} | Len:{length} | Ent:{ent:.2f} | Score:{score}")

print("Listening for DNS tunneling... Ctrl+C to stop")
print("Try: ping google.com in another terminal to generate traffic")
sniff(filter="udp port 53", prn=dns_callback, store=0)
