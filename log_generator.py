import random
import time
from datetime import datetime, timedelta

def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.93 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 9; SM-J320F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Mobile Safari/537.36',
]

sql_injection_patterns = [
    "/search?q=%27%20OR%201%3D1%3B--",
    "/search?q=%27%20DROP%20TABLE%20users%3B--"
]

normal_paths = [
    "/", "/index.html", "/about", "/contact", "/products", "/services", "/blog", "/login", "/register"
]

def generate_log_entry(timestamp):
    ip = generate_ip()
    user_agent = random.choice(user_agents)
    
    if random.random() > 0.8:  # 20% chance of failed login
        status = 401
        path = "/login"
        method = "POST"
    elif random.random() > 0.95:  # 5% chance of SQL injection attempt
        status = 200
        path = random.choice(sql_injection_patterns)
        method = "GET"
    else:
        status = 200
        path = random.choice(normal_paths)
        method = "GET"
    
    size = random.randint(1000, 10000)
    
    log_entry = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {size}'
    return log_entry

# Generate logs
start_time = datetime.now() - timedelta(days=1)  # Start logs from 24 hours ago
with open("sample_access.log", "w") as f:
    for _ in range(1000):  # Generate 1000 log entries
        timestamp = start_time + timedelta(seconds=random.randint(0, 86400))  # Random time within last 24 hours
        log_entry = generate_log_entry(timestamp)
        f.write(log_entry + "\n")

print("Sample log file 'sample_access.log' has been generated.")