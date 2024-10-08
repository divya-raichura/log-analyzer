from flask import Flask, request, jsonify, render_template
import pandas as pd
import re

app = Flask(__name__)

def parse_log_line(line):
    # Improved regular expression to handle log parsing with correct grouping
    pattern = r'(\S+) - - \[(.*?)\] "(GET|POST|PUT|DELETE) (.*?) HTTP/1\.1" (\d{3}) (\d+)'
    match = re.match(pattern, line)
    if match:
        ip, timestamp, method, path, status, size = match.groups()
        return {
            'ip': ip,
            'timestamp': pd.to_datetime(timestamp, format='%d/%b/%Y:%H:%M:%S %z'),
            'method': method,
            'path': path,
            'status': int(status),
            'size': int(size)
        }
    return None

def analyze_log(log_content):
    log_lines = log_content.strip().split('\n')
    log_data = [parse_log_line(line) for line in log_lines if parse_log_line(line)]
    
    if len(log_data) == 0:
        return {'error': 'No valid log entries found'}
    
    df = pd.DataFrame(log_data)
    
    analysis = {}
    
    # Unique IP addresses
    analysis['unique_ips'] = df['ip'].nunique()
    
    # Top 5 IP addresses
    analysis['top_ips'] = df['ip'].value_counts().head(5).to_dict()
    
    # HTTP status codes
    analysis['status_codes'] = df['status'].value_counts().to_dict()
    
    # Failed logins (assuming 401 status code)
    failed_logins = df[df['status'] == 401]
    analysis['failed_logins'] = len(failed_logins)
    
    # Potential brute force attempts (more than 10 failed logins from same IP)
    potential_brute_force = failed_logins['ip'].value_counts()
    analysis['potential_brute_force'] = potential_brute_force[potential_brute_force > 10].to_dict()
    
    # Potential SQL injection attempts
    sql_injection_pattern = r"(%27|')|(--|#)|(%23)|(\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b)"
    potential_sql_injection = df[df['path'].str.contains(sql_injection_pattern, regex=True, na=False)]
    analysis['potential_sql_injection'] = len(potential_sql_injection)
    
    # Requests over time data
    requests_over_time = df.groupby(df['timestamp'].dt.floor('h')).size().reset_index(name='count')
    requests_over_time['timestamp'] = requests_over_time['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    analysis['requests_over_time'] = requests_over_time.to_dict(orient='records')
    
    return analysis

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file:
        log_content = file.read().decode('utf-8')
        analysis_result = analyze_log(log_content)
        return jsonify(analysis_result)

if __name__ == '__main__':
    app.run(debug=True)
