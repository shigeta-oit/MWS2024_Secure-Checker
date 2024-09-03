from flask import Flask, render_template, request, redirect, url_for
from selenium import webdriver
import datetime
import threading,webbrowser
import requests
import time
import os
import hashlib

ServiceName = "VirusTotal Scan"
API_KEY = '64a2e867d722327cc2f8372ec04f3c74fda01dc218414f9386632986c5160f21'
app = Flask(__name__, static_url_path='/static')

#ハッシュ値を計算する
def file_sha256(file):
    file.seek(0)
    sha256 = hashlib.sha256(file.read()).hexdigest()
    return sha256
#スクリーンショットを撮る
def get_screenshot(url):
    driver = webdriver.PhantomJS(service_log_path=os.path.devnull)
    driver.get(url)
    driver.save_screenshot("static/img/tmp.jpg")
    driver.quit()
#URLの分析
def analyze_url(data):
    url = data['meta']['url_info']['url']
    get_screenshot(url)
    timestamp = data['data']['attributes']['date']
    date = datetime.datetime.fromtimestamp(timestamp)
    malicious=data['data']['attributes']['stats']['malicious']
    suspicious=data['data']['attributes']['stats']['suspicious']
    undetected=data['data']['attributes']['stats']['undetected']
    harmless=data['data']['attributes']['stats']['harmless']
    timeout=data['data']['attributes']['stats']['timeout']
    analyze_data={"url":url,"date":date,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,"timeout":timeout}
    return analyze_data
#ファイルの分析
def analyze_file(data):
    timestamp = data['data']['attributes']['date']
    date = datetime.datetime.fromtimestamp(timestamp)
    size = data['meta']['file_info']['size']
    malicious=data['data']['attributes']['stats']['malicious']
    suspicious=data['data']['attributes']['stats']['suspicious']
    undetected=data['data']['attributes']['stats']['undetected']
    harmless=data['data']['attributes']['stats']['harmless']
    timeout=data['data']['attributes']['stats']['timeout']
    confirmed_timeout=data['data']['attributes']['stats']['confirmed-timeout']
    failure=data['data']['attributes']['stats']['failure']
    type_unsupported=data['data']['attributes']['stats']['type-unsupported']
    analyze_data={"date":date,"size":size,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":confirmed_timeout,"failure":failure,"type_unsupported":type_unsupported}
    return analyze_data
#ファイルハッシュの分析
def analyze_hash(data):
    timestamp = data['data']['attributes']['last_analysis_date']
    date = datetime.datetime.fromtimestamp(timestamp)
    size = data['data']['attributes']['size']
    name = data['data']['attributes']['meaningful_name']
    malicious=data['data']['attributes']['last_analysis_stats']['malicious']
    suspicious=data['data']['attributes']['last_analysis_stats']['suspicious']
    undetected=data['data']['attributes']['last_analysis_stats']['undetected']
    harmless=data['data']['attributes']['last_analysis_stats']['harmless']
    timeout=data['data']['attributes']['last_analysis_stats']['timeout']
    confirmed_timeout=data['data']['attributes']['last_analysis_stats']['confirmed-timeout']
    failure=data['data']['attributes']['last_analysis_stats']['failure']
    type_unsupported=data['data']['attributes']['last_analysis_stats']['type-unsupported']
    analyze_data={"date":date,"size":size,"name":name,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":confirmed_timeout,"failure":failure,"type_unsupported":type_unsupported}
    return analyze_data
#IPアドレスの分析
def analyze_ip(data):
    timestamp = data['data']['attributes']['last_analysis_date']
    date = datetime.datetime.fromtimestamp(timestamp)
    malicious=data['data']['attributes']['last_analysis_stats']['malicious']
    suspicious=data['data']['attributes']['last_analysis_stats']['suspicious']
    undetected=data['data']['attributes']['last_analysis_stats']['undetected']
    harmless=data['data']['attributes']['last_analysis_stats']['harmless']
    timeout=data['data']['attributes']['last_analysis_stats']['timeout']
    analyze_data={"date":date,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,"timeout":timeout}
    return analyze_data
#ドメインの分析
def analyze_domain(data):
    timestamp = data['data']['attributes']['last_analysis_date']
    date = datetime.datetime.fromtimestamp(timestamp)
    malicious=data['data']['attributes']['last_analysis_stats']['malicious']
    suspicious=data['data']['attributes']['last_analysis_stats']['suspicious']
    undetected=data['data']['attributes']['last_analysis_stats']['undetected']
    harmless=data['data']['attributes']['last_analysis_stats']['harmless']
    timeout=data['data']['attributes']['last_analysis_stats']['timeout']
    analyze_data={"date":date,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,"timeout":timeout}
    return analyze_data
#ホーム画面
@app.route('/')
def index():
    return render_template('index.html',ServiceName = ServiceName)
#よくあるご質問
@app.route('/support')
def support():
    return render_template('support.html',ServiceName = ServiceName)
#お問い合わせ
@app.route('/contact')
def contact():
    return render_template('contact.html',ServiceName = ServiceName)
#URLが入力された場合の処理
@app.route('/scan_url', methods=['POST'])
def scan_url():
    url_to_scan = request.form['url']
    url = 'https://www.virustotal.com/api/v3/urls'
    headers = {
        'x-apikey': API_KEY
    }
    params = {'url': url_to_scan}
    response = requests.post(url, headers=headers, data=params)
    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        return redirect(url_for('get_results', analysis_id=analysis_id,scan="url"))
    else:
        return redirect(url_for('error',message=f"URLのスキャン中にエラーが発生しました: {response.status_code}"))
#ファイルが入力された場合の処理
@app.route('/scan_file', methods=['POST'])
def scan_file():
    file = request.files['file']
    ck = request.form.get('check')
    headers = {'x-apikey': API_KEY}
    if ck != "on":
        url = 'https://www.virustotal.com/api/v3/files'
        headers = {
            'x-apikey': API_KEY
        }
        files = {'file': (file.filename, file.stream, file.mimetype)}
        response = requests.post(url, headers=headers, files=files)
        
        if response.status_code == 200:
            result = response.json()
            analysis_id = result['data']['id']
            return redirect(url_for('get_results', analysis_id=analysis_id,scan="file"))
        else:
            return redirect(url_for('error',message=f"ファイルのスキャン中にエラーが発生しました: {response.status_code}"))
    else:
        hash=file_sha256(file)
        return redirect(url_for('get_results', analysis_id=hash,scan="hash"))
#IPアドレスが入力された場合の処理
@app.route('/scan_ip', methods=['POST'])
def scan_ip():
    ip = request.form['ip']
    if ip=="":
        return redirect(url_for('error',message="IPアドレスを入力してください"))
    return redirect(url_for('get_results', analysis_id=ip,scan="ip"))
#ドメインが入力された場合の処理
@app.route('/scan_domain', methods=['POST'])
def scan_domain():
    domain = request.form['domain']
    if domain=="":
        return redirect(url_for('error',message="ドメインを入力してください"))
    return redirect(url_for('get_results', analysis_id=domain,scan="domain"))
#分析結果の取得と結果の表示
@app.route('/results/<scan>/<analysis_id>')
def get_results(analysis_id,scan):
    headers = {'x-apikey': API_KEY}
    #URL
    if scan == "url":
        url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        while True:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if result['data']['attributes']['status'] == 'completed':
                    analyzed_result=analyze_url(result)
                    return render_template('result.html', summary=analyzed_result,ServiceName = ServiceName,scan=scan)
                else:
                    time.sleep(5)
            else:
                return redirect(url_for('error',message=f"エラー: {response.status_code}"))
    #ファイル
    elif scan == "file":
        url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        while True:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if result['data']['attributes']['status'] == 'completed':
                    analyzed_result=analyze_file(result)
                    return render_template('result.html', summary=analyzed_result,ServiceName = ServiceName,scan=scan)
                else:
                    time.sleep(5)
            else:
                return redirect(url_for('error',message=f"エラー: {response.status_code}"))
    #ファイルハッシュ
    elif scan == "hash":
        url=f'https://www.virustotal.com/api/v3/files/{analysis_id}'
        while True:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if 'data' in result and 'attributes' in result['data']:
                    if 'last_analysis_stats' in result['data']['attributes']:
                        analysis_stats = result['data']['attributes']['last_analysis_stats']
                        if analysis_stats['malicious'] > 0 or analysis_stats['undetected'] > 0:
                            analyzed_result=analyze_hash(result)
                            return render_template('result.html', summary=analyzed_result,ServiceName = ServiceName,scan=scan)
                else:
                    time.sleep(5)
            else:
                return redirect(url_for('error',message=f"エラー:ファイルのデータが見つかりませんでした {response.status_code}"))
    #IPアドレス
    elif scan == "ip":
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{analysis_id}'
        while True:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if 'data' in result and result['data']['attributes']['last_analysis_stats']['malicious'] == 0:
                    analyzed_result=analyze_ip(result)
                    return render_template('result.html', summary=analyzed_result,ServiceName = ServiceName,scan=scan)
                else:
                    time.sleep(5)
            else:
                return redirect(url_for('error',message=f"エラー: {response.status_code}"))
    #ドメイン
    elif scan == "domain":
        url = f'https://www.virustotal.com/api/v3/domains/{analysis_id}'
        while True:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    analysis_stats = result['data']['attributes']['last_analysis_stats']
                    if analysis_stats['malicious'] > 0 or analysis_stats['undetected'] > 0:
                        analyzed_result=analyze_domain(result)
                        return render_template('result.html', summary=analyzed_result,ServiceName = ServiceName,scan=scan)
                else:
                        time.sleep(5)
            else:
                return redirect(url_for('error',message=f"エラー: {response.status_code}"))
#エラー画面の表示
@app.route('/error/<message>')
def error(message):
    return render_template('error.html',ServiceName = ServiceName,message=message)

if __name__ == '__main__':
    #threading.Timer(1.0, lambda: webbrowser.open('http://localhost:5000') ).start()
    #app.run(debug=False)
    app.run(debug=True)
