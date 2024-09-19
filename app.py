from flask import Flask, render_template, request, redirect, url_for
from selenium import webdriver
from datetime import datetime
import threading,webbrowser
import requests
import time
import os
import hashlib

ServiceName = "VirusTotal Scan"
API_KEY = 'a8084c5dfb91ac17e34c90f7ec51dbd46a967479a75ce71fa9f4412e47d81db3'
app = Flask(__name__, static_url_path='/static')

#ハッシュ値を計算する
def file_sha256(file):
    file.seek(0)
    sha256 = hashlib.sha256(file.read()).hexdigest()
    return sha256
#スクリーンショットを撮る
def get_screenshot(url):
    driver = webdriver.PhantomJS(executable_path="static/img/phantomjs.exe",service_log_path=os.path.devnull)
    driver.get(url)
    driver.save_screenshot("static/img/tmp.jpg")
    driver.quit()

def interpret_behavior(malware_type):
    behavior_descriptions = {
        "virus": {
            "name": "ウイルス",
            "description": "自己複製し、感染したファイルやシステムを変更します。",
            "actions": [
                "起動や動作速度の低下",
                "警告メッセージの表示",
                "データの破壊・削除"
            ],
            "risk_level": "高",
            "recommendation": "不審なファイルを削除し、システム全体をスキャンしてください。"
        },
        "trojan": {
            "name": "トロイの木馬",
            "description": "正当なソフトウェアを装い、システムに侵入後、不正な操作を行います。",
            "actions": [
                "外部からのリモートアクセスを許可",
                "システム設定の改変",
                "機密情報の窃取"
            ],
            "risk_level": "高",
            "recommendation": "不審なファイルを削除し、システム全体をスキャンしてください。"
        },
        "worm": {
            "name": "ワーム",
            "description": "ネットワークを通じて自己複製し、システム全体に感染を広げます。",
            "actions": [
                "自己複製と拡散",
                "ネットワークトラフィックの増加",
                "システムリソースの消耗"
            ],
            "risk_level": "中",
            "recommendation": "感染拡大を防ぐためにネットワークを監視し、感染源を除去してください。"
        },
        "ransomware": {
            "name": "ランサムウェア",
            "description": "システム内のファイルを暗号化し、復号化のために身代金を要求します。",
            "actions": [
                "ファイルの暗号化",
                "ランサムメッセージの表示",
                "暗号鍵の外部サーバ送信"
            ],
            "risk_level": "非常に高い",
            "recommendation": "直ちにネットワークを切断し、バックアップからシステムを復旧してください。"
        },
        "spyware": {
            "name": "スパイウェア",
            "description": "ユーザーの活動を密かに監視し、機密情報を収集します。",
            "actions": [
                "キーストロークの記録",
                "スクリーンショットの撮影",
                "ブラウジング履歴の収集"
            ],
            "risk_level": "高",
            "recommendation": "スパイウェアの駆除ツールを使用して、システム全体をスキャンしてください。"
        },
        "adware": {
            "name": "アドウェア",
            "description": "不要な広告を表示し、ユーザーの操作を妨げます。",
            "actions": [
                "広告の表示",
                "ブラウザのリダイレクト",
                "ユーザーのクリック行動の追跡"
            ],
            "risk_level": "低",
            "recommendation": "信頼できるアンチウイルスソフトを使用して、アドウェアを削除してください。"
        },
        "backdoor": {
            "name": "バックドア",
            "description": "攻撃者がシステムに密かにアクセスできるようにする不正な入口を作ります。",
            "actions": [
                "リモートアクセスの確立",
                "機密情報の窃取",
                "システム設定の変更"
            ],
            "risk_level": "高",
            "recommendation": "システムのセキュリティ設定を見直し、不審なプロセスやポートを確認してください。"
        },
        "rootkit": {
            "name": "ルートキット",
            "description": "システムに深く潜伏し、不正な操作を隠蔽します。",
            "actions": [
                "システム権限の奪取",
                "ログの改ざん",
                "アンチウイルスソフトの無効化"
            ],
            "risk_level": "非常に高い",
            "recommendation": "専門的なツールを使用して、システム全体をクリーンアップしてください。"
        },
        "bot": {
            "name": "ボット",
            "description": "システムをリモートで操作可能な状態にし、ボットネットの一部として使用します。",
            "actions": [
                "スパムメールの送信",
                "DDoS攻撃への参加",
                "リモートコマンドの実行"
            ],
            "risk_level": "高",
            "recommendation": "ネットワークトラフィックを監視し、不審な動作を検出してください。"
        },
        "keylogger": {
            "name": "キーロガー",
            "description": "ユーザーのキーストロークを記録し、入力されたデータを窃取します。",
            "actions": [
                "キーストロークの記録",
                "ログイン情報の窃取",
                "機密データの送信"
            ],
            "risk_level": "高",
            "recommendation": "アンチスパイウェアツールを使用して、キーロガーを検出および削除してください。"
        },
        "dropper": {
            "name": "ドロッパー",
            "description": "他のマルウェアをシステムに感染させます。",
            "actions": [
                "セキュリティのバイパス",
                "リモートアクセス",
                "データの破損や暗号化"
            ],
            "risk_level": "高",
            "recommendation": "感染が疑われるファイルやプロセスを隔離し、システムをネットワークから切断して、システムをスキャンしてください。"
        },
        "exploit": {
            "name": "エクスプロイト",
            "description": "システムやソフトウェアの脆弱性を悪用して、不正な操作を行います。",
            "actions": [
                "脆弱性の悪用",
                "システムのクラッシュ",
                "不正なコードの実行"
            ],
            "risk_level": "非常に高い",
            "recommendation": "システムやソフトウェアを最新の状態に保ち、脆弱性を修正してください。"
        },
        "phishing": {
            "name": "フィッシング",
            "description": "偽のウェブサイトやメッセージを使用して、ユーザーの個人情報を詐取します。",
            "actions": [
                "偽のログインページへの誘導",
                "個人情報の窃取",
                "偽装メッセージの送信"
            ],
            "risk_level": "中",
            "recommendation": "不審なリンクをクリックしないよう注意し、二要素認証を設定してください。"
        },
        "malware": {
            "name": "マルウェア",
            "description": "コンピュータやネットワークに悪影響を及ぼすプログラム",
            "actions": [
                "データの損失と暗号化",
                "個人情報の窃取",
                "システムの制御喪失"
            ],
            "risk_level": "非常に高い",
            "recommendation": "感染が疑われるファイルやプロセスを隔離し、システムをネットワークから切断して、システムをスキャンしてください。"
        },
        "xss": {
            "name": "クロスサイトスクリプティング",
            "description": "ユーザーのブラウザで悪意のあるスクリプトを実行させるための脆弱性を持つサイトです。",
            "actions": [
                "個人情報の窃取",
                "ウェブアプリケーションの改ざん",
                "フィッシング攻撃"
            ],
            "risk_level": "中",
            "recommendation": "影響を受けたシステムをネットワークから切断し、システムをスキャンしてください。"
        },
        "fraud": {
            "name": "詐欺",
            "description": "ユーザーを騙して金銭を詐取します。",
            "actions": [
                "偽のセキュリティ警告の表示",
                "金銭の詐取"
            ],
            "risk_level": "低",
            "recommendation": "偽の警告を無視し、信頼できるセキュリティソフトを使用してください。"
        },
        "scareware": {
            "name": "スケアウェア",
            "description": "偽の警告を表示し、不要なソフトウェアを購入させようとします。",
            "actions": [
                "偽のセキュリティ警告の表示",
                "不正なソフトウェアのインストール促進",
                "金銭の詐取"
            ],
            "risk_level": "低",
            "recommendation": "偽の警告を無視し、信頼できるセキュリティソフトを使用してください。"
        },
        "cryptominer": {
            "name": "クリプトマイナー",
            "description": "システムのリソースを使用して、仮想通貨を不正に採掘します。",
            "actions": [
                "CPU/GPUのリソース消耗",
                "システムのパフォーマンス低下",
                "電力消費の増加"
            ],
            "risk_level": "中",
            "recommendation": "不審なプロセスを停止し、システムをスキャンしてください。"
        },
        "pup": {
            "name": "PUP（望ましくない可能性のあるプログラム）",
            "description": "ユーザーが意図せずにインストールした、不要なソフトウェアです。",
            "actions": [
                "ブラウザ設定の変更",
                "広告の表示",
                "システムパフォーマンスの低下"
            ],
            "risk_level": "低",
            "recommendation": "不要なソフトウェアを削除し、ブラウザ設定をリセットしてください。"
        },
        "c2": {
            "name": "c2",
            "description": "攻撃者が感染したコンピュータをリモートで操作するために使用します。",
            "actions": [
                "リモート操作",
                "データの流出",
                "ネットワーク内の拡張"
            ],
            "risk_level": "高",
            "recommendation": "感染が疑われるファイルやプロセスを隔離し、システムをネットワークから切断して、システムをスキャンしてください。"
        },
        "riskware": {
            "name": "リスクウェア",
            "description": "意図的に悪意のあるソフトウェアではなく、通常のソフトウェアやツールであっても、セキュリティリスクを引き起こす可能性があるプログラムです。",
            "actions": [
                "データ漏洩",
                "セキュリティホールの悪用",
                "システムのパフォーマンス低下"
            ],
            "risk_level": "高",
            "recommendation": "システムをスキャンしてください。"
        },
        "spam": {
            "name": "スパム",
            "description": "不審なファイルやURL",
            "actions": [
                "フィッシング詐欺",
                "マルウェアの配布",
                "リソースの消費"
            ],
            "risk_level": "中",
            "recommendation": "システムをスキャンしてください。"
        },
        "drive-by download": {
            "name": "ドライブバイダウンロード",
            "description": "ユーザーが意図せずにマルウェアをダウンロードさせます。",
            "actions": [
                "マルウェアの感染",
                "個人情報の漏洩",
                "ネットワークのセキュリティリスク"
            ],
            "risk_level": "高",
            "recommendation": "感染が疑われるファイルやプロセスを隔離し、システムをネットワークから切断して、システムをスキャンしてください。"
        },
        "rat": {
            "name": "リモートアクセスツール",
            "description": "リモートでユーザーのコンピュータにアクセスするためのツールをダウンロードさせます。",
            "actions": [
                "データの窃取",
                "システムの完全な制御",
                "監視とスパイ行為"
            ],
            "risk_level": "中",
            "recommendation": "システムをスキャンしてください。"
        },
        "something threat": {
            "name": "何らかの脅威",
            "description": "このファイルの動作は不明です。",
            "actions": [
                "不明"
            ],
            "risk_level": "不明",
            "recommendation": "専門家に相談してください。"
        },
        "unknown": {
            "name": "なし",
            "description": "安全な可能性が高いです。",
            "actions": [
                "なし"
            ],
            "risk_level": "低",
            "recommendation": "なし"
        }
    }
    return behavior_descriptions.get(malware_type, behavior_descriptions["unknown"])
#マルウェアタイプの分析
def interpret_results(result):
    sum=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    malware_type = ["virus","trojan","worm","ransomware","spyware","adware","backdoor","rootkit","bot","keylogger","dropper","exploit","phishing",
                    "xss","fraud","scareware","cryptominer","pup","c2","riskware","spam","drive-by download","rat","malware","something threat","unknown"]
    for engine, details in result.items():
        if details["result"] and details["result"].lower().find("virus")>=0:
            sum[0]=sum[0]+1
        elif details["result"] and details["result"].lower().find("trojan")>=0:
            sum[1]=sum[1]+1
        elif details["result"] and details["result"].lower().find("worm")>=0:
            sum[2]=sum[2]+1
        elif details["result"] and details["result"].lower().find("ransomware")>=0:
            sum[3]=sum[3]+1
        elif details["result"] and (details["result"].lower().find("spyware")>=0 or "data harvesting" in details["result"].lower() or "information theft" in details["result"].lower()):
            sum[4]=sum[4]+1
        elif details["result"] and (details["result"].lower().find("adware")>=0 or "advertising" in details["result"].lower()):
            sum[5]=sum[5]+1
        elif details["result"] and details["result"].lower().find("backdoor")>=0:
            sum[6]=sum[6]+1
        elif details["result"] and details["result"].lower().find("rootkit")>=0:
            sum[7]=sum[7]+1
        elif details["result"] and details["result"].lower().find("bot")>=0:
            sum[8]=sum[8]+1
        elif details["result"] and details["result"].lower().find("keylogger")>=0:
            sum[9]=sum[9]+1
        elif details["result"] and details["result"].lower().find("dropper")>=0:
            sum[10]=sum[10]+1
        elif details["result"] and details["result"].lower().find("exploit")>=0:
            sum[11]=sum[11]+1
        elif details["result"] and (details["result"].lower().find("phishing")>=0 or details["result"].lower().find("fraudulent")>=0 or "fake site" in details["result"].lower()):
            sum[12]=sum[12]+1
        elif details["result"] and details["result"].lower().find("xss")>=0:
            sum[13]=sum[13]+1
        elif details["result"] and (details["result"].lower().find("fraud")>=0 or details["result"].lower().find("scam")>=0):
            sum[14]=sum[14]+1
        elif details["result"] and details["result"].lower().find("scareware")>=0:
            sum[15]=sum[15]+1
        elif details["result"] and (details["result"].lower().find("crypto")>=0 or "mining" in details["result"].lower()):
            sum[16]=sum[16]+1
        elif details["result"] and (details["result"].lower().find("pup")>=0 or "potentially unwanted program" in details["result"].lower()):
            sum[17]=sum[17]+1
        elif details["result"] and (details["result"].lower().find("c2")>=0 or "command and control" in details["result"].lower()):
            sum[18]=sum[18]+1
        elif details["result"] and details["result"].lower().find("riskware")>=0:
            sum[19]=sum[19]+1
        elif details["result"] and details["result"].lower().find("spam")>=0:
            sum[20]=sum[20]+1
        elif details["result"] and details["result"].lower().find("drive-by download")>=0:
            sum[21]=sum[21]+1
        elif details["result"] and details["result"].lower().find("rat")>=0 and not("unrated" in details["result"].lower()):
            sum[22]=sum[22]+1
        elif details["result"] and details["result"].lower().find("malware")>=0:
            sum[23]=sum[23]+1
        elif details["result"] and (details["result"].lower().find("malicious")>=0 or details["result"].lower().find("threat")>=0
                                    or details["result"].lower().find("suspicious")>=0 or details["result"].lower().find("unwanted")>=0):
            sum[24]=sum[24]+1
    max_i=0
    for i in range(1,23):
        if sum[max_i]<sum[i]:
            max_i=i
    if sum[max_i]==0:
        if sum[24]>0:
            max_i=24
        else:
            max_i=25
    behavior_info = interpret_behavior(malware_type[max_i])
    return behavior_info
#URLの分析
def analyze_url(data):
    url = data['data']['attributes']['url']
    get_screenshot(url)
    timestamp = data['data']['attributes']['last_analysis_date']
    date = datetime.datetime.fromtimestamp(timestamp)
    malicious=data['data']['attributes']['last_analysis_stats']['malicious']
    suspicious=data['data']['attributes']['last_analysis_stats']['suspicious']
    undetected=data['data']['attributes']['last_analysis_stats']['undetected']
    harmless=data['data']['attributes']['last_analysis_stats']['harmless']
    timeout=data['data']['attributes']['last_analysis_stats']['timeout']
    details=data["data"]["attributes"]["last_analysis_results"]
    behavior_info=interpret_results(data["data"]["attributes"]["last_analysis_results"])
    name=behavior_info["name"]
    description=behavior_info["description"]
    actions=behavior_info["actions"]
    risk_level=behavior_info["risk_level"]
    recommendation=behavior_info["recommendation"]
    analyze_data={"url":url,"date":date,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":0,"failure":0,"type_unsupported":0,
                "name":name,"description":description,"actions":actions,"risk_level":risk_level,"recommendation":recommendation}
    return analyze_data,details
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
    details=data["data"]["attributes"]["results"]
    behavior_info=interpret_results(data["data"]["attributes"]["results"])
    name=behavior_info["name"]
    description=behavior_info["description"]
    actions=behavior_info["actions"]
    risk_level=behavior_info["risk_level"]
    recommendation=behavior_info["recommendation"]
    analyze_data={"date":date,"size":size,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":confirmed_timeout,"failure":failure,"type_unsupported":type_unsupported,
                "name":name,"description":description,"actions":actions,"risk_level":risk_level,"recommendation":recommendation}
    return analyze_data,details
#ファイルハッシュの分析
def analyze_hash(data):
    timestamp = data['data']['attributes']['last_analysis_date']
    date = datetime.datetime.fromtimestamp(timestamp)
    size = data['data']['attributes']['size']
    filename = data['data']['attributes']['meaningful_name']
    malicious=data['data']['attributes']['last_analysis_stats']['malicious']
    suspicious=data['data']['attributes']['last_analysis_stats']['suspicious']
    undetected=data['data']['attributes']['last_analysis_stats']['undetected']
    harmless=data['data']['attributes']['last_analysis_stats']['harmless']
    timeout=data['data']['attributes']['last_analysis_stats']['timeout']
    confirmed_timeout=data['data']['attributes']['last_analysis_stats']['confirmed-timeout']
    failure=data['data']['attributes']['last_analysis_stats']['failure']
    type_unsupported=data['data']['attributes']['last_analysis_stats']['type-unsupported']
    details=data["data"]["attributes"]["last_analysis_results"]
    behavior_info=interpret_results(data["data"]["attributes"]["last_analysis_results"])
    name=behavior_info["name"]
    description=behavior_info["description"]
    actions=behavior_info["actions"]
    risk_level=behavior_info["risk_level"]
    recommendation=behavior_info["recommendation"]
    analyze_data={"date":date,"size":size,"filename":filename,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":confirmed_timeout,"failure":failure,"type_unsupported":type_unsupported,
                "name":name,"description":description,"actions":actions,"risk_level":risk_level,"recommendation":recommendation}
    return analyze_data,details
#IPアドレスの分析
def analyze_ip(data):
    timestamp = data['data']['attributes'].get('last_analysis_date', 'Unknown')
    if timestamp == "Unknown":
        date = "不明"
    else:
        date = datetime.datetime.fromtimestamp(timestamp)
    malicious=data['data']['attributes']['last_analysis_stats']['malicious']
    suspicious=data['data']['attributes']['last_analysis_stats']['suspicious']
    undetected=data['data']['attributes']['last_analysis_stats']['undetected']
    harmless=data['data']['attributes']['last_analysis_stats']['harmless']
    timeout=data['data']['attributes']['last_analysis_stats']['timeout']
    country = data['data']['attributes'].get('country', 'Unknown')
    isp = data['data']['attributes'].get('asn', 'Unknown')
    details=data["data"]["attributes"]["last_analysis_results"]
    behavior_info=interpret_results(data["data"]["attributes"]["last_analysis_results"])
    name=behavior_info["name"]
    description=behavior_info["description"]
    actions=behavior_info["actions"]
    risk_level=behavior_info["risk_level"]
    recommendation=behavior_info["recommendation"]
    analyze_data={"date":date,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":0,"failure":0,"type_unsupported":0,
                "country":country,"isp":isp,
                "name":name,"description":description,"actions":actions,"risk_level":risk_level,"recommendation":recommendation}
    return analyze_data,details
#ドメインの分析
def analyze_domain(data):
    timestamp = data['data']['attributes']['last_analysis_date']
    date = datetime.datetime.fromtimestamp(timestamp)
    malicious=data['data']['attributes']['last_analysis_stats']['malicious']
    suspicious=data['data']['attributes']['last_analysis_stats']['suspicious']
    undetected=data['data']['attributes']['last_analysis_stats']['undetected']
    harmless=data['data']['attributes']['last_analysis_stats']['harmless']
    timeout=data['data']['attributes']['last_analysis_stats']['timeout']
    details=data["data"]["attributes"]["last_analysis_results"]
    behavior_info=interpret_results(data["data"]["attributes"]["last_analysis_results"])
    name=behavior_info["name"]
    description=behavior_info["description"]
    actions=behavior_info["actions"]
    risk_level=behavior_info["risk_level"]
    recommendation=behavior_info["recommendation"]
    analyze_data={"date":date,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":0,"failure":0,"type_unsupported":0,
                "name":name,"description":description,"actions":actions,"risk_level":risk_level,"recommendation":recommendation}
    return analyze_data,details
#ホーム画面
@app.route('/')
def index():
    return render_template('index.html',ServiceName = ServiceName)
#Q&A
@app.route('/support')
def support():
    return render_template('support.html',ServiceName = ServiceName)
#お問い合わせ
@app.route('/contact')
def contact():
    return render_template('contact.html',ServiceName = ServiceName)
@app.route('/submit', methods=['POST'])
def submit():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        # 問い合わせ内容をファイルに保存
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open('inquiries.txt', 'a', encoding='utf-8') as f:
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Name: {name}\n")
            f.write(f"Email: {email}\n")
            f.write(f"Message: {message}\n")
            f.write("-" * 50 + "\n")
        
        return render_template('thank_you.html', name=name,ServiceName = ServiceName)
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
        analysis_id = result['data']['id'].split('-')[1]
        return redirect(url_for('get_results', analysis_id=analysis_id,scan="url"))
    else:
        return redirect(url_for('error',message=f"URLのスキャン中にエラーが発生しました: {response.status_code}"))
#ファイルが入力された場合の処理
@app.route('/scan_file', methods=['POST'])
def scan_file():
    file = request.files['file']
    ck = request.form.get('check')
    headers = {
        'x-apikey': API_KEY
        }
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
#ハッシュが入力された場合の処理
@app.route('/scan_hash', methods=['POST'])
def scan_hash():
    hash = request.form['hash']
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
    headers = {
        'x-apikey': API_KEY
    }
    #URL
    if scan == "url":
        url = f'https://www.virustotal.com/api/v3/urls/{analysis_id}'
        while True:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                analyzed_result,details=analyze_url(result)
                return render_template('result.html', summary=analyzed_result,ServiceName=ServiceName,scan=scan,details=details)
            elif response.status_code == 204 or response.status_code == 404:
                time.sleep(10)
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
                    analyzed_result,details=analyze_file(result)
                    return render_template('result.html', summary=analyzed_result,ServiceName=ServiceName,scan=scan,details=details)
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
                            analyzed_result,details=analyze_hash(result)
                            return render_template('result.html', summary=analyzed_result,ServiceName=ServiceName,scan=scan,details=details)
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
                    analyzed_result,details=analyze_ip(result)
                    return render_template('result.html', summary=analyzed_result,ServiceName=ServiceName,scan=scan,details=details)
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
                        analyzed_result,details=analyze_domain(result)
                        return render_template('result.html', summary=analyzed_result,ServiceName=ServiceName,scan=scan,details=details)
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
