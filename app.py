from flask import Flask, render_template, request, redirect, url_for, jsonify
from selenium import webdriver
import datetime
import threading,webbrowser
import requests
import time
import os
import hashlib
import re
import subprocess
import socket
from urllib.parse import urlparse
import validators
import ipaddress

ServiceName = "セキュアチェッカー"
API_KEY = '7c6ed7ab61d3cd5920a01710bf2bc03e01ef2672cb7160d1968d0926970c5ed0'
app = Flask(__name__, static_url_path='/static')
traceroute_results = {}
traceroute_lock = threading.Lock()
ip_domain_data = {"ip":None,"domain":None}

TRANSLATIONS = {
    "blacklist": "ブラックリスト",
    "harmless": "安全",
    "malicious": "危険",
    "suspicious": "怪しい",
    "undetected": "判定不可",
    "failure":"失敗",
    "type_unsupported":"非対応",
    "timeout":"タイムアウト",
    "confirmed_timeout":"タイムアウト(確認済み)",
    "unrated": "評価なし",
    "clean": "安全",
    "malware": "マルウェア",
    "phishing": "フィッシング",
    "spam": "スパム",
    "malicious site": "悪意のあるサイト",
    "malware distribution site": "マルウェア配布サイト",
    "virus":"ウイルス",
    "trojan":"トロイの木馬",
    "worm":"ワーム",
    "ransomware":"ランサムウェア",
    "spyware":"スパイウェア",
    "malware":"マルウェア"
}

def translate(details):
    translated_results = {}
    for engine_name, analysis in details.items():
                method = analysis.get('method', 'Unknown')
                category = analysis.get('category', 'unrated')
                result_text = analysis.get('result', 'unrated')
                # 辞書を使用して翻訳
                translated_results[engine_name] = {
                    "method": TRANSLATIONS.get(method, method),
                    "category": TRANSLATIONS.get(category, category),
                    "result": TRANSLATIONS.get(result_text, result_text)
                }
    return translated_results

def is_ip_address(input_data):
    """入力がIPアドレスかどうかを判定する"""
    try:
        socket.inet_aton(input_data)
        return True
    except socket.error:
        return False
def is_domain_name(input_data):
    """入力がドメイン名かどうかを判定する"""
    return validators.domain(input_data)
def get_traceroute(ip_address):
    """通信経路を取得するための関数"""
    # Windows 環境と Unix 環境でコマンドを切り替え
    command = ['tracert', ip_address] if os.name == 'nt' else ['traceroute', ip_address]
    try:
        # コマンドの実行
        result = subprocess.run(command, text=True, capture_output=True, timeout=180)
        
        # 正常な出力を返す
        return result.stdout
    except subprocess.CalledProcessError as e:
        # コマンドの実行に失敗した場合
        return f"通信経路の取得に失敗しました: {e}"
    except Exception as e:
        # その他のエラー
        return f"通信経路の取得中にエラーが発生しました: {e}"

def extract_whois_info(whois_data):
    cidr_pattern = re.compile(r'CIDR:\s*([^\n]*)')
    address_pattern = re.compile(r'address:\s*([^\n]*)')
    regdate_pattern = re.compile(r'RegDate:\s*([^\n]*)')
    updated_pattern = re.compile(r'Updated:\s*([^\n]*)')
    admin_pattern = re.compile(r'admin-c:\s*([^\n]*)')
    tech_pattern = re.compile(r'tech-c:\s*([^\n]*)')
    abuse_pattern = re.compile(r'abuse-c:\s*([^\n]*)')
    email_pattern = re.compile(r'e-mail:\s*([^\n]*)')
    phone_pattern = re.compile(r'phone:\s*([^\n]*)')
    organization_pattern = re.compile(r'netname:\s*([^\n]*)')
    descr_pattern = re.compile(r'descr:\s*([^\n]*)')

    cidr = cidr_pattern.search(whois_data).group(1) if cidr_pattern.search(whois_data) else 'N/A'
    address = address_pattern.search(whois_data).group(1) if address_pattern.search(whois_data) else 'N/A'
    regdate = regdate_pattern.search(whois_data).group(1) if regdate_pattern.search(whois_data) else 'N/A'
    updated = updated_pattern.search(whois_data).group(1) if updated_pattern.search(whois_data) else 'N/A'
    admin = admin_pattern.search(whois_data).group(1) if admin_pattern.search(whois_data) else 'N/A'
    tech = tech_pattern.search(whois_data).group(1) if tech_pattern.search(whois_data) else 'N/A'
    abuse = abuse_pattern.search(whois_data).group(1) if abuse_pattern.search(whois_data) else 'N/A'
    email = email_pattern.search(whois_data).group(1) if email_pattern.search(whois_data) else 'N/A'
    phone = phone_pattern.search(whois_data).group(1) if phone_pattern.search(whois_data) else 'N/A'
    organization = organization_pattern.search(whois_data).group(1) if organization_pattern.search(whois_data) else 'N/A'
    descr = descr_pattern.search(whois_data).group(1) if descr_pattern.search(whois_data) else 'N/A'

    return {
        'cidr': cidr,
        'address': address,
        'regdate': regdate,
        'updated': updated,
        'admin-c': admin,
        'tech-c': tech,
        'abuse-c': abuse,
        'e-mail': email,
        'phone': phone,
        'organization': organization,
        'descr': descr
    }

def cidr_to_range(cidr):
    """CIDR形式からネットワーク範囲に変換する"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return f"{network.network_address} - {network.broadcast_address}"
    except ValueError:
        return "不明なネットワーク範囲"
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
    url = data['data']['attributes'].get('url', 'Unknown')
    if url != "Unknown":
        get_screenshot(url)
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
    details=data["data"]["attributes"]["last_analysis_results"]
    behavior_info=interpret_results(data["data"]["attributes"]["last_analysis_results"])
    reputation = data['data']['attributes'].get('reputation', 'Unknown')
    name=behavior_info["name"]
    description=behavior_info["description"]
    actions=behavior_info["actions"]
    risk_level=behavior_info["risk_level"]
    recommendation=behavior_info["recommendation"]
    analyze_data={"url":url,"date":date,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":0,"failure":0,"type_unsupported":0,"reputation":reputation,
                "name":name,"description":description,"actions":actions,"risk_level":risk_level,"recommendation":recommendation}
    return analyze_data,details
#ファイルの分析
def analyze_file(data):
    timestamp = data['data']['attributes'].get('date', 'Unknown')
    if timestamp == "Unknown":
        date = "不明"
    else:
        date = datetime.datetime.fromtimestamp(timestamp)
    size = data['meta']['file_info'].get('size', 'Unknown')
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
    timestamp = data['data']['attributes'].get('last_analysis_date', 'Unknown')
    if timestamp == "Unknown":
        date = "不明"
    else:
        date = datetime.datetime.fromtimestamp(timestamp)
    size = data['data']['attributes'].get('size', 'Unknown')
    filename = data['data']['attributes'].get('meaningful_name', 'Unknown')
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
    reputation = data['data']['attributes'].get('reputation', 'Unknown')
    name=behavior_info["name"]
    description=behavior_info["description"]
    actions=behavior_info["actions"]
    risk_level=behavior_info["risk_level"]
    recommendation=behavior_info["recommendation"]
    analyze_data={"date":date,"size":size,"filename":filename,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":confirmed_timeout,"failure":failure,"type_unsupported":type_unsupported,"reputation":reputation,
                "name":name,"description":description,"actions":actions,"risk_level":risk_level,"recommendation":recommendation}
    return analyze_data,details
#IPアドレス,ドメインの分析
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
    ip=ip_domain_data['ip']
    domain=ip_domain_data['domain']
    country = data['data']['attributes'].get('country', 'Unknown')
    asn = data['data']['attributes'].get('asn', 'Unknown')
    as_owner = data['data']['attributes'].get('as_owner', 'Unknown')
    reverse_dns = data['data']['attributes'].get('reverse_dns', 'Unknown')
    network = cidr_to_range(data['data']['attributes'].get('network', 'Unknown'))
    reputation = data['data']['attributes'].get('reputation', 'Unknown'),
    detected_urls = data['data']['attributes'].get('detected_urls', [])
    undetected_downloaded_samples = data['data']['attributes'].get('undetected_downloaded_samples', [])
    resolutions = data['data']['attributes'].get('resolutions', 'Unknown')
    hosted_domains = data['data']['attributes'].get('hosted_domains', 'Unknown'),
    cidr_sub = data['data']['attributes'].get('network', 'Unknown')
    details=data["data"]["attributes"]["last_analysis_results"]
    behavior_info=interpret_results(data["data"]["attributes"]["last_analysis_results"])
    name=behavior_info["name"]
    description=behavior_info["description"]
    actions=behavior_info["actions"]
    risk_level=behavior_info["risk_level"]
    recommendation=behavior_info["recommendation"]
    whois = extract_whois_info(data["data"]["attributes"].get('whois', 'Unknown'))
    analyze_data={"date":date,"malicious":malicious,"suspicious":suspicious,"undetected":undetected,"harmless":harmless,
                "timeout":timeout,"confirmed_timeout":0,"failure":0,"type_unsupported":0,
                "country":country,"asn":asn,"as_owner":as_owner,"reverse_dns":reverse_dns,"network":network,"reputation":reputation,
                "detected_urls":detected_urls,"undetected_downloaded_samples":undetected_downloaded_samples,"resolutions":resolutions,
                "hosted_domains":hosted_domains,"cidr_sub":cidr_sub,"ip":ip,"domain":domain,
                "name":name,"description":description,"actions":actions,"risk_level":risk_level,"recommendation":recommendation}
    return analyze_data,details,whois
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
#概要
@app.route('/outline')
def outline():
    return render_template('outline.html',ServiceName = ServiceName)
@app.route('/submit', methods=['POST'])
def submit():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        # 問い合わせ内容をファイルに保存
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
#IPアドレス,ドメインが入力された場合の処理
@app.route('/scan_ip_domain', methods=['POST'])
def scan_ip_domain():
    global traceroute_results
    global ip_domain_data
    user_input = request.form['ip_domain']
    if user_input=="":
        return redirect(url_for('error',message="IPアドレスやドメインを入力してください"))
    elif is_ip_address(user_input):
        ip_address = user_input
        domain = None
    else:
        if not user_input.startswith(('http://', 'https://')):
            user_input = 'http://' + user_input
        if validators.url(user_input):
            parsed_url = urlparse(user_input)
            domain = parsed_url.netloc
            if is_domain_name(domain):
                try:
                    ip_address = socket.gethostbyname(domain)
                except socket.gaierror:
                    # IPアドレスが取得できない場合、ドメインの情報のみを表示
                    ip_address = None
            else:
                return render_template('error.html', error="有効なドメイン形式ではありません。")
        else:
            return render_template('error.html', error="有効なURL形式ではありません。")
    if ip_address:
        analysis_id = "ip"
    else:
        analysis_id = "domain"
    ip_domain_data["ip"]=ip_address
    ip_domain_data["domain"]=domain
    return redirect(url_for('get_results', analysis_id=analysis_id,scan="ip_domain"))
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
                details_jp=translate(details)
                return render_template('result.html', summary=analyzed_result,ServiceName=ServiceName,scan=scan,details=details_jp)
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
                    details_jp=translate(details)
                    return render_template('result.html', summary=analyzed_result,ServiceName=ServiceName,scan=scan,details=details_jp)
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
                            details_jp=translate(details)
                            return render_template('result.html', summary=analyzed_result,ServiceName=ServiceName,scan=scan,details=details_jp)
                else:
                    time.sleep(5)
            else:
                return redirect(url_for('error',message=f"エラー:ファイルのデータが見つかりませんでした {response.status_code}"))
    #IPアドレス,ドメイン
    elif scan == "ip_domain":
        if analysis_id == "ip":
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_domain_data["ip"]}'
        else:
            url = f'https://www.virustotal.com/api/v3/domain/{ip_domain_data["domain"]}'
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            analyzed_result,details,whois=analyze_ip(result)
            details_jp=translate(details)
            ip_address=ip_domain_data["ip"]
            if ip_address:
            # 別スレッドで通信経路の取得を行う
                def fetch_traceroute():
                    global traceroute_results
                    with traceroute_lock:
                        traceroute_results[ip_address] = '通信経路取得中...'
                    traceroute_results[ip_address] = get_traceroute(ip_address)
                traceroute_thread = threading.Thread(target=fetch_traceroute)
                traceroute_thread.start()
            return render_template('result.html', summary=analyzed_result,ServiceName=ServiceName,scan=scan,details=details_jp,whois=whois,ip_address=ip_address)
        else:
            return redirect(url_for('error',message=f"エラー:情報の取得に失敗しました {response.status_code}"))

@app.route('/traceroute_result')
def traceroute_result():
    ip_address = request.args.get('ip_address')
    print(ip_address)
    with traceroute_lock:
        result = traceroute_results.get(ip_address, '通信経路の取得に失敗しました')

    return jsonify({"result": result})

#エラー画面の表示
@app.route('/error/<message>')
def error(message):
    return render_template('error.html',ServiceName = ServiceName,message=message)

if __name__ == '__main__':
    #threading.Timer(1.0, lambda: webbrowser.open('http://localhost:5000') ).start()
    #app.run(debug=False)
    app.run(debug=True)
