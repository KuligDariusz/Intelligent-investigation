
import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
except ImportError:
    print("Brak modułu 'requests'. Zainstaluj: pip install requests")
    sys.exit(1)

# Zmienne globalne
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
log_file = f"{pwd}/logs/integrations.log"
socket_addr = f"{pwd}/queue/sockets/queue"

def debug(msg):
    
    if debug_enabled:
        msg = f"{now}: {msg}\n"
        print(msg)
    with open(log_file, "a") as f:
        f.write(msg)

def main(args):
    
    debug("# Start")
    if len(args) < 3:
        debug("# Zakończono: Za mało argumentów.")
        sys.exit(1)

    alert_file_location = args[1]
    apikey = args[2]
    debug(f"# Klucz API: {apikey}")
    debug(f"# Lokalizacja pliku: {alert_file_location}")

    
    try:
        with open(alert_file_location) as alert_file:
            raw_data = alert_file.read()
            debug(f"# Surowe dane alertu: {raw_data}")
            json_alert = json.loads(raw_data)
    except Exception as e:
        debug(f"# Błąd ładowania pliku alertu: {e}")
        sys.exit(1)

    
    msg = process_alert(json_alert, apikey)
    if msg:
        send_event(msg)

def process_alert(alert, apikey):
    """Wyciąga komendę PowerShell i pyta ChatGPT."""
    
    ps_command = alert.get("data", {}).get("win", {}).get("eventdata", {}).get("scriptBlockText")
    if not ps_command:
        debug("# Brak komendy PowerShell w eventdata. Pomijam alert.")
        return None

    
    debug(f"# Znaleziona komenda PowerShell: {ps_command}")

    
    chatgpt_response = query_chatgpt(ps_command, apikey)
    if not chatgpt_response:
        debug("# Brak odpowiedzi z ChatGPT.")
        return None

    
    enriched_alert = {
        "chatgpt": {
            "found": 1,
            "powerShellCommand": ps_command,
            "chatgptAnalysis": chatgpt_response
        },
        "integration": "powershell-chatgpt-enrichment",
        "source": {
            "alert_id": alert.get("id", ""),
            "rule": alert.get("rule", {}).get("id", ""),
            "description": alert.get("rule", {}).get("description", ""),
            "full_log": alert.get("full_log", "")
        }
    }

    debug(f"# Wzbogacony alert: {json.dumps(enriched_alert, indent=4, ensure_ascii=False)}")
    return enriched_alert

def query_chatgpt(ps_command, apikey):
    """Wysyła zapytanie do ChatGPT API z komendą PowerShell i oczekuje odpowiedzi po polsku."""
    headers = {
        'Authorization': f'Bearer {apikey}',
        'Content-Type': 'application/json',
    }

    
    payload = {
        'model': 'gpt-3.5-turbo',
        'messages': [
            {
                'role': 'user',
                'content': (
                    f"Przeanalizuj tę komendę PowerShell i odpowiedz po polsku: oceń czy jest złośliwa czy nie, "
                    f"uzasadnij swoją ocenę i zaproponuj konkretne, dobrze sformatowane zalecenia co do dalszych kroków lub działań naprawczych. Komenda: {ps_command}"
                )
            }
        ]
    }

    debug(f"# ChatGPT payload: {json.dumps(payload, indent=4, ensure_ascii=False)}")

    try:
        response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=payload)
        if response.status_code == 200:
            debug("# Odpowiedź z ChatGPT API otrzymana pomyślnie.")
            return response.json()["choices"][0]["message"]["content"]
        else:
            debug(f"# Błąd ChatGPT API: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        debug(f"# Błąd zapytania do ChatGPT API: {e}")
        return None

def send_event(msg):
    """Wysyła wzbogacony alert do Wazuh."""
    string = f'1:chatgpt:{json.dumps(msg, ensure_ascii=False)}'

    debug(f"# Wysyłam wzbogacony alert: {string}")

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        debug(f"# Błąd podczas wysyłania alertu: {e}")

if __name__ == "__main__":
    try:
        debug_enabled = len(sys.argv) > 3 and sys.argv[3] == 'debug'
        main(sys.argv)
    except Exception as e:
        debug(f"# Wyjątek w main: {e}")
        raise
