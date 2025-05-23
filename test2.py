#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# Szablon integracji z ChatGPT - wersja polska

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

# Próba importu requests – jeśli nie ma, wyświetl komunikat i zakończ program
try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("Brak modułu 'requests'. Zainstaluj: pip install requests")
    sys.exit(1)

# Zmienne globalne
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

print(pwd)
#exit()

json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Ustawienie ścieżek do pliku logów oraz socketu do komunikacji z Wazuh
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def main(args):
    """
    Główna funkcja programu:
    - Odczytuje argumenty,
    - Ładuje plik alertu,
    - Przetwarza alert,
    - Wysyła wynik do Wazuh.
    """
    debug("# Start programu")
    # Odczytanie argumentów
    alert_file_location = args[1]
    apikey = args[2]
    debug("# Klucz API")
    debug(apikey)
    debug("# Lokalizacja pliku")
    debug(alert_file_location)

    # Wczytaj plik alertu i przetwórz JSON
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Przetwarzanie alertu")
    debug(json_alert)

    # Zapytanie ChatGPT o dane
    msg = request_chatgpt_info(json_alert, apikey)
    # Jeśli jest odpowiedź, wyślij zdarzenie do Wazuh Managera
    if msg:
        send_event(msg, json_alert["agent"])

def debug(msg):
    """
    Funkcja do logowania komunikatów debugujących oraz wypisywania na konsoli
    """
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
    print(msg)
    f = open(log_file,"a")
    f.write(str(msg))
    f.close()

def collect(data):
    """
    Zbiera IP źródłowe i dane z odpowiedzi ChatGPT
    """
    srcip = data['srcip']
    choices = data['content']
    return srcip, choices

def in_database(data, srcip):
    """
    Sprawdza, czy ChatGPT zwrócił dane dla tego IP
    """
    result = data['srcip']
    if result == 0:
        return False
    return True

def query_api(srcip, apikey):
    """
    Wysyła zapytanie do API ChatGPT z danym adresem IP.
    Odpowiedź oraz prompt są po polsku!
    """
    headers = {
        'Authorization': 'Bearer ' + apikey,
        'Content-Type': 'application/json',
    }

    # Prompt po polsku:
    json_data = {
        'model': 'gpt-4.1',
        'messages': [
            {
                'role': 'user',
                'content': (
                    'Podaj więcej informacji o tym adresie IP oraz oceń jego potencjalną szkodliwość (odpowiedz po polsku): ' + srcip
                ),
            },
        ],
    }

    response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=json_data)

    if response.status_code == 200:
        # Utwórz nowy JSON i dodaj IP
        ip = {"srcip": srcip}
        new_json = {}
        new_json = response.json()["choices"][0]["message"]
        new_json.update(ip)
        json_response = new_json

        data = json_response
        return data
    else:
        # Obsługa błędu – przygotowanie komunikatu dla Wazuh
        alert_output = {}
        alert_output["chatgpt"] = {}
        alert_output["integration"] = "custom-chatgpt"
        json_response = response.json()
        debug("# Błąd: ChatGPT napotkał błąd")
        alert_output["chatgpt"]["error"] = response.status_code
        alert_output["chatgpt"]["description"] = json_response["errors"][0]["detail"]
        send_event(alert_output)
        exit(0)

def request_chatgpt_info(alert, apikey):
    """
    Zbiera informacje z alertu i odpytuje ChatGPT, czy posiada dane o danym IP.
    """
    alert_output = {}
    # Jeśli nie ma adresu źródłowego w alercie, kończymy funkcję
    if not "srcip" in alert["data"]:
        return 0

    # Zapytaj ChatGPT o dane dotyczące adresu IP
    data = query_api(alert["data"]["srcip"], apikey)
    # Tworzenie struktury wynikowej
    alert_output["chatgpt"] = {}
    alert_output["integration"] = "custom-chatgpt"
    alert_output["chatgpt"]["found"] = 0
    alert_output["chatgpt"]["source"] = {}
    alert_output["chatgpt"]["source"]["alert_id"] = alert["id"]
    alert_output["chatgpt"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["chatgpt"]["source"]["description"] = alert["rule"]["description"]
    alert_output["chatgpt"]["source"]["full_log"] = alert["full_log"]
    alert_output["chatgpt"]["source"]["srcip"] = alert["data"]["srcip"]
    srcip = alert["data"]["srcip"]

    # Sprawdź czy ChatGPT znalazł dane dla tego IP
    if in_database(data, srcip):
        alert_output["chatgpt"]["found"] = 1
    # Jeśli znaleziono informacje, wypełnij strukturę
    if alert_output["chatgpt"]["found"] == 1:
        srcip, choices = collect(data)
        # Dodaj do wyniku IP oraz dane z ChatGPT
        alert_output["chatgpt"]["srcip"] = srcip
        alert_output["chatgpt"]["choices"] = choices

        debug(alert_output)

    return alert_output

def send_event(msg, agent = None):
    """
    Wysyła gotowe dane do Wazuh (po UNIX socketcie), w zależności czy podany jest agent.
    """
    if not agent or agent["id"] == "000":
        string = '1:chatgpt:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->chatgpt:{3}'.format(
            agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg)
        )

    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

if __name__ == "__main__":
    try:
        # Odczytaj argumenty wywołania programu
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                now, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else ''
            )
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Błędne argumenty'.format(now)
            bad_arguments = True

        # Loguj wywołanie
        f = open(log_file, 'a')
        f.write(str(msg) + '\n')
        f.close()

        if bad_arguments:
            debug("# Zakończono: błędne argumenty.")
            sys.exit(1)

        # Wywołaj główną funkcję programu
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
