import os
import scapy.all as scapy
import socket
import nmap
from prompt_toolkit import prompt
from prettytable import PrettyTable
import json
import requests

messages = {
    "en": {
        "select_language": "Select language (en/ru/es): ",
        "enter_interface": "Enter the network interface (e.g., eth0, wlan0): ",
        "use_default_gateway": "Do you want to use the default gateway? (yes/no): ",
        "enter_ip_range": "Enter the IP range to scan (e.g., 192.168.1.1/24): ",
        "full_port_scan": "Do you want to perform a full port scan? (yes/no): ",
        "detect_os": "Do you want to detect the OS of the devices? (yes/no): ",
        "detect_vulns": "Do you want to detect vulnerabilities? (yes/no): ",
        "scanning_network": "Scanning network...",
        "save_results": "Do you want to save the results? (yes/no): ",
        "results_saved": "Results saved in {file_path}",
        "scanning_with_cidr": "Scanning with CIDR {cidr}...",
        "scan_complete": "Scan complete.",
        "field_names": ["IP", "MAC Address", "Hostname", "Ports", "OS", "Latency", "Location", "Vulnerabilities"],
        "unknown": "Unknown"
    },
    "ru": {
        "select_language": "Выберите язык (en/ru/es): ",
        "enter_interface": "Введите сетевой интерфейс (например, eth0, wlan0): ",
        "use_default_gateway": "Хотите использовать шлюз по умолчанию? (да/нет): ",
        "enter_ip_range": "Введите диапазон IP для сканирования (например, 192.168.1.1/24): ",
        "full_port_scan": "Хотите выполнить полное сканирование портов? (да/нет): ",
        "detect_os": "Хотите обнаружить ОС устройств? (да/нет): ",
        "detect_vulns": "Хотите обнаружить уязвимости? (да/нет): ",
        "scanning_network": "Сканирование сети...",
        "save_results": "Хотите сохранить результаты? (да/нет): ",
        "results_saved": "Результаты сохранены в {file_path}",
        "scanning_with_cidr": "Сканирование с CIDR {cidr}...",
        "scan_complete": "Сканирование завершено.",
        "field_names": ["IP", "MAC адрес", "Имя хоста", "Порты", "ОС", "Задержка", "Местоположение", "Уязвимости"],
        "unknown": "Неизвестно"
    },
    "es": {
        "select_language": "Seleccione idioma (en/ru/es): ",
        "enter_interface": "Ingrese la interfaz de red (ej. eth0, wlan0): ",
        "use_default_gateway": "¿Desea usar la puerta de enlace predeterminada? (sí/no): ",
        "enter_ip_range": "Ingrese el rango de IP para escanear (ej. 192.168.1.1/24): ",
        "full_port_scan": "¿Desea realizar un escaneo completo de puertos? (sí/no): ",
        "detect_os": "¿Desea detectar el sistema operativo de los dispositivos? (sí/no): ",
        "detect_vulns": "¿Desea detectar vulnerabilidades? (sí/no): ",
        "scanning_network": "Escaneando la red...",
        "save_results": "¿Desea guardar los resultados? (sí/no): ",
        "results_saved": "Resultados guardados en {file_path}",
        "scanning_with_cidr": "Escaneando con CIDR {cidr}...",
        "scan_complete": "Escaneo completo.",
        "field_names": ["IP", "MAC Address", "Nombre del Host", "Puertos", "OS", "Latencia", "Ubicación", "Vulnerabilidades"],
        "unknown": "Desconocido"
    }
}

lang = prompt(messages["en"]["select_language"]).lower()
if lang not in messages:
    lang = "en"

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        return answered_list[0][1].hwsrc
    except IndexError:
        return None

def scan(ip_range, iface, full_port_scan, detect_os, detect_vulns):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, iface=iface, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "hostname": get_hostname(element[1].psrc),
            "ports": get_services(element[1].psrc, full_port_scan),
            "os": get_os(element[1].psrc) if detect_os else messages[lang]["unknown"],
            "vulnerabilities": get_vulnerabilities(element[1].psrc) if detect_vulns else messages[lang]["unknown"],
            "latency": get_latency(element[1].psrc),
            "location": get_location(element[1].psrc)
        }
        clients_list.append(client_dict)
        print_result([client_dict])
    return clients_list

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = messages[lang]["unknown"]
    return hostname

def get_services(ip, full_port_scan):
    nm = nmap.PortScanner()
    port_range = '1-65535' if full_port_scan else '1-1024'
    nm.scan(ip, port_range)
    services = []
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            services.append(f"{port}/{proto}: {nm[ip][proto][port]['name']}")
    return services

def get_vulnerabilities(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='--script vuln')
    vulnerabilities = []
    if 'hostscript' in nm[ip]:
        for script in nm[ip]['hostscript']:
            vulnerabilities.append(script['output'])
    return vulnerabilities

def get_os(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-O')
    if 'osclass' in nm[ip]:
        return nm[ip]['osclass'][0]['osfamily']
    else:
        return messages[lang]["unknown"]

def get_latency(ip):
    ping_response = os.popen(f"ping -c 1 {ip}").read()
    latency = messages[lang]["unknown"]
    if "time=" in ping_response:
        latency = ping_response.split("time=")[1].split(" ")[0]
    return latency

def get_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        return data.get("city", messages[lang]["unknown"]) + ", " + data.get("region", messages[lang]["unknown"]) + ", " + data.get("country", messages[lang]["unknown"])
    except:
        return messages[lang]["unknown"]

def print_result(results_list):
    table = PrettyTable()
    table.field_names = messages[lang]["field_names"]

    for client in results_list:
        ports = ", ".join(client['ports'])
        vulnerabilities = "; ".join(client['vulnerabilities'])
        table.add_row([client['ip'], client['mac'], client['hostname'], ports, client['os'], client['latency'], client['location'], vulnerabilities])
    
    print(table)

def save_results(results_list):
    os.makedirs(os.path.expanduser("~/Recon"), exist_ok=True)
    file_path = os.path.expanduser("~/Recon/scan_results.json")
    with open(file_path, "w") as file:
        json.dump(results_list, file, indent=4)
    print(messages[lang]["results_saved"].format(file_path=file_path))

def main():
    iface = prompt(messages[lang]["enter_interface"])
    ip_option = prompt(messages[lang]["use_default_gateway"]).lower()
    
    if ip_option in ["si", "yes", "да"]:
        ip_range = scapy.conf.route.route("0.0.0.0")[2] + "/24"
    else:
        ip_range = prompt(messages[lang]["enter_ip_range"])
    
    full_port_scan = prompt(messages[lang]["full_port_scan"]).lower() in ["si", "yes", "да"]
    detect_os = prompt(messages[lang]["detect_os"]).lower() in ["si", "yes", "да"]
    detect_vulns = prompt(messages[lang]["detect_vulns"]).lower() in ["si", "yes", "да"]

    print(messages[lang]["scanning_network"])
    results = scan(ip_range, iface, full_port_scan, detect_os, detect_vulns)
    
    save_option = prompt(messages[lang]["save_results"]).lower()
    if save_option in ["si", "yes", "да"]:
        save_results(results)
    
    print(messages[lang]["scan_complete"])

if __name__ == "__main__":
    main()
