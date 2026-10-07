import ipaddress
import subprocess
import socket
import threading
import time
import sys
import platform
import os
import re
import urllib.request
import ssl
import concurrent.futures
import locale
from typing import List, Dict, Optional, Tuple

# ============================================
# БЛОК 0: ЛОКАЛИЗАЦИЯ (I18N)
# ============================================

def detect_lang() -> str:
    """Определяет системный язык ОС"""
    try:
        loc = locale.getdefaultlocale()[0]
        if loc and loc.lower().startswith('ru'):
            return 'ru'
    except Exception:
        pass
    for var in ('LC_ALL', 'LC_MESSAGES', 'LANG'):
        val = os.environ.get(var, '')
        if val.lower().startswith('ru'):
            return 'ru'
    return 'en'

LANG = detect_lang()

STRINGS = {
    'ru': {
        'net_status': 'Сетевой статус:',
        'host_ip': 'IP хоста:',
        'subnet': 'Подсеть:',
        'arp_cache': 'Записей в ARP-кэше:',
        'raw_sockets_ok': 'Raw сокеты: Доступны (права администратора)',
        'raw_sockets_fail': 'Raw сокеты: Ограничены (обычный пользователь)',
        'err_ip': 'Не удалось определить IP хоста',
        'scan_options': 'Опции сканирования:',
        'opt_auto': '1. Автоопределение подсети',
        'opt_manual': '2. Ввести сеть вручную',
        'opt_single': '3. Сканировать одиночный IP',
        'opt_help': '4. Справка / Решение проблем',
        'opt_exit': '5. Выход',
        'select_choice': 'Выберите (1-5): ',
        'target': 'Цель:',
        'enter_cidr': 'Введите сеть (CIDR): ',
        'enter_ip': 'Введите IP адрес: ',
        'starting_scan': 'Запуск сканирования #{count}:',
        'exiting': 'Выход из программы...',
        'press_enter': 'Нажмите Enter для продолжения или введите "exit" для выхода... ',
        'scan_aborted': 'Сканирование прервано пользователем.',
        'scan_results': 'Результаты сканирования:',
        'active_hosts': '{alive} активных хостов',
        'found_in': 'найдено за {time:.2f} сек ({total} всего проверено)',
        'no_hosts': 'Активные хосты не найдены.',
        'scan_complete': 'Сканирование завершено.',
        'press_return_menu': 'Нажмите Enter, чтобы вернуться в меню...',
        'cat_pc': 'КОМПЬЮТЕРЫ И РАБОЧИЕ СТАНЦИИ',
        'cat_printers': 'ПРИНТЕРЫ И МФУ',
        'cat_net': 'СЕТЕВЫЕ УСТРОЙСТВА',
        'cat_voip': 'VOIP И ТЕЛЕФОНИЯ',
        'cat_vm': 'ВИРТУАЛЬНЫЕ МАШИНЫ',
        'cat_other': 'ДРУГИЕ УСТРОЙСТВА',
        'help_title': 'IPADMIN — Справка и устранение проблем:',
        'help_privs': '1. Права доступа:',
        'help_privs_desc': '   • Запускайте консоль от имени Администратора (Windows) или через sudo (Linux).\n   • Без прав Администратора недоступны Raw Sockets (ICMP ping) и чтение\n     полной таблицы ARP, из-за чего часть устройств может не определиться.',
        'help_arp': '2. Устройства не найдены или старые MAC-адреса:',
        'help_arp_desc': '   • Очистите ARP-кэш:\n     Windows:  arp -d *\n     Linux:    ip -s -s neigh flush all\n   • Очистите DNS-кэш:\n     Windows:  ipconfig /flushdns\n     Linux:    resolvectl flush-caches',
        'help_firewall': '3. Сетевые экраны (Брандмауэр):',
        'help_firewall_desc': '   • Windows Defender или антивирусы могут блокировать ICMP Echo-Reply.\n   • Сканер простукивает порты (80, 443, 22, 445), чтобы хост появился\n     в ARP-таблице даже при выключенном Ping.',
        'help_cidr': '4. Форматы ввода адресов:',
        'help_cidr_desc': '   • Подсеть целиком:    192.168.1.0/24 или 10.66.2.0/24\n   • Одиночный адрес:    192.168.1.15 (автоматически переводится в /32)\n   • Большая сеть:       10.66.0.0/23 (510 хостов, сканирование длится дольше)'
    },
    'en': {
        'net_status': 'Network Status:',
        'host_ip': 'Host IP:',
        'subnet': 'Subnet:',
        'arp_cache': 'ARP entries in cache:',
        'raw_sockets_ok': 'Raw sockets: Available (elevated)',
        'raw_sockets_fail': 'Raw sockets: Restricted (standard user)',
        'err_ip': 'Could not determine host IP',
        'scan_options': 'Scan Options:',
        'opt_auto': '1. Auto-detect subnet',
        'opt_manual': '2. Enter network manually',
        'opt_single': '3. Scan single IP',
        'opt_help': '4. Help / Troubleshooting',
        'opt_exit': '5. Exit',
        'select_choice': 'Select (1-5): ',
        'target': 'Target:',
        'enter_cidr': 'Enter network (CIDR): ',
        'enter_ip': 'Enter IP address: ',
        'starting_scan': 'Starting scan #{count}:',
        'exiting': 'Exiting IPADMIN...',
        'press_enter': 'Press Enter to continue, or "exit" to quit... ',
        'scan_aborted': 'Scan aborted by user.',
        'scan_results': 'Scan Results:',
        'active_hosts': '{alive} active hosts',
        'found_in': 'found in {time:.2f}s ({total} total scanned)',
        'no_hosts': 'No active hosts found.',
        'scan_complete': 'Scan complete.',
        'press_return_menu': 'Press Enter to return to menu...',
        'cat_pc': 'COMPUTERS & WORKSTATIONS',
        'cat_printers': 'PRINTERS & IMAGING',
        'cat_net': 'NETWORK DEVICES',
        'cat_voip': 'VOIP & PHONES',
        'cat_vm': 'VIRTUAL MACHINES',
        'cat_other': 'OTHER DEVICES',
        'help_title': 'IPADMIN — Troubleshooting & Help:',
        'help_privs': '1. Privileges:',
        'help_privs_desc': '   • Run console as Administrator (Windows) or root via sudo (Linux).\n   • Without admin rights, Raw Sockets (ICMP ping) and system ARP table\n     may not reveal all passive hosts.',
        'help_arp': '2. Outdated MACs or missing hosts:',
        'help_arp_desc': '   • Flush ARP cache:\n     Windows:  arp -d *\n     Linux:    ip -s -s neigh flush all\n   • Flush DNS cache:\n     Windows:  ipconfig /flushdns\n     Linux:    resolvectl flush-caches',
        'help_firewall': '3. Firewalls:',
        'help_firewall_desc': '   • Local firewalls may silently drop ICMP Echo packets.\n   • Scanner verifies TCP ports (80, 443, 22, 445) to force ARP registration\n     even when ICMP ping is disabled.',
        'help_cidr': '4. Address formats:',
        'help_cidr_desc': '   • Subnet CIDR:    192.168.1.0/24 or 10.66.2.0/24\n   • Single IP:      192.168.1.15 (automatically converted to /32)\n   • Large network:  10.66.0.0/23 (510 hosts, scan takes more time)'
    }
}

def tr(key: str, **kwargs) -> str:
    text = STRINGS.get(LANG, STRINGS['en']).get(key, STRINGS['en'].get(key, key))
    if kwargs:
        return text.format(**kwargs)
    return text

# ============================================
# БЛОК 1: КОНФИГУРАЦИЯ И ЦВЕТА
# ============================================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    GRAY = '\033[90m'

VENDOR_DB = {
    # APPLE
    '00:11:22': 'Apple Inc.', '00:1B:21': 'Apple Inc.', '00:1E:52': 'Apple Inc.',
    '00:1F:03': 'Apple Inc.', '00:21:E9': 'Apple Inc.', '00:24:36': 'Apple Inc.',
    '00:25:00': 'Apple Inc.', '00:25:BC': 'Apple Inc.', '44:38:39': 'Apple Inc.',
    'F4:F1:5A': 'Apple Inc.',
    # MICROSOFT
    '00:15:5D': 'Microsoft Corporation',
    # INTEL
    '00:23:24': 'Intel Corporation', '00:24:8C': 'Intel Corporation',
    '00:1E:2A': 'Intel Corporate', '00:1F:33': 'Intel Corporate',
    # DELL
    '00:25:64': 'Dell Inc.', '00:1E:8C': 'Dell Inc.',
    '00:21:5A': 'Dell Inc.', '00:26:08': 'Dell Inc.',
    # HP / HEWLETT PACKARD
    '00:03:47': 'HP Inc.', '00:04:75': 'HP Inc.', '00:09:6B': 'HP Inc.',
    '00:0B:5A': 'HP Inc.', '00:0E:7F': 'HP Inc.', '00:0F:20': 'HP Inc.',
    '00:10:18': 'HP Inc.', '00:10:83': 'HP Inc.', '00:12:79': 'HP Inc.',
    '00:13:21': 'HP Inc.', '00:13:72': 'HP Inc.', '00:14:38': 'HP Inc.',
    '00:15:60': 'HP Inc.', '00:15:F2': 'HP Inc.', '00:16:17': 'HP Inc.',
    '00:16:D4': 'HP Inc.', '00:17:08': 'HP Inc.', '00:17:A4': 'HP Inc.',
    '00:18:F1': 'HP Inc.', '00:19:2F': 'HP Inc.', '00:1A:4B': 'HP Inc.',
    '00:1B:78': 'HP Inc.', '00:1C:23': 'HP Inc.', '00:1D:09': 'HP Inc.',
    '00:1D:7A': 'HP Inc.', '00:1E:0B': 'HP Inc.', '00:1F:29': 'HP Inc.',
    '00:1F:3C': 'HP Inc.', '00:20:6B': 'HP Inc.', '00:21:5A': 'HP Inc.',
    '00:21:B7': 'HP Inc.', '00:22:64': 'HP Inc.', '00:23:7D': 'HP Inc.',
    '00:24:81': 'HP Inc.', '00:25:9C': 'HP Inc.', '00:26:22': 'HP Inc.',
    '00:26:55': 'HP Inc.', '00:27:24': 'HP Inc.', '00:30:48': 'HP Inc.',
    '00:30:6E': 'HP Inc.', '00:40:CA': 'HP Inc.', '00:50:60': 'HP Inc.',
    '00:50:DA': 'HP Inc.', '00:60:B0': 'HP Inc.', '00:80:77': 'HP Inc.',
    '08:00:46': 'HP Inc.', '0C:37:DC': 'HP Inc.', '10:60:4B': 'HP Inc.',
    '18:2D:44': 'HP Inc.', '1C:1A:C0': 'HP Inc.', '2C:41:38': 'HP Inc.',
    '30:10:E4': 'HP Inc.', '30:85:A9': 'HP Inc.', '34:64:A9': 'HP Inc.',
    '38:CA:84': 'HP Inc.', '3C:2E:F9': 'HP Inc.', '3C:D0:F8': 'HP Inc.',
    '40:A8:F0': 'HP Inc.', '44:1E:A1': 'HP Inc.', '48:21:0B': 'HP Inc.',
    '4C:77:66': 'HP Inc.', '54:7E:1D': 'HP Inc.', '5C:BA:EF': 'HP Inc.',
    '64:31:50': 'HP Inc.', '68:5B:35': 'HP Inc.', '6C:3B:E5': 'HP Inc.',
    '6C:3B:E6': 'HP Inc.', '70:5A:0F': 'HP Inc.', '70:9E:29': 'HP Inc.',
    '74:46:A0': 'HP Inc.', '78:4B:87': 'HP Inc.', '7C:6A:60': 'HP Inc.',
    '7C:D1:C3': 'HP Inc.', '80:2B:F9': 'HP Inc.', '84:2B:2B': 'HP Inc.',
    '88:51:FB': 'HP Inc.', '8C:04:BA': 'HP Inc.', '90:2E:1C': 'HP Inc.',
    '94:57:A5': 'HP Inc.', '98:5A:EB': 'HP Inc.', 'A0:48:1C': 'HP Inc.',
    'A0:91:69': 'HP Inc.', 'A4:77:33': 'HP Inc.', 'A8:1D:16': 'HP Inc.',
    'AC:16:2D': 'HP Inc.', 'B0:5A:DA': 'HP Inc.', 'B4:47:62': 'HP Inc.',
    'B4:9E:1F': 'HP Inc.', 'B8:6A:97': 'HP Inc.', 'B8:C7:5D': 'HP Inc.',
    'BC:05:43': 'HP Inc.', 'BC:3B:AF': 'HP Inc.', 'BC:5F:F4': 'HP Inc.',
    'C0:18:85': 'HP Inc.', 'C4:65:16': 'HP Inc.', 'C8:0A:A9': 'HP Inc.',
    'CC:46:D6': 'HP Inc.', 'CC:5D:4E': 'HP Inc.', 'D0:27:88': 'HP Inc.',
    'D4:61:9D': 'HP Inc.', 'D8:33:4F': 'HP Inc.', 'D8:D2:5E': 'HP Inc.',
    'E0:2A:82': 'HP Inc.', 'E4:11:5B': 'HP Inc.', 'E4:5F:01': 'HP Inc.',
    'E8:4A:12': 'HP Inc.', 'EC:43:F6': 'HP Inc.', 'F0:92:1C': 'HP Inc.',
    'F0:9E:4A': 'HP Inc.', 'F4:8E:38': 'HP Inc.', 'F8:30:EA': 'HP Inc.',
    'FC:60:9B': 'HP Inc.',
    # ВИРТУАЛИЗАЦИЯ
    '00:50:56': 'VMware, Inc.', '00:0C:29': 'VMware, Inc.',
    '08:00:27': 'Oracle Corporation (VirtualBox)', '00:50:8D': 'VMware, Inc.',
    '00:05:69': 'VMware, Inc.', '00:1C:42': 'VMware, Inc.',
    # ПРИНТЕРЫ
    '00:14:60': 'Kyocera Corporation', '00:17:C8': 'Kyocera Corporation',
    '00:1F:BD': 'Kyocera Corporation', '00:22:94': 'Kyocera Corporation',
    '80:73:9F': 'Kyocera Corporation', 'C4:21:C8': 'Kyocera Corporation',
    'CC:82:EB': 'Kyocera Corporation', '00:04:75': 'Brother Industries',
    '00:12:3F': 'Brother Industries', '00:80:92': 'Brother Industries',
    '00:1B:AF': 'Brother Industries', '00:1E:CD': 'Brother Industries',
    '00:23:3A': 'Brother Industries', '00:26:4A': 'Brother Industries',
    '3C:2E:F9': 'Brother Industries', '9C:02:98': 'Brother Industries',
    '00:1E:4F': 'Seiko Epson', '00:24:AB': 'Seiko Epson',
    '00:26:D6': 'Seiko Epson', '00:30:6E': 'Seiko Epson',
    '00:40:AF': 'Seiko Epson', '00:0A:5E': 'Xerox Corporation',
    '00:16:35': 'Xerox Corporation', '00:1E:37': 'Xerox Corporation',
    '00:22:6B': 'Xerox Corporation', '00:26:78': 'Xerox Corporation',
    '00:01:AA': 'Xerox Corporation', '00:04:51': 'Canon Inc.',
    '00:0B:5A': 'Canon Inc.', '00:0E:6E': 'Canon Inc.',
    '00:17:EE': 'Canon Inc.', '00:1A:D4': 'Canon Inc.',
    '00:1C:DA': 'Canon Inc.', '00:23:68': 'Canon Inc.',
    '00:26:5C': 'Canon Inc.', '00:1B:A5': 'Lexmark International',
    '00:1E:BF': 'Lexmark International', '00:24:D2': 'Lexmark International',
    '00:27:81': 'Lexmark International', '00:09:6B': 'Samsung Electronics',
    '00:18:6B': 'Samsung Electronics', '00:1C:F0': 'Samsung Electronics',
    '00:24:54': 'Samsung Electronics', '00:26:AB': 'Samsung Electronics',
    '00:40:95': 'Samsung Electronics', '00:20:EE': 'Panasonic',
    '00:30:CF': 'Panasonic', '00:40:F4': 'Panasonic',
    '00:24:7E': 'Panasonic', '00:26:28': 'Panasonic',
    '00:21:9F': 'Panasonic',
    # СЕТЕВОЕ ОБОРУДОВАНИЕ
    '00:0C:42': 'MikroTik', 'CC:2D:E0': 'MikroTik',
    '00:1C:42': 'Cisco Systems, Inc', 'C0:56:27': 'Cisco Systems, Inc',
    '00:1B:D4': 'Cisco Systems, Inc', '00:1C:58': 'Cisco Systems, Inc',
    '00:21:D8': 'Cisco Systems, Inc', '00:22:BD': 'Cisco Systems, Inc',
    '00:23:04': 'Cisco Systems, Inc', '00:26:0B': 'Cisco Systems, Inc',
    '00:26:98': 'Cisco Systems, Inc', '00:27:0D': 'Cisco Systems, Inc',
    '74:DA:88': 'TP-Link Technologies', '50:C7:BF': 'TP-Link Technologies',
    '54:AF:97': 'TP-Link Technologies', 'D8:07:B6': 'TP-Link Technologies',
    'DC:4A:3E': 'TP-Link Technologies', 'E8:94:F6': 'TP-Link Technologies',
    'F0:FE:6B': 'TP-Link Technologies', '70:62:B8': 'D-Link Corporation',
    'B0:C5:54': 'D-Link Corporation', 'C0:3E:BA': 'D-Link Corporation',
    'E0:91:F5': 'D-Link Corporation', 'F0:B4:29': 'D-Link Corporation',
    '00:22:B0': 'D-Link Corporation', '00:24:01': 'D-Link Corporation',
    '00:25:9B': 'D-Link Corporation', '00:26:5A': 'D-Link Corporation',
    '00:40:05': 'D-Link Corporation', '00:80:C8': 'D-Link Corporation',
    '1C:7E:E5': 'Ubiquiti Networks', '44:D9:E7': 'Ubiquiti Networks',
    '74:83:C2': 'Ubiquiti Networks', '78:8A:20': 'Ubiquiti Networks',
    '80:2A:A8': 'Ubiquiti Networks', 'B0:7B:25': 'Ubiquiti Networks',
    'BC:EE:7B': 'Ubiquiti Networks', 'F0:9F:C2': 'Ubiquiti Networks',
    '00:0F:66': 'Zyxel Communications', '00:19:CB': 'Zyxel Communications',
    '00:23:F8': 'Zyxel Communications', '00:27:01': 'Zyxel Communications',
    '00:60:6E': 'Zyxel Communications', '00:A0:C5': 'Zyxel Communications',
    '00:04:5A': 'Netgear', '00:0F:B5': 'Netgear',
    '00:14:6C': 'Netgear', '00:18:4D': 'Netgear',
    '00:1F:33': 'Netgear', '00:22:3F': 'Netgear',
    '00:24:B2': 'Netgear', '00:26:4C': 'Netgear',
    '00:30:AB': 'Netgear', '00:80:E8': 'Netgear',
    '00:0D:88': 'Juniper Networks', '00:1F:12': 'Juniper Networks',
    '00:23:9C': 'Juniper Networks', '00:26:88': 'Juniper Networks',
    '00:04:96': 'Huawei Technologies', '00:14:A8': 'Huawei Technologies',
    '00:18:82': 'Huawei Technologies', '00:1A:4B': 'Huawei Technologies',
    '00:1F:45': 'Huawei Technologies', '00:25:9E': 'Huawei Technologies',
    '00:27:E4': 'Huawei Technologies', '48:5B:39': 'Huawei Technologies',
    '70:E4:22': 'Huawei Technologies', '00:0D:5D': 'Alcatel-Lucent',
    '00:11:0A': 'Alcatel-Lucent', '00:18:F2': 'Alcatel-Lucent',
    '00:1A:1E': 'Alcatel-Lucent', '00:20:DA': 'Alcatel-Lucent',
    '00:E0:2B': 'Alcatel-Lucent',
    # VoIP
    '00:0E:08': 'Grandstream Networks', '00:1B:7B': 'Grandstream Networks',
    '00:20:6B': 'Grandstream Networks', '00:23:8B': 'Grandstream Networks',
    '00:25:96': 'Grandstream Networks', '00:60:B9': 'Grandstream Networks',
    '00:0D:E0': 'AudioCodes', '00:1A:79': 'AudioCodes',
    '00:20:B2': 'AudioCodes', '00:50:2B': 'AudioCodes',
    '00:08:5D': 'Cisco Systems (VoIP)', '00:0D:29': 'Cisco Systems (VoIP)',
    '00:12:7F': 'Cisco Systems (VoIP)', '00:18:B9': 'Cisco Systems (VoIP)',
    '00:1B:D5': 'Cisco Systems (VoIP)', '00:1E:7A': 'Cisco Systems (VoIP)',
    '00:23:5D': 'Cisco Systems (VoIP)', '00:25:84': 'Cisco Systems (VoIP)',
    '00:12:6F': 'Polycom', '00:19:46': 'Polycom',
    '00:1E:8D': 'Polycom', '00:22:1D': 'Polycom',
    '00:24:75': 'Polycom', '00:26:D5': 'Polycom',
    '00:04:F2': 'Polycom', '00:0E:F7': 'Polycom', '00:15:65': 'Polycom',
    '00:08:85': 'Yealink Network Technology', '00:18:61': 'Yealink Network Technology',
    '00:1B:80': 'Yealink Network Technology', '00:24:1F': 'Yealink Network Technology',
    '00:25:4B': 'Yealink Network Technology', '00:26:21': 'Yealink Network Technology',
    '00:2A:70': 'Yealink Network Technology', '00:30:96': 'Yealink Network Technology',
    '3C:CD:93': 'Yealink Network Technology', '5C:0A:3B': 'Yealink Network Technology',
    '98:46:0A': 'Yealink Network Technology', '00:0A:F4': 'Avaya',
    '00:0D:5F': 'Avaya', '00:1B:16': 'Avaya', '00:1D:6D': 'Avaya',
    '00:20:8A': 'Avaya', '00:25:A0': 'Avaya', '00:30:37': 'Avaya',
    '00:50:DA': 'Avaya', '00:90:7A': 'Avaya', '00:13:E7': 'Siemens AG',
    '00:17:6F': 'Siemens AG', '00:1B:EB': 'Siemens AG', '00:1E:66': 'Siemens AG',
    '00:21:6A': 'Siemens AG', '00:24:68': 'Siemens AG', '00:30:6F': 'Siemens AG',
    '00:40:82': 'Siemens AG', '00:60:8B': 'Siemens AG', '00:03:6B': 'Nortel Networks',
    '00:0B:6E': 'Nortel Networks', '00:0F:24': 'Nortel Networks', '00:12:7C': 'Nortel Networks',
    '00:16:95': 'Nortel Networks', '00:18:4E': 'Nortel Networks', '00:1A:6C': 'Nortel Networks',
    '00:1E:BE': 'Nortel Networks', '00:22:65': 'Nortel Networks', '00:30:BE': 'Nortel Networks',
    '00:80:95': 'Nortel Networks', '00:01:03': 'Panasonic (VoIP)', '00:0F:B3': 'Panasonic (VoIP)',
    '00:18:71': 'Panasonic (VoIP)', '00:22:4A': 'Panasonic (VoIP)', '00:25:54': 'Panasonic (VoIP)',
    '00:30:FD': 'Panasonic (VoIP)', '00:40:F4': 'Panasonic (VoIP)', '00:60:13': 'Panasonic (VoIP)',
    # ДРУГОЕ
    '7C:2E:0D': 'Xiaomi Communications', '80:32:53': 'Hikvision Digital Technology',
    'BC:6A:29': 'Amazon Technologies', 'E8:6A:64': 'Xiaomi Communications',
    'F0:9E:4A': 'ZTE Corporation', 'F8:4D:89': 'Amazon Technologies',
    'B4:E6:2D': 'Xiaomi Communications', 'C8:2E:18': 'Xiaomi Communications',
    '04:45:B3': 'Hikvision Digital Technology', '20:2D:5C': 'Hikvision Digital Technology',
    '2C:54:91': 'Hikvision Digital Technology', '3C:33:6A': 'Hikvision Digital Technology',
    '44:19:B6': 'Hikvision Digital Technology', '70:4B:71': 'Hikvision Digital Technology',
    '8C:9A:E8': 'Hikvision Digital Technology', '98:DE:D0': 'Hikvision Digital Technology',
    'AC:CC:8E': 'Hikvision Digital Technology', 'C8:3A:6B': 'Hikvision Digital Technology',
    'D4:6A:6A': 'Hikvision Digital Technology', 'F0:02:9D': 'Hikvision Digital Technology',
}

LINE_WIDTH = 75

def get_os_name() -> str:
    return platform.system()

def get_vendor(mac: str) -> Optional[str]:
    if not mac:
        return None
    prefix = mac[:8].upper()
    vendor = VENDOR_DB.get(prefix)
    if not vendor or 'Unknown' in vendor:
        return None
    return vendor

def get_local_network() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"

# ============================================
# БЛОК 2: ARP-СКАНИРОВАНИЕ
# ============================================

class ARPScanner:
    @staticmethod
    def get_mac_arp(ip: str) -> Optional[str]:
        os_name = get_os_name()
        try:
            if os_name == 'Windows':
                cmd = ['arp', '-a', ip]
                output = subprocess.check_output(cmd, timeout=1.5, stderr=subprocess.DEVNULL)
                try:
                    output_str = output.decode('cp866')
                except Exception:
                    output_str = output.decode('utf-8', errors='ignore')
                
                match = re.search(r'([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})', output_str)
                if match:
                    return match.group(1).replace('-', ':').upper()
            else:
                cmd = ['arp', '-n', ip]
                output_str = subprocess.check_output(cmd, timeout=1.5, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', output_str)
                if match:
                    return match.group(1).upper()
        except Exception:
            pass
        return None

# ============================================
# БЛОК 3: TCP-ПРОВЕРКА
# ============================================

def tcp_ping(ip: str, port: int = 80, timeout: float = 0.2) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

# ============================================
# БЛОК 4: КОМБИНИРОВАННАЯ ПРОВЕРКА ХОСТА
# ============================================

def is_host_alive(ip: str) -> Tuple[bool, Optional[str]]:
    mac = ARPScanner.get_mac_arp(ip)
    if mac:
        return True, mac
    
    os_name = get_os_name()
    try:
        if os_name == 'Windows':
            cmd = ['ping', '-n', '1', '-w', '400', ip]
        else:
            cmd = ['ping', '-c', '1', '-W', '1', ip]
        
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
        mac = ARPScanner.get_mac_arp(ip)
        if mac:
            return True, mac
    except Exception:
        pass
    
    common_ports = [80, 443, 22, 445]
    for port in common_ports:
        if tcp_ping(ip, port, timeout=0.2):
            time.sleep(0.02)
            mac = ARPScanner.get_mac_arp(ip)
            return True, mac
    
    return False, None

# ============================================
# БЛОК 5: СКАНИРОВАНИЕ ПОРТОВ И СЕРВИСОВ
# ============================================

def get_netbios_name(ip: str, timeout: float = 0.4) -> Tuple[Optional[str], Optional[str]]:
    try:
        query = b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41' \
                b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41' \
                b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) > 56:
            num_names = data[56]
            names = []
            for i in range(num_names):
                offset = 57 + i * 18
                if len(data) >= offset + 16:
                    name_bytes = data[offset:offset+15]
                    name_type = data[offset+15]
                    name_str = name_bytes.decode('ascii', errors='ignore').strip()
                    names.append((name_str, name_type))
            
            pc_name = next((n[0] for n in names if n[1] == 0x00), None)
            domain_name = next((n[0] for n in names if n[1] == 0x1E or (n[1] == 0x00 and n[0] != pc_name)), None)
            return pc_name, domain_name
    except Exception:
        pass
    return None, None

def get_http_title(ip: str, port: int) -> Optional[str]:
    proto = "https" if port in [443, 8443] else "http"
    url = f"{proto}://{ip}:{port}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req, timeout=1.2, context=ctx) as response:
            header_server = response.headers.get('Server', '')
            html = response.read(2048).decode('utf-8', errors='ignore')
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()
                if title:
                    clean_title = re.sub(r'\s+', ' ', title.replace('\n', ' ').replace('\r', ''))
                    return clean_title
            if header_server:
                return header_server.strip()
    except Exception:
        pass
    return None

def scan_port(ip: str, port: int, timeout: float = 0.15) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_port_service(port: int) -> str:
    common_ports = {
        20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        111: 'RPCbind', 135: 'MS RPC', 139: 'NetBIOS',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        515: 'LPD', 631: 'IPP', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Alt', 8291: 'WinBox', 8443: 'HTTPS-Alt',
        8728: 'API', 8729: 'API-SSL', 9100: 'JetDirect', 27017: 'MongoDB'
    }
    return common_ports.get(port, 'Unknown')

def get_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return 'Unknown'

def detect_os(ip: str) -> str:
    try:
        os_name = get_os_name()
        if os_name == 'Windows':
            cmd = ['ping', '-n', '1', '-w', '1000', ip]
        else:
            cmd = ['ping', '-c', '1', '-W', '1', ip]
        
        output = subprocess.check_output(cmd, timeout=1.5, stderr=subprocess.DEVNULL)
        
        if os_name == 'Windows':
            match = re.search(r'TTL=(\d+)', output.decode('cp866', errors='ignore'))
        else:
            match = re.search(r'ttl=(\d+)', output.decode('utf-8', errors='ignore'), re.IGNORECASE)
        
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:
                try:
                    hostname = socket.gethostbyaddr(ip)[0].lower()
                    if 'raspberry' in hostname or 'pi' in hostname:
                        return 'Raspberry Pi'
                    elif 'mac' in hostname or 'apple' in hostname:
                        return 'macOS'
                    elif 'ubuntu' in hostname or 'debian' in hostname:
                        return 'Linux (Debian/Ubuntu)'
                    elif 'centos' in hostname or 'redhat' in hostname:
                        return 'Linux (RHEL/CentOS)'
                    else:
                        return 'Linux / Unix'
                except Exception:
                    return 'Linux / Unix'
            elif ttl <= 128:
                return 'Windows'
            elif ttl <= 255:
                return 'Network Device'
            else:
                return f'TTL={ttl}'
        return 'Unknown'
    except Exception:
        return 'Unknown'

def detect_device_type(ip: str, ports: List[int], mac: Optional[str] = None, vendor: Optional[str] = None) -> Dict[str, any]:
    result = {
        'is_printer': False,
        'is_mikrotik': False,
        'is_vm': False,
        'is_network_device': False,
        'is_voip': False,
        'is_hp': False,
        'device_type': 'Unknown'
    }
    
    vendor_str = vendor or ''
    if 'HP Inc.' in vendor_str:
        result['is_hp'] = True
    
    vm_vendors = ['VMware, Inc.', 'Oracle Corporation (VirtualBox)', 'Microsoft Corporation']
    if vendor_str in vm_vendors:
        result['is_vm'] = True
        result['device_type'] = 'Virtual Machine'
    
    mikrotik_ports = [8291, 8728, 8729]
    if any(p in ports for p in mikrotik_ports):
        result['is_mikrotik'] = True
        result['device_type'] = 'MikroTik Router'
    elif mac and mac.upper().startswith('00:0C:42'):
        result['is_mikrotik'] = True
        result['device_type'] = 'MikroTik'
    
    printer_ports = [9100, 515, 631]
    printer_http_ports = [80, 443, 8080]
    printer_vendors = [
        'HP Inc.', 'Kyocera Corporation', 'Brother Industries', 
        'Seiko Epson', 'Xerox Corporation', 'Canon Inc.', 
        'Lexmark International', 'Samsung Electronics', 'Panasonic'
    ]
    
    if 9100 in ports:
        result['is_printer'] = True
        result['device_type'] = 'Printer (JetDirect)'
    elif (515 in ports or 631 in ports) and any(p in ports for p in printer_http_ports):
        result['is_printer'] = True
        result['device_type'] = 'Printer (Network)'
    elif vendor_str in printer_vendors:
        result['is_printer'] = True
        result['device_type'] = 'Printer'
    else:
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            printer_keywords = ['printer', 'print', 'hp', 'brother', 'kyocera', 'xerox', 'canon', 'epson', 'lexmark']
            if any(k in hostname for k in printer_keywords):
                result['is_printer'] = True
                result['device_type'] = 'Printer'
        except Exception:
            pass
    
    voip_vendors = [
        'Grandstream Networks', 'AudioCodes', 'Cisco Systems (VoIP)',
        'Polycom', 'Yealink Network Technology', 'Avaya',
        'Siemens AG', 'Nortel Networks', 'Panasonic (VoIP)'
    ]
    voip_ports = [5060, 5061, 5070, 10000, 10001, 20000, 30000]
    
    if vendor_str in voip_vendors or any(p in ports for p in voip_ports):
        if not result['is_printer']:
            result['is_voip'] = True
            result['device_type'] = 'VoIP Phone'
    
    if not result['is_printer'] and not result['is_mikrotik'] and not result['is_voip']:
        router_ports = [53, 67, 68, 69, 123, 161, 179, 520]
        network_vendors = [
            'Cisco Systems, Inc', 'TP-Link Technologies', 'MikroTik',
            'D-Link Corporation', 'Ubiquiti Networks', 'Zyxel Communications',
            'Netgear', 'Juniper Networks', 'Huawei Technologies', 'Alcatel-Lucent'
        ]
        
        if any(p in ports for p in router_ports) or vendor_str in network_vendors:
            result['is_network_device'] = True
            if result['device_type'] == 'Unknown':
                result['device_type'] = 'Network Device'
        elif 80 in ports and 22 in ports and not result['is_vm']:
            result['device_type'] = 'Server / NAS'
        elif not result['is_vm'] and result['device_type'] == 'Unknown':
            result['device_type'] = 'Computer'
    
    if result['is_hp'] and not result['is_printer'] and (80 in ports or 443 in ports):
        result['device_type'] = 'HP Device'
    
    return result

def detect_mikrotik_os(ip: str, ports: List[int]) -> str:
    if 161 not in ports and 22 not in ports:
        return 'RouterOS'
    try:
        if 161 in ports:
            try:
                cmd = ['snmpget', '-v', '2c', '-c', 'public', '-O', 'qv', ip, '1.3.6.1.2.1.1.1.0']
                output = subprocess.check_output(cmd, timeout=1.5, stderr=subprocess.DEVNULL)
                output = output.decode('utf-8', errors='ignore').strip()
                if 'RouterOS' in output:
                    match = re.search(r'RouterOS\s+([\d.]+)', output)
                    return f'RouterOS v{match.group(1)}' if match else 'RouterOS'
                elif 'MikroTik' in output:
                    return 'RouterOS'
            except Exception:
                pass
        
        if 22 in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                sock.connect((ip, 22))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                if 'SSH' in banner and ('MikroTik' in banner or 'RouterOS' in banner):
                    match = re.search(r'RouterOS\s+([\d.]+)', banner)
                    return f'RouterOS v{match.group(1)}' if match else 'RouterOS'
            except Exception:
                pass
        return 'RouterOS'
    except Exception:
        return 'RouterOS'

# ============================================
# БЛОК 6: ОСНОВНОЙ КЛАСС СКАНЕРА
# ============================================

class IPScanner:
    def __init__(self, network: str, scan_ports: bool = True, max_threads: int = 150):
        self.network = network
        self.scan_ports = scan_ports
        self.max_threads = max_threads
        self.results = []
        self.lock = threading.Lock()
        self.total_hosts = 0
        self.scanned_hosts = 0
        self.found_hosts = 0
        self.interesting_ports = [22, 80, 443, 445, 515, 631, 3306, 3389, 8080, 8291, 8443, 8728, 8729, 9100]
        self.scan_start_time = 0
        self.last_update_time = 0
        
    def scan_host(self, ip: str) -> Dict:
        result = {
            'ip': ip,
            'alive': False,
            'mac': None,
            'vendor': None,
            'hostname': None,
            'domain': None,
            'device_model': None,
            'web_ui': None,
            'os': 'Unknown',
            'device_type': 'Unknown',
            'is_printer': False,
            'is_mikrotik': False,
            'is_vm': False,
            'show_os': True,
            'ports': []
        }
        
        alive, mac = is_host_alive(ip)
        
        if alive:
            result['alive'] = True
            if mac:
                result['mac'] = mac
                result['vendor'] = get_vendor(mac)
            
            nb_name, nb_domain = get_netbios_name(ip)
            dns_hostname = get_hostname(ip)
            
            if nb_name:
                result['hostname'] = nb_name
                result['domain'] = nb_domain
            elif dns_hostname != 'Unknown':
                if '.' in dns_hostname:
                    parts = dns_hostname.split('.', 1)
                    result['hostname'] = parts[0]
                    result['domain'] = parts[1]
                else:
                    result['hostname'] = dns_hostname
            
            result['os'] = detect_os(ip)
            
            if self.scan_ports:
                open_ports = []
                port_list = []
                for port in self.interesting_ports:
                    if scan_port(ip, port, timeout=0.15):
                        open_ports.append({
                            'port': port,
                            'service': get_port_service(port)
                        })
                        port_list.append(port)
                result['ports'] = open_ports
                
                web_ports = [80, 443, 8080, 8443]
                found_web_port = None
                for wp in web_ports:
                    if wp in port_list:
                        if not found_web_port:
                            found_web_port = wp
                        model_name = get_http_title(ip, wp)
                        if model_name:
                            result['device_model'] = model_name
                            found_web_port = wp
                            break

                if found_web_port:
                    proto = 'https' if found_web_port in [443, 8443] else 'http'
                    port_part = f":{found_web_port}" if found_web_port not in [80, 443] else ""
                    result['web_ui'] = f"{proto}://{ip}{port_part}/"

                device_info = detect_device_type(ip, port_list, mac, result['vendor'])
                result['device_type'] = device_info['device_type']
                result['is_printer'] = device_info['is_printer']
                result['is_mikrotik'] = device_info['is_mikrotik']
                result['is_vm'] = device_info['is_vm']
                
                if result['is_printer']:
                    result['os'] = ''
                    result['show_os'] = False
                elif result['is_mikrotik']:
                    result['os'] = detect_mikrotik_os(ip, port_list)
                    result['show_os'] = True
                elif result['is_vm']:
                    if result['os'] == 'Unknown' or 'Linux' in result['os']:
                        result['os'] = 'VM Guest'
                    result['show_os'] = True
                elif 'Network' in result['device_type']:
                    if result['os'] == 'Unknown' or 'Linux' in result['os']:
                        result['os'] = 'Network OS'
                    result['show_os'] = True
                elif 'Server' in result['device_type'] or 'NAS' in result['device_type']:
                    if result['os'] == 'Unknown':
                        result['os'] = 'Server OS'
                    result['show_os'] = True
                else:
                    result['show_os'] = True
        
        return result
    
    def print_progress(self):
        current_time = time.time()
        if current_time - self.last_update_time < 0.05 and self.scanned_hosts < self.total_hosts:
            return
        self.last_update_time = current_time
        
        bar_length = 24
        progress = self.scanned_hosts / max(self.total_hosts, 1)
        
        blocks = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"]
        filled_length = progress * bar_length
        full_blocks = int(filled_length)
        remainder = int((filled_length - full_blocks) * 8)
        
        bar = '█' * full_blocks
        if full_blocks < bar_length:
            bar += blocks[remainder]
            bar += ' ' * (bar_length - full_blocks - 1)
        else:
            bar = '█' * bar_length
            
        color = Colors.GREEN if progress > 0.8 else (Colors.YELLOW if progress > 0.4 else Colors.CYAN)
        percent = progress * 100
        elapsed = current_time - self.scan_start_time
        speed = self.scanned_hosts / max(elapsed, 0.1)
        
        remaining_time = (self.total_hosts - self.scanned_hosts) / max(speed, 0.1)
        eta_str = f"{int(remaining_time)}s" if remaining_time < 60 else f"{int(remaining_time//60)}m{int(remaining_time%60)}s"
        
        sys.stdout.write('\033[?25l\r\033[K')
        line = (
            f'{Colors.GRAY}│{color}{bar}{Colors.GRAY}│{Colors.END} '
            f'{Colors.BOLD}{percent:5.1f}%{Colors.END}  '
            f'{Colors.CYAN}{self.scanned_hosts}/{self.total_hosts}{Colors.END}  '
            f'{Colors.GREEN}● {self.found_hosts}{Colors.END}  '
            f'{Colors.GRAY}{speed:.1f}/s  ETA {eta_str}{Colors.END}'
        )
        sys.stdout.write(line)
        sys.stdout.flush()
    
    def worker(self, ip: str):
        result = self.scan_host(ip)
        with self.lock:
            self.results.append(result)
            self.scanned_hosts += 1
            if result['alive']:
                self.found_hosts += 1
            self.print_progress()
    
    def print_results(self, elapsed_time: float):
        sys.stdout.write('\033[?25h\r\033[K\n')
        sys.stdout.flush()
        
        print(f"{Colors.GRAY}{'━' * LINE_WIDTH}{Colors.END}")
        alive_hosts = [r for r in self.results if r['alive']]
        print(f"{Colors.BOLD}{tr('scan_results')}{Colors.END} {Colors.GREEN}{tr('active_hosts', alive=len(alive_hosts))}{Colors.END} {tr('found_in', time=elapsed_time, total=len(self.results))}")
        print(f"{Colors.GRAY}{'━' * LINE_WIDTH}{Colors.END}")
        
        if not alive_hosts:
            print(f"{Colors.YELLOW}{tr('no_hosts')}{Colors.END}\n")
            return

        grouped = {
            tr('cat_pc'): [],
            tr('cat_printers'): [],
            tr('cat_net'): [],
            tr('cat_voip'): [],
            tr('cat_vm'): [],
            tr('cat_other'): []
        }
        
        for h in alive_hosts:
            if h.get('is_printer'):
                grouped[tr('cat_printers')].append(h)
            elif h.get('is_voip'):
                grouped[tr('cat_voip')].append(h)
            elif h.get('is_mikrotik') or 'Network' in h.get('device_type', ''):
                grouped[tr('cat_net')].append(h)
            elif h.get('is_vm'):
                grouped[tr('cat_vm')].append(h)
            elif 'Computer' in h.get('device_type', '') or 'Server' in h.get('device_type', ''):
                grouped[tr('cat_pc')].append(h)
            else:
                grouped[tr('cat_other')].append(h)
        
        ip_sort = lambda x: [int(octet) for octet in x['ip'].split('.')]

        for category_name, hosts in grouped.items():
            if not hosts:
                continue
            
            hosts.sort(key=ip_sort)
            
            print(f"\n{Colors.BOLD}{Colors.CYAN}{category_name} ({len(hosts)}){Colors.END}")
            print(f"{Colors.GRAY}{'━' * LINE_WIDTH}{Colors.END}")
            
            for idx, host in enumerate(hosts, 1):
                print(f" {Colors.GREEN}▸{Colors.END} {Colors.BOLD}{host['ip']}{Colors.END}")
                
                if host.get('hostname'):
                    domain_str = f" {Colors.BOLD}[{host['domain']}]{Colors.END}" if host.get('domain') else ""
                    print(f"   {Colors.GRAY}Host:{Colors.END}  {Colors.BOLD}{host['hostname']}{Colors.END}{domain_str}")
                
                info_line = []
                if host.get('device_model'):
                    info_line.append(f"{Colors.HEADER}{host['device_model']}{Colors.END}")
                elif host.get('device_type') and host['device_type'] != 'Unknown':
                    info_line.append(host['device_type'])
                    
                if host.get('show_os', True) and host.get('os') and host['os'] != 'Unknown':
                    info_line.append(host['os'])
                    
                if info_line:
                    print(f"   {Colors.GRAY}Info:{Colors.END}  {' / '.join(info_line)}")
                
                if host.get('web_ui') and category_name != tr('cat_pc'):
                    print(f"   {Colors.GRAY}Web UI:{Colors.END} {Colors.CYAN}{host['web_ui']}{Colors.END}")

                if host.get('mac'):
                    vendor = host.get('vendor')
                    vendor_part = f" ({vendor})" if vendor else ""
                    print(f"   {Colors.GRAY}MAC:{Colors.END}   {host['mac']}{vendor_part}")
                
                if host.get('ports'):
                    port_str = ", ".join([f"{p['port']}/{p['service']}" for p in host['ports']])
                    print(f"   {Colors.GRAY}Ports:{Colors.END} {port_str}")
                print()
            
        print(f"{Colors.GRAY}{'━' * LINE_WIDTH}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}{tr('scan_complete')}{Colors.END}\n")
    
    def scan(self):
        self.scan_start_time = time.time()
        self.last_update_time = 0
        
        try:
            network = ipaddress.ip_network(self.network, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
            if not ip_list:
                ip_list = [str(network.network_address)]
        except ValueError as e:
            print(f"{Colors.RED}Error: Invalid network format - {e}{Colors.END}")
            return
        
        self.total_hosts = len(ip_list)
        self.scanned_hosts = 0
        self.found_hosts = 0
        self.results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.worker, ip) for ip in ip_list]
            concurrent.futures.wait(futures)
        
        elapsed_time = time.time() - self.scan_start_time
        self.print_results(elapsed_time)

# ============================================
# БЛОК 7: ДИАГНОСТИКА
# ============================================

def diagnose_network():
    print(f"\n{Colors.BOLD}{tr('net_status')}{Colors.END}")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        my_ip = s.getsockname()[0]
        s.close()
        parts = my_ip.split('.')
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        print(f"  {Colors.GREEN}✓{Colors.END} {tr('host_ip')} {my_ip} ({tr('subnet')} {network})")
    except Exception:
        print(f"  {Colors.RED}✗{Colors.END} {tr('err_ip')}")
    
    try:
        if get_os_name() == 'Windows':
            output = subprocess.check_output(['arp', '-a'], timeout=2).decode('cp866', errors='ignore')
        else:
            output = subprocess.check_output(['arp', '-n'], timeout=2).decode('utf-8', errors='ignore')
        
        arp_entries = len(re.findall(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', output, re.I))
        print(f"  {Colors.GREEN}✓{Colors.END} {tr('arp_cache')} {arp_entries}")
    except Exception:
        pass
    
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        test_socket.close()
        print(f"  {Colors.GREEN}✓{Colors.END} {tr('raw_sockets_ok')}")
    except PermissionError:
        print(f"  {Colors.YELLOW}⚠{Colors.END} {tr('raw_sockets_fail')}")
    except Exception:
        pass

# ============================================
# БЛОК 8: ПОКАЗ СПРАВКИ
# ============================================

def show_help():
    print(f"""
{Colors.BOLD}{tr('help_title')}{Colors.END}

{Colors.YELLOW}{tr('help_privs')}{Colors.END}
{tr('help_privs_desc')}

{Colors.YELLOW}{tr('help_arp')}{Colors.END}
{tr('help_arp_desc')}

{Colors.YELLOW}{tr('help_firewall')}{Colors.END}
{tr('help_firewall_desc')}

{Colors.YELLOW}{tr('help_cidr')}{Colors.END}
{tr('help_cidr_desc')}
    """)
    input(f"{Colors.GRAY}{tr('press_return_menu')}{Colors.END}")

# ============================================
# БЛОК 9: ГЛАВНЫЙ ЦИКЛ ПРОГРАММЫ
# ============================================

def print_banner():
    print(f"{Colors.BOLD}{Colors.HEADER}")
    print(r" ___________  ___ _________  ________ _   _ ")
    print(r"|_   _| ___ \/ _ \|  _  \  \/  |_   _| \ | |")
    print(r"  | | | |_/ / /_\ \ | | | .  . | | | |  \| |")
    print(r"  | | |  __/|  _  | | | | |\/| | | | | . ` |")
    print(r" _| |_| |   | | | | |/ /| |  | |_| |_| |\  |")
    print(r" \___/\_|   \_| |_/___/ \_|  |_/\___/\_| \_/")
    print(f"{Colors.END}")
    print(f"{Colors.GRAY}{'━' * LINE_WIDTH}{Colors.END}")

def get_scan_parameters():
    print(f"\n{Colors.BOLD}{tr('scan_options')}{Colors.END}")
    print(f"{Colors.GRAY}{'━' * LINE_WIDTH}{Colors.END}")
    print(f"  {tr('opt_auto')}")
    print(f"  {tr('opt_manual')}")
    print(f"  {tr('opt_single')}")
    print(f"  {tr('opt_help')}")
    print(f"  {tr('opt_exit')}")
    
    choice = input(f"\n{Colors.BOLD}{tr('select_choice')}{Colors.END}").strip()
    
    if choice == '5' or choice.lower() in ('exit', 'quit', 'выход'):
        return None, None, True
    
    if choice == '4':
        show_help()
        return None, None, False
    
    network = None
    scan_ports = True
    
    if choice == '1':
        network = get_local_network()
        print(f"{Colors.GREEN}{tr('target')} {network}{Colors.END}")
    elif choice == '2':
        network = input(tr('enter_cidr')).strip()
        if not network:
            network = get_local_network()
            print(f"{tr('target')} {network}")
    elif choice == '3':
        single_ip = input(tr('enter_ip')).strip()
        if single_ip:
            network = single_ip + "/32"
        else:
            network = get_local_network()
            print(f"{tr('target')} {network}")
    else:
        network = get_local_network()
        print(f"{tr('target')} {network}")
    
    return network, scan_ports, False

def main():
    print_banner()
    diagnose_network()
    
    running = True
    scan_count = 0
    
    while running:
        network, scan_ports, should_exit = get_scan_parameters()
        
        if should_exit:
            print(f"\n{Colors.GREEN}{tr('exiting')}{Colors.END}")
            break
        
        if network is None:
            continue
        
        scan_count += 1
        print(f"\n{Colors.GRAY}{'━' * LINE_WIDTH}{Colors.END}")
        print(f"{Colors.BOLD}{tr('starting_scan', count=scan_count)}{Colors.END} {Colors.CYAN}{network}{Colors.END}")
        print(f"{Colors.GRAY}{'━' * LINE_WIDTH}{Colors.END}\n")
        
        scanner = IPScanner(network, scan_ports=scan_ports, max_threads=150)
        scanner.scan()
        
        user_input = input(f"{Colors.GRAY}{tr('press_enter')}{Colors.END}").strip().lower()
        if user_input in ('exit', 'quit', 'выход'):
            print(f"\n{Colors.GREEN}{tr('exiting')}{Colors.END}")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write('\033[?25h')
        print(f"\n\n{Colors.YELLOW}{tr('scan_aborted')}{Colors.END}")
        sys.exit(0)
    except Exception as e:
        sys.stdout.write('\033[?25h')
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)