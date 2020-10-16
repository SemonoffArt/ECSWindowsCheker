#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import logging
import re
import subprocess
import sys
from pathlib import Path

PRG_DIR = Path(__file__).parent.absolute()
LOG_FILE = PRG_DIR / 'ecs_chk_windows.log'
_log_format = f"%(asctime)s - [%(levelname)s] - %(name)s - (%(filename)s).%(funcName)s(%(lineno)d) - %(message)s"
logging.basicConfig(format=_log_format, filename=LOG_FILE, filemode='w', level=logging.INFO)
logger = logging.getLogger(__name__)
SRV_NAME = {'10.24.1.1': 'ECS2261SRV1', '10.24.1.2': 'ECS2261SRV2'}


def get_args() -> list:
    # Check arguments for script
    ip_addr = None
    command = None
    items_args = len(sys.argv)
    if items_args >= 2:
        if check_ip(sys.argv[1]):
            ip_addr = sys.argv[1]
        else:
            logger.info(f"Wrong IP {sys.argv[1]}")
        if items_args > 2:
            command = sys.argv[2] if sys.argv[2] == 'get_users' or sys.argv[2] == 'get_servers' else None

    else:
        logger.info("Not def param")
    logger.info(f"Arguments: {ip_addr}, {command}")
    return [ip_addr, command]


def check_ip(ip):
    logger.debug(f"Chek IP {ip}")
    if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
        return True
    else:
        return False


def _get_text_from_file(file_name):
    """ Чтение файла с выводом команд для отладки"""
    logger.debug(f"Open text file {file_name}")
    file = Path.cwd() / file_name
    text = None
    if not file.is_file():
        err_msg = f"Cannot find file: {file} "
        logger.error(err_msg)
    else:
        text = file.read_text()

    return text


def _run_zabbix_get(host_ip, command) -> chr:
    """Выполнение на удалённом хосте, через Zabbix агента, произвольной команды"""
    result = ""
    logger.debug(f"Run remote command {command}")
    try:
        stdout = subprocess.run(['zabbix_get',
                                 '-s', host_ip,
                                 '-k', f'system.run[{command}]'],
                                stdout=subprocess.PIPE,
                                encoding='utf-8', errors='ignore')
        result = stdout.stdout
    except FileNotFoundError as e:
        logger.info(f"Can't run remote command {command}. {e}")
        result = None

    return result


class NoDataFromHost(Exception):
    pass


class ECSWindows(object):
    """Проверяет количесто окон ECS на хосте, сервера их поключения через zabbix агента.
        Возвращает структуру:
        "10.24.1.10":{
            "ECS2261REM01\\masterkip_1":{
                window_pid:{
                    "ImageName": "SdrOpStationUI30.exe",
                    "PID": "6692",
                    "SessionName": "RDP-Tcp0_1",
                    "Session": "1",
                    "MemUsage": "52\u044f692K_1",
                    "Status": "Unknown_1",
                    "UserName": "ECS2261REM01\\masterkip_1",
                    "CPUTime": "0:00:39_1",
                    "WindowTitle": "N/A_1",
                    "LocAddr": "10.24.1.10:59336",
                    "ForAddr": "10.24.1.2:49173"
        }}}
     """
    CMD_NETSTAT = "netstat -bon"
    CMD_TASKLIST = 'tasklist /V /FI "IMAGENAME eq  SdrOpStationUI30.exe"  /FO LIST'

    def __init__(self, host_ip='127.0.0.1', test_on_file=False):
        """Иницилизация класса"""
        self.host_ip = host_ip
        self.test_on_file = test_on_file
        self.host_process = {}
        self.qty_hosts = 0
        self.qty_windows = 0
        self.qty_users = 0
        self.users = []
        self.servers = {}
        self.report_json = ""
        self.report_dict = {}
        netstat_stdo = self._get_netstat(self.host_ip)
        tasklist_stdo = self._get_tasklist(self.host_ip)
        if netstat_stdo and tasklist_stdo:
            self.items = self._parse_stdo(tasklist_stdo, netstat_stdo)
            self._make_report()
        else:
            self.items = None
            raise NoDataFromHost

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(self.items)

    def __get__(self, instance, owner):
        return self.items

    def __getitem__(self, key):
        # если значение или тип ключа некорректны, list выбросит исключение
        return self.items[key]

    def get_json(self):
        return json.dumps(self.items, indent=4)

    def _get_netstat(self, host_ip=None) -> chr:
        """Выполнение на удалённом хосте, через Zabbix агента, комманды netstat, получение ввывода"""
        if self.test_on_file:
            stdout = _get_text_from_file('netstat.txt')
        else:
            stdout = _run_zabbix_get(self.host_ip, ECSWindows.CMD_NETSTAT)
        return stdout

    def _get_tasklist(self, host_ip=None) -> chr:
        """Выполнение на удалённом хосте, через Zabbix агента, комманды tasklist, получение ввывода"""
        if self.test_on_file:
            stdout = _get_text_from_file('task_list.txt')
        else:
            stdout = _run_zabbix_get(self.host_ip, ECSWindows.CMD_TASKLIST)
        return stdout

    def _parse_netstat(self, netstat_stdo: str) -> dict:
        """ Парсит вывод команды cli windows: netsat.exe -bon
         [SdrOpStationUI30.exe]
          TCP    10.24.1.10:58573       10.24.1.2:49172        ESTABLISHED     13136
        """
        tasks = {}
        next_lines_is_values = False
        for line in netstat_stdo.splitlines():
            if next_lines_is_values:
                next_lines_is_values = False
                # TCP    10.24.1.10:51235       10.24.1.2:49166        ESTABLISHED     11440
                result = re.search(r'TCP\s+(.*?):\d+\s+(.*?):\d+\s+(\w+)\s+(\d+)', line)
                if result:
                    pid = result.group(4)
                    # Заменяем IP на имя сервера
                    server_name = SRV_NAME[result.group(2)] if result.group(2) in SRV_NAME else result.group(2)
                    tasks[pid] = {'LocAddr': result.group(1).split(':')[0], 'ForAddr': server_name}

            if re.search('SdrOpStationUI30', line):
                next_lines_is_values = True

        return tasks

    def _parse_stdo(self, tasklist_stdo: str, netstat_stdo: str) -> dict:
        """
        Парсит вывод команды cli windows:  "tasklist /V /FI \"IMAGENAME eq  SdrOpStationUI30.exe\"  /FO LIST"
        Вывод tasklist:
            Image Name:   SdrOpStationUI30.exe
            PID:          6692
            Session Name: RDP-Tcp#0
            Session#:     7
            Mem Usage:    52я692 K
            Status:       Unknown
            User Name:    ECS2261REM01\masterkip
            CPU Time:     0:00:39
            Window Title: N/A

            Возвращает:
            [{'ImageName': 'SdrOpStationUI30.exe_1', 'PID': '6692', 'LocAddr': '10.24.1.10', 'ForAddr': '10.24.1.2',
            'SessionName': 'RDP-Tcp0_1', 'Session': '1', 'MemUsage': '52я692K_1', 'Status': 'Unknown_1',
            'UserName': 'ECS2261REM01\\masterkip_1', 'CPUTime': '0:00:39_1', 'WindowTitle': 'N/A_1'}]
        """
        logger.debug(f"Parse stdo ")
        netstat_tasks = self._parse_netstat(netstat_stdo)
        taskslist = []
        task = {}
        tasks = {}
        cnt_strngs = 0
        len_strngs = len(tasklist_stdo.splitlines())
        for line in tasklist_stdo.splitlines():
            cnt_strngs += 1
            line = line.replace(' ', '')
            line = line.replace('#', '')
            line = line.replace('\\', '_')
            result = re.match(r'^(\w+):(.+)', line)
            if result:
                key = result.group(1)
                value = result.group(2)
                if key in ['ImageName', 'PID', 'SessionName', 'Session', 'UserName']:
                    # if key == 'UserName':
                    # value.replace('\\', '_')
                    task[key] = value
                    if key == 'PID' and netstat_tasks.get(value):
                        task.update(netstat_tasks[value])

            if line == '' or cnt_strngs == len_strngs:
                if len(task) > 0:
                    taskslist.append(task.copy())
                    task.clear()

        for task in taskslist:
            tasks[task['PID']] = task

        return tasks

    def get_users(self) -> list:
        """Возвращает список с именами пользователей окон"""
        windows = self.items
        for pid in windows:
            if not (windows[pid]['UserName'] in self.users):
                self.users.append(windows[pid]['UserName'])
        return self.users

    def get_users_json(self) -> str:
        """Возвращает пользователей для LLD zabbix"""
        users = []
        for user in self.users:
            users.append({'{#USER}': user})
        return json.dumps(users, indent=4)

    def get_user_windows(self, user) -> []:
        """Возвращает список окон пользователя"""
        if not user:
            raise ValueError("Not def user")
        user_windows = []
        windows = self.items
        for pid in windows:
            if windows[pid]['UserName'] == user:
                user_windows.append(windows[pid])
        return user_windows

    def get_servers(self) -> dict:
        """возвращает словарь 'srv_addr':[PID1,PID2]"""
        self.servers = {}
        windows = self.items
        for pid in windows:
            if 'ForAddr' in windows[pid]:
                if windows[pid]['ForAddr'] in self.servers:
                    self.servers[windows[pid]['ForAddr']].append(pid)
                else:
                    self.servers[windows[pid]['ForAddr']] = [pid]
        return self.servers

    def get_servers_json(self) -> str:
        """Возвращает сервера хоста для LLD Zabbix"""
        servers = []
        for server in self.servers.keys():
            servers.append({'{#SERVER}': server})
        return json.dumps(servers, indent=4)

    def get_servers_win_qnty(self, server_name='ECS2261SRV1') -> int:
        """Возвращает кол-во ECS окон работающих с данным сервером"""
        if server_name in self.servers:
            win_qnty = len(self.servers[server_name])
        else:
            win_qnty = 0
        return win_qnty

    def _make_report(self) -> dict:
        """Формирует отчёт для ZABBIX"""
        users = self.get_users()
        usr_wnds = {}
        usr_wnds_qnty = {}
        servers = self.get_servers()
        servers_win_qnty = {}

        for server in servers:
            servers_win_qnty[server] = self.get_servers_win_qnty(server)

        for user in users:
            usr_wnd = self.get_user_windows(user)
            usr_wnds[user] = usr_wnd
            usr_wnds_qnty[user] = len(usr_wnd)

        self.report_dict = {
            'host': self.host_ip,
            'users': users,
            'servers': servers,
            'users_windows': usr_wnds,
            'windows_qnty': len(self.items),
            'user_windows_qnty': usr_wnds_qnty,
            'users_qnty': len(users),
            'servers_windows_qnty': servers_win_qnty,
            'ECS2261SRV1_windows_qnty': self.get_servers_win_qnty('ECS2261SRV1'),
            'ECS2261SRV2_windows_qnty': self.get_servers_win_qnty('ECS2261SRV2')

        }
        self.report_json = json.dumps(self.report_dict, indent=4)


def main():
    logger.info("Start utils")
    host_ip, command = get_args()
    result = ""

    try:
        ecs_windows = ECSWindows(host_ip=host_ip, test_on_file=False)
        if command == 'get_users':
            result = ecs_windows.get_users_json()
        elif command == 'get_servers':
            result = ecs_windows.get_servers_json()
        else:
            result = ecs_windows.report_json

        print(result)

    except Exception as e:
        logger.info(f"Can't get data from host {host_ip} {e}")
        print(f"Can't get data from host {host_ip} \n{e}")

    logger.info("End utils")


if __name__ == '__main__':
    main()
