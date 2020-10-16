# ECS Windows Cheker for ZABBIX
[![License](https://img.shields.io/github/license/m-lundberg/simple-pid.svg)](https://github.com/m-lundberg/simple-pid/blob/master/LICENSE.md)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Скрипт предназначен для сбора информации по открытым окнам **SCADA FLS ECS** на хостах и передаче системе мониторинга Zabbix.

Так как открытые окна ECS лицензируются, требуется контроль с каких хостов, какие пользователи, 
с каким количеством мнемосхем работают, и каким ECS серверам они подключены.
Скрип вызывается zabbix сервером как ключ *"External Check"* c передачей ip адреса хоста и команды, 
результат работы json структура с информацией по открытым окнам ECS.

Скрипт используя утилиту zabbix_get выполняет через zabbix агента, установленного на удалённом хосте, утилиты:
* 'netstat.exe -bon' -  информация о подключениях окон к серверам ECS;
* 'tasklist.exe /V /FI "IMAGENAME eq  SdrOpStationUI30.exe"  /FO LIST' - информация о колличестве окон и их владельах (пользователях).

Вывод парсится скриптом и предоставляется в JSON, на основании в Zabbix формируются items и triggers.

## Installation
Скопируйте скрипт в папку **externalscripts** Zabbix. 

Создайте в конфигурации хоста item типа *"External check"*, 
в поле KEY введите *ecs_chk_windows.py[{HOST.CONN}]*.

![Make Item](/img/make_external_check_item.PNG)

## Python Version
Скрипт создан и тестировался на Python 3.6.9

## Dependencies
Без внешних зависимостей, только стандартные библиотеки Python.


## License
Licensed under the [MIT License](https://github.com/m-lundberg/simple-pid/blob/master/LICENSE.md).
