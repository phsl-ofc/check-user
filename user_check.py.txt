#!/usr/bin/env python3

import typing as t

import os
import sys
import json

import socket
import threading
import queue

import logging
import argparse

from datetime import datetime
from urllib.parse import urlparse

__author__ = '@DuTra01'
__version__ = '2.1.4'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger(__name__)


class OpenVPNManager:
    def __init__(self, port: int = 7505):
        self.port = port
        self.config_path = '/etc/openvpn/'
        self.config_file = 'server.conf'
        self.log_file = 'openvpn.log'
        self.log_path = '/var/log/openvpn/'

        self.start_manager()

    @property
    def config(self) -> str:
        return os.path.join(self.config_path, self.config_file)

    @property
    def log(self) -> str:
        path = os.path.join(self.log_path, self.log_file)
        if os.path.exists(path):
            return path

        self.log_path = 'openvpn-status.log'
        return os.path.join(self.config_path, self.log_file)

    def create_connection(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', self.port))
        return sock

    def start_manager(self) -> None:
        if os.path.exists(self.config):
            with open(self.config, 'r') as f:
                data = f.readlines()

                management = 'management localhost %d\n' % self.port
                if management in data:
                    return

                data.insert(1, management)

            with open(self.config, 'w') as f:
                f.writelines(data)

            os.system('service openvpn restart')

    def count_connection_from_manager(self, username: str) -> int:
        try:
            soc = self.create_connection()
            soc.send(b'status\n')

            data = b''
            buf = data

            while b'\r\nEND\r\n' not in buf:
                buf = soc.recv(1024)
                data += buf

            soc.close()
            count = data.count(username.encode())
            return count // 2 if count > 0 else 0
        except Exception:
            return -1

    def count_connection_from_log(self, username: str) -> int:
        if os.path.exists(self.log):
            with open(self.log, 'r') as f:
                data = f.read()
                count = data.count(username)
                return count // 2 if count > 0 else 0
        return 0

    def count_connections(self, username: str) -> int:
        count = self.count_connection_from_manager(username)
        return count if count > -1 else self.count_connection_from_log(username)

    def kill_connection(self, username: str) -> None:
        soc = self.create_connection()
        soc.send(b'kill %s\n' % username.encode())
        soc.close()


class SSHManager:
    def count_connections(self, username: str) -> int:
        command = 'ps -u %s' % username
        result = os.popen(command).readlines()
        return len([line for line in result if 'sshd' in line])

    def get_pids(self, username: str) -> t.List[int]:
        command = 'ps -u %s' % username
        result = os.popen(command).readlines()
        return [int(line.split()[0]) for line in result if 'sshd' in line]

    def kill_connection(self, username: str) -> None:
        pids = self.get_pids(username)
        for pid in pids:
            os.kill(pid, 9)


class CheckerUserManager:
    def __init__(self, username: str):
        self.username = username
        self.ssh_manager = SSHManager()
        self.openvpn_manager = OpenVPNManager()

    def get_expiration_date(self) -> t.Optional[str]:
        command = 'chage -l %s' % self.username
        result = os.popen(command).readlines()

        for line in result:
            line = list(map(str.strip, line.split(':')))
            if line[0].lower() == 'account expires' and line[1] != 'never':
                return datetime.strptime(line[1], '%b %d, %Y').strftime('%d/%m/%Y')

        return None

    def get_expiration_days(self, date: str) -> int:
        if not isinstance(date, str) or date.lower() == 'never' or not isinstance(date, str):
            return -1

        return (datetime.strptime(date, '%d/%m/%Y') - datetime.now()).days

    def get_connections(self) -> int:
        return self.ssh_manager.count_connections(
            self.username
        ) + self.openvpn_manager.count_connections(self.username)

    def get_time_online(self) -> t.Optional[str]:
        command = 'ps -u %s -o etime --no-headers' % self.username
        result = os.popen(command).readlines()
        return result[0].strip() if result else None

    def get_limiter_connection(self) -> int:
        path = '/root/usuarios.db'

        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    split = line.strip().split()
                    if len(split) == 2 and split[0] == self.username:
                        return int(split[1].strip())

        return -1

    def kill_connection(self) -> None:
        self.ssh_manager.kill_connection(self.username)
        self.openvpn_manager.kill_connection(self.username)


class CheckerUserConfig:
    CONFIG_FILE = 'config.json'
    PATH_CONFIG = '/etc/checker/'
    PATH_CONFIG_OPTIONAL = os.path.join(os.path.expanduser('~'), 'checker')

    def __init__(self):
        self.config = self.load_config()

    @property
    def path_config(self) -> str:
        path = os.path.join(self.PATH_CONFIG, self.CONFIG_FILE)

        try:
            if not os.path.exists(path):
                os.makedirs(self.PATH_CONFIG, exist_ok=True)
        except PermissionError:
            path = os.path.join(self.PATH_CONFIG_OPTIONAL, self.CONFIG_FILE)

            if not os.path.exists(path):
                os.makedirs(self.PATH_CONFIG_OPTIONAL, exist_ok=True)

        return path

    @property
    def exclude(self) -> t.List[str]:
        return self.config.get('exclude', [])

    @exclude.setter
    def exclude(self, value: t.List[str]):
        self.config['exclude'] = value
        self.save_config()

    def include(self, name: str) -> bool:
        if name in self.exclude:
            self.exclude.remove(name)
            self.save_config()
            return True

        return False

    @property
    def port(self) -> int:
        return self.config.get('port', 5000)

    @port.setter
    def port(self, value: int):
        self.config['port'] = value
        self.save_config()

    def load_config(self) -> dict:
        default_config = {
            'exclude': [],
            'port': 5000,
        }

        if os.path.exists(self.path_config):
            with open(self.path_config, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, dict) else default_config

        return default_config

    def save_config(self, config: dict = None):
        self.config = config or self.config

        with open(self.path_config, 'w') as f:
            f.write(json.dumps(self.config, indent=4))

    @staticmethod
    def remove_config() -> None:
        if os.path.exists(CheckerUserConfig.PATH_CONFIG):
            os.system('rm -rf %s' % CheckerUserConfig.PATH_CONFIG)


class ServiceManager:
    CONFIG_SYSTEMD_PATH = '/etc/systemd/system/'
    CONFIG_SYSTEMD = 'user_check.service'

    @property
    def config(self) -> str:
        return os.path.join(self.CONFIG_SYSTEMD_PATH, self.CONFIG_SYSTEMD)

    @property
    def is_created(self) -> bool:
        return os.path.exists(self.config)

    @property
    def is_enabled(self) -> bool:
        return os.system('systemctl is-enabled %s >/dev/null' % self.CONFIG_SYSTEMD) == 0

    def status(self) -> str:
        command = 'systemctl status %s' % self.CONFIG_SYSTEMD
        result = os.popen(command).readlines()
        return ''.join(result)

    def start(self):
        status = self.status()
        if 'Active: active' not in status:
            os.system('systemctl start %s' % self.CONFIG_SYSTEMD)
            return True

        logger.info('Service is already running')
        return False

    def stop(self):
        status = self.status()
        if 'Active: inactive' not in status:
            os.system('systemctl stop %s' % self.CONFIG_SYSTEMD)
            return True

        logger.info('Service is already stopped')
        return False

    def restart(self) -> bool:
        command = 'systemctl restart %s' % self.CONFIG_SYSTEMD
        return os.system(command) == 0

    def remove_service(self):
        os.system('systemctl stop %s' % self.CONFIG_SYSTEMD)
        os.system('systemctl disable %s' % self.CONFIG_SYSTEMD)
        os.system('rm %s' % self.config)
        os.system('systemctl daemon-reload')

    def create_systemd_config(self):
        config_template = ''.join(
            [
                '[Unit]\n',
                'Description=User check service\n',
                'After=network.target\n\n',
                '[Service]\n',
                'Type=simple\n',
                'ExecStart=%s %s --run\n' % (sys.executable, os.path.abspath(__file__)),
                'Restart=always\n',
                'User=root\n',
                'Group=root\n\n',
                '[Install]\n',
                'WantedBy=multi-user.target\n',
            ]
        )

        config_path = os.path.join(self.CONFIG_SYSTEMD_PATH, self.CONFIG_SYSTEMD)
        if not os.path.exists(config_path):
            try:
                with open(config_path, 'w') as f:
                    f.write(config_template)
            except PermissionError:
                logging.warning('Permission denied to create systemd config')
                return

            os.system('systemctl daemon-reload >/dev/null')

    def enable_auto_start(self) -> bool:
        if not self.is_enabled:
            os.system('systemctl enable %s >/dev/null' % self.CONFIG_SYSTEMD)

        return self.is_enabled

    def disable_auto_start(self) -> bool:
        if self.is_enabled:
            os.system('systemctl disable %s >/dev/null' % self.CONFIG_SYSTEMD)

        return not self.is_enabled

    def create_service(self) -> bool:
        self.create_systemd_config()
        return self.is_created


class CheckerManager:
    RAW_URL_DATA = 'https://raw.githubusercontent.com/NT-GIT-HUB/DataPlugin/main/user_check.py'

    EXECUTABLE_PATH = '/usr/bin/'
    EXECUTABLE_NAME = 'checker'
    EXECUTABLE_FILE = EXECUTABLE_PATH + EXECUTABLE_NAME

    @staticmethod
    def create_executable() -> None:
        of_path = os.path.join(os.path.expanduser('~'), 'chk.py')
        to_path = CheckerManager.EXECUTABLE_FILE

        if os.path.exists(to_path):
            os.unlink(to_path)

        logger.info('Creating executable file...')
        logger.info('From: %s' % of_path)
        logger.info('To: %s' % to_path)

        try:
            os.chmod(of_path, 0o755)
            os.symlink(of_path, to_path)
            logger.info('Done!')
        except Exception as e:
            logger.error(e)

    @staticmethod
    def get_data() -> str:
        import requests

        response = requests.get(CheckerManager.RAW_URL_DATA)
        return response.text

    @staticmethod
    def check_update() -> t.Union[bool, str]:
        data = CheckerManager.get_data()

        if data:
            version = data.split('__version__ = ')[1].split('\n')[0].strip('\'')
            return version != __version__, version

        return False, __version__

    @staticmethod
    def update() -> bool:
        success, version = CheckerManager.check_update()
        if not success:
            logger.info('No update available')
            return False

        logger.info('New version available: %s' % version)

        data = CheckerManager.get_data()
        if not data:
            return False

        with open(__file__, 'w') as f:
            f.write(data)

        CheckerManager.create_executable()
        ServiceManager().restart()
        return True

    @staticmethod
    def remove_executable() -> None:
        os.remove(CheckerManager.EXECUTABLE_FILE)


def check_user(username: str) -> t.Dict[str, t.Any]:
    try:
        checker = CheckerUserManager(username)

        count = checker.get_connections()
        expiration_date = checker.get_expiration_date()
        expiration_days = checker.get_expiration_days(expiration_date)
        limit_connection = checker.get_limiter_connection()
        time_online = checker.get_time_online()

        return {
            'username': username,
            'count_connection': count,
            'limit_connection': limit_connection,
            'expiration_date': expiration_date,
            'expiration_days': expiration_days,
            'time_online': time_online,
            'version': __version__,
        }
    except Exception as e:
        return {'error': str(e)}


def kill_user(username: str) -> dict:
    result = {
        'success': True,
        'error': None,
    }

    try:
        checker = CheckerUserManager(username)
        checker.kill_connection()
        return result
    except Exception as e:
        result['success'] = False
        result['error'] = str(e)


class ParserServerRequest:
    def __init__(self, data: bytes):
        self.data = data
        self.command = None
        self.content = None

        self.commands_allowed = ['CHECK' 'KILL']

    def parse(self) -> None:
        try:
            data = self.data.decode('utf-8')

            first_line = data.split('\n')[0]
            path = first_line.split(' ')[1]

            self.command = path.split('/')[1]
            self.content = path.split('/')[2].split('?')[0]

        except Exception:
            self.command = None
            self.content = None


class FunctionExecutor:
    def __init__(self, command: str, content: str):
        self.command = command
        self.content = content

    def execute(self) -> t.Dict[str, t.Any]:
        if self.command.upper() == 'CHECK':
            return check_user(self.content)

        if self.command.upper() == 'KILL':
            return kill_user(self.content)

        return {'error': 'Command not allowed'}


class WorkerThread(threading.Thread):
    def __init__(self, queue: queue.Queue):
        super(WorkerThread, self).__init__()
        self.queue = queue
        self.daemon = True

        self.is_running = False

    def parse_request(self, data: bytes) -> t.Dict[str, t.Any]:
        request = ParserServerRequest(data.strip())
        request.parse()

        function_executor = FunctionExecutor(request.command, request.content)
        return function_executor.execute()

    def run(self):
        self.is_running = True
        while self.is_running:
            try:
                client, addr = self.queue.get()
                logger.info('Client connected: %s' % addr)

                data = client.recv(8192 * 8)
                if not data:
                    continue

                response_data = 'HTTP/1.1 200 OK\r\n Content-Type: application/json\r\n\r\n'
                response_data += json.dumps(self.parse_request(data))

                client.send(response_data.encode('utf-8'))
                client.close()

                logger.info('Client disconnected: %s' % addr)
            except Exception as e:
                logger.error(e)

    def stop(self):
        self.is_running = False


class ThreadPool:
    def __init__(self, max_workers: int = 10):
        self.queue = queue.Queue()
        self.workers = []
        self.max_workers = max_workers

    def start(self):
        for _ in range(self.max_workers):
            worker = WorkerThread(self.queue)
            worker.start()
            self.workers.append(worker)

    def join(self):
        for worker in self.workers:
            worker.stop()
            worker.join()

    def add_task(self, task: socket.socket, *args):
        self.queue.put((task, args))


class Server:
    def __init__(self, host: str, port: int, num_workers: int = 10):
        self.host = host
        self.port = port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.pool = ThreadPool(num_workers)
        self.pool.start()

    def handle(self, client, addr) -> None:
        self.pool.add_task(client, addr)

    def run(self) -> None:
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)

        logger.info('Server started on %s:%s' % (self.host, self.port))

        try:
            while True:
                client, addr = self.socket.accept()
                self.handle(client, addr)

        except KeyboardInterrupt:
            pass

        finally:
            self.socket.close()
            logger.info('Server stopped')


def main():
    parser = argparse.ArgumentParser(
        description='Check user v%s' % __version__,
        prog=CheckerManager.EXECUTABLE_NAME,
    )
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-p', '--port', type=int, help='Port to run server')
    parser.add_argument('--json', action='store_true', help='Output in json format')

    parser.add_argument('--run', action='store_true', help='Run server')
    parser.add_argument('--workers', type=int, default=10, help='Number of workers')

    parser.add_argument('--create-service', action='store_true', help='Create service')
    parser.add_argument('--remove-service', action='store_true', help='Remove service')

    parser.add_argument('--start', action='store_true', help='Start server')
    parser.add_argument('--stop', action='store_true', help='Stop server')
    parser.add_argument('--status', action='store_true', help='Check server status')
    parser.add_argument('--restart', action='store_true', help='Restart server')

    parser.add_argument('--kill', action='store_true', help='Kill user')

    parser.add_argument('--update', action='store_true', help='Update server')
    parser.add_argument('--check-update', action='store_true', help='Check update')

    parser.add_argument('--exclude', type=str, nargs='+', help='Exclude fields')
    parser.add_argument('--include', type=str, nargs='+', help='Include fields')

    parser.add_argument('--uninstall', action='store_true', help='Uninstall server')

    parser.add_argument('--create-executable', action='store_true', help='Create executable')
    parser.add_argument('--enable-auto-start', action='store_true', help='Enable auto start')
    parser.add_argument('--disable-auto-start', action='store_true', help='Disable auto start')

    parser.add_argument('--start-screen', action='store_true', help='Start server on screen')
    parser.add_argument('--stop-screen', action='store_true', help='Stop server on screen')

    parser.add_argument('--version', action='version', version='%(prog)s v' + str(__version__))

    args = parser.parse_args()
    config = CheckerUserConfig()
    service = ServiceManager()

    if args.start_screen:
        service.stop()

        cmd = 'screen -dmS %s %s --run' % (
            CheckerManager.EXECUTABLE_NAME,
            CheckerManager.EXECUTABLE_NAME,
        )
        os.system(cmd)
        return

    if args.stop_screen:
        cmd = 'screen -X -S %s quit' % CheckerManager.EXECUTABLE_NAME
        os.system(cmd)
        return

    if args.create_service:
        message = 'Create service success'

        if not service.create_service():
            message = 'Create service failed'

        logger.info(message)

    if args.remove_service:
        message = 'Remove service success'

        if not service.remove_service():
            message = 'Remove service failed'

        logger.info(message)

    if args.create_executable and not os.path.exists(CheckerManager.EXECUTABLE_FILE):
        CheckerManager.create_executable()

        if os.path.exists(CheckerManager.EXECUTABLE_FILE):
            logger.info('Create executable success')
            logger.info('Run: {} --help'.format(os.path.basename(CheckerManager.EXECUTABLE_FILE)))
        else:
            logger.error('Create executable failed')

    if args.enable_auto_start:
        if service.is_enabled:
            logger.error('Service already enabled')
        elif not service.enable_auto_start():
            logger.error('Enable service failed')
        else:
            logger.info('Enable service success')

    if args.disable_auto_start:
        if not service.disable_auto_start():
            logger.error('Disable service failed')
        else:
            logger.info('Disable service success')

    if args.username:
        if args.kill:
            if kill_user(args.username):
                logger.info('Kill user success')
            else:
                logger.error('Kill user failed')

        if args.json:
            logger.info(json.dumps(check_user(args.username), indent=4))
            return

        logger.info(check_user(args.username))

    if args.port:
        config.port = args.port

    if args.exclude:
        config.exclude = args.exclude

    if args.include:
        for name in args.include:
            config.include(name)

    if args.uninstall:
        service.remove_service()
        CheckerManager.remove_executable()
        CheckerUserConfig.remove_config()

    if args.run:
        workers = args.workers
        logger.info('Workers: %s' % workers)
        logger.info('Run Socket server')
        server = Server('0.0.0.0', config.port, workers)
        server.run()

    if args.start:
        if not service.is_created:
            logger.error('Service not created')
            return

        service.start()
        return

    if args.stop:
        service.stop()
        return

    if args.status:
        logger.info(service.status())
        return

    if args.restart:
        service.restart()
        return

    if args.update:
        is_update = CheckerManager.update()

        if is_update:
            logger.info('Update success')
            return

        logger.info('Not found new version')
        return

    if args.check_update:
        is_update, version = CheckerManager.check_update()
        logger.info('Have new version: {}'.format('Yes' if is_update else 'No'))
        logger.info('Version: {}'.format(version))

        while is_update:
            response = input('Do you want to update? (Y/n) ')

            if response.lower() == 'y':
                CheckerManager.update()
                break

            if response.lower() == 'n':
                break

            logger.error('Invalid response')

        return

    if len(sys.argv) == 1:
        parser.print_help()


if __name__ == '__main__':
    main()
