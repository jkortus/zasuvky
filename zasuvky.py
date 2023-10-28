#!/usr/bin/env python3
import socket
import ipaddress
import logging
import asyncio
import time
import aiohttp
import sys
import os
import json
import configparser
import psutil
import ipaddress

logging.basicConfig(
    level=logging.CRITICAL, format="%(asctime)s - %(levelname)s - %(message)s"
)
log = logging.getLogger(__name__)


SCAN_TIMEOUT = 0.5
DEFAULT_INI = "defaults.ini"
CONFIG_DIR = "config"
BACKUP_DIR = "backup"

HTTP_AUTH_CREDS = None  # tuple (username, password) or None
DRY_RUN = False


class HTTPCommandExeption(Exception):
    pass


async def scan_host(host, port):
    """Scans one IP address for open port"""
    running_loop = asyncio.get_running_loop()
    log.debug(f"Scanning {host}:{port}")

    async def _connect(host, port):
        _, writer = await asyncio.open_connection(host, port)
        writer.close()
        await writer.wait_closed()

    open = False
    try:
        result = await asyncio.wait_for(_connect(host, port), timeout=SCAN_TIMEOUT)
        log.debug(f"{host}:{port} is OPEN")
        open = True
    except Exception as ex:
        err_str = str(ex)
        if not err_str and isinstance(ex, asyncio.TimeoutError):
            err_str = "timeout"
        log.debug(f"{host}:{port} is closed ({ex})")
        pass
    return (host, port, open)


async def scan(subnet, port):
    """Scans the network for open port"""
    start_time = time.time()
    subnet = ipaddress.ip_network(subnet, strict=False)
    log.info(
        f"Scanning {subnet} ({len(list(subnet.hosts()))} hosts) for open {port} port"
    )
    tasks = []
    async with asyncio.TaskGroup() as tg:
        for ip in subnet.hosts():
            task = tg.create_task(scan_host(str(ip), port))
            tasks.append(task)
    result = []
    for task in tasks:
        tresult = task.result()
        if tresult[2]:
            result.append(tresult[0])
            log.debug(f"{tresult[0]}:{tresult[1]} is OPEN")
    log.debug(f"Scanning finished in {time.time() - start_time} seconds")
    return result


async def detect_power_plug_parallel(ips):
    """
    runs detect_power_plug calls in parallel for all ips and returns a list of results
    as tuple (ip, results_json)
    """
    results = []
    tasks = []
    async with asyncio.TaskGroup() as tg:
        for ip in ips:
            task = tg.create_task(detect_power_plug(ip))
            tasks.append((ip, task))
    results = [(ip, task.result()) for ip, task in tasks]
    return results


async def detect_power_plug(ip):
    """Detects if the IP is a power plug and returns a JSON status of it if it is"""
    url = f"http://{ip}/cm?cmnd=status%200"
    auth = None
    if HTTP_AUTH_CREDS:
        auth = aiohttp.BasicAuth(*HTTP_AUTH_CREDS)
        log.debug(f"Using http auth.")
    async with aiohttp.ClientSession(auth=auth) as session:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    log.debug(f"Response from {ip}: {result}")
                    try:
                        for k, v in result["Status"].items():
                            if (
                                k.lower().startswith("power")
                                and len(k) <= len("power") + 1
                            ):  # power, power1 .. power 9
                                log.info(f"Power plug detected at {ip}: {result}")
                                return result
                    except Exception as ex:
                        log.debug(f"Error parsing response from {ip}: {ex}")
                log.debug(f"Bad response from {ip}: {resp.status}: {resp.reason}")

        except Exception as ex:
            log.debug(f"Error during power plug detection at {ip}: {ex}")


def power_calibration(ip, watt, miliamps, volts, save_to_ini=True):
    """
    Setup calibration on the power plug using known values
    for actual power consumption
    """
    command = f"Backlog PowerSet {watt};VoltageSet {volts};CurrentSet {miliamps};"
    try:
        asyncio.run(send_http_command(ip, command))
        time.sleep(
            2
        )  # wait for values propagation, reading them immediately will read old values
        print("Power calibration set up successfully")
        cal_data = {}
        for command in ["PowerCal", "VoltageCal", "CurrentCal"]:
            result = asyncio.run(send_http_command(ip, command))
            cal_data[command] = result[command]
            print(f"{command} result: {result}")
        if save_to_ini:
            status = asyncio.run(send_http_command(ip, "status 0"))
            mac = get_mac(status)
            plug_ini = os.path.join(CONFIG_DIR, f"{mac}.ini")
            if os.path.isfile(plug_ini):
                log.debug(f"Loading plug ini file {plug_ini}")
                config = configparser.ConfigParser()
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                config.read(plug_ini)
                config.write(open(plug_ini + f"-backup-{timestamp}", "w"))
                if "power" not in config.sections():
                    config["power"] = {}
                config["power"]["powercal"] = str(cal_data["PowerCal"])
                config["power"]["voltagecal"] = str(cal_data["VoltageCal"])
                config["power"]["currentcal"] = str(cal_data["CurrentCal"])
                config.write(open(plug_ini, "w"))
                print(f"Config file {plug_ini} updated.")
            else:
                print(
                    f"Config file {plug_ini} not found and could not be updated",
                    file=sys.stderr,
                )
                return False

    except HTTPCommandExeption as ex:
        log.error(f"Error during power calibration {ip}: {ex}")
        print("Command failed: ", ex)
        return False


async def send_http_command(ip, command):
    """Send a command over HTTP to the power plug"""
    url = f"http://{ip}/cm"
    params = {"cmnd": command}
    auth = None
    request_timeout = 5
    if HTTP_AUTH_CREDS:
        auth = aiohttp.BasicAuth(*HTTP_AUTH_CREDS)
        log.debug(f"Using http auth.")
    async with aiohttp.ClientSession(
        auth=auth, timeout=aiohttp.ClientTimeout(total=request_timeout)
    ) as session:
        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    log.debug(f"GOOD Response from {ip}: {result}")
                    return result
                log.debug(f"Bad response from {ip}: {resp.status}: {resp.reason}")
                raise HTTPCommandExeption(
                    f"Bad response from {ip}: {resp.status}: {resp.reason}"
                )
        except Exception as ex:
            log.debug(f"Error during command sending {ip}: {ex}")
            raise HTTPCommandExeption(f"Error during command sending {ip}: {ex}")


def load_ini(mac):
    """Load configuration from ini file and returns config parser instance"""
    config = configparser.ConfigParser()
    default_ini = os.path.join(CONFIG_DIR, DEFAULT_INI)
    if os.path.isfile(default_ini):
        log.debug(f"Loading default ini file {default_ini}")
        config.read(default_ini)
    else:
        log.debug(f"Default ini file {default_ini} not found")
    plug_ini = os.path.join(CONFIG_DIR, f"{mac}.ini")
    if os.path.isfile(plug_ini):
        log.debug(f"Loading plug ini file {plug_ini}")
        config.read(plug_ini)
    else:
        log.error(f"Plug ini file {plug_ini} not found")
        raise FileNotFoundError(f"Plug ini file {plug_ini} not found")
    return config


def ini2commands(config, sections=None):
    """converts parsed ini file to commands for power plug"""
    commands = []  # list of tuples (command:str, restart_required: bool)
    command_sections = [
        "wifi",
        "management",
        "mqtt",
        "power",
    ]  # sections converted to commands (attrs must be valid commands)
    restart_sections = [
        "mqtt",
        # wifi not here, as we do not want to wait for it, since it is going
        # to appear with a different IP
    ]  # sections that will cause device restart and we need to wait longer
    sections_include = []
    sections_exclude = []
    if sections is not None:
        for item in sections.strip().split(","):
            if item.startswith("!"):
                sections_exclude.append(item[1:])
            else:
                sections_include.append(item)
    log.debug(f"Sections: include: {sections_include} exclude: {sections_exclude}")
    config_sections = config.sections()
    if "wifi" in config_sections:
        # wifi section must be last, as the device restarts with different IP (likely)
        config_sections.remove("wifi")
        config_sections.append("wifi")
    for section in config_sections:
        if section in sections_exclude or (
            len(sections_include) and section not in sections_include
        ):
            log.debug(f"Skipping section {section}")
            continue
        if section in command_sections:
            command = "Backlog "
            for key, value in config[section].items():
                command += f"{key} {value};"
            if section in restart_sections:
                command += "Restart 1;"
            commands.append((command, section in restart_sections))
            log.debug(f"Adding command: {command}")
        else:
            log.debug(f"Skipping non-command section {section}")
    return commands


def generate_config_ini(ip):
    """generates basic configuration for the power plug that we want to edit later"""
    status = asyncio.run(send_http_command(ip, "status 0"))
    mac = get_mac(status)
    plug_ini = os.path.join(CONFIG_DIR, f"{mac}.ini")
    if os.path.isfile(plug_ini):
        log.error(f"Plug ini file {plug_ini} already exists")
        return
    config = configparser.ConfigParser()
    config["management"] = {}
    config["management"]["devicename"] = f"Zasuvka-{mac[-6:]}"
    config["management"]["friendlyname"] = f"Zasuvka-{mac[-6:]}"
    if not os.path.isdir(CONFIG_DIR):
        os.mkdir(CONFIG_DIR)
    config.write(open(plug_ini, "w"))
    print(f"Config file {plug_ini} created")


def setup_plug(ip, sections=None):
    """Setup the power plug using ini file"""
    status = asyncio.run(send_http_command(ip, "status 0"))
    mac = get_mac(status)
    try:
        config = load_ini(mac)
    except FileNotFoundError as ex:
        log.info(f"Plug ini file not found, generating one.")
        log.warning(
            "New config file was generated. Please make sure you run the power calibration for the powerplug!"
        )
        generate_config_ini(ip)
        config = load_ini(mac)
    commands = ini2commands(config, sections=sections)
    boot_count = int(status["StatusPRM"]["BootCount"])
    log.debug(f"Boot count: {boot_count}")
    for command, restart_required in commands:
        if DRY_RUN:
            print(f"would send command: {command}")
        else:
            print(f"Executing command: {command}")
            asyncio.run(send_http_command(ip, command))
            if restart_required:
                print("Waiting for device restart.", end="", flush=True)
                max_attempts = 10
                delay = 1
                time.sleep(
                    2
                )  # wait for the device to start the restart, it's not instant, 1s is the default delay, so let's put 2 here
                while True:
                    try:
                        status = asyncio.run(send_http_command(ip, "status 0"))
                        if status:
                            if int(status["StatusPRM"]["BootCount"]) > boot_count:
                                print("Device restarted")
                                boot_count = int(status["StatusPRM"]["BootCount"])
                                break
                            else:
                                log.debug(
                                    f"Device responding, but has not restarted yet."
                                )

                    except Exception as ex:
                        log.debug(f"Error while waiting for device restart: {ex}")
                    max_attempts -= 1
                    if max_attempts == 0:
                        print("Device restart timeout", file=sys.stderr)
                        return False
                    print(".", end="", flush=True)
                    time.sleep(delay)
                if max_attempts < 1:
                    print(
                        "Device setup failed. Could not connect to device after restart.",
                        file=sys.stderr,
                    )
                    return False


def get_mac(status_json):
    """Returns MAC address from the status json or raises KeyError"""
    mac = status_json["StatusNET"]["Mac"]
    mac = mac.replace(":", "")
    return mac


def reset_counters(ip):
    """Resets energy consumption counters to 0"""
    try:
        result = asyncio.run(
            send_http_command(
                ip, "Backlog EnergyToday 0;EnergyTotal 0; EnergyYesterday 0;"
            )
        )
        log.debug(f"Reset counters result: {result}")
        print("Counters reset successfully")
    except Exception as ex:
        log.error(f"Error during counters reset {ip}: {ex}")
        print("Command failed: ", ex, file=sys.stderr)
        return False


def backup_config(ip):
    """Downloads binary config dump from the power plug"""
    if not os.path.isdir(BACKUP_DIR):
        os.mkdir(BACKUP_DIR)
    auth = None
    if HTTP_AUTH_CREDS:
        auth = aiohttp.BasicAuth(*HTTP_AUTH_CREDS)
        log.debug(f"Using http auth.")
    url = f"http://{ip}/dl"
    status = asyncio.run(send_http_command(ip, "status 0"))
    mac = get_mac(status)
    timestamp = time.strftime("%Y%m%d-%H%M%S")

    async def dl_firmware():
        async with aiohttp.ClientSession(auth=auth) as session:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        filename = f"{mac}-{timestamp}.dmp"
                        filepath = os.path.join(BACKUP_DIR, filename)
                        with open(filepath, "wb") as f:
                            f.write(await resp.read())
                        print(f"Config backup saved to {filepath}")
                    else:
                        print(
                            f"Bad response from {ip}: {resp.status}: {resp.reason}",
                            file=sys.stderr,
                        )
            except Exception as ex:
                print(f"Error during config backup {ip}: {ex}", file=sys.stderr)
                return False

    return asyncio.run(dl_firmware())


def upgrade_firmware(ip):
    """Upgrades firmware using the url stored in the power plug"""
    status = asyncio.run(send_http_command(ip, "status 0"))
    mac = get_mac(status)
    url = status["StatusPRM"]["OtaUrl"]
    if not url:
        print("No upgrade url found", file=sys.stderr)
        return False
    print("Backing up running configuration...")
    if backup_config(ip) is False:
        print("Backup failed, aborting firmware upgrade", file=sys.stderr)
        return False
    print(f"Sending command to upgrade firmware from {url}")
    try:
        result = asyncio.run(send_http_command(ip, f"Upgrade 1"))
        log.debug(f"Upgrade result: {result}")
        print(
            "Upgrade command sent successfully. Wait for the device to reboot, it might take a couple of minutes."
        )
    except Exception as ex:
        log.error(f"Error during firmware upgrade {ip}: {ex}")
        print("Command failed: ", ex, file=sys.stderr)
        return False


def get_host_networks():
    """returns a list of host ipv4 networks"""
    ifaces = psutil.net_if_addrs()
    addresses = []
    for iface in ifaces:
        for addr in ifaces[iface]:
            if addr.family == socket.AF_INET:  # ipv4 only
                if addr.address.startswith("127."):
                    continue
                addresses.append((addr.address, addr.netmask))
    networks = []
    for address in addresses:
        network = ipaddress.ip_network(address[0] + "/" + address[1], strict=False)
        networks.append(network)
    return networks


def arg_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description="Scans the network for open port and detects power plugs"
    )
    parser.add_argument(
        "--scan",
        type=str,
        metavar="IP spec",
        nargs="?",
        const=True,
        default=None,
        help="Scans the network/ip for available power plugs. Tries scanning current network if there is only one available.",
    )
    parser.add_argument(
        "--username",
        type=str,
        help="Username for power plug authentication. Default: admin.",
        default="admin",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password for power plug authentication.",
        default="",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--power-calibration",
        nargs=3,
        metavar=("WATT", "MILIAMPS", "VOLTS"),
        help="Setup power calibration on the power plug",
    )
    parser.add_argument("--ip", type=str, help="IP of the power plug")
    parser.add_argument("--command", type=str, help="Command to send to the power plug")
    parser.add_argument(
        "--setup", metavar="IP", type=str, help="Setup the power plug using ini file"
    )
    parser.add_argument(
        "--generate-config",
        metavar="IP",
        type=str,
        help="Generate config file for the power plug",
    )
    parser.add_argument(
        "--sections",
        type=str,
        help="Sections to process '!' negates the section, comma separated list. Default: all. Example: !wifi,management,!mqtt",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry run, no commands are sent to the device. Works only for --setup.",
    )
    parser.add_argument(
        "--reset-counters",
        action="store_true",
        help="Reset energy consumption counters to 0",
    )
    parser.add_argument(
        "--backup-config", action="store_true", help="Backup config from the device"
    )
    parser.add_argument(
        "--upgrade-firmware", action="store_true", help="Upgrade firmware"
    )

    return parser


def main():
    global HTTP_AUTH_CREDS, DRY_RUN
    log.setLevel(logging.ERROR)
    parser = arg_parser()
    args = parser.parse_args()
    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.dry_run:
        DRY_RUN = True
        print("Dry run, no commands will be sent to the device.")

    if os.environ.get("HTTP_AUTH_PASSWORD"):
        log.debug("Using http auth from environment")
        HTTP_AUTH_CREDS = ("admin", os.environ.get("HTTP_AUTH_PASSWORD"))

    if args.password:
        HTTP_AUTH_CREDS = (args.username, args.password)

    if args.upgrade_firmware:
        if not args.ip:
            print("IP is required for firmware upgrade")
            parser.print_help()
            sys.exit(1)
        result = upgrade_firmware(args.ip)
        if result is False:
            sys.exit(1)
        return

    if args.backup_config:
        if not args.ip:
            print("IP is required for config backup")
            parser.print_help()
            sys.exit(1)
        result = backup_config(args.ip)
        if result is False:
            sys.exit(1)
        return
    if args.reset_counters:
        if not args.ip:
            print("IP is required for counters reset")
            parser.print_help()
            sys.exit(1)
        result = reset_counters(args.ip)
        if result is False:
            sys.exit(1)
        return

    if args.scan:
        if args.scan is True:
            # present with no argument - let's find the network
            networks = get_host_networks()
            log.debug(f"Found networks: {networks}")
            if len(networks) != 1:
                print(
                    f"Could not determine the network to scan. Please specify the network to scan.",
                    file=sys.stderr,
                )
                print(f"Available networks: {networks}", file=sys.stderr)
                sys.exit(1)
            network = networks[0]
        else:
            network = args.scan
        print(f"Scanning network {network}")
        # scan for open ports, these are plug candidates
        result = asyncio.run(scan(network, 80))
        # for all candidates, try to detect if they are power plugs
        results = asyncio.run(detect_power_plug_parallel(result))
        for ip, status_json in results:
            if status_json:
                extra_info = "No extra info could be parsed"
                try:
                    extra_info = f"{status_json['StatusSNS']['ENERGY']['Power']:4d} W"
                    extra_info += (
                        f" DeviceName: {status_json['Status']['DeviceName']:15s}"
                    )
                    extra_info += (
                        f" FriendlyName: {status_json['Status']['FriendlyName'][0]:15s}"
                    )
                    extra_info += f" MAC: {status_json['StatusNET']['Mac']}"
                    extra_info += f" Version: {status_json['StatusFWR']['Version']}"
                except KeyError:
                    pass

                print(f"Power plug detected at {ip}: {extra_info}")
        return

    if args.power_calibration:
        if not args.ip:
            print("IP is required for power calibration")
            parser.print_help()
            sys.exit(1)
        power_calibration(args.ip, *args.power_calibration)
        return
    if args.command:
        if not args.ip:
            print("IP is required for sending a command")
            parser.print_help()
            sys.exit(1)
        response = asyncio.run(send_http_command(args.ip, args.command))
        response = json.dumps(response, indent=2)
        print(response)
        return
    if args.setup:
        result = setup_plug(args.setup, sections=args.sections)
        if result is False:
            sys.exit(1)
        return
    if args.generate_config:
        generate_config_ini(args.generate_config)
        return
    parser.print_help()
    sys.exit(1)
    # http://<ip>/cm?user=admin&password=joker&cmnd=Power%20Toggle
    # status0


if __name__ == "__main__":
    main()
