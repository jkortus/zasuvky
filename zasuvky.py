#!/usr/bin/env python3
""" Management module for tasmota power plugs (power plugs only and single socket only) """
import sys
import os
import json
import configparser
import socket
import ipaddress
import logging
import asyncio
import time
import aiohttp
import psutil

# pylint: disable=logging-fstring-interpolation

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
    """Exception raised when HTTP command fails"""


async def scan_host(host, port):
    """Scans one IP address for open port"""
    log.debug(f"Scanning {host}:{port}")

    async def _connect(host, port):
        _, writer = await asyncio.open_connection(host, port)
        writer.close()
        await writer.wait_closed()

    port_open = False
    try:
        await asyncio.wait_for(_connect(host, port), timeout=SCAN_TIMEOUT)
        log.debug(f"{host}:{port} is OPEN")
        port_open = True
    except Exception as ex:  # pylint: disable=broad-except
        err_str = str(ex)
        if not err_str and isinstance(ex, asyncio.TimeoutError):
            err_str = "timeout"
        log.debug(f"{host}:{port} is closed ({ex})")
    return (host, port, port_open)


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
        log.debug("Using http auth.")
    async with aiohttp.ClientSession(auth=auth) as session:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    log.debug(f"Response from {ip}: {result}")
                    try:
                        for k, _ in result["Status"].items():
                            if (
                                k.lower().startswith("power")
                                and len(k) <= len("power") + 1
                            ):  # power, power1 .. power 9
                                log.info(f"Power plug detected at {ip}: {result}")
                                return result
                    except Exception as ex:  # pylint: disable=broad-except
                        log.debug(f"Error parsing response from {ip}: {ex}")
                log.debug(f"Bad response from {ip}: {resp.status}: {resp.reason}")

        except Exception as ex:  # pylint: disable=broad-except
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
                with open(
                    plug_ini + f"-backup-{timestamp}", "w", encoding="utf-8"
                ) as _:
                    config.write(_)
                if "power" not in config.sections():
                    config["power"] = {}
                config["power"]["powercal"] = str(cal_data["PowerCal"])
                config["power"]["voltagecal"] = str(cal_data["VoltageCal"])
                config["power"]["currentcal"] = str(cal_data["CurrentCal"])
                with open(plug_ini, "w", encoding="utf-8") as _:
                    config.write(_)
                print(f"Config file {plug_ini} updated.")
            else:
                print(
                    f"Config file {plug_ini} not found and could not be updated",
                    file=sys.stderr,
                )
                return False
        return True
    except HTTPCommandExeption as ex:
        log.error(f"Error during power calibration {ip}: {ex}")
        print("Command failed: ", ex)
        return False


async def send_http_command_parallel(ips, command):
    """
    runs send_http_command calls in parallel for all ips and returns a list of results
    as tuple (ip, results_json)
    """
    results = []
    tasks = []
    async with asyncio.TaskGroup() as tg:
        for ip in ips:
            task = tg.create_task(send_http_command(ip, command))
            tasks.append((ip, task))
    results = [(ip, task.result()) for ip, task in tasks]
    return results


def name2ip(name, network=None):
    """
    Returns IP address of a plug with a given devicename or firendlyname.
    Raises ValueError if not found or any other error is encountered.
    Matches on substring of both and requires unique match across all plugs.
    network is optional, taking form of "10.0.2.1/24"
    """
    # scan first
    if network is None:
        networks = get_host_networks()
        log.debug(f"Found networks: {networks}")
        if len(networks) != 1:
            msg = "Could not determine the network to scan. Multiple are available."
            msg += f"Available networks: {networks}"
            raise ValueError(msg)
        network = networks[0]
    scan_results = asyncio.run(scan(network, 80))
    # for all candidates, try to detect if they are power plugs
    results = asyncio.run(detect_power_plug_parallel(scan_results))
    # now we have a list of tuples (ip, status_json)
    # let's find the one with matching name
    matching_ips = []  # tuple (ip, status_json)
    for ip, status_json in results:
        if status_json:
            try:
                if (
                    name.lower() in status_json["Status"]["DeviceName"].lower()
                    or name.lower() in status_json["Status"]["FriendlyName"][0].lower()
                ):
                    matching_ips.append((ip, status_json))
            except KeyError:
                pass
    if len(matching_ips) == 0:
        raise ValueError(f"No matching plug found for {name}")
    if len(matching_ips) > 1:
        devname_desc = [
            f"({ip}, {status_json['Status']['DeviceName']}, "
            f"{status_json['Status']['FriendlyName'][0]}, "
            f"{status_json['StatusNET']['Mac']})"
            for ip, status_json in matching_ips
        ]
        msg = f"Multiple matching plugs found for {name}: \n"
        msg += "\n".join(devname_desc)
        raise ValueError(msg)
    return matching_ips[0][0]


async def send_http_command(ip, command):
    """Send a command over HTTP to the power plug"""
    url = f"http://{ip}/cm"
    params = {"cmnd": command}
    auth = None
    request_timeout = 5
    if HTTP_AUTH_CREDS:
        auth = aiohttp.BasicAuth(*HTTP_AUTH_CREDS)
        log.debug("Using http auth.")
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
            raise HTTPCommandExeption(
                f"Error during command sending {ip}: {ex}"
            ) from ex


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
            len(sections_include) > 0 and section not in sections_include
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
    config["management"]["devicename"] = status["Status"]["DeviceName"]
    config["management"]["friendlyname"] = status["Status"]["FriendlyName"][0]
    config["power"] = {}
    for command in ["PowerCal", "VoltageCal", "CurrentCal"]:
        result = asyncio.run(send_http_command(ip, command))
        config["power"][command.lower()] = str(result[command])

    if not os.path.isdir(CONFIG_DIR):
        os.mkdir(CONFIG_DIR)
    with open(plug_ini, "w", encoding="utf-8") as _:
        config.write(_)
    print(f"Config file {plug_ini} created")


def setup_plug(ip, sections=None):
    """Setup the power plug using ini file"""
    status = asyncio.run(send_http_command(ip, "status 0"))
    mac = get_mac(status)
    try:
        config = load_ini(mac)
    except FileNotFoundError:
        log.info("Plug ini file not found, generating one.")
        log.warning(
            "New config file was generated. Please make sure you run "
            "the power calibration for the powerplug!"
        )
        generate_config_ini(ip)
        config = load_ini(mac)
    commands = ini2commands(config, sections=sections)
    boot_count = int(status["StatusPRM"]["BootCount"])
    log.debug(f"Boot count: {boot_count}")
    for command, restart_required in commands:  # pylint: disable=too-many-nested-blocks
        if DRY_RUN:
            print(f"would send command: {command}")
            return
        print(f"Executing command: {command}")
        asyncio.run(send_http_command(ip, command))
        if restart_required:
            print("Waiting for device restart.", end="", flush=True)
            max_attempts = 10
            delay = 1
            # wait for the device to start the restart, it's not instant,
            # 1s is the default delay, so let's put 2 here
            time.sleep(2)
            while True:
                try:
                    status = asyncio.run(send_http_command(ip, "status 0"))
                    if status:
                        if int(status["StatusPRM"]["BootCount"]) > boot_count:
                            print("Device restarted")
                            boot_count = int(status["StatusPRM"]["BootCount"])
                            break
                        log.debug("Device responding, but has not restarted yet.")

                except Exception as ex:  # pylint: disable=broad-except
                    log.debug(f"Error while waiting for device restart: {ex}")
                max_attempts -= 1
                if max_attempts == 0:
                    msg = "Device restart timeout"
                    print(msg, file=sys.stderr)
                    raise RuntimeError(msg)
                print(".", end="", flush=True)
                time.sleep(delay)
            if max_attempts < 1:
                msg = "Device setup failed. Could not connect to device after restart."
                print(
                    msg,
                    file=sys.stderr,
                )
                raise RuntimeError(msg)


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
        return True
    except Exception as ex:  # pylint: disable=broad-except
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
        log.debug("Using http auth.")
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
            except Exception as ex:  # pylint: disable=broad-except
                print(f"Error during config backup {ip}: {ex}", file=sys.stderr)
                return False

    return asyncio.run(dl_firmware())


def upgrade_firmware(ip):
    """Upgrades firmware using the url stored in the power plug"""
    status = asyncio.run(send_http_command(ip, "status 0"))
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
        result = asyncio.run(send_http_command(ip, "Upgrade 1"))
        log.debug(f"Upgrade result: {result}")
        print(
            "Upgrade command sent successfully. Wait for the device to "
            "reboot, it might take a couple of minutes."
        )
        return True
    except Exception as ex:  # pylint: disable=broad-except
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


def get_default_http_password():
    """
    sets default http auth from:
    1. config file
    2. environment
    """
    password = None
    # env takes precedence
    if os.environ.get("HTTP_AUTH_PASSWORD"):
        log.debug("Using http auth from environment")
        password = os.environ.get("HTTP_AUTH_PASSWORD")
        return password
    # config file
    ini_file = os.path.join(CONFIG_DIR, DEFAULT_INI)
    if os.path.isfile(ini_file):
        config = configparser.ConfigParser()
        config.read(ini_file)
        try:
            password = config["wifi"]["webpassword"]
            log.debug("Using http auth from default config file")
            return password
        except KeyError as ex:
            log.debug(f"No http auth password found in config file: {ex}")
    log.debug("No http auth password found")
    return password


def arg_parser():
    """Argument parser"""
    import argparse  # pylint: disable=import-outside-toplevel

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
        help="Scans the network/ip for available power plugs. Tries scanning "
        "current network if there is only one available.",
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
    parser.add_argument(
        "--ip", type=str, help="IP of the power plug. Mutually exclusive with --name"
    )
    parser.add_argument("--command", type=str, help="Command to send to the power plug")
    parser.add_argument(
        "--setup", action="store_true", help="Setup the power plug using ini file"
    )
    parser.add_argument(
        "--generate-config",
        action="store_true",
        help="Generate config file for the power plug",
    )
    parser.add_argument(
        "--sections",
        type=str,
        help="Sections to process '!' negates the section, comma separated "
        "list. Default: all. Example: !wifi,management,!mqtt",
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
    parser.add_argument(
        "--name",
        type=str,
        help="Name of the power plug (device or friendly). Partial "
        "matches supported. Case insensitive. Mutually exclusive with --ip",
    )

    return parser


def main():
    """Main function"""
    # pylint: disable=too-many-branches,too-many-statements,too-many-return-statements
    global HTTP_AUTH_CREDS, DRY_RUN  # pylint: disable=global-statement
    log.setLevel(logging.ERROR)
    parser = arg_parser()
    args = parser.parse_args()
    ip = None  # we'll store IP here in case of name resolution to reuse it later
    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.dry_run:
        DRY_RUN = True
        print("Dry run, no commands will be sent to the device.")

    # try to guess password here and let it be overriden from cmdline later
    password = get_default_http_password()
    if password is not None:
        HTTP_AUTH_CREDS = ("admin", password)

    if args.password:
        log.debug("Using http auth from command line")
        HTTP_AUTH_CREDS = (args.username, args.password)

    if args.name:
        if args.ip:
            print("IP and name cannot be specified together", file=sys.stderr)
            parser.print_help()
            sys.exit(1)
        try:
            ip = name2ip(args.name)
            print("Using IP: ", ip, file=sys.stderr)
        except ValueError as ex:
            print(ex, file=sys.stderr)
            sys.exit(1)

    if args.ip:
        ip = args.ip

    if args.upgrade_firmware:
        if not ip:
            print("IP is required for firmware upgrade")
            parser.print_help()
            sys.exit(1)
        result = upgrade_firmware(ip)
        if result is False:
            sys.exit(1)
        return

    if args.backup_config:
        if not ip:
            print("IP is required for config backup")
            parser.print_help()
            sys.exit(1)
        result = backup_config(ip)
        if result is False:
            sys.exit(1)
        return
    if args.reset_counters:
        if not ip:
            print("IP is required for counters reset")
            parser.print_help()
            sys.exit(1)
        result = reset_counters(ip)
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
                    "Could not determine the network to scan. Please specify the network to scan.",
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
        if not ip:
            print("IP is required for power calibration")
            parser.print_help()
            sys.exit(1)
        power_calibration(ip, *args.power_calibration)
        return
    if args.command:
        if not ip:
            print("IP is required for sending a command")
            parser.print_help()
            sys.exit(1)
        response = asyncio.run(send_http_command(ip, args.command))
        response = json.dumps(response, indent=2)
        print(response)
        return
    if args.setup:
        if not ip:
            print("IP is required for setup", file=sys.stderr)
            parser.print_help()
            sys.exit(1)
        try:
            setup_plug(ip, sections=args.sections)
            print("Setup finished successfully")
        except Exception as ex:  # pylint: disable=broad-except
            print(f"Setup failed: {ex}", file=sys.stderr)
            sys.exit(1)
        return
    if args.generate_config:
        if not ip:
            print("IP is required for generating config", file=sys.stderr)
            parser.print_help()
            sys.exit(1)
        generate_config_ini(ip)
        return
    parser.print_help()
    sys.exit(1)
    # http://<ip>/cm?user=admin&password=joker&cmnd=Power%20Toggle
    # status0


if __name__ == "__main__":
    main()
