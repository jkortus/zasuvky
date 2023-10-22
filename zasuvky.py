#!/usr/bin/env python3
import socket
import ipaddress
import logging
import asyncio
import time
import aiohttp
import sys

logging.basicConfig(
    level=logging.CRITICAL, format="%(asctime)s - %(levelname)s - %(message)s"
)
log = logging.getLogger(__name__)


SCAN_TIMEOUT = 0.5


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


async def detect_power_plug(ip, username="", password=""):
    """Detects if the IP is a power plug and returns a JSON status of it if it is"""
    url = f"http://{ip}/cm?cmnd=status%200"
    auth = aiohttp.BasicAuth(username, password)
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


def arg_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description="Scans the network for open port and detects power plugs"
    )
    parser.add_argument(
        "--scan",
        type=str,
        metavar="IP spec",
        help="Scans the network/ip for available power plugs.",
    )
    parser.add_argument(
        "--username",
        type=str,
        help="Username for power plug authentication.",
        default="",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password for power plug authentication.",
        default="",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    return parser


async def main():
    log.setLevel(logging.ERROR)
    parser = arg_parser()
    args = parser.parse_args()
    if args.debug:
        log.setLevel(logging.DEBUG)
    if args.scan:
        # scan for open ports, these are plug candidates
        result = await scan(args.scan, 80)
        username = args.username
        password = args.password
        # for all candidates, try to detect if they are power plugs
        for ip in result:
            status_json = await detect_power_plug(ip, username, password)
            if status_json:
                extra_info = "No extra info could be parsed"
                try:
                    extra_info = f"DeviceName: {status_json['Status']['DeviceName']}"
                    extra_info += (
                        f" FriendlyName: {status_json['Status']['FriendlyName']}"
                    )
                    extra_info += f" Power: {status_json['Status']['Power']}"
                    extra_info += f" MAC: {status_json['StatusNET']['Mac']}"
                    extra_info += f" Version: {status_json['StatusFWR']['Version']}"
                except KeyError:
                    pass

                print(f"Power plug detected at {ip}: {extra_info}")
        return
    parser.print_help()
    sys.exit(1)
    # http://<ip>/cm?user=admin&password=joker&cmnd=Power%20Toggle
    # status0


if __name__ == "__main__":
    asyncio.run(main())
