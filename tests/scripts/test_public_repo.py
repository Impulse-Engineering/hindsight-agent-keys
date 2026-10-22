"""This repo is public, so it names no real hostnames or hosts (docs/cutover.md).

No tracked file may name the company's domains or a private IPv4 address. A
real host belongs in Conductor's records, read with `platform_get_app`.
"""

import ipaddress
import os
import re
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Every example here is split ("192" + ".168…") so that no line of this file matches; it is checked like any other.
DOMAIN = re.compile("aseva" + r"\.(?:ai|com)\b", re.IGNORECASE)
# An address may end a sentence or begin a hostname (<address>.nip.io), but is not part of a longer number.
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
PRIVATE = [ipaddress.ip_network((first + ".0.0", bits)) for first, bits in (("10.0", 8), ("172.16", 12), ("192.168", 16), ("100.64", 10))]


def tracked_text():
    """(path, text) for every tracked file, undecodable bytes replaced so a binary's ASCII is still read."""
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    for path in out.decode().split("\0"):
        if not path:
            continue
        try:
            with open(os.path.join(ROOT, path), encoding="utf-8", errors="replace") as f:
                yield path, f.read()
        except FileNotFoundError:
            continue


def private(word):
    try:
        address = ipaddress.ip_address(word)
    except ValueError:
        return False
    return any(address in network for network in PRIVATE)


def names_a_real_host(line):
    return bool(DOMAIN.search(line)) or any(private(m.group()) for m in IPV4.finditer(line))


def test_no_tracked_file_names_a_real_host():
    found = []
    for path, text in tracked_text():
        for n, line in enumerate(text.splitlines(), 1):
            if names_a_real_host(line):
                found.append(f"{path}:{n}: {line.strip()[:120]}")
    assert found == []


@pytest.mark.parametrize(
    "line",
    ["open https://ui." + "aseva" + ".ai/", "mail ops@" + "ASEVA" + ".com", "the host is at 192" + ".168.7.9.", "ssh 10" + ".1.2.3",
     "curl http://10" + ".0.0.5.nip.io/", "172" + ".20.1.1:8888"],
)
def test_the_check_sees_a_domain_or_a_private_address(line):
    assert names_a_real_host(line)


@pytest.mark.parametrize(
    "line", ["127.0.0.1", "HOSTNAME=0.0.0.0", "X-Real-IP: 203.0.113.61", "version 10.0.3", "1.2.3.4.5", "example.ai"]
)
def test_the_check_passes_loopback_test_and_version_numbers(line):
    assert not names_a_real_host(line)
