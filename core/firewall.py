import subprocess

class FirewallManager:
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip):
        if ip in self.blocked_ips:
            return
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            self.blocked_ips.add(ip)
        except subprocess.CalledProcessError:
            print(f"Nie udało się zablokować IP: {ip}")

    def get_blocked(self):
        return list(self.blocked_ips)
