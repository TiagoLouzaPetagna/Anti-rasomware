import os
import getpass
import random
import string
import time
import subprocess
from collections import Counter
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ================================
# CONFIGURAÇÕES
# ================================
NUM_FILES = 50
FILE_SIZE = 1024*50
ALERTA_LIMITE = 10

WHITELIST = {
    "systemd", "init", "bash", "zsh", "sh", "sshd",
    "cron", "crond", "dbus-daemon", "NetworkManager",
    "agetty", "login", "Xorg", "gnome-shell", "kdeinit"
}

# ================================
# GERADOR DE ARQUIVOS ISCAS
# ================================
def criar_arquivos_isca(pasta):
    os.makedirs(pasta, exist_ok=True)
    for i in range(NUM_FILES):
        caminho = os.path.join(pasta, f"documento_{i}.txt")
        if not os.path.exists(caminho):
            conteudo = ''.join(random.choices(string.ascii_letters + string.digits, k=FILE_SIZE))
            with open(caminho, "w") as f:
                f.write(conteudo)

# ================================
# MONITORAMENTO DE ALTERAÇÕES
# ================================
class MonitorRansomware(FileSystemEventHandler):
    def __init__(self):
        self.alteracoes = 0
        self.pids = []
        self.ppids = {}
        self.comms = {}

    def get_pid_ppid_comm(self, filepath):
        try:
            syscalls = ["openat", "rename", "write", "unlink", "stat"]
            for sc in syscalls:
                cmd = ["ausearch", "-f", filepath, "-sc", sc, "--raw", "--success", "yes", "--message", "SYSCALL", "--start", "recent"]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                pid, ppid, comm = None, None, None
                for line in result.stdout.splitlines():
                    if " pid=" in line:
                        for p in line.split():
                            if p.startswith("pid="):
                                pid = p.split("=")[1]
                            if p.startswith("ppid="):
                                ppid = p.split("=")[1]
                            if p.startswith("comm="):
                                comm = p.split("=")[1].strip('"')
                return pid, ppid, comm
        except Exception as e:
            print(f"    [ERRO ao consultar ausearch: {e}]")
            return None, None, None

    def on_modified(self, event):
        if not event.is_directory:
            self.alteracoes += 1
            print(f"[!] Arquivo modificado: {event.src_path}")

            pid, ppid, comm = self.get_pid_ppid_comm(event.src_path)
            if pid:
                self.pids.append(pid)
                if ppid:
                    self.ppids[pid] = ppid
                if comm:
                    self.comms[ppid] = comm
                print(f"    → PID: {pid}, PPID: {ppid}, COMM: {comm}")
            else:
                print("    → PID não encontrado no ausearch")

            if self.alteracoes >= ALERTA_LIMITE:
                print("\n[ALERTA] Possível ransomware detectado! Muitos arquivos foram alterados.\n")

                if self.pids:
                    pid_mais_comum, ocorrencias = Counter(self.pids).most_common(1)[0]
                    ppid = self.ppids.get(pid_mais_comum)
                    comm = self.comms.get(ppid)

                    print(f"[AÇÃO] PID mais suspeito: {pid_mais_comum} (alterou {ocorrencias} arquivos).")
                    print(f"[INFO] PPID: {ppid}, COMM: {comm}")

                    alvo = None
                    if comm and comm in WHITELIST:
                        print(f"[INFO] PPID {ppid} ({comm}) está na whitelist → matando apenas PID {pid_mais_comum}")
                        alvo = pid_mais_comum
                    elif ppid:
                        print(f"[INFO] PPID {ppid} não está na whitelist → matando PPID {ppid}")
                        alvo = ppid
                    else:
                        print(f"[INFO] Não consegui resolver PPID → matando PID {pid_mais_comum}")
                        alvo = pid_mais_comum

                    try:
                        os.kill(int(alvo), 9)
                        print(f"[SUCESSO] Processo {alvo} finalizado.")
                    except ProcessLookupError:
                        print(f"[ERRO] Processo {alvo} já não existe mais.")
                    except Exception as e:
                        print(f"[ERRO] Não foi possível matar {alvo}: {e}")

                # Reset
                self.alteracoes = 0
                self.pids = []
                self.ppids = {}
                self.comms = {}

# ================================
# MAIN
# ================================
if __name__ == "__main__":
    usuario = getpass.getuser()
    pastas = [f"/home/{usuario}/honeypot", "/srv/share/honeypot"]

    for pasta in pastas:
        criar_arquivos_isca(pasta)

    event_handler = MonitorRansomware()
    observer = Observer()
    for pasta in pastas:
        observer.schedule(event_handler, pasta, recursive=True)
        print(f"[+] Monitorando: {pasta}")
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()