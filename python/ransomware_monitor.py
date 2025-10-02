import os
import sys
import math
import getpass
import random
import string
import time
import subprocess
import shutil
import platform
import threading
import queue
import signal
import re
from subprocess import run, DEVNULL

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

NUM_ARQS = 50
ARQ_SIZE = 1024 * 10 

def obter_pastas_usuarios():
    pastas_usuarios = []
    
    try:
        home_dir = "/home"
        if os.path.exists(home_dir):
            for usuario in os.listdir(home_dir):
                usuario_path = os.path.join(home_dir, usuario)
                if os.path.isdir(usuario_path):
                    pastas_alvo = ["Documents", "Desktop", "Downloads"]
                    for pasta in pastas_alvo:
                        pasta_path = os.path.join(usuario_path, pasta)
                        if os.path.exists(pasta_path):
                            pastas_usuarios.append(pasta_path)

        root_home = "/root"
        if os.path.exists(root_home):
            pastas_alvo = ["Documents", "Desktop", "Downloads"]
            for pasta in pastas_alvo:
                pasta_path = os.path.join(root_home, pasta)
                if os.path.exists(pasta_path):
                    pastas_usuarios.append(pasta_path)

        root_home = "/home/root"
        if os.path.exists(root_home):
            pastas_alvo = ["Documents", "Desktop", "Downloads"]
            for pasta in pastas_alvo:
                pasta_path = os.path.join(root_home, pasta)
                if os.path.exists(pasta_path):
                    pastas_usuarios.append(pasta_path)
        return pastas_usuarios
        
    except Exception as e:
        queue_log(f"[ERRO] Ao obter pastas dos usuários: {e}", "ERRO")
        return []

PASTAS = obter_pastas_usuarios() 
PASTAS_HONEYPOT_CRIADAS = []


KEY = "pastas_ob"
SYSCALLS = ["rename", "openat", "write", "unlink", "sendto", "creat", "openat2", "writev",]


ALERTA_LIMITE = 10

QUARENTENA_DIR = "/var/quarentena_execs"

WHITELIST = {
    "systemd", "init", "bash", "zsh", "sh", "sshd",
    "cron", "crond", "dbus-daemon", "NetworkManager",
    "agetty", "login", "Xorg", "gnome-shell", "kdeinit"
}

def atualizar_tracker_miner_ppids():
    """Atualiza a lista de PIDs do tracker miner"""
    global TRACKER_MINER_PPIDS
    try:
        result = subprocess.run([
            "pgrep", "-f", "tracker"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            tracker_pids = result.stdout.strip().split('\n')
            TRACKER_MINER_PPIDS.update(tracker_pids)
            queue_log(f"[INFO] Tracker miner PIDs encontrados: {tracker_pids}", "INFO")
            
    except Exception as e:
        queue_log(f"[ERRO] Ao buscar tracker miner: {e}", "ERRO")

TRACKER_MINER_PPIDS = set()
PID_PR = str(os.getpid())

# ================================
# FILA
# ================================
msg_queue = queue.Queue()

def queue_log(text, tipo="INFO"):
    msg_queue.put(("log", text, tipo))

def queue_process_update(action, data):
    msg_queue.put(("process", action, data))

def queue_file_update(action, data):
    msg_queue.put(("file", action, data))

def queue_counter_update():
    msg_queue.put(("counter",))

# ================================
# CONFIGURAÇÃO AUDITD
# ================================
    
def verificar_instalar_auditd():
    if shutil.which("auditd"):
        queue_log("[INFO] auditd já está instalado.", "INFO")
        return True

    queue_log("[INFO] auditd não encontrado. Tentando instalar... (requer root)", "INFO")

    distro = platform.system()
    if distro != "Linux":
        queue_log("[ERRO] Este script só funciona em Linux.", "ERRO")
        return False
    try:
        if os.path.exists("/etc/debian_version"):
            subprocess.run(["apt-get", "update"], check=False)
            subprocess.run(["apt-get", "install", "-y", "auditd"], check=True)
        elif os.path.exists("/etc/redhat-release"):
            subprocess.run(["yum", "install", "-y", "audit"], check=True)
        elif os.path.exists("/etc/fedora-release"):
            subprocess.run(["dnf", "install", "-y", "audit"], check=True)
        else:
            queue_log("[ERRO] Distribuição não suportada para instalação automática.", "ERRO")
            return False

        queue_log("[SUCESSO] auditd instalado com sucesso.", "SUCESSO")
        return True
    except subprocess.CalledProcessError as e:
        queue_log(f"[ERRO] Falha ao instalar auditd: {e}", "ERRO")
        return False
    except PermissionError:
        queue_log("[ERRO] Permissão negada ao tentar instalar auditd. Rode como root.", "ERRO")
        return False
    except Exception as e:
        queue_log(f"[ERRO] Erro inesperado ao instalar auditd: {e}", "ERRO")
        return False

def configurar_auditd(max_log_file=2, max_log_file_action="ROTATE", num_logs=2):
    conf_path = "/etc/audit/auditd.conf"
    try:
        with open(conf_path, "r") as f:
            linhas = f.readlines()

        novas_linhas = []
        for linha in linhas:
            palavra = linha.strip().split('=')[0].strip()
            if palavra == "max_log_file_action":
                novas_linhas.append(f"max_log_file_action = {max_log_file_action}\n")
            elif palavra == "max_log_file":
                novas_linhas.append(f"max_log_file = {max_log_file}\n")
            elif palavra == "num_logs":
                novas_linhas.append(f"num_logs = {num_logs}\n")
            else:
                novas_linhas.append(linha)

        with open(conf_path, "w") as f:
            f.writelines(novas_linhas)

        queue_log("[INFO] auditd.conf atualizado.", "INFO")
    except PermissionError:
        queue_log("[ERRO] Precisa rodar como root para editar /etc/audit/auditd.conf", "ERRO")
    except FileNotFoundError:
        queue_log("[ERRO] arquivo auditd.conf não encontrado.", "ERRO")
    except Exception as e:
        queue_log(f"[ERRO] Falha ao editar auditd.conf: {e}", "ERRO")

# SETAR REGRA DO AUDITD

def regra_audit():
    syscalls_string = ",".join(SYSCALLS)
    regras = []
    for pasta in PASTAS:
        for arch in ["b64", "b32"]:
            regra = (
                f"-a always,exit "
                f"-F dir={pasta} "
                f"-F arch={arch} "
                f"-S {syscalls_string} "
                f"-k {KEY}"
            )
            regras.append(regra)

    rules_file = f"/etc/audit/rules.d/{KEY}.rules"
    try:
        with open(rules_file, "w") as f:
            f.write("\n".join(regras) + "\n")
        queue_log(f"[INFO] Regras de audit escritas em {rules_file}", "INFO")
    except PermissionError:
        queue_log("[ERRO] Precisa rodar como root para escrever em /etc/audit/rules.d/", "ERRO")
    except Exception as e:
        queue_log(f"[ERRO] Falha ao escrever regras de audit: {e}", "ERRO")

def aplicar_regras():
    try:
        run(["augenrules", "--load"], check=False, stdout=DEVNULL, stderr=DEVNULL)
        subprocess.run(["systemctl", "restart", "auditd"], check=False)
        queue_log("[INFO] Regras aplicadas e auditd reiniciado.", "INFO")
    except Exception as e:
        queue_log(f"[ERRO] Falha ao aplicar regras: {e}", "ERRO")

# ===============================
# GEReNCIADOR DO HONEYPOT
# ================================


def criar_arquivos_isca(pasta):
    EXTENSOES_ISCA = [
        ".docx", ".xlsx", ".txt", ".sql", ".pptx"
    ]

    NOMES_BASE = [
        "passwords", "acesso_vpn", "financeiro_2025", "backup_keys", 
        "rh_salarios", "projeto_secreto", "lista_clientes", "impostos_2024"
    ]

    NOMES_DIRETORIOS = [
        "Documentos", "Relatorios", "Financeiro", "Projetos",
        "TempFiles", "Backup2025", "Downloads", "Logs", "Arquivos"
    ]

    try:
        nome_dir = random.choice(NOMES_DIRETORIOS) + "H"
        dir_final = os.path.join(pasta, nome_dir)
        os.makedirs(dir_final, exist_ok=True)
        
        # ADICIONE: Registrar a pasta criada
        global PASTAS_HONEYPOT_CRIADAS
        if dir_final not in PASTAS_HONEYPOT_CRIADAS:
            PASTAS_HONEYPOT_CRIADAS.append(dir_final)

        arquivos_criados = 0

        for i in range(NUM_ARQS):
            nome_base = random.choice(NOMES_BASE)
            extensao = random.choice(EXTENSOES_ISCA)
            
            caminho_arquivo = os.path.join(
                dir_final, 
                f"{nome_base}_{random.randint(100, 999)}{extensao}"
            )

            conteudo_aleatorio = ''.join(
                random.choices(string.ascii_letters + string.digits, k=ARQ_SIZE)
            )

            with open(caminho_arquivo, "w", encoding='utf-8') as f:
                f.write(conteudo_aleatorio)
            
            arquivos_criados += 1
            
        queue_log(f"[SUCESSO] {arquivos_criados} arquivos isca criados em {dir_final}", "SUCESSO")
        
    except Exception as e:
        queue_log(f"[ERRO] Falha ao criar arquivos isca em {pasta}: {e}", "ERRO")


def limpar_pastas_honeypot():
    """Remove todas as pastas honeypot criadas pelo programa"""
    global PASTAS_HONEYPOT_CRIADAS
    pastas_removidas = 0
    
    for pasta in PASTAS_HONEYPOT_CRIADAS[:]:  # Usar cópia da lista para evitar problemas durante iteração
        try:
            if os.path.exists(pasta):
                shutil.rmtree(pasta)  # Remove recursivamente
                pastas_removidas += 1
                queue_log(f"[INFO] Pasta honeypot removida: {pasta}", "INFO")
        except Exception as e:
            queue_log(f"[ERRO] Falha ao remover pasta {pasta}: {e}", "ERRO")
    
    PASTAS_HONEYPOT_CRIADAS.clear()


# ================================
# MONITORAMENTO DE ALTERAÇÕES
# ================================

#VERIFICAR SE É UM ZIP
        
def verificar_formato_zip(filepath):
    try:
        with open(filepath, 'rb') as f:
            magic_number = f.read(4)
            if magic_number == b'PK\x03\x04':
                return True
    except Exception:
        pass
    return False

def verificar_formato_pdf(filepath):
    try:
        with open(filepath, 'rb') as f:
            magic_number = f.read(5) 
            if magic_number == b'%PDF-':
                return True
    except Exception:
        pass
    return False

# CALCULAR ENTROPIA              

def calcular_entropia(dados: bytes):
    if not dados:
        return 0.0
    frequencias = {}
    for b in dados:
        frequencias[b] = frequencias.get(b, 0) + 1
    entropia = 0.0
    tamanho = len(dados)
    for freq in frequencias.values():
        p = freq / tamanho
        entropia -= p * math.log2(p)
    return entropia

# PEGAR EXECUTAVEL LINK SIMBOLICO DO ELF

def executavel_pid(pid):
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
        return exe_path
    except Exception as e:
        queue_log(f"[ERRO] Não foi possível obter executável do PID {pid}: {e}", "ERRO")
        return None

# QUARENTENA

def mover_executavel_quarentena(pid):
    exe_path = executavel_pid(pid)
    if not exe_path:
        return None
    if "nautilus" in exe_path or os.path.basename(exe_path) in WHITELIST:
        queue_log(f"[INFO] Ignorando quarentena de {exe_path}.", "INFO")
        return None

    try:
        os.makedirs(QUARENTENA_DIR, exist_ok=True)
        base_name = os.path.basename(exe_path)
        destino = os.path.join(QUARENTENA_DIR, f"{base_name}_{pid}_{int(time.time())}")
        shutil.move(exe_path, destino)
        queue_log(f"[QUARENTENA] Executável {exe_path} movido para {destino}", "SUCESSO")
        return destino
    except PermissionError:
        queue_log("[ERRO] Permissão negada ao mover executável para quarentena. Rode como root.", "ERRO")
        return None
    except Exception as e:
        queue_log(f"[ERRO] Falha ao mover executável para quarentena: {e}", "ERRO")
        return None

# ================================
# CLASSE PRINCIPAL
# ================================
class MonitorRansomware(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.contagem_pids = {}
        self.total_alteracoes = {}   
        self.ppids = {}
        self.comms = {}
        self.processos_finalizados = set()
        self.arquivos_por_pid = {}
        self.processos_finalizados.add(str(os.getpid()))
        self.quarentena_count = 0


# DECODIFICA SE LOG AUDIT ESTIVER EM HEX

    def maybe_decode_hex(self, s: str) -> str:
        if re.fullmatch(r"[0-9A-Fa-f]+", s) and len(s) % 2 == 0:
            try:
                return bytes.fromhex(s).decode("utf-8", errors="replace")
            except Exception:
                return s
        return s

# PESQUISA PID, PPID E COMM

    def ausearch_arquivo_mod(self, filepath):
        try:
            filename = os.path.basename(filepath)
            cmd = ["ausearch", "-f", filename, "-k", KEY, "--success", "yes", "--start", "recent"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            pid, ppid, comm, new_name = None, None, None, None
            for line in result.stdout.splitlines():
                if " pid=" in line:
                    for p in line.split():
                        if p.startswith("pid="):
                            pid = p.split("=")[1]
                        if p.startswith("ppid="):
                            ppid = p.split("=")[1]
                        if p.startswith("comm="):
                            comm = p.split("=")[1].strip('"')

                if "nametype=CREATE" in line and " name=" in line:
                    raw_name = line.split("name=")[1].split()[0].strip('"')
                    new_name = self.maybe_decode_hex(raw_name)

            if new_name:
                if not os.path.isabs(new_name):
                    base_dir = os.path.dirname(filepath)
                    filepath = os.path.join(base_dir, os.path.basename(new_name))
                else:
                    filepath = new_name

            return pid, ppid, comm, filepath
        except Exception as e:
            print(f"    [ERRO ao consultar ausearch: {e}]")
            return None, None, None, None

# DEFINIR CRIPTOGRAFIA

    def medir_entropia_arquivos(self, arquivos):
        criptografados = 0
        analisados = 0
        resultados = []
        for arq in arquivos:
            try:
                with open(arq, "rb") as f:
                    dados = f.read(4096)
                entropia = calcular_entropia(dados)
                analisados += 1

                if entropia > 7.6:
                    if entropia > 7.6:
                        if verificar_formato_zip(arq):
                            queue_log(f"[INFO] {arq} → entropia {entropia:.2f} (É um ZIP)", "INFO")
                        elif verificar_formato_pdf(arq):
                            queue_log(f"[INFO] {arq} → entropia {entropia:.2f} (É um PDF)", "INFO")
                        else:
                            criptografados += 1
                            queue_log(f"[INFO] {arq} → entropia {entropia:.2f} (SUSPEITO)", "INFO")
                    else:
                        queue_log(f"[INFO] {arq} → entropia {entropia:.2f} (OK)", "INFO")
                resultados.append((arq, entropia))
            except Exception as e:
                queue_log(f"[ERRO lendo {arq}: {e}]", "ERRO")

        if analisados == 0:
            return False, 0, resultados
        return (criptografados > (analisados / 2), criptografados, resultados)


    def eh_processo_tracker_miner(self, pid, ppid, comm):
        """Verifica se o processo é filho do tracker miner"""
        if not ppid:
            return False

        if ppid in TRACKER_MINER_PPIDS:
            return True

        if comm and any(nome in comm.lower() for nome in ['tracker', 'miner', 'extract', 'pool']):
            return True
            
        return False

# VERIFICAÇÃO RAMSOMWARE
    def on_modified(self, event):
        if not event.is_directory:
            pid, ppid, comm, filepath = self.ausearch_arquivo_mod(event.src_path)
            if not pid:
                queue_log(f"[!] Arquivo modificado: {event.src_path}", "ALERTA")
                queue_log(" → PID não encontrado no ausearch", "ALERTA")
                return
            
            if self.eh_processo_tracker_miner(pid, ppid, comm):
                queue_log(f"[INFO] Ignorando evento do tracker miner (PID: {pid}, PPID: {ppid}, COMM: {comm})", "INFO")
                return
            
            if pid == PID_PR:
                return

            self.total_alteracoes[pid] = self.total_alteracoes.get(pid, 0) + 1
            
            if pid in self.processos_finalizados:
                queue_log(f"[INFO] {filepath} Ignorando evento de PID {pid} (já finalizado). Total: {self.total_alteracoes[pid]}", "INFO")
                
                queue_file_update("add", {
                    "arquivo": filepath,
                    "pid": pid,
                    "status": "Modificado por processo em quarentena" 
                })
                
                proc_data = {
                    "pid": pid,
                    "ppid": ppid or "",
                    "comm": comm or "",
                    "count": self.total_alteracoes[pid],
                    "status": "FINALIZADO"
                }
                queue_process_update("add_or_update", proc_data)
                return

            # Código para PIDs ATIVOS
            self.contagem_pids[pid] = self.contagem_pids.get(pid, 0) + 1
            if ppid:
                self.ppids[pid] = ppid
            if comm:
                self.comms[ppid] = comm
            self.arquivos_por_pid.setdefault(pid, []).append(filepath)
            
            queue_log(f"[!] Arquivo modificado: {filepath}", "ALERTA")
            queue_log(
                f" → PID: {pid}, PPID: {ppid}, COMM: {comm}, "
                f"Alterações neste ciclo: {self.contagem_pids[pid]}, "
                f"Total acumulado: {self.total_alteracoes[pid]}", "INFO"
            )

            proc_data = {
                "pid": pid,
                "ppid": ppid or "",
                "comm": comm or "",
                "count": self.total_alteracoes[pid],
                "status": "ATIVO"
            }
            queue_process_update("add_or_update", proc_data)

            queue_file_update("add", {
                "arquivo": filepath,
                "pid": pid,
                "status": "Modificado"  
            })

            # VERIFICAÇÃO DO LIMITE
            if self.contagem_pids[pid] >= ALERTA_LIMITE:
                arquivos = self.arquivos_por_pid.get(pid, [])
                suspeito, criptografados, resultados = self.medir_entropia_arquivos(arquivos)
                queue_log(f"[ALERTA] PID {pid} alterou {ALERTA_LIMITE} arquivos.", "ALERTA")
                queue_log(f" → Quantidade de arquivos criptografados: {criptografados}", "INFO")
                
                for arq, ent in resultados:
                    status_arquivo = "Criptografado" if ent > 7.6 and not verificar_formato_zip(arq) else "Modificado"
                    queue_file_update("update_status", {
                        "arquivo": arq,
                        "pid": pid,
                        "status": status_arquivo
                    })
                
                if suspeito:
                    queue_log(f"[ATAQUE SUSPEITO] PID {pid}", "ERRO")
                    destino = mover_executavel_quarentena(pid)
                    try:
                        os.kill(int(pid), 9)
                        queue_log(f"[SUCESSO] Processo {pid} finalizado.", "SUCESSO")
                    except ProcessLookupError:
                        queue_log(f"[ERRO] Processo {pid} já não existe mais.", "ERRO")
                    except PermissionError:
                        queue_log("[ERRO] Sem permissão para matar o processo. Rode como root.", "ERRO")
                    except Exception as e:
                        queue_log(f"[ERRO] ao terminar processo {pid}: {e}", "ERRO")
                    finally:
                        self.processos_finalizados.add(pid)
                        
                        for arq in self.arquivos_por_pid.get(pid, []):
                            queue_file_update("update_status", {
                                "arquivo": arq,
                                "pid": pid,
                                "status": "Modificado por processo em quarentena"
                            })
                        
                        proc_quar = {
                            "pid": pid,
                            "ppid": self.ppids.get(pid, ""),
                            "comm": self.comms.get(self.ppids.get(pid, ""), ""),
                            "count": self.contagem_pids.get(pid, 0),
                            "total": self.total_alteracoes.get(pid, 0),
                            "status": "QUARENTENA",
                            "destino": destino or "N/A",
                            "arquivos": self.arquivos_por_pid.get(pid, [])
                        }
                        queue_process_update("quarantine", proc_quar)
                        self.quarentena_count += 1
                        queue_counter_update()
                        
                        self.contagem_pids[pid] = 0
                        self.arquivos_por_pid[pid] = []
                else:
                    queue_log("[INFO] Alterações não parecem criptografia.", "INFO")
                    self.contagem_pids[pid] = 0
                    self.arquivos_por_pid[pid] = []

# ================================
# THREAD DE MONITORAMENTO
# ================================
class MonitorThread(threading.Thread):
    def __init__(self, stop_event):
        super().__init__(daemon=True)
        self.stop_event = stop_event
        self.observer = None

    def run(self):
        if not verificar_instalar_auditd():
            queue_log("[WARN] auditd não instalado ou não acessível. Algumas funcionalidades exigem auditd.", "ERRO")
        try:
            configurar_auditd()
            regra_audit()
            aplicar_regras()
        except Exception as e:
            queue_log(f"[WARN] Erro ao configurar/aplicar regras de auditd: {e}", "ERRO")

        usuario = getpass.getuser()
        honeypots = [f"/home/{usuario}/honeypot"] + PASTAS
        for pasta in honeypots:
            try:
                criar_arquivos_isca(pasta)
            except Exception as e:
                queue_log(f"[ERRO] criando iscas em {pasta}: {e}", "ERRO")

        manipulador = MonitorRansomware()
        observer = Observer()
        self.observer = observer

        if not PASTAS:
            queue_log("[WARN] Nenhuma pasta configurada em PASTAS. Só o honeypot do usuário será monitorado.", "INFO")

        for pasta in PASTAS:
            try:
                os.makedirs(pasta, exist_ok=True)
                observer.schedule(manipulador, pasta, recursive=True)
                queue_log(f"[+] Monitorando: {pasta}", "INFO")
            except Exception as e:
                queue_log(f"[ERRO] ao agendar monitoramento para {pasta}: {e}", "ERRO")

        user_honeypot = f"/home/{getpass.getuser()}/honeypot"
        try:
            os.makedirs(user_honeypot, exist_ok=True)
            observer.schedule(manipulador, user_honeypot, recursive=True)
            queue_log(f"[+] Monitorando: {user_honeypot}", "INFO")
        except Exception as e:
            queue_log(f"[ERRO] ao agendar monitoramento para {user_honeypot}: {e}", "ERRO")

        observer.start()
        queue_log("[INFO] Watchdog iniciado.", "INFO")
        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        except Exception as e:
            queue_log(f"[ERRO] Thread de monitor principal: {e}", "ERRO")
        finally:
            try:
                observer.stop()
                observer.join()
            except Exception:
                pass
            limpar_pastas_honeypot()
            
            queue_log("[INFO] Monitoramento parado.", "INFO")
        

# Função para executar sem GUI
def executar_sem_gui():
    print("Iniciando monitoramento de ransomware...")
    stop_event = threading.Event()
    
    try:
        monitor_thread = MonitorThread(stop_event)
        monitor_thread.start()
        
        print("Monitoramento ativo. Pressione Ctrl+C para parar.")
        while monitor_thread.is_alive():
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nParando monitoramento...")
        stop_event.set()
        monitor_thread.join(timeout=5)

if __name__ == "__main__":
    executar_sem_gui()