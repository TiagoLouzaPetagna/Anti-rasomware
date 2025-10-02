import sys
import os
import time
import subprocess
import threading
import queue
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QTabWidget, QTableWidget, QTableWidgetItem,
    QListWidget, QLineEdit, QFileDialog, QMessageBox
)
from PyQt5.QtGui import QPalette, QColor, QFont
from PyQt5.QtWidgets import QHeaderView
from PyQt5.QtCore import QTimer

from ransomware_monitor import (
    PASTAS, msg_queue, queue_log,
    MonitorThread
)

class RansomwareGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitor de Ransomware - PyQt5")
        self.resize(1100, 750)

        # Variáveis de controle
        self.stop_event = threading.Event()
        self.monitor_thread = None
        self.proc_items = {}
        self.quarantine_count = 0

        # Layout principal
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Cabeçalho de status
        header_layout = QHBoxLayout()
        self.status_label = QLabel("Status: Parado")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
        self.counter_label = QLabel("Processos bloqueados: 0")
        self.counter_label.setStyleSheet("color: darkred; font-weight: bold;")
        header_layout.addWidget(self.status_label)
        header_layout.addStretch()
        header_layout.addWidget(self.counter_label)
        layout.addLayout(header_layout)

        # Tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Aba Logs
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.tabs.addTab(self.log_area, "Logs")

        # Aba Processos
        self.table_procs = QTableWidget(0, 5)
        self.table_procs.setHorizontalHeaderLabels(
            ["PID", "PPID", "COMM", "Alterações", "Status"]
        )
        self.table_procs.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tabs.addTab(self.table_procs, "Processos")

        # Aba de Arquivos Modificados
        self.table_files = QTableWidget(0, 3)
        self.table_files.setHorizontalHeaderLabels(["Arquivo", "PID", "Status"])
        self.table_files.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tabs.addTab(self.table_files, "Arquivos Modificados")
        

        # Aba Pastas
        self.folder_tab = QWidget()
        folder_layout = QVBoxLayout(self.folder_tab)

        ctrl_layout = QHBoxLayout()
        self.folder_entry = QLineEdit()
        btn_select = QPushButton("Selecionar pasta...")
        btn_add = QPushButton("Adicionar")
        btn_remove = QPushButton("Remover selecionada")
        btn_clear = QPushButton("Limpar lista")
        ctrl_layout.addWidget(self.folder_entry)
        ctrl_layout.addWidget(btn_select)
        ctrl_layout.addWidget(btn_add)
        ctrl_layout.addWidget(btn_remove)
        ctrl_layout.addWidget(btn_clear)
        folder_layout.addLayout(ctrl_layout)

        self.folder_list = QListWidget()
        folder_layout.addWidget(self.folder_list)
        self.tabs.addTab(self.folder_tab, "Pastas / Controle")

        # Iniciar Parar
        control_layout = QHBoxLayout()
        self.start_btn = QPushButton("Iniciar Monitoramento")
        self.stop_btn = QPushButton("Parar Monitoramento")
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        layout.addLayout(control_layout)

        # Conectar botões
        btn_select.clicked.connect(self.select_folder)
        btn_add.clicked.connect(self.add_folder_from_entry)
        btn_remove.clicked.connect(self.remove_selected_folder)
        btn_clear.clicked.connect(self.clear_folder_list)
        self.start_btn.clicked.connect(self.start_monitor)
        self.stop_btn.clicked.connect(self.stop_monitor)

        # Timer da fila
        self.timer = QTimer()
        self.timer.timeout.connect(self.process_queue)
        self.timer.start(200)

        # Carregar pastas iniciais
        self.refresh_folder_listbox()

        self.table_procs.doubleClicked.connect(self.on_process_double_click)
        
        # Botão para limpar filtro
        self.btn_clear_filter = QPushButton("Limpar Filtro")
        self.btn_clear_filter.clicked.connect(self.clear_pid_filter)
        self.btn_clear_filter.setVisible(False)
    
        header_layout.addWidget(self.btn_clear_filter)
        
        self.pid_filter = None

    def on_process_double_click(self, index):
        """Quando clica duas vezes em um processo, filtra os arquivos por PID"""
        row = index.row()
        pid_item = self.table_procs.item(row, 0)
        
        if pid_item:
            pid = pid_item.text()
            self.filter_files_by_pid(pid)

    def filter_files_by_pid(self, pid):
        """Filtra a tabela de arquivos para mostrar apenas os do PID especificado"""
        self.pid_filter = pid
        self.btn_clear_filter.setVisible(True)
        self.btn_clear_filter.setText(f"Limpar Filtro (PID: {pid})")
        
        # Mostrar apenas arquivos do PID selecionado
        for row in range(self.table_files.rowCount()):
            pid_item = self.table_files.item(row, 1)
            if pid_item and pid_item.text() == pid:
                self.table_files.setRowHidden(row, False)
            else:
                self.table_files.setRowHidden(row, True)
        
        self.log(f"Filtrado: mostrando apenas arquivos do PID {pid}", "INFO")
        
        # Mudar para a aba de arquivos automaticamente
        self.tabs.setCurrentIndex(2) 

    def clear_pid_filter(self):
        """Remove o filtro e mostra todos os arquivos"""
        self.pid_filter = None
        self.btn_clear_filter.setVisible(False)
        
        # Mostrar todas as linhas
        for row in range(self.table_files.rowCount()):
            self.table_files.setRowHidden(row, False)
        
        self.log("Filtro removido: mostrando todos os arquivos", "INFO")

    def add_file(self, data):
        arquivo = data.get("arquivo", "")
        pid = data.get("pid", "")
        status = data.get("status", "")
        
        # Verificar se o arquivo já existe na tabela
        for row in range(self.table_files.rowCount()):
            if self.table_files.item(row, 0).text() == arquivo:
                self.table_files.setItem(row, 1, QTableWidgetItem(str(pid)))
                self.table_files.setItem(row, 2, QTableWidgetItem(status))
                
                if self.pid_filter and str(pid) != self.pid_filter:
                    self.table_files.setRowHidden(row, True)
                else:
                    self.table_files.setRowHidden(row, False)
                return
        
        row = self.table_files.rowCount()
        self.table_files.insertRow(row)
        self.table_files.setItem(row, 0, QTableWidgetItem(arquivo))
        self.table_files.setItem(row, 1, QTableWidgetItem(str(pid)))
        self.table_files.setItem(row, 2, QTableWidgetItem(status))
        
        if self.pid_filter and str(pid) != self.pid_filter:
            self.table_files.setRowHidden(row, True)

    def update_file_status(self, data):
        arquivo = data.get("arquivo", "")
        pid = data.get("pid", "")
        status = data.get("status", "")
        
        for row in range(self.table_files.rowCount()):
            if self.table_files.item(row, 0).text() == arquivo:
                self.table_files.setItem(row, 1, QTableWidgetItem(str(pid)))
                self.table_files.setItem(row, 2, QTableWidgetItem(status))
                
                if self.pid_filter and str(pid) != self.pid_filter:
                    self.table_files.setRowHidden(row, True)
                else:
                    self.table_files.setRowHidden(row, False)
                return

    # METODOS da Interface grafica
    def log(self, text, tipo="INFO"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {text}"

        if tipo == "ERRO":
            color = "red"
        elif tipo == "ALERTA":
            color = "white"   
        elif tipo == "SUCESSO":
            color = "green"
        else: 
            color = "white"

        self.log_area.append(f'<span style="color:{color}">{line}</span>')

    def refresh_folder_listbox(self):
        self.folder_list.clear()
        for p in PASTAS:
            self.folder_list.addItem(p)

    def select_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Selecionar pasta")
        if d:
            self.folder_entry.setText(d)

    def add_folder_from_entry(self):
        path = self.folder_entry.text().strip()
        if not path:
            QMessageBox.information(self, "Aviso", "Digite ou selecione uma pasta.")
            return
        path = os.path.abspath(path)
        if path in PASTAS:
            QMessageBox.information(self, "Aviso", "Pasta já está na lista.")
            return
        PASTAS.append(path)
        self.refresh_folder_listbox()
        queue_log(f"[GUI] Pasta adicionada: {path}", "INFO")

    def remove_selected_folder(self):
        sel = self.folder_list.currentRow()
        if sel < 0:
            QMessageBox.information(self, "Aviso", "Nenhuma pasta selecionada.")
            return
        path = self.folder_list.item(sel).text()
        try:
            PASTAS.remove(path)
            self.refresh_folder_listbox()
            queue_log(f"[GUI] Pasta removida: {path}", "INFO")
        except ValueError:
            queue_log(f"[WARN] Pasta não encontrada para remover: {path}", "ALERTA")

    def clear_folder_list(self):
        if not PASTAS:
            QMessageBox.information(self, "Aviso", "Lista já está vazia.")
            return
        if QMessageBox.question(self, "Confirmar", "Deseja limpar a lista de pastas?") == QMessageBox.Yes:
            PASTAS.clear()
            self.refresh_folder_listbox()
            queue_log("[GUI] Lista de pastas limpa.", "INFO")

    # Funções de iniciar e parar
    def start_monitor(self):
        if self.monitor_thread and self.monitor_thread.is_alive():
            QMessageBox.information(self, "Já rodando", "O monitor já está em execução.")
            return
            
        # Log das pastas que serão monitoradas
        if PASTAS:
            queue_log(f"[INFO] Monitorando {len(PASTAS)} pastas automaticamente", "INFO")
            for pasta in PASTAS:
                queue_log(f"[INFO] - {pasta}", "INFO")
        else:
            queue_log("[INFO] Nenhuma pasta encontrada para monitorar", "INFO")

        self.stop_event.clear()
        self.monitor_thread = MonitorThread(self.stop_event)
        self.monitor_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Rodando")
        self.status_label.setStyleSheet("color: green; font-weight: bold;")
        queue_log("[GUI] Monitor iniciado.", "INFO")

    def stop_monitor(self):
        if not (self.monitor_thread and self.monitor_thread.is_alive()):
            return
            
        self.stop_event.set()
        self.monitor_thread.join(timeout=5)
        self.monitor_thread = None
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Status: Parado")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
        queue_log("[GUI] Pedido de parada enviado.", "INFO")
    try:
        from ransomware_monitor import limpar_pastas_honeypot
        limpar_pastas_honeypot()
    except Exception as e:
        queue_log(f"[ERRO] Ao limpar pastas honeypot: {e}", "ERRO")

    # FILA
    def process_queue(self):
        processed = 0
        while not msg_queue.empty() and processed < 200:
            try:
                item = msg_queue.get_nowait()
            except queue.Empty:
                break
            if not item:
                continue
            kind = item[0]
            if kind == "log":
                _, text, tipo = item
                self.log(text, tipo)
            elif kind == "process":
                _, action, data = item
                if action == "add_or_update":
                    self.update_process_table(data)
                elif action == "quarantine":
                    self.handle_quarantine(data)
            elif kind == "file":
                _, action, data = item
                if action == "add":
                    self.add_file(data)
                elif action == "update_status":
                    self.update_file_status(data)
            elif kind == "counter":
                self.update_counter()
            processed += 1

    def update_process_table(self, data):
        pid = data["pid"]
        found = None
        for row in range(self.table_procs.rowCount()):
            if self.table_procs.item(row, 0).text() == str(pid):
                found = row
                break

        if found is not None:
            self.table_procs.setItem(found, 1, QTableWidgetItem(str(data.get("ppid", ""))))
            self.table_procs.setItem(found, 2, QTableWidgetItem(data.get("comm", "")))
            self.table_procs.setItem(found, 3, QTableWidgetItem(str(data.get("count", ""))))
            self.table_procs.setItem(found, 4, QTableWidgetItem(data.get("status", "")))
        else:
            row = self.table_procs.rowCount()
            self.table_procs.insertRow(row)
            self.table_procs.setItem(row, 0, QTableWidgetItem(str(pid)))
            self.table_procs.setItem(row, 1, QTableWidgetItem(str(data.get("ppid", ""))))
            self.table_procs.setItem(row, 2, QTableWidgetItem(data.get("comm", "")))
            self.table_procs.setItem(row, 3, QTableWidgetItem(str(data.get("count", ""))))
            self.table_procs.setItem(row, 4, QTableWidgetItem(data.get("status", "")))

    def handle_quarantine(self, data):
        pid = data["pid"]
        destino = data.get("destino", "N/A")
        self.log(f"Processo {pid} em quarentena (movido para {destino})", "ALERTA")
        QMessageBox.warning(self, "Processo em Quarentena",
                            f"PID: {pid}\nPrograma: {data.get('comm','')}\nMovido para: {destino}")
        self.update_counter()

    def add_file(self, data):
        arquivo = data.get("arquivo", "")
        pid = data.get("pid", "")
        status = data.get("status", "")
        
        for row in range(self.table_files.rowCount()):
            if self.table_files.item(row, 0).text() == arquivo:
                self.table_files.setItem(row, 1, QTableWidgetItem(str(pid)))
                self.table_files.setItem(row, 2, QTableWidgetItem(status))
                return

        row = self.table_files.rowCount()
        self.table_files.insertRow(row)
        self.table_files.setItem(row, 0, QTableWidgetItem(arquivo))
        self.table_files.setItem(row, 1, QTableWidgetItem(str(pid)))
        self.table_files.setItem(row, 2, QTableWidgetItem(status))

    def update_counter(self):
        count = 0
        for row in range(self.table_procs.rowCount()):
            if self.table_procs.item(row, 4) and self.table_procs.item(row, 4).text() == "QUARENTENA":
                count += 1
        self.counter_label.setText(f"Processos bloqueados: {count}")

    def update_file_status(self, data):
        arquivo = data.get("arquivo", "")
        pid = data.get("pid", "")
        status = data.get("status", "")
        
        for row in range(self.table_files.rowCount()):
            if self.table_files.item(row, 0).text() == arquivo:
                self.table_files.setItem(row, 1, QTableWidgetItem(str(pid)))
                self.table_files.setItem(row, 2, QTableWidgetItem(status))
                return

def relancar_com_pkexec():
    script = os.path.abspath(sys.argv[0])
    display = os.environ.get("DISPLAY")
    xauthority = os.environ.get("XAUTHORITY")
    cmd = ["pkexec", "env"]
    if display:
        cmd.append(f"DISPLAY={display}")
    if xauthority:
        cmd.append(f"XAUTHORITY={xauthority}")
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        cmd.append(f"XDG_RUNTIME_DIR={xdg}")
    cmd += [script] + sys.argv[1:]
    os.execvp("pkexec", cmd)

def verificar_e_solicitar_root():
    if os.geteuid() != 0:
        relancar_com_pkexec()

def apply_dark_theme(app):
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(30, 30, 30))     
    palette.setColor(QPalette.WindowText, QColor(220, 220, 220)) 
    palette.setColor(QPalette.Base, QColor(20, 20, 20))        
    palette.setColor(QPalette.AlternateBase, QColor(30, 30, 30))
    palette.setColor(QPalette.ToolTipBase, QColor(220, 220, 220))
    palette.setColor(QPalette.ToolTipText, QColor(220, 220, 220))
    palette.setColor(QPalette.Text, QColor(220, 220, 220))
    palette.setColor(QPalette.Button, QColor(45, 45, 45))
    palette.setColor(QPalette.ButtonText, QColor(220, 220, 220))
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    app.setPalette(palette)

#====================
# MAIN
#====================
def main():
    app = QApplication(sys.argv)
    apply_dark_theme(app)

    fonte = QFont("Segoe UI", 10) 
    app.setFont(fonte)

    window = RansomwareGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    verificar_e_solicitar_root()
    main()
