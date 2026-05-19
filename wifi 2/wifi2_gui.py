#!/usr/bin/env python3
"""
Quantum GUI - Interface Gráfica para a ferramenta de Auditoria Wi-Fi
"""

import sys
import os
import re
import threading
import queue
import subprocess
import builtins
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

import customtkinter as ctk

# Adiciona o diretório atual ao path para importar wifi2
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wifi2 import Waircut, AccessPoint

# Regex para remover códigos ANSI
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

ANSI_COLOR_MAP = {
    '\033[91m': 'red',
    '\033[92m': 'green',
    '\033[93m': 'yellow',
    '\033[94m': 'blue',
    '\033[95m': 'purple',
    '\033[96m': 'cyan',
    '\033[97m': 'white',
    '\033[1m':  'bold',
}


class TextRedirector:
    """Redireciona stdout/stderr para a fila de output da GUI."""
    def __init__(self, output_queue):
        self.queue = output_queue

    def write(self, string):
        if string:
            self.queue.put(string)

    def flush(self):
        pass


class WaircutGUI:
    def __init__(self):
        self._elevate_if_needed()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("Quantum - Wi-Fi Auditing Tool")
        self.root.geometry("1280x780")
        self.root.minsize(960, 620)

        self.tool = Waircut()
        self.output_queue = queue.Queue()
        self.running_task = False

        self._build_ui()
        self._redirect_output()
        self._schedule_queue()

        self._print_welcome()
        self.root.mainloop()

    # ─── Admin ────────────────────────────────────────────────────────────────

    def _is_admin(self):
        try:
            return os.getuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

    def _elevate_if_needed(self):
        if not self._is_admin():
            if os.name == 'nt':
                import ctypes
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable,
                    ' '.join(f'"{a}"' for a in sys.argv),
                    None, 1
                )
                sys.exit(0)
            else:
                print("Execute com: sudo python wifi2_gui.py")
                sys.exit(1)

    # ─── UI Build ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Title bar ──
        title_bar = ctk.CTkFrame(self.root, fg_color="#0d1b2a", height=55, corner_radius=0)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)

        ctk.CTkLabel(
            title_bar,
            text="⚡  QUANTUM — Wi-Fi Auditing Tool",
            font=ctk.CTkFont(family="Courier New", size=18, weight="bold"),
            text_color="#00d4ff"
        ).pack(side="left", padx=20, pady=10)

        ctk.CTkLabel(
            title_bar, text="GUI v1.0",
            font=ctk.CTkFont(size=11), text_color="#4a6fa5"
        ).pack(side="right", padx=20)

        # ── Main content ──
        content = ctk.CTkFrame(self.root, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=8, pady=(6, 0))

        # Left sidebar
        self._build_sidebar(content)

        # Right terminal
        self._build_terminal(content)

        # Status bar
        self._build_statusbar()

    def _build_sidebar(self, parent):
        sidebar = ctk.CTkScrollableFrame(parent, width=230, fg_color="#111827", corner_radius=8)
        sidebar.pack(side="left", fill="y", padx=(0, 6))

        # Interface selector
        self._section_label(sidebar, "INTERFACE DE REDE")
        ctk.CTkButton(
            sidebar, text="🔌  Selecionar Interface",
            command=self._select_interface,
            fg_color="#1e3a5f", hover_color="#2c5282"
        ).pack(fill="x", padx=8, pady=2)

        self.iface_label = ctk.CTkLabel(
            sidebar, text="Nenhuma interface selecionada",
            text_color="#00d4ff", font=ctk.CTkFont(size=11), wraplength=200
        )
        self.iface_label.pack(pady=(2, 4))

        self.ap_badge = ctk.CTkLabel(
            sidebar, text="AP: Nenhum selecionado",
            text_color="#f39c12", font=ctk.CTkFont(size=10), wraplength=200
        )
        self.ap_badge.pack(pady=(0, 8))

        # Reconhecimento
        self._section_label(sidebar, "RECONHECIMENTO")
        self._sidebar_btn(sidebar, "📡  Escanear Redes Wi-Fi", self._scan)
        self._sidebar_btn(sidebar, "📋  Listar APs Encontrados", self._show_ap_list)
        self._sidebar_btn(sidebar, "🎯  Selecionar AP Alvo", self._select_ap)

        # Análise
        self._section_label(sidebar, "ANÁLISE")
        self._sidebar_btn(sidebar, "🔍  Análise de Segurança", self._security_analysis)
        self._sidebar_btn(sidebar, "🔑  Credenciais Padrão", self._default_creds)
        self._sidebar_btn(sidebar, "💪  Teste de Força de Senha", self._password_test)

        # Ataques WPS
        self._section_label(sidebar, "ATAQUES WPS")
        self._sidebar_btn(sidebar, "🔨  Brute Force WPS", self._wps_brute, "#6b21a8")
        self._sidebar_btn(sidebar, "✨  Pixie Dust", self._pixie_dust, "#6b21a8")

        # Ataques WPA
        self._section_label(sidebar, "ATAQUES WPA/WPA2")
        self._sidebar_btn(sidebar, "📖  Ataque de Dicionário", self._dict_attack, "#6b21a8")

        # Avançado
        self._section_label(sidebar, "AVANÇADO")
        self._sidebar_btn(sidebar, "👥  Escanear Clientes", self._scan_clients, "#7f1d1d")
        self._sidebar_btn(sidebar, "💥  Desautenticação", self._deauth, "#7f1d1d")
        self._sidebar_btn(sidebar, "📊  Analisar Tráfego", self._traffic_analyzer)
        self._sidebar_btn(sidebar, "🔎  Descobrir Dispositivos", self._discover_devices)

        # Utilitários
        self._section_label(sidebar, "UTILITÁRIOS")
        self._sidebar_btn(sidebar, "🗑️   Limpar Terminal", self._clear_output, "#374151")
        self._sidebar_btn(sidebar, "❌  Sair", self.root.destroy, "#7f1d1d")

    def _build_terminal(self, parent):
        right = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=8)
        right.pack(side="left", fill="both", expand=True)

        # Terminal header
        header = ctk.CTkFrame(right, fg_color="#0d1b2a", height=36, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(
            header, text="  Terminal de Saída",
            font=ctk.CTkFont(family="Courier New", size=12),
            text_color="#4a6fa5"
        ).pack(side="left", padx=8, pady=6)

        self.status_indicator = ctk.CTkLabel(
            header, text="● Pronto",
            text_color="#22c55e", font=ctk.CTkFont(size=11)
        )
        self.status_indicator.pack(side="right", padx=12)

        # Text widget
        text_frame = tk.Frame(right, bg="#0d1117")
        text_frame.pack(fill="both", expand=True, padx=2, pady=2)

        self.output_text = tk.Text(
            text_frame,
            bg="#0d1117", fg="#e2e8f0",
            font=("Courier New", 11),
            insertbackground="white",
            wrap="word", state="disabled",
            relief="flat", bd=0,
            padx=14, pady=10,
            selectbackground="#1e3a5f"
        )

        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.output_text.pack(fill="both", expand=True)

        # Color tags
        self.output_text.tag_configure("green",  foreground="#22c55e")
        self.output_text.tag_configure("red",    foreground="#ef4444")
        self.output_text.tag_configure("yellow", foreground="#f59e0b")
        self.output_text.tag_configure("cyan",   foreground="#06b6d4")
        self.output_text.tag_configure("blue",   foreground="#60a5fa")
        self.output_text.tag_configure("purple", foreground="#a78bfa")
        self.output_text.tag_configure("white",  foreground="#f8fafc")
        self.output_text.tag_configure("bold",   font=("Courier New", 11, "bold"))

    def _build_statusbar(self):
        bar = ctk.CTkFrame(self.root, height=26, fg_color="#0d1b2a", corner_radius=0)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.statusbar_text = ctk.CTkLabel(
            bar, text="Pronto  |  Interface: Nenhuma  |  AP: Nenhum",
            font=ctk.CTkFont(size=10), text_color="#4a6fa5"
        )
        self.statusbar_text.pack(side="left", padx=10)

    # ─── UI Helpers ───────────────────────────────────────────────────────────

    def _section_label(self, parent, text):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=8, pady=(10, 0))
        ctk.CTkLabel(
            frame, text=text,
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color="#4a6fa5"
        ).pack(side="left")
        sep = ctk.CTkFrame(frame, height=1, fg_color="#1e3a5f")
        sep.pack(side="left", fill="x", expand=True, padx=(6, 0), pady=0)

    def _sidebar_btn(self, parent, text, command, color="#1e3a5f"):
        def lighter(hex_color):
            try:
                h = hex_color.lstrip('#')
                r, g, b = (min(255, int(h[i:i+2], 16) + 25) for i in (0, 2, 4))
                return f"#{r:02x}{g:02x}{b:02x}"
            except Exception:
                return hex_color

        ctk.CTkButton(
            parent, text=text, command=command,
            fg_color=color, hover_color=lighter(color),
            anchor="w", font=ctk.CTkFont(size=12),
            height=32
        ).pack(fill="x", padx=8, pady=2)

    def _print_welcome(self):
        msg = [
            ("=" * 62 + "\n", "cyan"),
            ("  QUANTUM — Wi-Fi Auditing Tool  |  Interface Gráfica\n", "cyan"),
            ("=" * 62 + "\n\n", "cyan"),
            ("[*] Selecione uma interface de rede para começar.\n", "yellow"),
            ("[!] Use apenas em redes que você tem autorização.\n\n", "red"),
        ]
        for text, tag in msg:
            self._insert_text(text, tag)

    # ─── Output Handling ──────────────────────────────────────────────────────

    def _redirect_output(self):
        redirector = TextRedirector(self.output_queue)
        sys.stdout = redirector
        sys.stderr = redirector

    def _schedule_queue(self):
        self._flush_queue()
        self.root.after(80, self._schedule_queue)

    def _flush_queue(self):
        try:
            while True:
                text = self.output_queue.get_nowait()
                self._write_ansi(text)
        except queue.Empty:
            pass

    def _write_ansi(self, text):
        """Processa e exibe texto com cores mapeadas a partir de códigos ANSI."""
        self.output_text.configure(state="normal")
        parts = re.split(r'(\x1B\[[0-9;]*m)', text)
        current_tag = None
        for part in parts:
            if part in ANSI_COLOR_MAP:
                current_tag = ANSI_COLOR_MAP[part]
            elif part in ('\033[0m', '\033[00m'):
                current_tag = None
            elif part:
                if current_tag:
                    self.output_text.insert("end", part, current_tag)
                else:
                    self.output_text.insert("end", part)
        self.output_text.see("end")
        self.output_text.configure(state="disabled")

    def _insert_text(self, text, tag=None):
        self.output_text.configure(state="normal")
        if tag:
            self.output_text.insert("end", text, tag)
        else:
            self.output_text.insert("end", text)
        self.output_text.see("end")
        self.output_text.configure(state="disabled")

    # ─── Status ───────────────────────────────────────────────────────────────

    def _update_statusbar(self, status="Pronto"):
        iface = self.tool.interface or "Nenhuma"
        ap = self.tool.selected_ap.ssid if self.tool.selected_ap else "Nenhum"
        self.statusbar_text.configure(
            text=f"{status}  |  Interface: {iface}  |  AP: {ap}"
        )
        self.iface_label.configure(text=iface if self.tool.interface else "Nenhuma interface selecionada")
        self.ap_badge.configure(text=f"AP: {ap}")

    def _set_busy(self, busy: bool):
        if busy:
            self.status_indicator.configure(text="⏳ Executando...", text_color="#f59e0b")
        else:
            self.status_indicator.configure(text="● Pronto", text_color="#22c55e")
            self.root.after(0, self._update_statusbar)

    # ─── Threading ────────────────────────────────────────────────────────────

    def _run_task(self, func, *args):
        if self.running_task:
            messagebox.showwarning("Aviso", "Aguarde a tarefa atual terminar.")
            return
        self.running_task = True
        self._set_busy(True)

        def wrapper():
            try:
                func(*args)
            except Exception as exc:
                self.output_queue.put(f"\n[ERRO] {exc}\n")
            finally:
                self.running_task = False
                self.root.after(0, lambda: self._set_busy(False))

        threading.Thread(target=wrapper, daemon=True).start()

    # ─── Guard helpers ────────────────────────────────────────────────────────

    def _need_interface(self):
        if not self.tool.interface:
            messagebox.showwarning("Interface", "Selecione uma interface de rede primeiro.")
            return False
        return True

    def _need_ap(self):
        if not self._need_interface():
            return False
        if not self.tool.selected_ap:
            messagebox.showwarning("AP", "Selecione um AP alvo primeiro.\n(Escanear → Selecionar AP)")
            return False
        return True

    # ─── Actions ──────────────────────────────────────────────────────────────

    def _select_interface(self):
        try:
            if os.name == 'nt':
                from scapy.arch.windows import get_windows_if_list
                all_ifaces = get_windows_if_list()
                if_names = [i['name'] for i in all_ifaces]
                # Prefer Wi-Fi/Wireless/Ethernet first
                preferred = [n for n in if_names if any(k in n for k in ('Wi-Fi', 'Wireless', 'Ethernet', 'WLAN'))]
                if_list = preferred if preferred else if_names
            else:
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                if_list = [l.split()[0] for l in result.stdout.split('\n') if 'IEEE 802.11' in l]

            if not if_list:
                messagebox.showerror("Erro", "Nenhuma interface encontrada.")
                return
        except Exception as exc:
            messagebox.showerror("Erro", f"Não foi possível listar interfaces:\n{exc}")
            return

        # Selection dialog
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Selecionar Interface")
        dialog.geometry("420x360")
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.lift()

        ctk.CTkLabel(
            dialog, text="Interfaces de Rede Disponíveis",
            font=ctk.CTkFont(size=14, weight="bold"), text_color="#00d4ff"
        ).pack(pady=(16, 8))

        selected_var = tk.StringVar(value=if_list[0])
        scroll_frame = ctk.CTkScrollableFrame(dialog, fg_color="#111827", height=200)
        scroll_frame.pack(fill="x", padx=16, pady=4)

        for iface in if_list:
            ctk.CTkRadioButton(
                scroll_frame, text=iface,
                variable=selected_var, value=iface,
                font=ctk.CTkFont(family="Courier New", size=12)
            ).pack(anchor="w", padx=12, pady=4)

        def confirm():
            chosen = selected_var.get()
            self.tool.interface = chosen
            self._update_statusbar()
            self._insert_text(f"\n[+] Interface selecionada: {chosen}\n", "green")
            dialog.destroy()

        ctk.CTkButton(dialog, text="✅  Confirmar", command=confirm,
                      fg_color="#1e3a5f", hover_color="#2c5282").pack(pady=14)

    def _scan(self):
        if not self._need_interface():
            return
        self._insert_text("\n" + "─" * 60 + "\n", "cyan")
        self._run_task(self.tool.scan_access_points)

    def _show_ap_list(self):
        if not self.tool.access_points:
            messagebox.showinfo("APs", "Nenhum AP encontrado.\nExecute o scan primeiro.")
            return
        self._open_ap_table(select_mode=False)

    def _select_ap(self):
        if not self.tool.access_points:
            messagebox.showinfo("APs", "Nenhum AP encontrado.\nExecute o scan primeiro.")
            return
        self._open_ap_table(select_mode=True)

    def _open_ap_table(self, select_mode=False):
        title = f"APs Encontrados — {len(self.tool.access_points)} redes"
        win = ctk.CTkToplevel(self.root)
        win.title(title)
        win.geometry("960x480")
        win.grab_set()
        win.lift()

        ctk.CTkLabel(
            win, text=title,
            font=ctk.CTkFont(size=14, weight="bold"), text_color="#00d4ff"
        ).pack(pady=(12, 4))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("AP.Treeview",
                        background="#0d1b2a", foreground="#e2e8f0",
                        fieldbackground="#0d1b2a", rowheight=26,
                        font=("Courier New", 10))
        style.configure("AP.Treeview.Heading",
                        background="#1e3a5f", foreground="#00d4ff",
                        font=("Courier New", 10, "bold"))
        style.map("AP.Treeview",
                  background=[("selected", "#2c5282")],
                  foreground=[("selected", "#ffffff")])

        cols = ("#", "BSSID", "SSID", "Fabricante", "Canal", "Sinal (dBm)", "WPS")
        tree = ttk.Treeview(win, columns=cols, show="headings",
                            style="AP.Treeview", height=14)

        col_widths = [35, 145, 200, 130, 60, 100, 100]
        for col, w in zip(cols, col_widths):
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor="center", stretch=False)
        tree.column("SSID", anchor="w", stretch=True)

        for i, ap in enumerate(self.tool.access_points):
            wps_text = "✅ Ativo" if not ap.wps_locked else "🔒 Bloqueado"
            tag = "wps_on" if not ap.wps_locked else "wps_off"
            tree.insert("", "end", iid=str(i),
                        values=(i + 1, ap.bssid, ap.ssid,
                                ap.manufacturer, ap.channel, ap.signal, wps_text),
                        tags=(tag,))

        tree.tag_configure("wps_on",  foreground="#22c55e")
        tree.tag_configure("wps_off", foreground="#ef4444")

        vsb = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y", padx=(0, 8))
        tree.pack(fill="both", expand=True, padx=8)

        if select_mode:
            def do_select():
                sel = tree.selection()
                if not sel:
                    messagebox.showwarning("Seleção", "Selecione um AP na tabela.", parent=win)
                    return
                idx = int(sel[0])
                ap = self.tool.access_points[idx]
                self.tool.selected_ap = ap
                self._update_statusbar()
                self._insert_text(f"\n[+] AP selecionado: {ap.ssid}  ({ap.bssid})\n", "green")
                win.destroy()

            ctk.CTkButton(win, text="🎯  Selecionar AP",
                          command=do_select, fg_color="#1e3a5f").pack(pady=10)
        else:
            ctk.CTkButton(win, text="Fechar", command=win.destroy,
                          fg_color="#374151").pack(pady=10)

    def _security_analysis(self):
        if not self._need_ap():
            return
        self._run_task(self.tool.analyze_network_security, self.tool.selected_ap)

    def _default_creds(self):
        if not self._need_ap():
            return
        self._run_task(self.tool.check_default_credentials, self.tool.selected_ap)

    def _password_test(self):
        password = simpledialog.askstring(
            "Teste de Força de Senha",
            "Digite a senha para analisar:",
            parent=self.root
        )
        if not password:
            return

        original_input = builtins.input

        def run():
            builtins.input = lambda _prompt="": password
            try:
                self.tool.password_strength_test()
            finally:
                builtins.input = original_input

        self._run_task(run)

    def _wps_brute(self):
        if not self._need_ap():
            return
        ap = self.tool.selected_ap
        if not messagebox.askyesno("Confirmar", f"Iniciar Brute Force WPS em:\n\n{ap.ssid}  ({ap.bssid})"):
            return
        self._run_task(self.tool.brute_force_wps, ap)

    def _pixie_dust(self):
        if not self._need_ap():
            return
        self._run_task(self.tool.pixie_dust_attack, self.tool.selected_ap)

    def _dict_attack(self):
        if not self._need_ap():
            return
        wordlist = filedialog.askopenfilename(
            title="Selecionar Wordlist (opcional — cancele para usar padrão)",
            filetypes=[("Arquivos de Texto", "*.txt"), ("Todos", "*.*")]
        )
        self._run_task(self.tool.dictionary_attack, self.tool.selected_ap,
                       wordlist if wordlist else None)

    def _scan_clients(self):
        if not self._need_ap():
            return
        duration = simpledialog.askinteger(
            "Duração", "Duração do scan (segundos):",
            initialvalue=30, minvalue=5, maxvalue=300, parent=self.root
        )
        if duration:
            self._run_task(self.tool.scan_clients, self.tool.selected_ap, duration)

    def _deauth(self):
        if not self._need_ap():
            return
        client = simpledialog.askstring(
            "Desautenticação",
            "MAC do cliente alvo:\n(deixe vazio para broadcast — todos os clientes)",
            parent=self.root
        )
        count = simpledialog.askinteger(
            "Pacotes", "Número de pacotes a enviar:",
            initialvalue=100, minvalue=1, maxvalue=10000, parent=self.root
        )
        if count is None:
            return
        client_mac = client.strip() if client and client.strip() else None
        self._run_task(self.tool.deauth_attack, self.tool.selected_ap, client_mac, count)

    def _traffic_analyzer(self):
        if not self._need_interface():
            return
        duration = simpledialog.askinteger(
            "Duração", "Duração da captura (segundos):",
            initialvalue=60, minvalue=5, maxvalue=600, parent=self.root
        )
        if duration:
            self._run_task(self.tool.network_traffic_analyzer,
                           self.tool.selected_ap, duration, False)

    def _discover_devices(self):
        network = simpledialog.askstring(
            "Rede Alvo",
            "Rede para escanear (ex: 192.168.1.0/24)\n(deixe vazio para detecção automática):",
            parent=self.root
        )
        self._run_task(self.tool.discover_network_devices,
                       network.strip() if network and network.strip() else None)

    def _clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.configure(state="disabled")
        self._print_welcome()


def main():
    WaircutGUI()


if __name__ == "__main__":
    main()
