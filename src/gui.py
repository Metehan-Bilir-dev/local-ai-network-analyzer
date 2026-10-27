import os
import platform
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox, ttk, font as tkfont

import core
from main import SCAN_PROFILES

SEV_COLORS = {
    "critical": "#8b0000",
    "high": "#c62828",
    "medium": "#e65100",
    "low": "#2e7d32",
}

class AutoScrollbar(ttk.Scrollbar):
    def set(self, lo, hi):
        try:
            if float(lo) <= 0.0 and float(hi) >= 1.0:
                self.grid_remove()
            else:
                self.grid()
            super().set(lo, hi)
        except Exception:
            pass

class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Yerel Ağ Zafiyet Analiz Aracı")
        self.geometry("1200x780")
        self.minsize(950, 650)
        self.is_dark = True
        self.queue = queue.Queue()
        self.rows = {}
        self.pdf_path = None
        
        self._set_modern_font()
        self._build()
        self.apply_theme()
        self.after(100, self._poll)

    def _set_modern_font(self):
        font_family = "Segoe UI" if platform.system() == "Windows" else "Helvetica"
        
        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(family=font_family, size=10)
        text_font = tkfont.nametofont("TkTextFont")
        text_font.configure(family=font_family, size=10)
        heading_font = tkfont.nametofont("TkHeadingFont")
        heading_font.configure(family=font_family, size=10, weight="bold")

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self.btn_theme.config(text="☀️ Açık Tema" if self.is_dark else "🌙 Koyu Tema")
        self.apply_theme()

    def apply_theme(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        if self.is_dark:
            bg = "#1e1e1e"             
            fg = "#e0e0e0"             
            header_bg = "#252526"      
            panel_bg = "#252526"       
            input_bg = "#333333"       
            btn_bg = "#3e3e42"         
            btn_fg = "#ffffff"         
            btn_hover = "#505050"      
            accent = "#007acc"         
        else:
            bg = "#f3f3f3"
            fg = "#111111"
            header_bg = "#ffffff"
            panel_bg = "#ffffff"
            input_bg = "#ffffff"
            btn_bg = "#e1e1e1"
            btn_fg = "#000000"
            btn_hover = "#d1d1d1"
            accent = "#0078d7"

        self.configure(bg=bg)
        
        style.configure(".", background=bg, foreground=fg)
        style.configure("TFrame", background=bg)
        
        style.configure("Header.TFrame", background=header_bg)
        style.configure("Header.TLabel", background=header_bg, foreground=accent)
        style.configure("Panel.TFrame", background=panel_bg)
        
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("Panel.TLabel", background=panel_bg, foreground=fg)
        
        style.configure("TCheckbutton", background=panel_bg, foreground=fg, focuscolor=panel_bg)
        style.map("TCheckbutton", 
                  background=[("active", panel_bg), ("pressed", panel_bg)],
                  indicatorcolor=[("selected", accent)])

        style.configure("TButton", background=btn_bg, foreground=btn_fg, borderwidth=0, padding=6, focuscolor=bg)
        style.map("TButton", background=[("active", btn_hover)])
        style.configure("Accent.TButton", background=accent, foreground="#ffffff", borderwidth=0, padding=6)
        style.map("Accent.TButton", background=[("active", "#005a9e")])
        
        style.configure("TEntry", fieldbackground=input_bg, foreground=fg, borderwidth=0, padding=4)
        style.configure("TCombobox", fieldbackground=input_bg, background=btn_bg, foreground=fg, borderwidth=0, padding=4, arrowcolor=fg)
        style.map("TCombobox", fieldbackground=[("readonly", input_bg)], selectbackground=[("readonly", accent)])
        
        style.configure("Treeview", background=input_bg, fieldbackground=input_bg, foreground=fg, rowheight=32, borderwidth=0)
        style.map("Treeview", background=[("selected", accent)], foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background=btn_bg, foreground=btn_fg, borderwidth=0, padding=4)
        style.map("Treeview.Heading", background=[("active", btn_hover)])

        style.configure("Status.TLabel", background=btn_bg, foreground=fg)
        self.status_lbl.configure(style="Status.TLabel")

        base_opts = {
            "bg": input_bg, "fg": fg, 
            "selectbackground": accent, "selectforeground": "#ffffff", 
            "relief": "flat", "highlightthickness": 1, 
            "highlightcolor": accent, "highlightbackground": btn_bg
        }
        
        self.host_list.config(**base_opts)
        
        text_opts = base_opts.copy()
        text_opts["insertbackground"] = fg
        self.details.config(**text_opts)
        
        self.header_frame.configure(style="Header.TFrame")
        self.title_lbl.configure(style="Header.TLabel")

        for widget in [self.left_frame, self.right_frame]:
            widget.configure(style="Panel.TFrame")
            for child in widget.winfo_children():
                if isinstance(child, ttk.Label):
                    child.configure(style="Panel.TLabel")

    # ---------- Arayüz ----------
    def _build(self):
        self.header_frame = ttk.Frame(self, height=65)
        self.header_frame.pack(fill="x", side="top")
        
        self.title_lbl = ttk.Label(self.header_frame, text="Yerel Ağ Zafiyet Analizi", font=("", 16, "bold"))
        self.title_lbl.pack(side="left", padx=24, pady=16)
        
        self.btn_theme = ttk.Button(self.header_frame, text="☀️ Açık Tema", command=self.toggle_theme)
        self.btn_theme.pack(side="right", padx=24, pady=16)

        self.status_var = tk.StringVar(value="Hazır.")
        self.status_lbl = ttk.Label(self, textvariable=self.status_var, padding=(12, 8))
        self.status_lbl.pack(side="bottom", fill="x")

        main = ttk.Frame(self, padding=24)
        main.pack(fill="both", expand=True)

        # GÜNCELLEME: Sol panel genişliği biraz artırıldı
        self.left_frame = ttk.Frame(main, width=350, padding=16)
        self.left_frame.pack(side="left", fill="y", padx=(0, 24))

        ttk.Label(self.left_frame, text="Alt Ağ (Boşsa otomatik)").pack(anchor="w")
        self.subnet_var = tk.StringVar()
        ttk.Entry(self.left_frame, textvariable=self.subnet_var).pack(fill="x", pady=(4, 12))

        self.btn_discover = ttk.Button(self.left_frame, text="Cihazları Bul", command=self.on_discover)
        self.btn_discover.pack(fill="x", pady=(0, 16))

        host_frame = ttk.Frame(self.left_frame)
        host_frame.pack(fill="both", expand=True, pady=(0, 16))
        host_frame.rowconfigure(0, weight=1)
        host_frame.columnconfigure(0, weight=1)
        
        # GÜNCELLEME: Listbox genişletildi (width=35) ve Yatay Kaydırma Çubuğu eklendi
        self.host_list = tk.Listbox(host_frame, exportselection=False, width=35)
        host_scroll_y = AutoScrollbar(host_frame, orient="vertical", command=self.host_list.yview)
        host_scroll_x = AutoScrollbar(host_frame, orient="horizontal", command=self.host_list.xview)
        self.host_list.configure(yscrollcommand=host_scroll_y.set, xscrollcommand=host_scroll_x.set)
        
        self.host_list.grid(row=0, column=0, sticky="nsew")
        host_scroll_y.grid(row=0, column=1, sticky="ns")
        host_scroll_x.grid(row=1, column=0, sticky="ew")
        
        self.host_list.bind("<<ListboxSelect>>", self._on_host_select)
        self.hosts = []

        ttk.Label(self.left_frame, text="Hedef IP").pack(anchor="w")
        self.target_var = tk.StringVar()
        ttk.Entry(self.left_frame, textvariable=self.target_var).pack(fill="x", pady=(4, 12))

        ttk.Label(self.left_frame, text="Tarama Tipi").pack(anchor="w")
        self.profile_var = tk.StringVar()
        values = [f"{k}. {v['label']}" for k, v in SCAN_PROFILES.items()]
        combo = ttk.Combobox(self.left_frame, textvariable=self.profile_var, values=values, state="readonly")
        combo.current(1)
        combo.pack(fill="x", pady=(4, 16))

        self.cve_var = tk.BooleanVar(value=True)
        self.ai_var = tk.BooleanVar(value=True)
        self.pdf_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.left_frame, text="NVD'de CVE Ara", variable=self.cve_var).pack(anchor="w", pady=2)
        ttk.Checkbutton(self.left_frame, text="Yapay Zeka (AI) Analizi", variable=self.ai_var).pack(anchor="w", pady=2)
        ttk.Checkbutton(self.left_frame, text="PDF Rapor Oluştur", variable=self.pdf_var).pack(anchor="w", pady=(2, 20))

        self.btn_start = ttk.Button(self.left_frame, text="Taramayı Başlat", style="Accent.TButton", command=self.on_start)
        self.btn_start.pack(fill="x", pady=(0, 12))

        self.btn_pdf = ttk.Button(self.left_frame, text="PDF'i Aç", command=self.on_open_pdf, state="disabled")
        self.btn_pdf.pack(fill="x", pady=(0, 12))

        self.progress = ttk.Progressbar(self.left_frame, mode="indeterminate")
        self.progress.pack(fill="x")

        self.right_frame = ttk.Frame(main, padding=16)
        self.right_frame.pack(side="left", fill="both", expand=True)

        self.summary_var = tk.StringVar(value="Henüz tarama yapılmadı.")
        ttk.Label(self.right_frame, textvariable=self.summary_var, wraplength=720, justify="left").pack(
            anchor="w", pady=(0, 16)
        )

        table_frame = ttk.Frame(self.right_frame)
        table_frame.pack(fill="both", expand=True, pady=(0, 16))
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        cols = ("port", "servis", "yazilim", "onem")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=12)
        
        # GÜNCELLEME: Sütun genişlikleri daraltıldı (Port: 80, Servis: 100, Önem: 90)
        for col, title, width in [
            ("port", "Port", 80),
            ("servis", "Servis", 100),
            ("yazilim", "Yazılım / Sürüm", 350),
            ("onem", "Önem", 90),
        ]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
            
        for sev, color in SEV_COLORS.items():
            self.tree.tag_configure(sev, background=color, foreground="white")
            
        scroll = AutoScrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<<TreeviewSelect>>", self._show_details)

        ttk.Label(self.right_frame, text="Ayrıntılar", font=("", 11, "bold")).pack(anchor="w", pady=(0, 6))
        # GÜNCELLEME: Ayrıntılar kutusu height=8 olarak küçültüldü
        self.details = tk.Text(self.right_frame, height=8, wrap="word", state="disabled")
        self.details.pack(fill="both", expand=True)

    # ---------- Yardımcılar ----------
    def _busy(self, flag, text=None):
        state = "disabled" if flag else "normal"
        self.btn_discover.config(state=state)
        self.btn_start.config(state=state)
        if flag:
            self.progress.start(12)
        else:
            self.progress.stop()
        if text:
            self.status_var.set(text)

    def _run(self, func):
        def worker():
            try:
                func()
            except SystemExit:
                self.queue.put(("error", "Nmap bulunamadı veya başlatılamadı."))
            except Exception as e:
                self.queue.put(("error", str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _poll(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                getattr(self, f"_on_{kind}")(payload)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _set_details(self, text):
        self.details.config(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.config(state="disabled")

    # ---------- Olaylar ----------
    def on_discover(self):
        subnet = self.subnet_var.get().strip() or None
        self._busy(True, "Ağ taranıyor...")
        def job():
            self.queue.put(("hosts", core.discover(subnet)))
        self._run(job)

    def _on_hosts(self, hosts):
        self.hosts = hosts
        self.host_list.delete(0, "end")
        for h in hosts:
            self.host_list.insert("end", f"{h['ip']}  ({h['hostname']})")
        self._busy(False, f"{len(hosts)} cihaz bulundu.")

    def _on_host_select(self, _event=None):
        sel = self.host_list.curselection()
        if sel:
            self.target_var.set(self.hosts[sel[0]]["ip"])

    def on_start(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Hedef Yok", "Önce bir cihaz seç ya da hedef IP gir.")
            return

        key = self.profile_var.get().split(".")[0]
        if key == "4" and hasattr(os, "geteuid") and os.geteuid() != 0:
            messagebox.showwarning(
                "Root Gerekli",
                "Kapsamlı Tarama (OS tespiti) root yetkisi ister.\n"
                "Başka bir tarama tipi seç ya da sudo ile çalıştır."
            )
            return

        use_cve = self.cve_var.get()
        use_ai = self.ai_var.get()
        make_pdf = self.pdf_var.get()

        self.btn_pdf.config(state="disabled")
        self.pdf_path = None
        self._busy(True, "Tarama başlıyor...")

        def job():
            self.queue.put(("status", "Nmap taraması çalışıyor..."))
            parsed = core.scan(target, key)

            if use_cve:
                self.queue.put(("status", "NVD sorgulanıyor..."))
                core.add_cves(parsed)

            ai_result, removed, ai_err = None, 0, None
            if use_ai:
                self.queue.put(("status", "Yerel model analiz ediyor..."))
                ai_result, removed, ai_err = core.analyze(parsed)

            self.queue.put(("status", "Sonuçlar kaydediliyor..."))
            paths = core.save(parsed, ai_result, make_pdf)

            self.queue.put(
                ("done", {
                        "parsed": parsed,
                        "ai": ai_result,
                        "removed": removed,
                        "ai_err": ai_err,
                        "paths": paths,
                })
            )

        self._run(job)

    def _on_status(self, text):
        self.status_var.set(text)

    def _on_error(self, message):
        self._busy(False, "Hata oluştu.")
        messagebox.showerror("Hata", message)

    def _on_done(self, result):
        parsed = result["parsed"]
        ai_result = result["ai"]
        paths = result["paths"]

        self._fill_results(parsed, ai_result)

        notes = []
        if ai_result:
            notes.append(ai_result.get("summary", ""))
        elif result["ai_err"]:
            notes.append(f"AI analizi yapılamadı: {result['ai_err']}")
        else:
            notes.append("AI analizi yapılmadı.")
        if result["removed"]:
            notes.append(f"{result['removed']} doğrulanamayan CVE numarası çıkarıldı.")
        if not any(p.get("script_output") for h in parsed["hosts"] for p in h["ports"]):
            notes.append("Zafiyet script'leri çalıştırılmadı; bu 'zafiyet yok' anlamına gelmez.")
        self.summary_var.set(" ".join(n for n in notes if n))

        if "pdf" in paths:
            self.pdf_path = paths["pdf"]
            self.btn_pdf.config(state="normal")

        self._busy(False, f"Tamamlandı. Kaydedildi: {paths['scan']}")

    def _fill_results(self, parsed, ai_result):
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        self._set_details("")

        findings = {f.get("port"): f for f in (ai_result or {}).get("findings", [])}
        for host in parsed["hosts"]:
            for p in host["ports"]:
                f = findings.get(p["port"])
                sev = str(f.get("severity", "")).lower() if f else ""
                software = f"{p.get('product') or ''} {p.get('version') or ''}".strip()
                iid = self.tree.insert(
                    "", "end",
                    values=(
                        f"{p['port']}/{p['protocol']}",
                        p.get("service") or "",
                        software,
                        sev.upper() if sev else "-",
                    ),
                    tags=(sev,) if sev in SEV_COLORS else (),
                )
                self.rows[iid] = (host["host"], p, f)

        if not self.rows:
            self._set_details("Açık port bulunamadı (firewall filtreliyor olabilir).")

    def _show_details(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        host, p, f = self.rows[sel[0]]

        lines = [f"{host} Port {p['port']}/{p['protocol']}  ({p.get('service') or ''})", ""]
        
        for r in p.get("rule_findings", []):
            lines.append(f"[KURAL] {r}")
        cves = p.get("cves", [])
        if cves:
            lines.append("NVD eşleşmeleri: " + ", ".join(f"{c['id']} (CVSS {c['cvss']})" for c in cves))
        if f:
            lines.append(f"Sebep: {f.get('reason', '')}")
            lines.append(f"Öneri: {f.get('recommendation', '')}")
        self._set_details("\n".join(lines))

    def on_open_pdf(self):
        if self.pdf_path and os.path.exists(self.pdf_path):
            if platform.system() == 'Windows':
                os.startfile(self.pdf_path)
            elif platform.system() == 'Darwin':
                subprocess.Popen(["open", self.pdf_path])
            else:
                subprocess.Popen(["xdg-open", self.pdf_path])


if __name__ == "__main__":
    App().mainloop()