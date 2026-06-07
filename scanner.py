import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import socket
import threading
import queue
import datetime
import os


# ─────────────────────────────────────────────────────────────
#  SERVICE MAP  —  Common TCP port → service name
# ─────────────────────────────────────────────────────────────

SERVICE_MAP = {
    21: "FTP",            22: "SSH",             23: "Telnet",
    25: "SMTP",           53: "DNS",             67: "DHCP",
    68: "DHCP",           69: "TFTP",            80: "HTTP",
    110: "POP3",          119: "NNTP",           123: "NTP",
    135: "MS-RPC",        137: "NetBIOS",        138: "NetBIOS",
    139: "NetBIOS",       143: "IMAP",           161: "SNMP",
    194: "IRC",           389: "LDAP",           443: "HTTPS",
    445: "SMB",           465: "SMTPS",          514: "Syslog",
    587: "SMTP (Sub)",    631: "IPP",            636: "LDAPS",
    993: "IMAPS",         995: "POP3S",          1080: "SOCKS Proxy",
    1194: "OpenVPN",      1433: "MSSQL",         1521: "Oracle DB",
    1723: "PPTP VPN",     2049: "NFS",           2083: "cPanel SSL",
    2086: "WHM",          2087: "WHM SSL",       2222: "SSH (Alt)",
    3000: "Node.js Dev",  3306: "MySQL",         3389: "RDP",
    3690: "SVN",          4000: "Dev Server",    4443: "HTTPS (Alt)",
    5000: "Flask Dev",    5432: "PostgreSQL",    5900: "VNC",
    5984: "CouchDB",      6379: "Redis",         6443: "Kubernetes API",
    7070: "RTSP",         8000: "HTTP (Alt)",    8008: "HTTP (Alt)",
    8080: "HTTP Proxy",   8443: "HTTPS (Alt)",   8888: "Jupyter",
    9000: "SonarQube",    9090: "Prometheus",    9200: "Elasticsearch",
    9300: "ES Cluster",   10000: "Webmin",       11211: "Memcached",
    27017: "MongoDB",     27018: "MongoDB",      50000: "SAP",
}

# Port reference data for the About page (port, service, description)
PORT_REFERENCE = [
    (21,   "FTP",        "File Transfer Protocol — uploads/downloads files between systems"),
    (22,   "SSH",        "Secure Shell — encrypted remote login and command execution"),
    (23,   "Telnet",     "Unencrypted remote login — largely replaced by SSH"),
    (25,   "SMTP",       "Simple Mail Transfer Protocol — sends outgoing email"),
    (53,   "DNS",        "Domain Name System — translates domain names to IP addresses"),
    (80,   "HTTP",       "HyperText Transfer Protocol — standard unencrypted web traffic"),
    (110,  "POP3",       "Post Office Protocol — downloads email from a mail server"),
    (143,  "IMAP",       "Internet Message Access Protocol — accesses email on server"),
    (443,  "HTTPS",      "HTTP Secure — encrypted web traffic using TLS/SSL"),
    (445,  "SMB",        "Server Message Block — Windows file and printer sharing"),
    (3306, "MySQL",      "MySQL database server default port"),
    (3389, "RDP",        "Remote Desktop Protocol — Windows remote desktop access"),
    (5432, "PostgreSQL", "PostgreSQL relational database server"),
    (5900, "VNC",        "Virtual Network Computing — graphical remote desktop"),
    (6379, "Redis",      "Redis in-memory data store / cache server"),
    (8080, "HTTP Proxy", "Common alternative HTTP port used by proxies and dev servers"),
    (8888, "Jupyter",    "Jupyter Notebook — interactive Python environment"),
    (27017,"MongoDB",    "MongoDB NoSQL database server"),
]


# ─────────────────────────────────────────────────────────────
#  PORT SCANNER ENGINE
# ─────────────────────────────────────────────────────────────

class PortScanner:
    """
    Multi-threaded TCP port scanner.
    Scans a range of ports on a target host and reports open ones.
    """

    def __init__(self, target, start_port, end_port,
                 result_callback, done_callback,
                 timeout=0.5, max_threads=150):
        self.target        = target
        self.start_port    = start_port
        self.end_port      = end_port
        self.result_cb     = result_callback
        self.done_cb       = done_callback
        self.timeout       = timeout
        self.max_threads   = max_threads
        self.open_ports    = []
        self.port_queue    = queue.Queue()
        self._stop_event   = threading.Event()

    def stop(self):
        """Signal all worker threads to stop."""
        self._stop_event.set()

    def _scan_port(self):
        """Worker thread: pull ports from queue and attempt TCP connection."""
        while not self._stop_event.is_set():
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    if sock.connect_ex((self.target, port)) == 0:
                        service = SERVICE_MAP.get(port, "Unknown")
                        self.open_ports.append((port, service))
                        self.result_cb(port, service)
            except Exception:
                pass
            finally:
                self.port_queue.task_done()

    def run(self):
        """Fill the queue, spin up threads, wait for completion."""
        for port in range(self.start_port, self.end_port + 1):
            self.port_queue.put(port)

        thread_count = min(self.max_threads, self.end_port - self.start_port + 1)
        threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=self._scan_port, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        self.done_cb(self.open_ports)

    def start(self):
        """Launch the scanner in a background thread."""
        threading.Thread(target=self.run, daemon=True).start()


# ─────────────────────────────────────────────────────────────
#  REPORT WRITER
# ─────────────────────────────────────────────────────────────

def save_report(target_ip, target_host, start_port, end_port, open_ports):
    """Generate a professional PDF scan report using fpdf2."""
    from fpdf import FPDF

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename  = "scan_report.pdf"

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Header banner ──────────────────────────────────────
    pdf.set_fill_color(0, 51, 102)
    pdf.rect(0, 0, 210, 32, style="F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_y(7)
    pdf.cell(0, 10, "NETWORK SCANNER", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, "TCP Port Scanning & Service Detection Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)

    # ── Scan summary card ──────────────────────────────────
    summary_y = pdf.get_y()
    pdf.set_fill_color(244, 248, 252)
    pdf.set_draw_color(208, 221, 232)
    pdf.rect(10, summary_y, 190, 46, style="FD")
    pdf.set_text_color(0, 51, 102)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_x(14)
    pdf.cell(0, 8, "Scan Summary", new_x="LMARGIN", new_y="NEXT")
    details = [
        ("Date / Time", timestamp),
        ("Target Host", target_host),
        ("Resolved IP", target_ip),
        ("Port Range",  f"{start_port} - {end_port}"),
        ("Open Ports",  str(len(open_ports))),
    ]
    pdf.set_font("Helvetica", "", 10)
    for label, value in details:
        pdf.set_text_color(90, 122, 153)
        pdf.set_x(14)
        pdf.cell(36, 7, f"{label}:", new_x="RIGHT", new_y="LAST")
        pdf.set_text_color(30, 30, 46)
        pdf.cell(0, 7, value, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # ── Results table ──────────────────────────────────────
    pdf.set_text_color(0, 51, 102)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Open Ports", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    # Table header row
    pdf.set_fill_color(0, 120, 215)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_x(10)
    pdf.cell(30, 9, "Port",    fill=True)
    pdf.cell(55, 9, "Service", fill=True)
    pdf.cell(85, 9, "Status",  fill=True)
    pdf.ln()

    # Table data rows
    if open_ports:
        for i, (port, svc) in enumerate(sorted(open_ports)):
            row_fill = (240, 245, 251) if i % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*row_fill)
            pdf.set_x(10)
            pdf.set_text_color(0, 120, 215)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(30, 8, str(port), fill=True)
            pdf.set_text_color(0, 51, 102)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(55, 8, svc, fill=True)
            pdf.set_text_color(12, 124, 63)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(85, 8, "OPEN", fill=True)
            pdf.ln()
    else:
        pdf.set_text_color(90, 122, 153)
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_x(10)
        pdf.cell(0, 9, "No open ports found in the specified range.", new_x="LMARGIN", new_y="NEXT")

    # ── Footer ─────────────────────────────────────────────
    pdf.ln(10)
    pdf.set_draw_color(208, 221, 232)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    pdf.set_text_color(90, 122, 153)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(0, 5, "Generated by Network Scanner v1.0  |  Developed by Adish VC", align="C")

    pdf.output(filename)
    return filename


# ─────────────────────────────────────────────────────────────
#  MAIN APPLICATION
# ─────────────────────────────────────────────────────────────

class NetworkScannerApp:
    """
    Main Tkinter application.
    Manages three pages: Home, Scanner, and About.
    """

    # Colour palette
    CLR_BG         = "#FFFFFF"
    CLR_PRIMARY    = "#003366"
    CLR_ACCENT     = "#0078D7"
    CLR_ACCENT_HVR = "#005A9E"
    CLR_SUBTLE     = "#F4F8FC"
    CLR_BORDER     = "#D0DDE8"
    CLR_TEXT_MUTED = "#5A7A99"
    CLR_SUCCESS    = "#0C7C3F"
    CLR_RESULT_BG  = "#F0F5FB"

    def __init__(self, root):
        self.root         = root
        self.scanner      = None
        self.scan_running = False
        self.open_ports   = []
        self.resolved_ip  = ""
        self.target_host  = ""

        self._setup_window()
        self._build_home_page()
        self._build_scanner_page()
        self._build_about_page()
        self._show_home()


    # ── Window setup ──────────────────────────────────────────

    def _setup_window(self):
        self.root.title("Network Scanner  v1.0")
        self.root.state("zoomed")
        self.sw = self.root.winfo_screenwidth()
        self.sh = self.root.winfo_screenheight()


    # ── Page navigation ───────────────────────────────────────

    def _show_home(self):
        self.scanner_frame.pack_forget()
        self.about_frame.pack_forget()
        self.home_frame.pack(fill="both", expand=True)

    def _show_scanner(self):
        self.home_frame.pack_forget()
        self.about_frame.pack_forget()
        self.scanner_frame.pack(fill="both", expand=True)

    def _show_about(self):
        self.home_frame.pack_forget()
        self.scanner_frame.pack_forget()
        self.about_frame.pack(fill="both", expand=True)
        self._switch_about_tab("app")       # always open on first tab


    # ── Shared utility helpers ────────────────────────────────

    def _bind_hover(self, widget, hover_bg, normal_bg, hover_fg, normal_fg):
        widget.bind("<Enter>", lambda e: widget.configure(bg=hover_bg, fg=hover_fg))
        widget.bind("<Leave>", lambda e: widget.configure(bg=normal_bg, fg=normal_fg))

    def _make_entry(self, parent, width=20):
        return tk.Entry(
            parent,
            width=width,
            font=("Segoe UI", 11),
            relief="solid",
            bd=1,
            bg="white",
            fg="#1A1A2E",
            insertbackground=self.CLR_ACCENT
        )

    def _set_status(self, msg):
        self.status_var.set(msg)


    # ─────────────────────────────────────────────────────────
    #  HOME PAGE
    # ─────────────────────────────────────────────────────────

    def _build_home_page(self):
        self.home_frame = tk.Frame(self.root)
        self.home_frame.pack(fill="both", expand=True)

        # Background image
        try:
            img = Image.open("assets/background1.jpg")
            img = img.resize((self.sw, self.sh), Image.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(img)
            bg_label = tk.Label(self.home_frame, image=self.bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except Exception:
            self.home_frame.configure(bg="#0B1E33")

        # Content card — sits on top of the background image
        card = tk.Frame(
            self.home_frame,
            bg="#0D2137",
            bd=0,
            highlightthickness=2,
            highlightbackground="#1A5276"
        )
        card.place(relx=0.5, rely=0.38, anchor="center", width=620, height=400)

        # Thin blue accent stripe at top of card
        tk.Frame(card, bg="#0078D7", height=4).pack(fill="x", side="top")

        # App title
        tk.Label(
            card,
            text="NETWORK SCANNER",
            font=("Segoe UI", 34, "bold"),
            bg="#0D2137",
            fg="#FFFFFF"
        ).pack(pady=(22, 2))

        # Subtitle
        tk.Label(
            card,
            text="Fast Multi-Threaded TCP Port Scanner",
            font=("Segoe UI", 13),
            bg="#0D2137",
            fg="#7EB8E8"
        ).pack(pady=(0, 12))

        # Horizontal divider
        tk.Frame(card, bg="#1A5276", height=1).pack(fill="x", padx=40, pady=(0, 14))

        # Description
        tk.Label(
            card,
            text=(
                "Discover open TCP ports, identify network services,\n"
                "and generate professional scan reports."
            ),
            font=("Segoe UI", 11),
            bg="#0D2137",
            fg="#A8C8E8",
            justify="center"
        ).pack(pady=(0, 14))

        # Feature checklist
        features = [
            "✓  Multi-threaded Scanning",
            "✓  Service Detection",
            "✓  Port Range Selection",
            "✓  Report Generation",
            "✓  Beginner Friendly",
        ]
        feat_frame = tk.Frame(card, bg="#0D2137")
        feat_frame.pack()
        for i, feat in enumerate(features):
            tk.Label(
                feat_frame,
                text=feat,
                font=("Segoe UI", 10, "bold"),
                bg="#0D2137",
                fg="#4EC9B0",
                anchor="w",
                width=28
            ).grid(row=i // 2, column=i % 2, sticky="w", padx=10, pady=2)

        # START SCANNING button
        self.start_btn = tk.Button(
            self.home_frame,
            text="▶   START SCANNING",
            font=("Segoe UI", 13, "bold"),
            bg="#0078D7",
            fg="white",
            width=24,
            height=2,
            bd=0,
            cursor="hand2",
            activebackground="#005A9E",
            activeforeground="white",
            command=self._show_scanner
        )
        self.start_btn.place(relx=0.5, rely=0.70, anchor="center")
        self._bind_hover(self.start_btn, "#005A9E", "#0078D7", "white", "white")

        # ABOUT button
        about_btn = tk.Button(
            self.home_frame,
            text="ℹ   ABOUT",
            font=("Segoe UI", 11),
            bg="#1A3A5C",
            fg="#7EB8E8",
            width=18,
            height=2,
            bd=0,
            cursor="hand2",
            activebackground="#0D2137",
            activeforeground="white",
            command=self._show_about
        )
        about_btn.place(relx=0.5, rely=0.79, anchor="center")
        self._bind_hover(about_btn, "#0D2137", "#1A3A5C", "white", "#7EB8E8")

        # Footer — two small floating labels directly over the background image
        tk.Label(
            self.home_frame,
            text="Developed by Adish VC",
            font=("Segoe UI", 9, "bold"),
            bg="#0D2137",
            fg="#7EB8E8",
            padx=10,
            pady=3
        ).place(relx=0.5, rely=0.955, anchor="center")

        tk.Label(
            self.home_frame,
            text="v1.0",
            font=("Segoe UI", 8),
            bg="#0D2137",
            fg="#3A6A99",
            padx=8,
            pady=2
        ).place(relx=0.5, rely=0.983, anchor="center")


    # ─────────────────────────────────────────────────────────
    #  SCANNER PAGE
    # ─────────────────────────────────────────────────────────

    def _build_scanner_page(self):
        self.scanner_frame = tk.Frame(self.root, bg=self.CLR_BG)

        # ── Top header bar ────────────────────────────────────
        header = tk.Frame(self.scanner_frame, bg=self.CLR_PRIMARY, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="🛡  NETWORK SCANNER",
            font=("Segoe UI", 18, "bold"),
            bg=self.CLR_PRIMARY,
            fg="white"
        ).pack(side="left", padx=30, pady=14)

        tk.Label(
            header,
            text="TCP Port Scanning & Service Detection",
            font=("Segoe UI", 10),
            bg=self.CLR_PRIMARY,
            fg="#7EB8E8"
        ).pack(side="left", pady=18)

        home_btn = tk.Button(
            header,
            text="⌂  HOME",
            font=("Segoe UI", 10, "bold"),
            bg="#1A4A7A",
            fg="white",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
            activebackground="#0078D7",
            activeforeground="white",
            command=self._go_home_safe
        )
        home_btn.pack(side="right", padx=20, pady=14)
        self._bind_hover(home_btn, "#0078D7", "#1A4A7A", "white", "white")

        # ── Input card ────────────────────────────────────────
        input_card = tk.Frame(
            self.scanner_frame,
            bg=self.CLR_SUBTLE,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.CLR_BORDER
        )
        input_card.pack(fill="x", padx=40, pady=20)

        inner = tk.Frame(input_card, bg=self.CLR_SUBTLE)
        inner.pack(pady=22, padx=30)

        # Column labels
        for col, label_text in enumerate(["Target Host / IP", "Start Port", "End Port"]):
            tk.Label(
                inner,
                text=label_text,
                font=("Segoe UI", 10, "bold"),
                bg=self.CLR_SUBTLE,
                fg=self.CLR_PRIMARY
            ).grid(row=0, column=col, padx=14, sticky="w")

        # Target input with placeholder
        self.target_entry = self._make_entry(inner, width=36)
        self.target_entry.grid(row=1, column=0, padx=14, ipady=5)
        self.target_entry.insert(0, "e.g. 192.168.1.1 or scanme.nmap.org")
        self.target_entry.configure(fg="#AAAAAA")
        self.target_entry.bind("<FocusIn>",  self._clear_placeholder)
        self.target_entry.bind("<FocusOut>", self._restore_placeholder)

        # Start port input
        self.start_port_entry = self._make_entry(inner, width=12)
        self.start_port_entry.grid(row=1, column=1, padx=14, ipady=5)
        self.start_port_entry.insert(0, "1")

        # End port input
        self.end_port_entry = self._make_entry(inner, width=12)
        self.end_port_entry.grid(row=1, column=2, padx=14, ipady=5)
        self.end_port_entry.insert(0, "1024")

        # ── Action buttons ────────────────────────────────────
        btn_row = tk.Frame(input_card, bg=self.CLR_SUBTLE)
        btn_row.pack(pady=(0, 18))

        self.scan_btn = tk.Button(
            btn_row,
            text="▶  START SCAN",
            font=("Segoe UI", 11, "bold"),
            bg=self.CLR_ACCENT,
            fg="white",
            width=18,
            height=2,
            bd=0,
            cursor="hand2",
            activebackground=self.CLR_ACCENT_HVR,
            activeforeground="white",
            command=self._start_scan
        )
        self.scan_btn.grid(row=0, column=0, padx=10)
        self._bind_hover(self.scan_btn, self.CLR_ACCENT_HVR, self.CLR_ACCENT, "white", "white")

        self.stop_btn = tk.Button(
            btn_row,
            text="⏹  STOP",
            font=("Segoe UI", 11, "bold"),
            bg="#C0392B",
            fg="white",
            width=12,
            height=2,
            bd=0,
            cursor="hand2",
            state="disabled",
            activebackground="#962D22",
            activeforeground="white",
            command=self._stop_scan
        )
        self.stop_btn.grid(row=0, column=1, padx=10)

        self.save_btn = tk.Button(
            btn_row,
            text="💾  SAVE REPORT",
            font=("Segoe UI", 11, "bold"),
            bg="#0C7C3F",
            fg="white",
            width=16,
            height=2,
            bd=0,
            cursor="hand2",
            state="disabled",
            activebackground="#085F30",
            activeforeground="white",
            command=self._save_report
        )
        self.save_btn.grid(row=0, column=2, padx=10)

        # ── Status bar ────────────────────────────────────────
        status_bar = tk.Frame(
            self.scanner_frame,
            bg=self.CLR_SUBTLE,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.CLR_BORDER,
            height=36
        )
        status_bar.pack(fill="x", padx=40)
        status_bar.pack_propagate(False)

        self.status_var = tk.StringVar(
            value="Ready — Enter a target and port range, then press Start Scan."
        )
        tk.Label(
            status_bar,
            textvariable=self.status_var,
            font=("Segoe UI", 9),
            bg=self.CLR_SUBTLE,
            fg=self.CLR_TEXT_MUTED,
            anchor="w"
        ).pack(side="left", padx=14, pady=8)

        self.open_count_var = tk.StringVar(value="Open Ports: 0")
        tk.Label(
            status_bar,
            textvariable=self.open_count_var,
            font=("Segoe UI", 9, "bold"),
            bg=self.CLR_SUBTLE,
            fg=self.CLR_SUCCESS,
            anchor="e"
        ).pack(side="right", padx=14, pady=8)

        # ── Progress bar ──────────────────────────────────────
        self.progress_canvas = tk.Canvas(
            self.scanner_frame,
            height=6,
            bg=self.CLR_BORDER,
            highlightthickness=0
        )
        self.progress_canvas.pack(fill="x", padx=40, pady=(6, 0))

        # ── Results section header ────────────────────────────
        results_header = tk.Frame(self.scanner_frame, bg=self.CLR_BG)
        results_header.pack(fill="x", padx=40, pady=(16, 4))

        tk.Label(
            results_header,
            text="Scan Results",
            font=("Segoe UI", 14, "bold"),
            bg=self.CLR_BG,
            fg=self.CLR_PRIMARY
        ).pack(side="left")

        tk.Button(
            results_header,
            text="Clear",
            font=("Segoe UI", 9),
            bg=self.CLR_SUBTLE,
            fg=self.CLR_TEXT_MUTED,
            bd=0,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._clear_results
        ).pack(side="right")

        # ── Results text area ─────────────────────────────────
        txt_frame = tk.Frame(
            self.scanner_frame,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.CLR_BORDER
        )
        txt_frame.pack(fill="both", expand=True, padx=40, pady=(0, 20))

        self.results_box = tk.Text(
            txt_frame,
            font=("Consolas", 10),
            bg=self.CLR_RESULT_BG,
            fg="#1A1A2E",
            relief="flat",
            bd=0,
            padx=14,
            pady=10,
            wrap="word",
            state="disabled"
        )
        self.results_box.pack(side="left", fill="both", expand=True)

        scrollbar = tk.Scrollbar(txt_frame, command=self.results_box.yview)
        scrollbar.pack(side="right", fill="y")
        self.results_box.configure(yscrollcommand=scrollbar.set)

        # Text colour tags
        self.results_box.tag_configure("header",  foreground="#003366", font=("Consolas", 10, "bold"))
        self.results_box.tag_configure("open",    foreground="#0C7C3F", font=("Consolas", 10, "bold"))
        self.results_box.tag_configure("info",    foreground="#5A7A99")
        self.results_box.tag_configure("error",   foreground="#C0392B", font=("Consolas", 10, "bold"))
        self.results_box.tag_configure("summary", foreground="#0078D7", font=("Consolas", 10, "bold"))

        self._write_results_banner()


    # ─────────────────────────────────────────────────────────
    #  ABOUT PAGE
    # ─────────────────────────────────────────────────────────

    def _build_about_page(self):
        self.about_frame = tk.Frame(self.root, bg=self.CLR_BG)
        self._active_about_tab = None

        # ── Header bar (matches scanner page style) ───────────
        header = tk.Frame(self.about_frame, bg=self.CLR_PRIMARY, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="ℹ  ABOUT",
            font=("Segoe UI", 18, "bold"),
            bg=self.CLR_PRIMARY,
            fg="white"
        ).pack(side="left", padx=30, pady=14)

        tk.Label(
            header,
            text="Learn about Network Scanner and TCP/IP fundamentals",
            font=("Segoe UI", 10),
            bg=self.CLR_PRIMARY,
            fg="#7EB8E8"
        ).pack(side="left", pady=18)

        home_btn = tk.Button(
            header,
            text="⌂  HOME",
            font=("Segoe UI", 10, "bold"),
            bg="#1A4A7A",
            fg="white",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
            activebackground="#0078D7",
            activeforeground="white",
            command=self._show_home
        )
        home_btn.pack(side="right", padx=20, pady=14)
        self._bind_hover(home_btn, "#0078D7", "#1A4A7A", "white", "white")

        # ── Two-column layout: sidebar tabs + content area ────
        body = tk.Frame(self.about_frame, bg=self.CLR_BG)
        body.pack(fill="both", expand=True, padx=0, pady=0)

        # Left sidebar
        sidebar = tk.Frame(body, bg="#EAF1F8", width=210,
                           highlightthickness=1, highlightbackground=self.CLR_BORDER)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(
            sidebar,
            text="SECTIONS",
            font=("Segoe UI", 9, "bold"),
            bg="#EAF1F8",
            fg=self.CLR_TEXT_MUTED,
            anchor="w"
        ).pack(fill="x", padx=18, pady=(20, 8))

        # Tab definitions: (tab_id, icon, label, builder_method)
        tabs = [
            ("app",       "📋", "About the App"),
            ("howto",     "📖", "How to Use"),
            ("ports",     "🔌", "Common Port Numbers"),
            ("tcp",       "🌐", "What is TCP?"),
            ("faq",       "❓", "FAQ"),
        ]

        self._tab_buttons = {}
        for tab_id, icon, label in tabs:
            btn = tk.Button(
                sidebar,
                text=f"  {icon}  {label}",
                font=("Segoe UI", 10),
                bg="#EAF1F8",
                fg=self.CLR_PRIMARY,
                anchor="w",
                bd=0,
                padx=10,
                pady=10,
                cursor="hand2",
                activebackground="#D0E4F7",
                activeforeground=self.CLR_PRIMARY,
                command=lambda tid=tab_id: self._switch_about_tab(tid)
            )
            btn.pack(fill="x", padx=8, pady=2)
            self._tab_buttons[tab_id] = btn

        # Right content panel (scrollable)
        content_outer = tk.Frame(body, bg=self.CLR_BG)
        content_outer.pack(side="left", fill="both", expand=True)

        self.about_canvas = tk.Canvas(content_outer, bg=self.CLR_BG, highlightthickness=0)
        about_scroll = tk.Scrollbar(content_outer, orient="vertical", command=self.about_canvas.yview)
        self.about_canvas.configure(yscrollcommand=about_scroll.set)
        about_scroll.pack(side="right", fill="y")
        self.about_canvas.pack(side="left", fill="both", expand=True)

        self.about_content = tk.Frame(self.about_canvas, bg=self.CLR_BG)
        self._about_window = self.about_canvas.create_window(
            (0, 0), window=self.about_content, anchor="nw"
        )
        self.about_content.bind("<Configure>", self._on_about_resize)
        self.about_canvas.bind("<Configure>", self._on_canvas_resize)

        # Mouse-wheel scrolling
        self.about_canvas.bind_all("<MouseWheel>",
            lambda e: self.about_canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))


    def _on_about_resize(self, event):
        self.about_canvas.configure(scrollregion=self.about_canvas.bbox("all"))

    def _on_canvas_resize(self, event):
        self.about_canvas.itemconfig(self._about_window, width=event.width)


    def _switch_about_tab(self, tab_id):
        """Clear content area and render the selected tab."""
        # Highlight active tab button
        for tid, btn in self._tab_buttons.items():
            if tid == tab_id:
                btn.configure(bg="#D0E4F7", fg=self.CLR_ACCENT, font=("Segoe UI", 10, "bold"))
            else:
                btn.configure(bg="#EAF1F8", fg=self.CLR_PRIMARY, font=("Segoe UI", 10))

        # Clear current content
        for widget in self.about_content.winfo_children():
            widget.destroy()

        # Render selected tab
        builders = {
            "app":   self._tab_about_app,
            "howto": self._tab_how_to_use,
            "ports": self._tab_port_reference,
            "tcp":   self._tab_what_is_tcp,
            "faq":   self._tab_faq,
        }
        builders[tab_id]()

        # Scroll back to top
        self.about_canvas.yview_moveto(0)
        self._active_about_tab = tab_id


    # ── About tab helpers ─────────────────────────────────────

    def _section_title(self, text, icon=""):
        """Render a bold section title inside the about content area."""
        tk.Label(
            self.about_content,
            text=f"{icon}  {text}" if icon else text,
            font=("Segoe UI", 16, "bold"),
            bg=self.CLR_BG,
            fg=self.CLR_PRIMARY,
            anchor="w"
        ).pack(fill="x", padx=40, pady=(30, 6))
        tk.Frame(self.about_content, bg=self.CLR_ACCENT, height=2).pack(fill="x", padx=40, pady=(0, 16))

    def _para(self, text):
        """Render a paragraph of body text."""
        tk.Label(
            self.about_content,
            text=text,
            font=("Segoe UI", 11),
            bg=self.CLR_BG,
            fg="#2C3E50",
            anchor="w",
            justify="left",
            wraplength=820
        ).pack(fill="x", padx=40, pady=(0, 12))

    def _sub_heading(self, text):
        """Render a smaller bold sub-heading."""
        tk.Label(
            self.about_content,
            text=text,
            font=("Segoe UI", 12, "bold"),
            bg=self.CLR_BG,
            fg=self.CLR_PRIMARY,
            anchor="w"
        ).pack(fill="x", padx=40, pady=(14, 4))

    def _bullet(self, text, color="#2C3E50"):
        """Render a single bullet point."""
        tk.Label(
            self.about_content,
            text=f"  •  {text}",
            font=("Segoe UI", 11),
            bg=self.CLR_BG,
            fg=color,
            anchor="w",
            justify="left",
            wraplength=800
        ).pack(fill="x", padx=50, pady=2)

    def _info_card(self, title, body, accent="#0078D7"):
        """Render a highlighted info card."""
        card = tk.Frame(
            self.about_content,
            bg=self.CLR_SUBTLE,
            highlightthickness=1,
            highlightbackground=self.CLR_BORDER
        )
        card.pack(fill="x", padx=40, pady=8)
        tk.Frame(card, bg=accent, width=4).pack(side="left", fill="y")
        inner = tk.Frame(card, bg=self.CLR_SUBTLE)
        inner.pack(side="left", fill="both", expand=True, padx=14, pady=12)
        tk.Label(inner, text=title, font=("Segoe UI", 11, "bold"),
                 bg=self.CLR_SUBTLE, fg=self.CLR_PRIMARY, anchor="w").pack(fill="x")
        tk.Label(inner, text=body, font=("Segoe UI", 10),
                 bg=self.CLR_SUBTLE, fg="#2C3E50", anchor="w",
                 justify="left", wraplength=750).pack(fill="x", pady=(4, 0))


    # ── Tab: About the App ────────────────────────────────────

    def _tab_about_app(self):
        self._section_title("About Network Scanner", "📋")

        self._para(
            "Network Scanner is a beginner-friendly desktop application built with Python "
            "and Tkinter. It allows you to scan TCP ports on any host or IP address to "
            "discover open ports and identify the services running on them."
        )

        self._info_card(
            "Version",
            "Network Scanner v1.0  |  Developed by Adish VC\n"
            "Built with Python 3 · Tkinter · Socket · Threading"
        )

        self._sub_heading("What This Tool Does")
        self._bullet("Scans any host or IP address for open TCP ports")
        self._bullet("Identifies common network services on discovered ports")
        self._bullet("Uses multi-threading to scan quickly (up to 150 threads)")
        self._bullet("Displays results in real time as ports are discovered")
        self._bullet("Generates a professional text report you can save")

        self._sub_heading("Who Is This For?")
        self._para(
            "This tool is designed for students, hobbyists, and beginner cybersecurity "
            "enthusiasts who want to learn about network scanning in a safe, educational "
            "environment. It is suitable for final-year projects, portfolio showcases, "
            "and internship demonstrations."
        )

        self._info_card(
            "⚠  Legal Notice",
            "Only scan hosts and networks you own or have explicit written permission "
            "to scan. Unauthorised port scanning may be illegal in your country and can "
            "violate terms of service. Use responsibly.",
            accent="#C0392B"
        )

        self._sub_heading("Technologies Used")
        self._bullet("Python 3 — core programming language")
        self._bullet("Tkinter — graphical user interface framework")
        self._bullet("socket — low-level TCP connection testing")
        self._bullet("threading — parallel port scanning engine")
        self._bullet("Pillow (PIL) — background image rendering")


    # ── Tab: How to Use ───────────────────────────────────────

    def _tab_how_to_use(self):
        self._section_title("How to Use Network Scanner", "📖")

        self._para(
            "Follow these steps to perform a port scan. The whole process takes "
            "less than a minute for common port ranges."
        )

        steps = [
            ("Step 1 — Enter a Target",
             "Type a hostname (e.g. scanme.nmap.org) or an IP address "
             "(e.g. 192.168.1.1) into the Target Host field. "
             "Make sure you have permission to scan the target."),
            ("Step 2 — Set the Port Range",
             "Enter the Start Port and End Port you want to scan. "
             "Common ranges: 1–1024 (well-known ports), 1–65535 (full scan). "
             "Larger ranges take more time."),
            ("Step 3 — Start the Scan",
             "Click ▶ START SCAN. The scanner will resolve the hostname, "
             "connect to each port in the range using multiple threads, "
             "and display open ports in real time as they are found."),
            ("Step 4 — Read the Results",
             "Open ports appear in green with their service name. "
             "The status bar at the bottom shows the scan progress "
             "and total open port count."),
            ("Step 5 — Save the Report",
             "Once scanning completes, click 💾 SAVE REPORT to write "
             "the results to scan_report.txt in the application folder."),
            ("Step 6 — Stop Early (optional)",
             "You can click ⏹ STOP at any time to cancel a running scan. "
             "Results collected so far will remain visible."),
        ]

        for title, body in steps:
            self._info_card(title, body, accent=self.CLR_ACCENT)

        self._sub_heading("Tips for Better Results")
        self._bullet("Start with ports 1–1024 — these cover almost all common services")
        self._bullet("Use scanme.nmap.org as a safe legal test target (provided by the Nmap project)")
        self._bullet("Scanning localhost (127.0.0.1) shows services running on your own machine")
        self._bullet("A lower timeout makes scans faster but may miss slow hosts")
        self._bullet("Very wide ranges (1–65535) can take several minutes — be patient")


    # ── Tab: Common Port Numbers ──────────────────────────────

    def _tab_port_reference(self):
        self._section_title("Common Port Numbers", "🔌")

        self._para(
            "Ports are 16-bit numbers (0–65535) that identify specific services on a "
            "networked device. Ports 0–1023 are called Well-Known Ports and are "
            "reserved for standard protocols by IANA."
        )

        # Table header
        table_frame = tk.Frame(
            self.about_content,
            bg=self.CLR_SUBTLE,
            highlightthickness=1,
            highlightbackground=self.CLR_BORDER
        )
        table_frame.pack(fill="x", padx=40, pady=(8, 20))

        header_row = tk.Frame(table_frame, bg=self.CLR_PRIMARY)
        header_row.pack(fill="x")
        for text, w in [("Port", 8), ("Service", 16), ("Description", 60)]:
            tk.Label(
                header_row,
                text=text,
                font=("Segoe UI", 10, "bold"),
                bg=self.CLR_PRIMARY,
                fg="white",
                width=w,
                anchor="w",
                padx=10,
                pady=8
            ).pack(side="left")

        # Table rows
        for i, (port, service, description) in enumerate(PORT_REFERENCE):
            row_bg = "#FFFFFF" if i % 2 == 0 else self.CLR_SUBTLE
            row = tk.Frame(table_frame, bg=row_bg)
            row.pack(fill="x")
            tk.Label(row, text=str(port), font=("Consolas", 10),
                     bg=row_bg, fg=self.CLR_ACCENT, width=8, anchor="w", padx=10, pady=6).pack(side="left")
            tk.Label(row, text=service, font=("Segoe UI", 10, "bold"),
                     bg=row_bg, fg=self.CLR_PRIMARY, width=16, anchor="w", padx=10).pack(side="left")
            tk.Label(row, text=description, font=("Segoe UI", 10),
                     bg=row_bg, fg="#2C3E50", anchor="w", padx=10, wraplength=580, justify="left").pack(side="left", fill="x", expand=True)

        self._sub_heading("Port Categories")
        self._bullet("Well-Known Ports (0–1023) — assigned by IANA to core internet services")
        self._bullet("Registered Ports (1024–49151) — used by applications and services")
        self._bullet("Dynamic / Ephemeral Ports (49152–65535) — assigned temporarily by the OS")


    # ── Tab: What is TCP? ─────────────────────────────────────

    def _tab_what_is_tcp(self):
        self._section_title("What is TCP?", "🌐")

        self._para(
            "TCP stands for Transmission Control Protocol. It is one of the core "
            "protocols of the Internet Protocol (IP) suite and is responsible for "
            "reliable, ordered, and error-checked delivery of data between applications."
        )

        self._sub_heading("The Three-Way Handshake")
        self._para(
            "Before any data is exchanged, TCP establishes a connection using a "
            "three-step process called the three-way handshake:"
        )
        self._info_card("1.  SYN",
            "The client sends a SYN (synchronise) packet to the server, "
            "asking to open a connection.", accent="#0078D7")
        self._info_card("2.  SYN-ACK",
            "If the port is open, the server replies with SYN-ACK "
            "(synchronise-acknowledge), confirming it received the request.", accent="#0C7C3F")
        self._info_card("3.  ACK",
            "The client sends an ACK (acknowledge) to complete the handshake. "
            "The connection is now established and data can flow.", accent="#8E44AD")

        self._sub_heading("How Port Scanning Uses TCP")
        self._para(
            "Network Scanner attempts to complete the TCP three-way handshake on "
            "each port. If the handshake succeeds (the server responds with SYN-ACK), "
            "the port is marked OPEN. If the connection is refused or times out, "
            "the port is considered closed or filtered."
        )

        self._sub_heading("TCP vs UDP")
        self._bullet("TCP — connection-oriented, reliable, ordered delivery (HTTP, SSH, FTP)")
        self._bullet("UDP — connectionless, faster but no guarantee of delivery (DNS, VoIP, gaming)")
        self._bullet("This tool scans TCP ports only — UDP scanning requires a different technique")

        self._sub_heading("Key TCP Concepts")
        self._bullet("Port — a number identifying a specific service on a device")
        self._bullet("Socket — a combination of IP address + port (e.g. 192.168.1.1:80)")
        self._bullet("Timeout — maximum time to wait for a server response before giving up")
        self._bullet("Firewall — a system that can block or filter port connections")


    # ── Tab: FAQ ──────────────────────────────────────────────

    def _tab_faq(self):
        self._section_title("Frequently Asked Questions", "❓")

        faqs = [
            ("Is it legal to scan ports?",
             "It depends on the target. Scanning your own machine (127.0.0.1) or "
             "your home network is generally fine. Scanning external hosts without "
             "written permission may be illegal under computer crime laws in many "
             "countries. Always get permission before scanning."),
            ("Why do some scans take a long time?",
             "Each port that doesn't respond must wait for a timeout (default 0.5 s). "
             "Scanning a large range like 1–65535 means up to 65,535 connection "
             "attempts. With 150 threads it still takes several minutes. Narrow your "
             "port range to speed things up."),
            ("What does 'Unknown' service mean?",
             "The port is open (connection succeeded) but it doesn't match any entry "
             "in our service map. The port could be running a custom application, a "
             "game server, or another non-standard service."),
            ("Why are no ports showing as open?",
             "The host may have a firewall blocking connections, the target may be "
             "offline, or the port range you selected may not include any listening "
             "services. Try scanning ports 1–1024 on a known-active host first."),
            ("Can I scan UDP ports?",
             "Not with this version. UDP scanning is more complex because UDP is "
             "connectionless — there is no handshake to test. A future version may "
             "include UDP scanning capability."),
            ("Where is the report saved?",
             "The report is saved as scan_report.txt in the same folder as the "
             "application. The full path is shown in a popup after saving."),
            ("What is scanme.nmap.org?",
             "It is a host maintained by the Nmap project specifically for people "
             "to practice port scanning legally and safely. It is an excellent "
             "beginner target — you have implicit permission to scan it."),
        ]

        for question, answer in faqs:
            self._info_card(f"Q:  {question}", f"A:  {answer}", accent=self.CLR_ACCENT)


    # ─────────────────────────────────────────────────────────
    #  SCAN CONTROL
    # ─────────────────────────────────────────────────────────

    def _start_scan(self):
        target = self.target_entry.get().strip()
        if target in ("", "e.g. 192.168.1.1 or scanme.nmap.org"):
            messagebox.showwarning("Input Error", "Please enter a target host or IP address.")
            return

        try:
            start_port = int(self.start_port_entry.get().strip())
            end_port   = int(self.end_port_entry.get().strip())
        except ValueError:
            messagebox.showwarning("Input Error", "Port values must be integers.")
            return

        if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
            messagebox.showwarning("Input Error", "Ports must be between 1 and 65535.")
            return

        if start_port > end_port:
            messagebox.showwarning("Input Error", "Start Port must be ≤ End Port.")
            return

        # Resolve hostname to IP
        self._set_status("Resolving hostname…")
        try:
            resolved = socket.gethostbyname(target)
        except socket.gaierror:
            messagebox.showerror("DNS Error", f"Could not resolve host: {target}")
            self._set_status("Error — hostname resolution failed.")
            return

        self.resolved_ip = resolved
        self.target_host = target
        self.open_ports  = []

        # Update UI to scanning state
        self.scan_running = True
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.save_btn.configure(state="disabled")
        self.open_count_var.set("Open Ports: 0")
        self._set_status(f"Scanning {target} ({resolved})  |  Ports {start_port}–{end_port} …")

        self._clear_results()
        self._print_scan_header(target, resolved, start_port, end_port)

        # Launch scanner engine
        self.scanner = PortScanner(
            target=resolved,
            start_port=start_port,
            end_port=end_port,
            result_callback=self._on_port_found,
            done_callback=self._on_scan_done
        )
        self.scanner.start()

    def _stop_scan(self):
        if self.scanner:
            self.scanner.stop()
        self._set_status("Scan stopped by user.")
        self._scan_finished()

    def _go_home_safe(self):
        if self.scan_running:
            if not messagebox.askyesno(
                "Scan Running",
                "A scan is in progress. Stop it and go home?"
            ):
                return
            self._stop_scan()
        self._show_home()


    # ─────────────────────────────────────────────────────────
    #  SCAN CALLBACKS  (called from worker threads via .after)
    # ─────────────────────────────────────────────────────────

    def _on_port_found(self, port, service):
        self.open_ports.append((port, service))
        self.root.after(0, self._append_open_port, port, service)

    def _on_scan_done(self, open_ports):
        self.root.after(0, self._scan_complete, open_ports)

    def _append_open_port(self, port, service):
        self.open_count_var.set(f"Open Ports: {len(self.open_ports)}")
        self._write(f"  PORT {port:<7}  {service:<25}  ●  OPEN\n", tag="open")

    def _scan_complete(self, open_ports):
        total = len(open_ports)
        self._write("\n", tag="info")
        self._write("─" * 58 + "\n", tag="header")

        if total == 0:
            self._write("  No open ports found in the specified range.\n", tag="info")
        else:
            self._write(f"  SCAN COMPLETE  —  {total} open port(s) found.\n", tag="summary")

        self._write("─" * 58 + "\n", tag="header")
        self._set_status(
            f"Scan complete.  {total} open port(s) found.  "
            f"Target: {self.target_host} ({self.resolved_ip})"
        )
        self._scan_finished()
        self.save_btn.configure(state="normal")
        self._update_progress(100)

    def _scan_finished(self):
        self.scan_running = False
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")


    # ─────────────────────────────────────────────────────────
    #  RESULTS BOX HELPERS
    # ─────────────────────────────────────────────────────────

    def _write(self, text, tag=None):
        self.results_box.configure(state="normal")
        if tag:
            self.results_box.insert("end", text, tag)
        else:
            self.results_box.insert("end", text)
        self.results_box.see("end")
        self.results_box.configure(state="disabled")

    def _clear_results(self):
        self.results_box.configure(state="normal")
        self.results_box.delete("1.0", "end")
        self.results_box.configure(state="disabled")

    def _write_results_banner(self):
        banner = (
            "  ┌─────────────────────────────────────────────────────┐\n"
            "  │          NETWORK SCANNER  —  Ready                  │\n"
            "  │  Enter a target and port range, then press          │\n"
            "  │  START SCAN to begin discovering open TCP ports.    │\n"
            "  └─────────────────────────────────────────────────────┘\n"
        )
        self._write(banner, tag="info")

    def _print_scan_header(self, host, ip, sp, ep):
        ts = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self._write("─" * 58 + "\n", tag="header")
        self._write("  NETWORK SCANNER  —  Scan Started\n", tag="header")
        self._write("─" * 58 + "\n", tag="header")
        self._write(f"  Timestamp   : {ts}\n",       tag="info")
        self._write(f"  Target Host : {host}\n",     tag="info")
        self._write(f"  Resolved IP : {ip}\n",       tag="info")
        self._write(f"  Port Range  : {sp} – {ep}\n", tag="info")
        self._write("─" * 58 + "\n", tag="header")
        self._write(f"  {'PORT':<12} {'SERVICE':<25} STATUS\n", tag="header")
        self._write("─" * 58 + "\n", tag="header")


    # ─────────────────────────────────────────────────────────
    #  PROGRESS BAR
    # ─────────────────────────────────────────────────────────

    def _update_progress(self, percent):
        self.progress_canvas.update_idletasks()
        w = self.progress_canvas.winfo_width()
        fill = int(w * percent / 100)
        self.progress_canvas.delete("all")
        self.progress_canvas.create_rectangle(
            0, 0, fill, 6,
            fill=self.CLR_ACCENT,
            outline=""
        )


    # ─────────────────────────────────────────────────────────
    #  REPORT SAVE
    # ─────────────────────────────────────────────────────────

    def _save_report(self):
        if not self.open_ports and not self.resolved_ip:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        sp = int(self.start_port_entry.get())
        ep = int(self.end_port_entry.get())
        fname    = save_report(self.resolved_ip, self.target_host, sp, ep, self.open_ports)
        abs_path = os.path.abspath(fname)
        messagebox.showinfo("Report Saved", f"Scan report saved successfully!\n\n{abs_path}")
        self._set_status(f"Report saved → {abs_path}")


    # ─────────────────────────────────────────────────────────
    #  ENTRY FIELD PLACEHOLDER HELPERS
    # ─────────────────────────────────────────────────────────

    def _clear_placeholder(self, event):
        if self.target_entry.get() == "e.g. 192.168.1.1 or scanme.nmap.org":
            self.target_entry.delete(0, "end")
            self.target_entry.configure(fg="#1A1A2E")

    def _restore_placeholder(self, event):
        if self.target_entry.get() == "":
            self.target_entry.insert(0, "e.g. 192.168.1.1 or scanme.nmap.org")
            self.target_entry.configure(fg="#AAAAAA")


# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app  = NetworkScannerApp(root)
    root.mainloop()