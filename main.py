import csv
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
except ModuleNotFoundError:
    FigureCanvasTkAgg = Figure = None
APP_TITLE = "Packet Loss Analyzer"
BG, PANEL = "#f5f7fb", "#ffffff"
LOST_MARKERS = ("request timed out", "destination host unreachable", "general failure", "ttl expired")
REPLY_RE = re.compile(r"Reply from (?P<ip>[\d.]+): bytes=\d+ time(?P<op>[=<])(?P<time>\d+)ms TTL=(?P<ttl>\d+)", re.I)
PING_RE = re.compile(r"Pinging (?P<ip>[\d.]+) with", re.I)
class PacketLossAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.current_file = None
        self.packets = []
        self.stats = self.empty_stats()
        self.stat_labels = {}
        self.chart_canvas = self.chart_placeholder = None
        self.root.title(APP_TITLE)
        self.root.geometry("1180x760")
        self.root.minsize(980, 620)
        self.setup_style()
        self.build_ui()
        self.show_chart_message("Відкрийте лог-файл для побудови графіків")
    def setup_style(self):
        self.root.configure(bg=BG)
        style = ttk.Style()
        style.theme_use("clam")
        for name, color in {"TFrame": BG, "TLabel": BG, "Panel.TFrame": PANEL, "Panel.TLabel": PANEL}.items():
            style.configure(name, background=color, foreground="#1f2937")
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), background=BG)
        style.configure("StatTitle.TLabel", font=("Segoe UI", 9), background=PANEL, foreground="#64748b")
        style.configure("StatValue.TLabel", font=("Segoe UI", 15, "bold"), background=PANEL, foreground="#111827")
        style.configure("TButton", font=("Segoe UI", 10), padding=(10, 6))
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
    def build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)
        header = ttk.Frame(self.root, padding=(16, 14, 16, 8))
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text=APP_TITLE, style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Аналіз ping-логів, розрахунок Packet Loss і побудова графіків").grid(row=1, column=0, sticky="w", pady=(4, 0))
        toolbar = ttk.Frame(self.root, padding=(16, 6, 16, 10))
        toolbar.grid(row=1, column=0, sticky="ew")
        toolbar.columnconfigure(4, weight=1)
        for col, (text, command) in enumerate((
            ("Відкрити лог", self.open_log_file),
            ("Оновити аналіз", self.reanalyze_current_file),
            ("Зберегти звіт", self.save_report),
            ("Експорт CSV", self.export_csv),
        )):
            ttk.Button(toolbar, text=text, command=command).grid(row=0, column=col, padx=(0, 8))
        self.file_label = ttk.Label(toolbar, text="Файл не вибрано")
        self.file_label.grid(row=0, column=4, sticky="e")
        content = ttk.Frame(self.root, padding=(16, 0, 16, 16))
        content.grid(row=2, column=0, sticky="nsew")
        content.columnconfigure(0, weight=2)
        content.columnconfigure(1, weight=3)
        content.rowconfigure(1, weight=1)
        self.build_stats(content)
        self.build_table(content)
        self.build_chart(content)
        self.status_bar = ttk.Label(self.root, text="Готово", anchor="w")
        self.status_bar.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 10))
        self.update_stats_view()
    def build_stats(self, parent):
        panel = ttk.Frame(parent, style="Panel.TFrame", padding=14)
        panel.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        items = (
            ("Всього пакетів", "sent"),
            ("Отримано", "received"),
            ("Втрачено", "lost"),
            ("Packet Loss", "loss_percent"),
            ("Середня затримка", "avg_latency"),
            ("Якість", "quality"),
        )
        for col, (title, key) in enumerate(items):
            panel.columnconfigure(col, weight=1)
            box = ttk.Frame(panel, style="Panel.TFrame")
            box.grid(row=0, column=col, sticky="ew", padx=6)
            ttk.Label(box, text=title, style="StatTitle.TLabel").grid(row=0, column=0, sticky="w")
            self.stat_labels[key] = ttk.Label(box, text="-", style="StatValue.TLabel")
            self.stat_labels[key].grid(row=1, column=0, sticky="w", pady=(3, 0))
    def build_table(self, parent):
        panel = ttk.Frame(parent, style="Panel.TFrame", padding=10)
        panel.grid(row=1, column=0, sticky="nsew", padx=(0, 12))
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)
        ttk.Label(panel, text="Пакети з логу", style="Panel.TLabel", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 8))
        columns = (
            ("seq", "№", 48, "center", False),
            ("ip", "IP", 105, "center", False),
            ("status", "Статус", 95, "center", False),
            ("time", "Час, ms", 78, "center", False),
            ("ttl", "TTL", 58, "center", False),
            ("line", "Рядок", 360, "w", True),
        )
        self.tree = ttk.Treeview(panel, columns=[c[0] for c in columns], show="headings", selectmode="browse")
        for key, title, width, anchor, stretch in columns:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor=anchor, stretch=stretch)
        self.tree.tag_configure("lost", background="#fee2e2", foreground="#991b1b")
        self.tree.tag_configure("received", background="#ecfdf5", foreground="#065f46")
        y_scroll = ttk.Scrollbar(panel, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(panel, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.tree.grid(row=1, column=0, sticky="nsew")
        y_scroll.grid(row=1, column=1, sticky="ns")
        x_scroll.grid(row=2, column=0, sticky="ew")
    def build_chart(self, parent):
        panel = ttk.Frame(parent, style="Panel.TFrame", padding=10)
        panel.grid(row=1, column=1, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)
        ttk.Label(panel, text="Графіки", style="Panel.TLabel", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.chart_container = ttk.Frame(panel, style="Panel.TFrame")
        self.chart_container.grid(row=1, column=0, sticky="nsew")
        self.chart_container.columnconfigure(0, weight=1)
        self.chart_container.rowconfigure(0, weight=1)
    def open_log_file(self):
        path = filedialog.askopenfilename(
            title="Виберіть ping-лог",
            filetypes=[("Log files", "*.log *.txt"), ("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self.current_file = path
            self.analyze_file(path)
    def reanalyze_current_file(self):
        if not self.current_file:
            messagebox.showinfo("Немає файлу", "Спочатку відкрийте лог-файл.")
            return
        self.analyze_file(self.current_file)
    def analyze_file(self, path):
        try:
            self.packets = self.parse_ping_log(self.read_lines(path))
        except OSError as error:
            messagebox.showerror("Помилка", f"Не вдалося відкрити файл:\n{error}")
            return
        self.stats = self.calculate_stats(self.packets)
        self.file_label.config(text=path)
        self.fill_table()
        self.update_stats_view()
        self.draw_charts()
        message = "У файлі не знайдено ping-відповідей." if not self.stats["sent"] else f"Проаналізовано пакетів: {self.stats['sent']}"
        self.status_bar.config(text=message)
    def read_lines(self, path):
        for encoding in ("utf-8", "cp1251"):
            try:
                with open(path, "r", encoding=encoding) as file:
                    return file.readlines()
            except UnicodeDecodeError:
                continue
        with open(path, "r", encoding="utf-8", errors="replace") as file:
            return file.readlines()
    def parse_ping_log(self, lines):
        packets, last_ip = [], ""
        for line_number, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line:
                continue
            ping_match = PING_RE.search(line)
            if ping_match:
                last_ip = ping_match.group("ip")
                continue
            reply_match = REPLY_RE.search(line)
            if reply_match:
                last_ip = reply_match.group("ip")
                packets.append(self.make_packet(len(packets) + 1, line_number, last_ip, "Отримано", "received", line, reply_match))
            elif any(marker in line.lower() for marker in LOST_MARKERS):
                packets.append(self.make_packet(len(packets) + 1, line_number, last_ip, "Втрачено", "lost", line))
        return packets
    def make_packet(self, seq, line_number, ip, status, status_key, raw, reply=None):
        latency = ttl = None
        if reply:
            latency = 0 if reply.group("op") == "<" else int(reply.group("time"))
            ttl = int(reply.group("ttl"))
        return dict(seq=seq, line_number=line_number, ip=ip, status=status, status_key=status_key, latency=latency, ttl=ttl, raw=raw)
    def calculate_stats(self, packets):
        stats = self.empty_stats()
        stats["sent"] = len(packets)
        stats["received"] = sum(p["status_key"] == "received" for p in packets)
        stats["lost"] = stats["sent"] - stats["received"]
        stats["loss_percent"] = round(stats["lost"] / stats["sent"] * 100, 2) if stats["sent"] else 0.0
        latencies = [p["latency"] for p in packets if p["latency"] is not None]
        if latencies:
            stats.update(avg_latency=round(sum(latencies) / len(latencies), 2), min_latency=min(latencies), max_latency=max(latencies))
        stats["quality"] = self.connection_quality(stats["loss_percent"])
        return stats
    def empty_stats(self):
        return dict(sent=0, received=0, lost=0, loss_percent=0.0, avg_latency=None, min_latency=None, max_latency=None, quality="-")
    def connection_quality(self, loss):
        if loss <= 1:
            return "Відмінна"
        if loss <= 5:
            return "Нормальна"
        if loss <= 10:
            return "Нестабільна"
        return "Погана"
    def fill_table(self):
        self.tree.delete(*self.tree.get_children())
        for p in self.packets:
            values = (p["seq"], p["ip"] or "-", p["status"], p["latency"] if p["latency"] is not None else "-", p["ttl"] or "-", p["raw"])
            self.tree.insert("", "end", values=values, tags=(p["status_key"],))
    def update_stats_view(self):
        values = {
            "sent": self.stats["sent"],
            "received": self.stats["received"],
            "lost": self.stats["lost"],
            "loss_percent": f"{self.stats['loss_percent']}%",
            "avg_latency": "-" if self.stats["avg_latency"] is None else f"{self.stats['avg_latency']} ms",
            "quality": self.stats["quality"],
        }
        for key, value in values.items():
            self.stat_labels[key].config(text=value)
    def draw_charts(self):
        if Figure is None:
            self.show_chart_message("Для графіків встановіть matplotlib:\npip install matplotlib")
            return
        if not self.packets:
            self.show_chart_message("Немає даних для графіків")
            return
        fig = Figure(figsize=(7, 5), dpi=100, facecolor=PANEL)
        fig.subplots_adjust(hspace=0.42)
        bar_ax, line_ax = fig.add_subplot(211), fig.add_subplot(212)
        bar_ax.bar(["Отримано", "Втрачено"], [self.stats["received"], self.stats["lost"]], color=["#16a34a", "#dc2626"])
        bar_ax.set(title="Отримані та втрачені пакети", ylabel="Кількість")
        bar_ax.grid(axis="y", linestyle="--", alpha=0.25)
        seq = [p["seq"] for p in self.packets]
        states = [1 if p["status_key"] == "received" else 0 for p in self.packets]
        lost_seq = [p["seq"] for p in self.packets if p["status_key"] == "lost"]
        line_ax.step(seq, states, where="mid", color="#2563eb", linewidth=1.8)
        line_ax.scatter(lost_seq, [0] * len(lost_seq), color="#dc2626", s=34, zorder=3)
        latency_packets = [p for p in self.packets if p["latency"] is not None]
        if latency_packets:
            latency_ax = line_ax.twinx()
            latency_ax.plot([p["seq"] for p in latency_packets], [p["latency"] for p in latency_packets], color="#f59e0b", linewidth=1.4)
            latency_ax.set_ylabel("Затримка, ms")
            latency_ax.tick_params(axis="y", labelcolor="#b45309")
        line_ax.set(title="Статус пакетів за порядком", xlabel="Номер пакета")
        line_ax.set_yticks([0, 1], labels=["Втрачено", "Отримано"])
        line_ax.set_ylim(-0.2, 1.2)
        line_ax.grid(axis="both", linestyle="--", alpha=0.25)
        self.render_figure(fig)
    def render_figure(self, figure):
        self.clear_chart()
        self.chart_canvas = FigureCanvasTkAgg(figure, master=self.chart_container)
        self.chart_canvas.draw()
        self.chart_canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew")
    def show_chart_message(self, text):
        self.clear_chart()
        self.chart_placeholder = ttk.Label(self.chart_container, text=text, style="Panel.TLabel", anchor="center", justify="center", font=("Segoe UI", 11))
        self.chart_placeholder.grid(row=0, column=0, sticky="nsew")
    def clear_chart(self):
        for widget in (self.chart_canvas.get_tk_widget() if self.chart_canvas else None, self.chart_placeholder):
            if widget:
                widget.destroy()
        self.chart_canvas = self.chart_placeholder = None
    def save_report(self):
        self.save_file("Зберегти звіт", ".txt", [("Text files", "*.txt"), ("All files", "*.*")], self.write_report)
    def export_csv(self):
        self.save_file("Експорт CSV", ".csv", [("CSV files", "*.csv"), ("All files", "*.*")], self.write_csv)
    def save_file(self, title, extension, filetypes, writer):
        if not self.packets:
            messagebox.showinfo("Немає даних", "Спочатку відкрийте та проаналізуйте лог.")
            return
        path = filedialog.asksaveasfilename(title=title, defaultextension=extension, filetypes=filetypes)
        if not path:
            return
        try:
            writer(path)
        except OSError as error:
            messagebox.showerror("Помилка", f"Не вдалося зберегти файл:\n{error}")
            return
        self.status_bar.config(text=f"Файл збережено: {path}")
    def write_report(self, path):
        latency = lambda key: "-" if self.stats[key] is None else f"{self.stats[key]} ms"
        lines = [
            APP_TITLE,
            "=" * len(APP_TITLE),
            f"Файл: {self.current_file or '-'}",
            "",
            f"Всього пакетів: {self.stats['sent']}",
            f"Отримано: {self.stats['received']}",
            f"Втрачено: {self.stats['lost']}",
            f"Packet Loss: {self.stats['loss_percent']}%",
            f"Середня затримка: {latency('avg_latency')}",
            f"Мінімальна затримка: {latency('min_latency')}",
            f"Максимальна затримка: {latency('max_latency')}",
            f"Оцінка якості: {self.stats['quality']}",
            "",
            "Деталізація пакетів:",
        ]
        for p in self.packets:
            time_value = "-" if p["latency"] is None else f"{p['latency']} ms"
            lines.append(f"{p['seq']:>3}. {p['status']:<9} IP={p['ip'] or '-':<15} time={time_value:<8} TTL={p['ttl'] or '-'}")
        with open(path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))
    def write_csv(self, path):
        with open(path, "w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["seq", "line_number", "ip", "status", "latency_ms", "ttl", "raw_line"])
            for p in self.packets:
                writer.writerow([p["seq"], p["line_number"], p["ip"], p["status"], p["latency"] or "", p["ttl"] or "", p["raw"]])
def main():
    root = tk.Tk()
    PacketLossAnalyzerApp(root)
    root.mainloop()
if __name__ == "__main__":
    main()
