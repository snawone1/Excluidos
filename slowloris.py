import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import subprocess
import threading
import os
import sys
import signal
import configparser
import webbrowser

# ------------------ Configuracin permanente ------------------
config_file = "config.ini"
config = configparser.ConfigParser()
if os.path.exists(config_file):
    config.read(config_file)
else:
    config['Paths'] = {'slowloris_path': ''}
    with open(config_file, 'w') as f:
        config.write(f)

procesos = {}

def guardar_config():
    with open(config_file, 'w') as f:
        config.write(f)

# ------------------ FUNCIONES ------------------

def tooltip(widget, text):
    def on_enter(event):
        tip = tk.Toplevel()
        tip.wm_overrideredirect(True)
        tip.configure(bg="#ffffe0")
        x, y = event.x_root + 10, event.y_root + 10
        tip.geometry(f"+{x}+{y}")
        label = tk.Label(tip, text=text, bg="#ffffe0", relief='solid', borderwidth=1, font=("Arial", 9))
        label.pack()
        widget.tooltip = tip
    def on_leave(event):
        if hasattr(widget, 'tooltip'):
            widget.tooltip.destroy()
            widget.tooltip = None
    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave)

def ejecutar_comando(comando, salida_box, mostrar_salida=True):
    salida_box.config(state='normal')
    try:
        proceso = subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        procesos[proceso.pid] = proceso
        salida_box.insert(tk.END, f"\n[+] Ejecutando: {comando} (PID: {proceso.pid})\n")
        salida_box.see(tk.END)

        for linea in proceso.stdout:
            if mostrar_salida or "slowloris" not in comando.lower():
                salida_box.insert(tk.END, linea)
                salida_box.see(tk.END)

        proceso.wait()
        salida_box.insert(tk.END, f"\n[+] Proceso {proceso.pid} finalizado.\n")
        salida_box.see(tk.END)
        del procesos[proceso.pid]
    except Exception as e:
        salida_box.insert(tk.END, f"\n[!] Error: {e}\n")
    salida_box.config(state='disabled')

def lanzar_nmap():
    target = entry_nmap_target.get()
    scan_type = nmap_scan_type.get()
    if not target:
        messagebox.showwarning("Error", "Debes ingresar un target.")
        return

    # Extraemos la opción real de la combo (e.g. "-sS" de "-sS (TCP SYN)")
    opcion = scan_type.split()[0]  
    comando = f"nmap {opcion} {target}"
    threading.Thread(target=ejecutar_comando, args=(comando, salida_nmap), daemon=True).start()

def lanzar_slowloris():
    slowloris_path = entry_slowloris_path.get()
    host = entry_slowloris_host.get()
    port = entry_slowloris_port.get()
    sockets = entry_slowloris_sockets.get()
    interval = entry_slowloris_interval.get()
    use_https = var_ssl.get()
    mostrar_salida = var_debug.get()

    if not os.path.isfile(slowloris_path):
        messagebox.showwarning("Error", "Ruta de Slowloris inválida.")
        return
    if not host:
        messagebox.showwarning("Error", "Debes ingresar el host objetivo.")
        return

    comando = f'perl "{slowloris_path}" -dns {host} -port {port} -timeout {interval} -num {sockets}'
    if use_https:
        comando += " -https"

    threading.Thread(target=ejecutar_comando, args=(comando, salida_slowloris, mostrar_salida), daemon=True).start()

def detener_proceso():
    pid_str = entry_pid.get()
    try:
        pid = int(pid_str)
        if pid in procesos:
            if sys.platform == "win32":
                subprocess.run(f"taskkill /PID {pid} /F", shell=True)
            else:
                os.kill(pid, signal.SIGTERM)
            salida_nmap.config(state='normal')
            salida_slowloris.config(state='normal')
            salida_nmap.insert(tk.END, f"\n[+] Proceso {pid} detenido.\n")
            salida_slowloris.insert(tk.END, f"\n[+] Proceso {pid} detenido.\n")
            salida_nmap.config(state='disabled')
            salida_slowloris.config(state='disabled')
            del procesos[pid]
        else:
            messagebox.showinfo("Aviso", "PID no encontrado o ya finalizado.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def detener_todos():
    for pid in list(procesos.keys()):
        try:
            if sys.platform == "win32":
                subprocess.run(f"taskkill /PID {pid} /F", shell=True)
            else:
                os.kill(pid, signal.SIGTERM)
            salida_slowloris.config(state='normal')
            salida_slowloris.insert(tk.END, f"\n[+] Proceso {pid} detenido.\n")
            salida_slowloris.config(state='disabled')
            del procesos[pid]
        except Exception as e:
            print(f"Error al detener PID {pid}: {e}")

def seleccionar_slowloris():
    ruta = filedialog.askopenfilename(title="Seleccionar slowloris.pl", filetypes=[("Archivos Perl", "*.pl"), ("Todos", "*.*")])
    if ruta:
        entry_slowloris_path.delete(0, tk.END)
        entry_slowloris_path.insert(0, ruta)
        config['Paths']['slowloris_path'] = ruta
        guardar_config()

def abrir_link(url):
    webbrowser.open(url)

def mostrar_pids_activos():
    if procesos:
        pids = "\n".join([f"PID: {pid} - Cmd: {proc.args}" for pid, proc in procesos.items()])
    else:
        pids = "No hay procesos activos."
    messagebox.showinfo("Procesos activos", pids)

# ------------------ INTERFAZ ------------------
root = tk.Tk()
root.title("Slowloris & Nmap - UI v0.0.3")
root.configure(bg="#f0f0f0")
root.attributes("-alpha", 0.95)

style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', font=('Arial', 10), padding=6, relief='groove')
style.configure('TEntry', font=('Arial', 10))
style.configure('TLabel', font=('Arial', 10))

# Ajuste tamaño compacto (mínimo y ajustable)
root.geometry("")  # deja que el layout determine el tamaño

notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True, fill='both')

# --- Nmap ---
frame_nmap = ttk.Frame(notebook)
notebook.add(frame_nmap, text='Nmap')

lbl_target = ttk.Label(frame_nmap, text="Target:")
lbl_target.grid(row=0, column=0, sticky="w", padx=5, pady=5)
entry_nmap_target = ttk.Entry(frame_nmap, width=50)
entry_nmap_target.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
tooltip(entry_nmap_target, "Host o IP a escanear con Nmap")

lbl_scan = ttk.Label(frame_nmap, text="Tipo de escaneo:")
lbl_scan.grid(row=1, column=0, sticky="w", padx=5, pady=5)

nmap_scan_type = ttk.Combobox(frame_nmap, values=[
    "-sS (TCP SYN)",
    "-sT (TCP Connect)",
    "-sU (UDP)",
    "-sV (Version detection)",
    "-O (OS detection)",
    "-A (Aggressive scan)",
    "-sn (Ping scan)",
    "-p- (Todos los puertos)",
    "-T4 -F (Fast scan)"
], state="readonly", width=47)
nmap_scan_type.current(0)
nmap_scan_type.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

desc_nmap = {
    "-sS (TCP SYN)": "Envia paquetes SYN para detectar puertos abiertos sin establecer conexión completa.",
    "-sT (TCP Connect)": "Conecta a puertos usando TCP completo (más visible, menos sigiloso).",
    "-sU (UDP)": "Escaneo de puertos UDP.",
    "-sV (Version detection)": "Detecta versiones de servicios en puertos abiertos.",
    "-O (OS detection)": "Detecta el sistema operativo del host.",
    "-A (Aggressive scan)": "Escaneo agresivo: OS, versiones, scripts y traceroute.",
    "-sn (Ping scan)": "Descubre hosts activos sin escanear puertos.",
    "-p- (Todos los puertos)": "Escanea todos los puertos TCP (1-65535).",
    "-T4 (Fast scan)": "Escaneo rápido optimizado para redes confiables."
}

desc_label = ttk.Label(frame_nmap, text=desc_nmap[nmap_scan_type.get()], wraplength=400, foreground="gray30")
desc_label.grid(row=2, column=0, columnspan=2, padx=5, pady=3)

def update_desc(event):
    desc_label.config(text=desc_nmap.get(nmap_scan_type.get(), ""))

nmap_scan_type.bind("<<ComboboxSelected>>", update_desc)

btn_nmap_run = ttk.Button(frame_nmap, text="Ejecutar Nmap", command=lanzar_nmap)
btn_nmap_run.grid(row=3, column=0, columnspan=2, pady=10, padx=5, sticky="ew")

salida_nmap = ScrolledText(frame_nmap, width=80, height=15, state='disabled', bg="#ffffff")
salida_nmap.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

# --- Slowloris ---
frame_slowloris = ttk.Frame(notebook)
notebook.add(frame_slowloris, text='Slowloris')

lbl_host = ttk.Label(frame_slowloris, text="Host objetivo:")
lbl_host.grid(row=0, column=0, sticky="w", padx=5, pady=5)
entry_slowloris_host = ttk.Entry(frame_slowloris, width=50)
entry_slowloris_host.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
tooltip(entry_slowloris_host, "Host o IP objetivo")

lbl_port = ttk.Label(frame_slowloris, text="Puerto:")
lbl_port.grid(row=1, column=0, sticky="w", padx=5, pady=5)
entry_slowloris_port = ttk.Entry(frame_slowloris, width=50)
entry_slowloris_port.insert(0, "80")
entry_slowloris_port.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

lbl_sockets = ttk.Label(frame_slowloris, text="Número de sockets:")
lbl_sockets.grid(row=2, column=0, sticky="w", padx=5, pady=5)
entry_slowloris_sockets = ttk.Entry(frame_slowloris, width=50)
entry_slowloris_sockets.insert(0, "200")
entry_slowloris_sockets.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

lbl_interval = ttk.Label(frame_slowloris, text="Timeout (segundos):")
lbl_interval.grid(row=3, column=0, sticky="w", padx=5, pady=5)
entry_slowloris_interval = ttk.Entry(frame_slowloris, width=50)
entry_slowloris_interval.insert(0, "100")
entry_slowloris_interval.grid(row=3, column=1, sticky="ew", padx=5, pady=5)

var_ssl = tk.IntVar()
chk_ssl = ttk.Checkbutton(frame_slowloris, text="Usar HTTPS", variable=var_ssl)
chk_ssl.grid(row=4, column=1, sticky="w", padx=5, pady=5)

var_debug = tk.IntVar()
chk_debug = ttk.Checkbutton(frame_slowloris, text="Mostrar salida detallada mientras ejecuta", variable=var_debug)
chk_debug.grid(row=5, column=1, sticky="w", padx=5, pady=5)

btn_frame = ttk.Frame(frame_slowloris)
btn_frame.grid(row=6, column=0, columnspan=2, pady=10, padx=5, sticky="ew")
btn_frame.columnconfigure((0,1), weight=1)

btn_slowloris_run = ttk.Button(btn_frame, text="Ejecutar Slowloris", command=lanzar_slowloris)
btn_slowloris_run.grid(row=0, column=0, sticky="ew", padx=3)

btn_slowloris_stopall = ttk.Button(btn_frame, text="Detener todos los Slowloris", command=detener_todos)
btn_slowloris_stopall.grid(row=0, column=1, sticky="ew", padx=3)

salida_slowloris = ScrolledText(frame_slowloris, width=80, height=15, state='disabled', bg="#ffffff")
salida_slowloris.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

# --- Configuración ---
frame_config = ttk.Frame(notebook)
notebook.add(frame_config, text='Configuración')

lbl_path = ttk.Label(frame_config, text="Ruta del slowloris.pl:")
lbl_path.grid(row=0, column=0, sticky="w", padx=5, pady=5)
entry_slowloris_path = ttk.Entry(frame_config, width=50)
entry_slowloris_path.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
entry_slowloris_path.insert(0, config['Paths'].get('slowloris_path', ''))
tooltip(entry_slowloris_path, "Ruta al script slowloris.pl")

btn_path = ttk.Button(frame_config, text="Seleccionar archivo", command=seleccionar_slowloris)
btn_path.grid(row=0, column=2, sticky="ew", padx=5, pady=5)

ttk.Separator(frame_config, orient='horizontal').grid(row=1, column=0, columnspan=3, sticky="ew", pady=10)

btn_nmap_dl = ttk.Button(frame_config, text="Descargar Nmap", command=lambda: abrir_link("https://nmap.org/download.html"))
btn_nmap_dl.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

btn_perl_dl = ttk.Button(frame_config, text="Descargar Strawberry Perl", command=lambda: abrir_link("https://strawberryperl.com/"))
btn_perl_dl.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

lbl_pid = ttk.Label(frame_config, text="Detener proceso por PID:")
lbl_pid.grid(row=3, column=0, sticky="w", padx=5, pady=5)
entry_pid = ttk.Entry(frame_config, width=15)
entry_pid.grid(row=3, column=1, sticky="w", padx=5, pady=5)

btn_detener_pid = ttk.Button(frame_config, text="Detener Proceso", command=detener_proceso)
btn_detener_pid.grid(row=3, column=2, sticky="ew", padx=5, pady=5)

btn_mostrar_pids = ttk.Button(frame_config, text="Mostrar PID activos", command=mostrar_pids_activos)
btn_mostrar_pids.grid(row=4, column=0, columnspan=3, sticky="ew", padx=5, pady=10)

for i in range(3):
    frame_config.columnconfigure(i, weight=1)

# Configurar columnas para expandir bien
for frame in (frame_nmap, frame_slowloris):
    frame.columnconfigure(1, weight=1)

root.mainloop()
