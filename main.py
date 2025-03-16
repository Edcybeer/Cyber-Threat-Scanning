import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import requests
import hashlib
import os
from PIL import Image, ImageTk

# 🔹 VirusTotal API Key
API_KEY = ""

# 🔹 File to store scan history
HISTORY_FILE = "history.txt"

# 🔹 List to store scan history
scan_history = []

# 🛠️ Function to calculate SHA-256 hash of a file
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# 🔍 Function to scan a file using VirusTotal API
def scan_file(file_path):
    file_hash = calculate_file_hash(file_path)
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return parse_results(response.json(), file_path)
    return f"Error: {response.status_code} - {response.text}"

# 📊 Function to parse VirusTotal results
def parse_results(result, file_path):
    attributes = result.get("data", {}).get("attributes", {})
    scans = attributes.get("last_analysis_results", {})
    positives = sum(1 for scan in scans.values() if scan["category"] == "malicious")
    total_engines = len(scans)
    file_size_kb = os.path.getsize(file_path) / 1024
    result_text = f"File: {os.path.basename(file_path)}\nDetection Ratio: {positives}/{total_engines} ({positives/total_engines:.2%})\nFile Size: {file_size_kb:.2f} KB\n\n"

    scan_history.append((os.path.basename(file_path), result_text))
    
    save_history_to_file()
    update_history_list()
    return result_text, positives > 0, scans

# 🔄 Function to update scan history list
def update_history_list():
    history_listbox.delete(0, tk.END)
    for file_name, _ in scan_history:
        history_listbox.insert(tk.END, file_name)

# 🖱️ Function to show previous scan results
def show_history_result(event):
    selected_index = history_listbox.curselection()
    if selected_index:
        _, result_text = scan_history[selected_index[0]]
        result_textbox.config(state=tk.NORMAL)
        result_textbox.delete(1.0, tk.END)
        result_textbox.insert(tk.END, result_text)
        result_textbox.config(state=tk.DISABLED)

# 🛡️ Function to move malicious files to Quarantine
def quarantine_file(file_path):
    quarantine_folder = "Quarantine"
    if not os.path.exists(quarantine_folder):
        os.makedirs(quarantine_folder)

    file_name = os.path.basename(file_path)
    new_path = os.path.join(quarantine_folder, file_name)

    try:
        os.rename(file_path, new_path)
        messagebox.showwarning("Quarantine", f"⚠️ Malicious file moved to {quarantine_folder} for safety!")
    except Exception as e:
        messagebox.showerror("Error", f"Could not move file: {str(e)}")

# 🛡️ Function to warn about suspicious file types
def warn_suspicious_file(file_path):
    dangerous_extensions = [".exe", ".bat", ".sh", ".py", ".js"]
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext in dangerous_extensions:
        response = messagebox.askyesno("Warning", f"⚠️ You are scanning a potentially dangerous file type ({file_ext}). Continue?")
        if not response:
            return False  
    return True  

# 💾 Function to save scan history to a text file
def save_history_to_file():
    with open(HISTORY_FILE, "w") as file:
        for file_name, result_text in scan_history:
            file.write(file_name + "\n" + result_text + "\n---\n")

# 📂 Function to load scan history from a text file
def load_history_from_file():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as file:
            content = file.read().strip().split("\n---\n")
            for entry in content:
                if entry:
                    lines = entry.split("\n")
                    file_name = lines[0]
                    result_text = "\n".join(lines[1:])
                    scan_history.append((file_name, result_text))

# 🎯 Function to display scan results
def display_results():
    file_path = filedialog.askopenfilename()
    if file_path:
        if not warn_suspicious_file(file_path):
            return  

        try:
            result_text, is_malicious, scans = scan_file(file_path)
            result_textbox.config(state=tk.NORMAL)
            result_textbox.delete(1.0, tk.END)
            result_textbox.insert(tk.END, result_text)
            result_textbox.config(state=tk.DISABLED)

            display_scan_engines(scans)

            if is_malicious:
                quarantine_file(file_path)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

# 🕵️ Function to display scan engines and highlight malicious results
def display_scan_engines(scans):
    scan_results_box.config(state=tk.NORMAL)
    scan_results_box.delete(1.0, tk.END)

    for engine, result in scans.items():
        category = result["category"]
        text = f"{engine}: {result['result']}\n"

        if category == "malicious":
            scan_results_box.insert(tk.END, text, "malicious")
        else:
            scan_results_box.insert(tk.END, text, "normal")
    
    scan_results_box.config(state=tk.DISABLED)

# 🖥️ Create main GUI window
root = tk.Tk()
root.title("Cybersecurity File Scanner")
root.geometry("800x600")
root.configure(bg="#1e1e1e")
root.iconbitmap("")  # Insert your .ico file

# 📌 Sidebar
sidebar = tk.Frame(root, bg="#2c2c2c", width=200)
sidebar.pack(side=tk.LEFT, fill=tk.Y)

for text, command in [("Scan File", display_results), ("Change API", lambda: simpledialog.askstring("Change API Key", "Enter new API Key:"))]:
    tk.Button(sidebar, text=text, font=("Arial", 12), bg="#0078D4", fg="white", relief="flat", width=15, height=2, command=command).pack(pady=10)

# 🏠 Main content frame
main_frame = tk.Frame(root, bg="#1e1e1e")
main_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)

tk.Label(main_frame, text="Cybersecurity File Scanner", font=("Arial", 20, "bold"), bg="#1e1e1e", fg="white").pack(pady=20)

history_listbox = tk.Listbox(main_frame, height=5, bg="#2c2c2c", fg="white", font=("Arial", 12))
history_listbox.pack(fill=tk.BOTH)
history_listbox.bind("<<ListboxSelect>>", show_history_result)

result_textbox = scrolledtext.ScrolledText(main_frame, height=6, bg="#2c2c2c", fg="white")
result_textbox.pack(fill=tk.BOTH)

scan_results_box = scrolledtext.ScrolledText(main_frame, height=10, bg="#2c2c2c", fg="white")
scan_results_box.pack(fill=tk.BOTH)
scan_results_box.tag_configure("malicious", foreground="red", font=("Arial", 12, "bold"))

load_history_from_file()
update_history_list()

root.mainloop()
