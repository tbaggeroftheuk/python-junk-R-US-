import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import sys
import os

SCRIPT_PATH = "vdb.exe"  # Change to your script filename

class CommandGUI:
    def __init__(self, master):
        self.master = master
        master.title("VDB Script Runner")
        master.geometry("600x300")

        # Command selection
        tk.Label(master, text="Select Command:").pack(pady=5)
        self.command_var = tk.StringVar(value="encode")
        tk.OptionMenu(master, self.command_var, "encode", "decode", "download").pack(pady=5)

        # Arguments frame
        self.args_frame = tk.Frame(master)
        self.args_frame.pack(pady=10)

        tk.Label(self.args_frame, text="Arg 1:").grid(row=0, column=0, sticky="e")
        self.arg1_entry = tk.Entry(self.args_frame, width=50)
        self.arg1_entry.grid(row=0, column=1, padx=5)

        tk.Label(self.args_frame, text="Arg 2:").grid(row=1, column=0, sticky="e")
        self.arg2_entry = tk.Entry(self.args_frame, width=50)
        self.arg2_entry.grid(row=1, column=1, padx=5)

        # Browse buttons
        self.browse1_btn = tk.Button(self.args_frame, text="Browse", command=self.browse_arg1)
        self.browse1_btn.grid(row=0, column=2, padx=5)
        self.browse2_btn = tk.Button(self.args_frame, text="Browse", command=self.browse_arg2)
        self.browse2_btn.grid(row=1, column=2, padx=5)

        # Run button
        self.run_btn = tk.Button(master, text="Run Command", command=self.run_command)
        self.run_btn.pack(pady=20)

        # Output text
        self.output_text = tk.Text(master, height=8, width=70)
        self.output_text.pack(pady=5)

    def browse_arg1(self):
        cmd = self.command_var.get()
        if cmd in ["encode", "decode"]:
            file_path = filedialog.askopenfilename()
        elif cmd == "download":
            file_path = filedialog.askstring("URL", "Enter YouTube URL:")
        else:
            file_path = ""
        if file_path:
            self.arg1_entry.delete(0, tk.END)
            self.arg1_entry.insert(0, file_path)

    def browse_arg2(self):
        cmd = self.command_var.get()
        if cmd == "decode":
            folder = filedialog.askdirectory()
            if folder:
                self.arg2_entry.delete(0, tk.END)
                self.arg2_entry.insert(0, folder)
        elif cmd == "encode":
            file_path = filedialog.asksaveasfilename(defaultextension=".vdb")
            if file_path:
                self.arg2_entry.delete(0, tk.END)
                self.arg2_entry.insert(0, file_path)

    def run_command(self):
        cmd = self.command_var.get()
        arg1 = self.arg1_entry.get().strip()
        arg2 = self.arg2_entry.get().strip()
        if not arg1:
            messagebox.showerror("Error", "Arg 1 is required")
            return

        command = [sys.executable, SCRIPT_PATH, cmd, arg1]
        if cmd in ["encode", "decode"] and arg2:
            command.append(arg2)

        self.output_text.insert(tk.END, f"Running: {' '.join(command)}\n")
        self.output_text.see(tk.END)

        try:
            result = subprocess.run(command, capture_output=True, text=True)
            self.output_text.insert(tk.END, result.stdout)
            self.output_text.insert(tk.END, result.stderr)
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {e}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = CommandGUI(root)
    root.mainloop()
