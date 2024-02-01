import tkinter as tk
from tkinter import filedialog
import hashlib
import pyperclip

class HashCalculator:
    def __init__(self, master):
        self.master = master
        self.master.title("Hash Calculator")
        self.master.geometry("400x500")

        self.default_font = ("Segoe UI", 12)  # Using "Segoe UI" font for a modern look

        self.file_path_label = tk.Label(master, text="File Path:", font=self.default_font)
        self.file_path_label.pack(pady=10)

        self.file_path_entry = tk.Entry(master, width=40, font=self.default_font)
        self.file_path_entry.pack(pady=10)

        self.browse_button = tk.Button(master, text="Browse", command=self.browse_file, bg="gray", fg="white", font=self.default_font)
        self.browse_button.pack(pady=10)

        self.hash_algorithm_label = tk.Label(master, text="Select Hash Algorithm:", font=self.default_font)
        self.hash_algorithm_label.pack(pady=10)

        self.hash_algorithms = ["MD5", "SHA-1", "SHA-256"]
        self.selected_algorithm = tk.StringVar(master)
        self.selected_algorithm.set(self.hash_algorithms[0])  # Set the default algorithm to MD5

        self.algorithm_dropdown = tk.OptionMenu(master, self.selected_algorithm, *self.hash_algorithms)
        self.algorithm_dropdown.config(font=self.default_font)
        self.algorithm_dropdown.pack(pady=10)

        self.calculate_button = tk.Button(master, text="Calculate Hash", command=self.calculate_hash, bg="gray", fg="white", font=self.default_font)
        self.calculate_button.pack(pady=10)

        self.hash_result_label = tk.Label(master, text="Hash Result:", font=self.default_font)
        self.hash_result_label.pack(pady=10)

        self.copy_button = tk.Button(master, text="Copy", command=self.copy_to_clipboard, bg="gray", fg="white", font=self.default_font)
        self.copy_button.pack(pady=10)

        self.author_label = tk.Label(master, text="Author: Abhishek Jawak", font=("Segoe UI", 10), fg="gray")
        self.author_label.pack(side="bottom", pady=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_entry.delete(0, tk.END)
        self.file_path_entry.insert(0, file_path)

    def calculate_hash(self):
        file_path = self.file_path_entry.get()

        if not file_path:
            self.hash_result_label.config(text="Please select a file.")
            return

        try:
            with open(file_path, "rb") as file:
                file_content = file.read()
                algorithm = self.selected_algorithm.get()
                hash_result = self.calculate_algorithm_hash(file_content, algorithm)
                self.hash_result_label.config(text=f"Hash Result ({algorithm}): {hash_result}")
        except FileNotFoundError:
            self.hash_result_label.config(text="File not found.")
        except Exception as e:
            self.hash_result_label.config(text=f"Error: {str(e)}")

    def calculate_algorithm_hash(self, data, algorithm):
        if algorithm == "MD5":
            return hashlib.md5(data).hexdigest()
        elif algorithm == "SHA-1":
            return hashlib.sha1(data).hexdigest()
        elif algorithm == "SHA-256":
            return hashlib.sha256(data).hexdigest()

    def copy_to_clipboard(self):
        hash_result = self.hash_result_label.cget("text")
        if "Hash Result" in hash_result:
            hash_value = hash_result.split(": ")[1]
            pyperclip.copy(hash_value)
            self.master.clipboard_append(hash_value)
            self.master.update()

if __name__ == "__main__":
    root = tk.Tk()
    app = HashCalculator(root)
    root.mainloop()
