# main.py

import tkinter as tk
from gui import ECU_GUI

if __name__ == "__main__":
    root = tk.Tk()
    app = ECU_GUI(root)
    root.mainloop()
