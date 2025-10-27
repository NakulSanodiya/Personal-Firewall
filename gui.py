import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

from .core import Firewall
from .rules import Rule

def run_gui(fw: Firewall) -> None:
    root = tk.Tk()
    root.title("Personal Firewall (PFW)")

    started = {"enforce": False, "monitor": False}

    def refresh_rules():
        for row in rules_tree.get_children():
            rules_tree.delete(row)
        for r in fw.list_rules():
            rules_tree.insert("", "end", iid=r.id, values=(r.priority, r.id, r.action, r.direction, r.protocol, r.src_ip or "", r.src_port or "", r.dst_ip or "", r.dst_port or "", r.interface or "", r.log, r.enabled))
        root.after(5000, refresh_rules)

    def on_start():
        try:
            fw.start(enforce=True, monitor=True)
            started["enforce"] = True
            started["monitor"] = True
            status_var.set("Running (enforce+monitor)")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_stop():
        try:
            fw.stop()
            started["enforce"] = False
            started["monitor"] = False
            status_var.set("Stopped")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_add_rule():
        try:
            dialog = tk.Toplevel(root)
            dialog.title("Add Rule")
            fields = {}
            labels = ["description", "action", "direction", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "interface", "priority", "log", "enabled"]
            defaults = {"action": "BLOCK", "direction": "INCOMING", "protocol": "ANY", "priority": "100", "log": "false", "enabled": "true"}
            for i, k in enumerate(labels):
                tk.Label(dialog, text=k).grid(row=i, column=0, sticky="e")
                ent = tk.Entry(dialog)
                ent.grid(row=i, column=1, sticky="w")
                ent.insert(0, defaults.get(k, ""))
                fields[k] = ent

            def submit():
                d = {k: fields[k].get().strip() for k in labels}
                r = Rule.from_dict({
                    "description": d["description"],
                    "action": d["action"].upper(),
                    "direction": d["direction"].upper(),
                    "protocol": d["protocol"].upper(),
                    "src_ip": d["src_ip"] or None,
                    "dst_ip": d["dst_ip"] or None,
                    "src_port": d["src_port"] or None,
                    "dst_port": d["dst_port"] or None,
                    "interface": d["interface"] or None,
                    "priority": int(d["priority"] or "100"),
                    "log": d["log"].lower() in ("1", "true", "yes"),
                    "enabled": d["enabled"].lower() in ("1", "true", "yes"),
                    "profiles": [fw.active_profile],
                })
                fw.add_rule(r)
                refresh_rules()
                dialog.destroy()

            tk.Button(dialog, text="Add", command=submit).grid(row=len(labels), column=0, columnspan=2, pady=5)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    # Layout
    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="both", expand=True)

    status_var = tk.StringVar(value="Stopped")
    ttk.Label(frm, textvariable=status_var).pack(anchor="w")

    btns = ttk.Frame(frm)
    btns.pack(fill="x", pady=5)
    ttk.Button(btns, text="Start", command=on_start).pack(side="left", padx=5)
    ttk.Button(btns, text="Stop", command=on_stop).pack(side="left", padx=5)
    ttk.Button(btns, text="Add Rule", command=on_add_rule).pack(side="left", padx=5)
    ttk.Button(btns, text="Reload", command=lambda: [fw.reload(), refresh_rules()]).pack(side="left", padx=5)

    cols = ["Priority", "ID", "Action", "Direction", "Protocol", "Src IP", "Src Port", "Dst IP", "Dst Port", "IF", "Log", "Enabled"]
    rules_tree = ttk.Treeview(frm, columns=cols, show="headings", height=15)
    for c in cols:
        rules_tree.heading(c, text=c)
        rules_tree.column(c, width=110 if c != "ID" else 220)
    rules_tree.pack(fill="both", expand=True)

    refresh_rules()
    root.mainloop()
