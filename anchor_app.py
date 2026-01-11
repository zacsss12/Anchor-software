#!/usr/bin/env python3
import json
import platform
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

from mnemonic import Mnemonic  # pip install mnemonic

import anchor_core as core

# Optional: system baseline (Linux/Arch)
try:
    import anchor_system as sysanchor
except Exception:
    sysanchor = None

APP_VERSION = "v0.3.2"


def canonical_seed_from_text(text_widget: tk.Text) -> str:
    raw = text_widget.get("1.0", "end").strip()
    words = raw.lower().split()
    return " ".join(words)


def load_logo_scaled(path: Path, target_px: int = 64):
    try:
        img = tk.PhotoImage(file=str(path))
        # If image bigger than target, subsample; if smaller, keep.
        w, h = img.width(), img.height()
        if w <= 0 or h <= 0:
            return None
        factor = max(1, int(max(w, h) / target_px))
        return img.subsample(factor, factor)
    except Exception:
        return None


class ScrollFrame(tk.Frame):
    def __init__(self, master, bg: str):
        super().__init__(master, bg=bg)

        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        self.vbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vbar.set)

        self.inner = tk.Frame(self.canvas, bg=bg)
        self.inner_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.canvas.pack(side="left", fill="both", expand=True)
        self.vbar.pack(side="right", fill="y")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self._bind_mousewheel(self.canvas)
        self._bind_mousewheel(self.inner)

    def _on_inner_configure(self, _):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, e):
        self.canvas.itemconfig(self.inner_id, width=e.width)

    def _bind_mousewheel(self, widget):
        def _on_enter(_event):
            widget.bind_all("<MouseWheel>", _on_mousewheel, add="+")
            widget.bind_all("<Button-4>", _on_linux_up, add="+")
            widget.bind_all("<Button-5>", _on_linux_down, add="+")

        def _on_leave(_event):
            widget.unbind_all("<MouseWheel>")
            widget.unbind_all("<Button-4>")
            widget.unbind_all("<Button-5>")

        def _on_mousewheel(event):
            # Windows/macOS
            delta = -1 * int(event.delta / 120)
            self.canvas.yview_scroll(delta, "units")

        def _on_linux_up(_event):
            self.canvas.yview_scroll(-3, "units")

        def _on_linux_down(_event):
            self.canvas.yview_scroll(3, "units")

        widget.bind("<Enter>", _on_enter)
        widget.bind("<Leave>", _on_leave)


class AnchorApp:
    def __init__(self, root: tk.Tk):
        self.master = root
        root.title(f"Anchor ({APP_VERSION})")
        root.minsize(980, 620)

        # Theme
        self.bg = "#0b0f14"
        self.panel = "#0f1620"
        self.panel2 = "#0d141d"
        self.text = "#e8eef7"
        self.muted = "#95a4b8"
        self.border = "#1f2a38"
        self.accent = "#33d1c6"
        self.accent_fg = "#052322"

        # ✅ FIX: readable button text across macOS/Windows
        self.btn_text_on_white = "#0b0f14" if platform.system() == "Darwin" else self.text

        self.safe_mode = tk.BooleanVar(value=True)
        self.section = tk.StringVar(value="File")

        self.file_path = ""
        self.proof_path = ""
        self.proof = None

        root.configure(bg=self.bg)

        self.sf = ScrollFrame(root, bg=self.bg)
        self.sf.pack(fill="both", expand=True)

        self._build_ui()
        self._update_seed_fp()

    def _font(self, size=12, weight="normal"):
        return ("Avenir", size, weight)

    def _panel_box(self, parent, title: str):
        box = tk.Frame(parent, bg=self.panel, highlightbackground=self.border, highlightthickness=1)
        box.pack(fill="x", padx=18, pady=10)

        lbl = tk.Label(box, text=title, fg=self.text, bg=self.panel, font=self._font(13, "bold"))
        lbl.pack(anchor="w", padx=14, pady=(10, 0))
        return box

    def _build_ui(self):
        inner = self.sf.inner

        # Header
        header = tk.Frame(inner, bg=self.bg)
        header.pack(fill="x", padx=18, pady=(14, 8))

        # Logo
        self.logo_img = None
        logo_path = Path(__file__).with_name("anchor_logo.png")
        self.logo_img = load_logo_scaled(logo_path, target_px=64)

        if self.logo_img:
            logo = tk.Label(header, image=self.logo_img, bg=self.bg)
            logo.pack(side="left", padx=(0, 12))
        else:
            spacer = tk.Frame(header, width=64, height=64, bg=self.bg)
            spacer.pack(side="left", padx=(0, 12))

        title = tk.Label(header, text="Anchor", fg=self.text, bg=self.bg, font=self._font(24, "bold"))
        title.pack(side="left")

        right = tk.Frame(header, bg=self.bg)
        right.pack(side="right")

        # Section tabs (top-right)  ✅ (esto es lo del rectángulo)
        tabs = tk.Frame(right, bg=self.bg)
        tabs.pack(side="left", padx=(0, 14))

        self.tab_btn_file = tk.Button(
            tabs, text="File", command=lambda: self._show_section("File"),
            bg=self.accent, fg=self.accent_fg,
            activebackground=self.accent, activeforeground=self.accent_fg,
            relief="flat", padx=12, pady=7, font=self._font(11, "bold")
        )
        self.tab_btn_file.pack(side="left")

        self.tab_btn_system = tk.Button(
            tabs, text="System", command=lambda: self._show_section("System"),
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=7, font=self._font(11, "bold")
        )
        self.tab_btn_system.pack(side="left", padx=(8, 0))

        chk = tk.Checkbutton(
            right, text="Safe mode", variable=self.safe_mode,
            bg=self.bg, fg=self.muted, activebackground=self.bg, activeforeground=self.muted,
            selectcolor=self.panel, font=self._font(12)
        )
        chk.pack(side="left", padx=(0, 12))

        info = tk.Button(
            right, text="What is Anchor?", command=self._show_info,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(12, "bold")
        )
        info.pack(side="left")

        # Sections container
        self.section_container = tk.Frame(inner, bg=self.bg)
        self.section_container.pack(fill="both", expand=True)
        self.section_container.grid_columnconfigure(0, weight=1)

        self.file_section = tk.Frame(self.section_container, bg=self.bg)
        self.system_section = tk.Frame(self.section_container, bg=self.bg)
        self.file_section.grid(row=0, column=0, sticky="nsew")
        self.system_section.grid(row=0, column=0, sticky="nsew")

        # File section (original)
        self._panel_seed(self.file_section)
        self._panel_file_proof(self.file_section)
        self._panel_actions(self.file_section)
        self._panel_status(self.file_section)

        # System section (new)
        self._panel_system(self.system_section)

        # Default view
        self._show_section("File")

    def _show_section(self, name: str):
        """Switch between top-level sections (File / System)."""
        self.section.set(name)

        if name == "System":
            self.system_section.tkraise()
            self.tab_btn_file.configure(
                bg=self.panel2, fg=self.btn_text_on_white,
                activebackground=self.panel2, activeforeground=self.btn_text_on_white
            )
            self.tab_btn_system.configure(
                bg=self.accent, fg=self.accent_fg,
                activebackground=self.accent, activeforeground=self.accent_fg
            )
        else:
            self.file_section.tkraise()
            self.tab_btn_system.configure(
                bg=self.panel2, fg=self.btn_text_on_white,
                activebackground=self.panel2, activeforeground=self.btn_text_on_white
            )
            self.tab_btn_file.configure(
                bg=self.accent, fg=self.accent_fg,
                activebackground=self.accent, activeforeground=self.accent_fg
            )

    def _panel_seed(self, parent):
        box = self._panel_box(parent, "1) Seed (24 words)")

        tk.Label(
            box, text="Paste your 24-word seed here (not stored):",
            fg=self.muted, bg=self.panel, font=self._font(11)
        ).pack(anchor="w", padx=14, pady=(8, 0))

        self.seed_text = tk.Text(
            box, height=3, wrap="word",
            bg=self.panel2, fg=self.text, insertbackground=self.text,
            relief="flat", font=self._font(12)
        )
        self.seed_text.pack(fill="x", padx=14, pady=(8, 10))
        self.seed_text.bind("<KeyRelease>", lambda e: self._update_seed_fp())

        self.seed_fp_label = tk.Label(
            box, text="Current seed fingerprint: —",
            fg=self.muted, bg=self.panel, font=self._font(12, "bold")
        )
        self.seed_fp_label.pack(anchor="w", padx=14, pady=(0, 8))

        btn_row = tk.Frame(box, bg=self.panel)
        btn_row.pack(fill="x", padx=14, pady=(0, 12))

        gen_btn = tk.Button(
            btn_row, text="Generate new 24-word seed", command=self._generate_seed,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(11, "bold")
        )
        gen_btn.pack(side="left")

        copy_btn = tk.Button(
            btn_row, text="Copy seed", command=self._copy_seed,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(11, "bold")
        )
        copy_btn.pack(side="left", padx=(10, 0))

    def _panel_file_proof(self, parent):
        box = self._panel_box(parent, "2) File + Proof")

        row = tk.Frame(box, bg=self.panel)
        row.pack(fill="x", padx=14, pady=(8, 8))

        btn_file = tk.Button(
            row, text="Choose file...", command=self._choose_file,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(11, "bold")
        )
        btn_file.pack(side="left")

        self.file_label = tk.Label(row, text="(no file selected)", fg=self.muted, bg=self.panel, font=self._font(11))
        self.file_label.pack(side="left", padx=(12, 0))

        row2 = tk.Frame(box, bg=self.panel)
        row2.pack(fill="x", padx=14, pady=(0, 6))

        tk.Label(row2, text="Proof path:", fg=self.muted, bg=self.panel, font=self._font(11)).pack(side="left")
        self.proof_path_label = tk.Label(row2, text="—", fg=self.text, bg=self.panel, font=self._font(11))
        self.proof_path_label.pack(side="left", padx=(8, 0))

        row3 = tk.Frame(box, bg=self.panel)
        row3.pack(fill="x", padx=14, pady=(0, 10))

        tk.Label(row3, text="Proof owner fingerprint:", fg=self.muted, bg=self.panel, font=self._font(11)).pack(side="left")
        self.proof_fp_label = tk.Label(row3, text="—", fg=self.text, bg=self.panel, font=self._font(11, "bold"))
        self.proof_fp_label.pack(side="left", padx=(8, 0))

        btns = tk.Frame(box, bg=self.panel)
        btns.pack(fill="x", padx=14, pady=(0, 12))

        load_btn = tk.Button(
            btns, text="Load proof...", command=self._load_proof,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(11, "bold")
        )
        load_btn.pack(side="right", padx=(10, 0))

        save_btn = tk.Button(
            btns, text="Save as...", command=self._save_proof_as,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(11, "bold")
        )
        save_btn.pack(side="right")

    def _panel_actions(self, parent):
        box = self._panel_box(parent, "3) Actions")

        row = tk.Frame(box, bg=self.panel)
        row.pack(fill="x", padx=14, pady=(8, 10))

        btn_anchor = tk.Button(
            row, text="ANCHOR (create proof.json)", command=self._do_anchor,
            bg=self.accent, fg=self.accent_fg,
            activebackground=self.accent, activeforeground=self.accent_fg,
            relief="flat", padx=14, pady=12, font=self._font(12, "bold")
        )
        btn_anchor.pack(side="left")

        btn_verify = tk.Button(
            row, text="VERIFY (file + proof.json)", command=self._do_verify,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=14, pady=12, font=self._font(12, "bold")
        )
        btn_verify.pack(side="left", padx=(12, 0))

        btn_diag = tk.Button(
            row, text="DIAGNOSE", command=self._do_diagnose,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=14, pady=12, font=self._font(12, "bold")
        )
        btn_diag.pack(side="left", padx=(12, 0))

    # ----------------------------
    # System baseline (Linux/Arch)
    # ----------------------------

    def _panel_system(self, parent):
        box = self._panel_box(parent, "System (baseline + verify)")

        hint = (
            "Create a reproducible baseline of a folder (or / on Linux) and verify drift over time.\n"
            "On Windows this section is limited; on Linux/Arch you can baseline '/'."
        )
        tk.Label(box, text=hint, fg=self.muted, bg=self.panel, justify="left", font=self._font(11)).pack(
            anchor="w", padx=14, pady=(8, 10)
        )

        row = tk.Frame(box, bg=self.panel)
        row.pack(fill="x", padx=14, pady=(0, 10))

        tk.Label(row, text="Root path:", fg=self.text, bg=self.panel, font=self._font(12, "bold")).pack(side="left")
        self.sys_root_var = tk.StringVar(value="/" if platform.system() == "Linux" else str(Path.home()))
        self.sys_root_entry = tk.Entry(
            row, textvariable=self.sys_root_var,
            bg=self.panel2, fg=self.text, insertbackground=self.text,
            relief="flat", font=self._font(12)
        )
        self.sys_root_entry.pack(side="left", fill="x", expand=True, padx=(10, 10))
        tk.Button(
            row, text="Browse...", command=self._browse_sys_root,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(11, "bold")
        ).pack(side="left")

        row2 = tk.Frame(box, bg=self.panel)
        row2.pack(fill="x", padx=14, pady=(0, 10))

        self.sys_baseline_dir = tk.StringVar(value="")
        tk.Label(row2, text="Baseline folder:", fg=self.text, bg=self.panel, font=self._font(12, "bold")).pack(side="left")
        self.sys_baseline_label = tk.Label(
            row2, textvariable=self.sys_baseline_dir,
            fg=self.muted, bg=self.panel, font=self._font(11)
        )
        self.sys_baseline_label.pack(side="left", padx=(10, 10), fill="x", expand=True)

        tk.Button(
            row2, text="Choose...", command=self._choose_baseline_dir,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(11, "bold")
        ).pack(side="left")

        row3 = tk.Frame(box, bg=self.panel)
        row3.pack(fill="x", padx=14, pady=(8, 12))

        tk.Button(
            row3, text="CREATE BASELINE", command=self._do_system_baseline_create,
            bg=self.accent, fg=self.accent_fg,
            activebackground=self.accent, activeforeground=self.accent_fg,
            relief="flat", padx=14, pady=12, font=self._font(12, "bold")
        ).pack(side="left")

        tk.Button(
            row3, text="VERIFY BASELINE", command=self._do_system_baseline_verify,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=14, pady=12, font=self._font(12, "bold")
        ).pack(side="left", padx=(12, 0))

        note = "Baseline will create: baseline.manifest.jsonl + baseline.proof.json"
        tk.Label(box, text=note, fg=self.muted, bg=self.panel, font=self._font(10)).pack(
            anchor="w", padx=14, pady=(0, 10)
        )

        if sysanchor is None:
            self.sys_root_entry.configure(state="disabled")
            # no status panel yet if user starts on System tab; that's ok.

    def _browse_sys_root(self):
        chosen = filedialog.askdirectory(title="Choose root folder to baseline")
        if chosen:
            self.sys_root_var.set(chosen)

    def _choose_baseline_dir(self):
        chosen = filedialog.askdirectory(title="Choose folder to store baseline files")
        if chosen:
            self.sys_baseline_dir.set(chosen)

    def _read_manifest_jsonl(self, path: Path):
        data = {}
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                data[obj["path"]] = obj
        return data

    def _do_system_baseline_create(self):
        if sysanchor is None:
            messagebox.showerror("System baseline", "anchor_system.py is missing or failed to import.")
            return

        seed = canonical_seed_from_text(self.seed_text)
        try:
            core.assert_24_words(core.normalize_seed(seed))
        except Exception as e:
            messagebox.showerror("Seed", str(e))
            return

        root_path = self.sys_root_var.get().strip() or "/"
        out_dir = self.sys_baseline_dir.get().strip()
        if not out_dir:
            messagebox.showwarning("Baseline folder", "Choose a baseline folder first.")
            return

        outp = Path(out_dir)
        outp.mkdir(parents=True, exist_ok=True)
        manifest_path = outp / "baseline.manifest.jsonl"
        proof_path = outp / "baseline.proof.json"

        self._set_status("Building baseline manifest... (this can take a while)")
        self.master.update_idletasks()

        try:
            manifest = sysanchor.build_manifest(root=root_path)
            manifest_jsonl = sysanchor.manifest_to_jsonl(manifest)
            manifest_sha = sysanchor.sha256_text(manifest_jsonl)
            proof = core.create_manifest_proof(seed, manifest_sha, label=f"system:{root_path}")

            manifest_path.write_text(manifest_jsonl, encoding="utf-8")
            core.save_proof(proof, proof_path)

            self._set_status(
                "✅ Baseline created\n"
                f"• Root: {root_path}\n"
                f"• Files: {len(manifest)}\n"
                f"• Manifest: {manifest_path}\n"
                f"• Proof: {proof_path}"
            )
        except Exception as e:
            self._set_status(f"❌ Baseline error: {e}")
            messagebox.showerror("Baseline error", str(e))

    def _do_system_baseline_verify(self):
        if sysanchor is None:
            messagebox.showerror("System baseline", "anchor_system.py is missing or failed to import.")
            return

        seed = canonical_seed_from_text(self.seed_text)
        try:
            core.assert_24_words(core.normalize_seed(seed))
        except Exception as e:
            messagebox.showerror("Seed", str(e))
            return

        root_path = self.sys_root_var.get().strip() or "/"
        base_dir = self.sys_baseline_dir.get().strip()
        if not base_dir:
            messagebox.showwarning("Baseline folder", "Choose the baseline folder you created earlier.")
            return

        basep = Path(base_dir)
        manifest_path = basep / "baseline.manifest.jsonl"
        proof_path = basep / "baseline.proof.json"

        if not manifest_path.exists() or not proof_path.exists():
            messagebox.showerror(
                "Baseline missing",
                "baseline.manifest.jsonl and/or baseline.proof.json not found in the selected folder."
            )
            return

        self._set_status("Verifying baseline... (rebuilding manifest)")
        self.master.update_idletasks()

        try:
            baseline_manifest = self._read_manifest_jsonl(manifest_path)
            proof = core.load_proof(proof_path)

            current_manifest = sysanchor.build_manifest(root=root_path)
            current_jsonl = sysanchor.manifest_to_jsonl(current_manifest)
            current_sha = sysanchor.sha256_text(current_jsonl)

            ok, msg = core.verify_manifest_proof(seed, current_sha, proof)

            old = {
                k: sysanchor.FileEntry(
                    path=v["path"],
                    sha256=v["sha256"],
                    size=v.get("size", 0),
                    mtime_ns=v.get("mtime_ns", 0),
                    mode=v.get("mode", 0),
                    uid=v.get("uid", 0),
                    gid=v.get("gid", 0),
                )
                for k, v in baseline_manifest.items()
            }
            new = current_manifest

            diff = sysanchor.diff_manifests(old, new)

            pac = None
            if platform.system() == "Linux":
                try:
                    pac = sysanchor.classify_changes_pacman(diff["modified"])
                except Exception:
                    pac = None

            report = [
                msg,
                "",
                f"Root: {root_path}",
                f"Added: {len(diff['added'])}",
                f"Removed: {len(diff['removed'])}",
                f"Modified: {len(diff['modified'])}",
            ]

            if diff["added"]:
                report.append("")
                report.append("➕ Added (first 25):")
                report += diff["added"][:25]

            if diff["removed"]:
                report.append("")
                report.append("➖ Removed (first 25):")
                report += diff["removed"][:25]

            if diff["modified"]:
                report.append("")
                report.append("✏ Modified (first 25):")
                report += diff["modified"][:25]

            if pac is not None and diff["modified"]:
                report.append("")
                report.append("Pacman classification (modified):")
                report.append(f"• Owned by package: {len(pac['owned_by_pkg'])}")
                report.append(f"• Not owned (manual / unknown): {len(pac['not_owned'])}")

            self._set_status("\n".join(report))
            messagebox.showinfo("System verify", "Verification report written in the Status panel.")
        except Exception as e:
            self._set_status(f"❌ Verify error: {e}")
            messagebox.showerror("Verify error", str(e))

    def _panel_status(self, parent):
        box = self._panel_box(parent, "Status")

        self.status_text = tk.Text(
            box, height=9, wrap="word",
            bg=self.panel2, fg=self.text, insertbackground=self.text,
            relief="flat", font=self._font(11)
        )
        self.status_text.pack(fill="both", expand=True, padx=14, pady=(8, 12))
        self._set_status("Ready.")

    def _set_status(self, msg: str):
        self.status_text.delete("1.0", "end")
        self.status_text.insert("1.0", msg)

    def _show_info(self):
        text = (
            "What is Anchor?\n"
            "Anchor is a local tool that creates a cryptographic proof (proof.json) that a file existed\n"
            "in an exact state at a specific time — and that you control that proof using your 24-word seed.\n\n"
            "How it works (simple):\n"
            "1) You paste your 24-word seed (never stored).\n"
            "2) You select a file.\n"
            "3) ANCHOR creates proof.json (file hash + HMAC signature).\n"
            "4) VERIFY checks the file still matches + your seed controls the proof.\n\n"
            "New: System tab\n"
            "• Create a baseline (manifest + proof) for a folder or system root and verify drift later.\n"
        )
        messagebox.showinfo("About Anchor", text)

    def _update_seed_fp(self):
        seed = canonical_seed_from_text(self.seed_text)
        if seed.strip():
            fp = core.seed_fingerprint(seed)
            self.seed_fp_label.configure(text=f"Current seed fingerprint: {fp}")
        else:
            self.seed_fp_label.configure(text="Current seed fingerprint: —")

    def _generate_seed(self):
        mnemo = Mnemonic("english")
        entropy = secrets.token_bytes(32)  # 256-bit -> 24 words
        seed = mnemo.to_mnemonic(entropy)
        self.seed_text.delete("1.0", "end")
        self.seed_text.insert("1.0", seed)
        self._update_seed_fp()

    def _copy_seed(self):
        seed = canonical_seed_from_text(self.seed_text)
        if not seed:
            messagebox.showwarning("Copy seed", "Seed is empty.")
            return
        self.master.clipboard_clear()
        self.master.clipboard_append(seed)
        messagebox.showinfo("Copy seed", "Seed copied to clipboard.")

    def _choose_file(self):
        path = filedialog.askopenfilename(title="Choose file")
        if not path:
            return
        self.file_path = path
        self.file_label.configure(text=Path(path).name)

    def _load_proof(self):
        path = filedialog.askopenfilename(title="Load proof.json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.proof = core.load_proof(path)
            self.proof_path = path
            self.proof_path_label.configure(text=path)
            fp = self.proof.get("seed_fp", "—")
            self.proof_fp_label.configure(text=fp)
            self._set_status("Proof loaded.")
        except Exception as e:
            messagebox.showerror("Load proof", str(e))

    def _save_proof_as(self):
        if not self.proof:
            messagebox.showwarning("Save proof", "No proof loaded/created yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Save proof as",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if not path:
            return
        try:
            core.save_proof(self.proof, path)
            self.proof_path = path
            self.proof_path_label.configure(text=path)
            self._set_status(f"Proof saved: {path}")
        except Exception as e:
            messagebox.showerror("Save proof", str(e))

    def _do_anchor(self):
        seed = canonical_seed_from_text(self.seed_text)
        if not self.file_path:
            messagebox.showwarning("Anchor", "Choose a file first.")
            return
        try:
            proof = core.create_proof(seed, self.file_path)
            self.proof = proof
            self.proof_fp_label.configure(text=proof.get("seed_fp", "—"))
            self._set_status("✅ Proof created. Use 'Save as...' to export proof.json.")
        except Exception as e:
            self._set_status(f"❌ Anchor error: {e}")
            messagebox.showerror("Anchor error", str(e))

    def _do_verify(self):
        seed = canonical_seed_from_text(self.seed_text)
        if not self.file_path:
            messagebox.showwarning("Verify", "Choose a file first.")
            return
        if not self.proof:
            messagebox.showwarning("Verify", "Load a proof.json first.")
            return
        ok, msg = core.verify(seed, self.file_path, self.proof)
        self._set_status(msg)
        messagebox.showinfo("Verify", msg)

    def _do_diagnose(self):
        seed = canonical_seed_from_text(self.seed_text)
        proof_path = self.proof_path if self.proof_path else None
        d = core.diagnose(seed, self.file_path, proof_path)
        pretty = json.dumps(d, indent=2, sort_keys=True)
        self._set_status(pretty)
        messagebox.showinfo("Diagnose", "DIAGNOSE output written in the Status panel.")


def main():
    root = tk.Tk()
    app = AnchorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
