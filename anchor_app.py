#!/usr/bin/env python3
import json
import platform
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

from mnemonic import Mnemonic  # pip install mnemonic

import anchor_core as core

APP_VERSION = "v0.3.2"


def canonical_seed_from_text(text_widget: tk.Text) -> str:
    raw = text_widget.get("1.0", "end-1c")
    return " ".join(raw.lower().split())


def safe_basename(p: str) -> str:
    return Path(p).name if p else "(no file selected)"


def load_logo_scaled(path: Path, target_px: int = 64):
    """
    Load logo and force display <= target_px using PhotoImage.subsample().
    Prevents 'giant logo' even if PNG is huge. No external deps.
    """
    if not path.exists():
        return None
    try:
        img = tk.PhotoImage(file=str(path))
    except Exception:
        return None

    w, h = img.width(), img.height()
    if w <= 0 or h <= 0:
        return img
    if w <= target_px and h <= target_px:
        return img

    factor = max(1, (max(w, h) + target_px - 1) // target_px)  # ceil(max/target)
    while (w // factor) > target_px or (h // factor) > target_px:
        factor += 1
    return img.subsample(factor, factor)


class ScrollFrame(tk.Frame):
    """Canvas + inner frame for real scrolling + wheel/trackpad support."""
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
            delta = event.delta
            if delta == 0:
                return
            if abs(delta) >= 120:
                steps = int(-delta / 120)
            else:
                steps = -1 if delta > 0 else 1
            self.canvas.yview_scroll(steps, "units")

        def _on_linux_up(_event):
            self.canvas.yview_scroll(-1, "units")

        def _on_linux_down(_event):
            self.canvas.yview_scroll(1, "units")

        widget.bind("<Enter>", _on_enter)
        widget.bind("<Leave>", _on_leave)


class AnchorApp:
    def __init__(self, root: tk.Tk):
        self.root = root

        # keep UI scale stable (avoid "everything huge")
        try:
            root.tk.call("tk", "scaling", 1.0)
        except Exception:
            pass

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
        # macOS (Darwin): keep dark text (mac sometimes draws “white buttons”)
        # Windows/Linux: use light text so it’s visible on dark buttons
        self.btn_text_on_white = "#0b0f14" if platform.system() == "Darwin" else self.text

        self.safe_mode = tk.BooleanVar(value=True)

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

    def _panel_box(self, parent, title_text: str) -> tk.Frame:
        wrapper = tk.Frame(parent, bg=self.border)
        wrapper.pack(fill="x", padx=18, pady=10)

        box = tk.Frame(wrapper, bg=self.panel)
        box.pack(fill="both", padx=1, pady=1)

        title = tk.Label(box, text=title_text, fg=self.text, bg=self.panel, font=self._font(13, "bold"))
        title.pack(anchor="w", padx=14, pady=(10, 6))
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

        self._panel_seed(inner)
        self._panel_file_proof(inner)
        self._panel_actions(inner)
        self._panel_status(inner)

    def _panel_seed(self, parent):
        box = self._panel_box(parent, "1) Seed (24 words)")

        hint = tk.Label(
            box, text="Paste your 24-word seed here (not stored):",
            fg=self.muted, bg=self.panel, font=self._font(12)
        )
        hint.pack(anchor="w", padx=14)

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

        # ✅ New: Generate + Copy buttons
        btn_row = tk.Frame(box, bg=self.panel)
        btn_row.pack(anchor="w", padx=14, pady=(0, 10))

        btn_gen = tk.Button(
            btn_row, text="Generate new 24-word seed", command=self._generate_seed,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(11, "bold")
        )
        btn_gen.pack(side="left")

        btn_copy = tk.Button(
            btn_row, text="Copy seed", command=self._copy_seed,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(11, "bold")
        )
        btn_copy.pack(side="left", padx=(10, 0))

    def _panel_file_proof(self, parent):
        box = self._panel_box(parent, "2) File + Proof")

        row1 = tk.Frame(box, bg=self.panel)
        row1.pack(fill="x", padx=14, pady=(6, 6))

        btn_file = tk.Button(
            row1, text="Choose file…", command=self._choose_file,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=10, font=self._font(12, "bold")
        )
        btn_file.pack(side="left")

        self.file_label = tk.Label(row1, text="(no file selected)", fg=self.muted, bg=self.panel, font=self._font(12))
        self.file_label.pack(side="left", padx=(12, 0))

        row2 = tk.Frame(box, bg=self.panel)
        row2.pack(fill="x", padx=14, pady=(8, 6))

        tk.Label(row2, text="Proof path:", fg=self.muted, bg=self.panel, font=self._font(12)).pack(side="left")

        self.proof_entry = tk.Entry(
            row2, bg=self.panel2, fg=self.text, insertbackground=self.text, relief="flat", font=self._font(12)
        )
        self.proof_entry.pack(side="left", fill="x", expand=True, padx=(10, 10), ipady=6)

        btn_load = tk.Button(
            row2, text="Load proof…", command=self._load_proof,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(12, "bold")
        )
        btn_load.pack(side="left", padx=(0, 8))

        btn_saveas = tk.Button(
            row2, text="Save as…", command=self._save_proof_as,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=12, pady=8, font=self._font(12, "bold")
        )
        btn_saveas.pack(side="left")

        row3 = tk.Frame(box, bg=self.panel)
        row3.pack(fill="x", padx=14, pady=(4, 10))

        self.proof_owner_label = tk.Label(
            row3, text="Proof owner fingerprint: —",
            fg=self.muted, bg=self.panel, font=self._font(12, "bold")
        )
        self.proof_owner_label.pack(anchor="w")

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
            bg=self.accent, fg=self.accent_fg,
            activebackground=self.accent, activeforeground=self.accent_fg,
            relief="flat", padx=14, pady=12, font=self._font(12, "bold")
        )
        btn_verify.pack(side="left", padx=(10, 0))

        btn_diag = tk.Button(
            row, text="DIAGNOSE", command=self._do_diagnose,
            bg=self.panel2, fg=self.btn_text_on_white,
            activebackground=self.panel2, activeforeground=self.btn_text_on_white,
            relief="flat", padx=14, pady=12, font=self._font(12, "bold")
        )
        btn_diag.pack(side="left", padx=(10, 0))

    def _panel_status(self, parent):
        box = self._panel_box(parent, "Status")
        self.status_text = tk.Text(
            box, height=6, wrap="word",
            bg=self.panel2, fg=self.text, relief="flat", font=self._font(11)
        )
        self.status_text.pack(fill="x", padx=14, pady=(8, 10))
        self._set_status("Ready.")

    # ---------------- actions ----------------

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
            "4) VERIFY checks later: file + proof.json + seed must match.\n\n"
            "Why it’s useful:\n"
            "• Integrity: detect if a file changed by even 1 byte.\n"
            "• Ownership/control: only the same seed can verify/control the proof.\n\n"
            "Two real situations where Anchor helps:\n"
            "1) Sending a proposal/contract draft:\n"
            "   You can prove the exact version you sent on that date, even if a copy later gets edited.\n"
            "2) Delivering a digital asset (design, report, dataset):\n"
            "   You can prove the delivered file is the original, and detect any tampering after delivery.\n\n"
            "Everything runs locally. No network. No seed storage."
        )
        messagebox.showinfo("What is Anchor?", text)

    def _update_seed_fp(self):
        seed = canonical_seed_from_text(self.seed_text)
        fp = core.seed_fingerprint(seed)
        self.seed_fp_label.configure(text=f"Current seed fingerprint:  {fp}")

    # --------- NEW: seed generation (BIP39 valid) ---------

    def _generate_seed(self):
        """
        Generates a valid BIP39 24-word mnemonic (english), fully offline.
        256-bit entropy => 24 words.
        """
        try:
            # Confirm to avoid accidental overwrite
            if canonical_seed_from_text(self.seed_text).strip():
                if not messagebox.askyesno(
                    "Generate seed?",
                    "This will replace the current seed in the box.\n\nGenerate a new 24-word seed now?"
                ):
                    return

            mnemo = Mnemonic("english")
            entropy = secrets.token_bytes(32)  # 256-bit
            seed = mnemo.to_mnemonic(entropy)

            # Safety check (checksum)
            if not mnemo.check(seed):
                raise ValueError("Generated seed failed BIP39 checksum (unexpected).")

            self.seed_text.delete("1.0", "end")
            self.seed_text.insert("1.0", seed)
            self._update_seed_fp()

            messagebox.showinfo(
                "Seed generated",
                "A new 24-word BIP39 seed was generated.\n\n"
                "WRITE IT DOWN and keep it offline.\n"
                "Anchor does NOT store your seed."
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate seed.\n\n{type(e).__name__}: {e}")

    def _copy_seed(self):
        seed = canonical_seed_from_text(self.seed_text).strip()
        if not seed:
            messagebox.showerror("Error", "No seed to copy.")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(seed)
            self.root.update()
            messagebox.showinfo(
                "Copied",
                "Seed copied to clipboard.\n\nBe careful: clipboard can be read by other apps."
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy seed.\n\n{type(e).__name__}: {e}")

    # -----------------------------------------------------

    def _choose_file(self):
        p = filedialog.askopenfilename(title="Choose file")
        if not p:
            return
        self.file_path = p
        self.file_label.configure(text=safe_basename(self.file_path))
        self._set_status(f"File selected: {safe_basename(self.file_path)}")

    def _load_proof(self):
        p = filedialog.askopenfilename(
            title="Load proof.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not p:
            return
        try:
            proof = core.load_proof(p)
        except Exception:
            messagebox.showerror("Error", "Failed — could not load proof.json (invalid JSON).")
            return

        self.proof_path = p
        self.proof_entry.delete(0, "end")
        self.proof_entry.insert(0, p)
        self.proof = proof

        owner = proof.get("seed_fp", "—")
        self.proof_owner_label.configure(text=f"Proof owner fingerprint:  {owner}")
        self._set_status(f"Proof loaded: {safe_basename(self.proof_path)}\nOwner: {owner}")

    def _save_proof_as(self):
        if not self.proof:
            messagebox.showerror("Error", "Failed — no proof in memory. Create or load a proof first.")
            return
        p = filedialog.asksaveasfilename(
            title="Save proof as…",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if not p:
            return
        try:
            core.save_proof(self.proof, p)
        except Exception:
            messagebox.showerror("Error", "Failed — could not save proof.")
            return
        self.proof_path = p
        self.proof_entry.delete(0, "end")
        self.proof_entry.insert(0, p)
        self._set_status(f"Proof saved: {safe_basename(self.proof_path)}")

    def _do_anchor(self):
        try:
            seed = canonical_seed_from_text(self.seed_text)
            if not self.file_path:
                messagebox.showerror("Error", "Failed — choose a file first.")
                return

            fn = getattr(core, "make_proof", None) or getattr(core, "create_proof", None)
            proof = fn(seed, self.file_path)

            self.proof = proof
            owner = proof.get("seed_fp", "—")
            self.proof_owner_label.configure(text=f"Proof owner fingerprint:  {owner}")

            p = filedialog.asksaveasfilename(
                title="Save proof.json",
                initialfile="proof.json",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            if not p:
                self._set_status("Proof created in memory (not saved).")
                return

            core.save_proof(proof, p)
            self.proof_path = p
            self.proof_entry.delete(0, "end")
            self.proof_entry.insert(0, p)

            self._set_status(
                f"Proof created ✅\nFile: {safe_basename(self.file_path)}\nSaved: {safe_basename(self.proof_path)}"
            )
            messagebox.showinfo("Anchor", "Proof created ✅")
        except Exception as e:
            messagebox.showerror("Error", "Failed — could not create proof. Use DIAGNOSE for details.")
            self._set_status(f"Error: {type(e).__name__}")

    def _do_verify(self):
        seed = canonical_seed_from_text(self.seed_text)
        proof_path = self.proof_entry.get().strip()

        if proof_path and not self.proof:
            try:
                self.proof = core.load_proof(proof_path)
                self.proof_path = proof_path
            except Exception:
                messagebox.showerror("Error", "Failed — could not load proof.json.")
                return

        if not self.file_path:
            messagebox.showerror("Error", "Failed — choose a file first.")
            return
        if not self.proof:
            messagebox.showerror("Error", "Failed — load a proof.json first.")
            return

        ok, msg = core.verify(seed, self.file_path, self.proof)

        if ok:
            success = "Valid ✅ — The file is real."
            self._set_status(success)
            messagebox.showinfo("Verify", success)
            return

        # Never show hashes on hash mismatch
        if "HASH MISMATCH" in msg or "hash" in msg.lower():
            fail = "Failed ❌ — Hash doesn’t match."
            self._set_status(fail)
            messagebox.showerror("Verify", fail)
            return

        if "SIGNATURE INVALID" in msg:
            fail = "Failed ❌ — Seed does not control this proof."
            self._set_status(fail)
            messagebox.showerror("Verify", fail)
            return

        fail = "Failed ❌ — Verification failed."
        self._set_status(fail)
        messagebox.showerror("Verify", fail)

    def _do_diagnose(self):
        seed = canonical_seed_from_text(self.seed_text)
        proof_path = self.proof_entry.get().strip()
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
