# ONYX CLIENT - GOLDEN MASTER v1.1
# Secure, Zero-Knowledge File Transfer
# Features: SRP Hardened Math, Integrity Check, Auto-Zip, Interactive Guide

import asyncio
import hashlib
import os
import shutil
import tempfile
import secrets
import re
import typer
import websockets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich.progress import Progress
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

app = typer.Typer(help="Onyx: Zero-Knowledge File Transfer Tool", add_completion=False)
console = Console()

# --- CONFIGURATION ---
# ⚠️ CHANGE THIS to your Render URL for production!
# Example: "wss://onyx-relay.onrender.com/ws/"
SERVER_URL = "wss://onyx-relay.onrender.com/ws/"

# RFC 3526 MODP Group 14 (2048-bit Prime)
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

CHUNK_SIZE = 64 * 1024  # 64KB chunks

WORDLIST = [
    "alpha", "bravo", "delta", "echo", "fox", "golf", "hotel", "india",
    "orbit", "lunar", "solar", "nebula", "comet", "star", "planet", "void",
    "cyber", "logic", "matrix", "node", "grid", "pixel", "vector", "code",
    "blue", "red", "green", "gold", "silver", "iron", "steel", "neon",
    "tiger", "lion", "wolf", "bear", "eagle", "hawk", "shark", "whale",
    "north", "south", "east", "west", "wind", "storm", "rain", "snow",
    "mountain", "river", "ocean", "forest", "desert", "island", "valley"
]

# --- SECURITY CORE ---

def get_generator_from_pass(password: str):
    """Derive g from password using PBKDF2 (Hardened against Brute-Force)."""
    salt = b"onyx_static_salt" 
    kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    num = int.from_bytes(kdf, 'big')
    
    # Square to ensure Quadratic Residue (Subgroup Safety)
    safe_g = pow(num, 2, P)
    if safe_g < 2: safe_g = 2
    return safe_g

def derive_shared_key(password: str, my_secret: int, other_public: int):
    """Calculate shared secret using SRP/Diffie-Hellman."""
    shared_int = pow(other_public, my_secret, P)
    return hashlib.sha256(str(shared_int).encode()).digest()

def sanitize_filename(filename):
    """Strips paths and dangerous characters to prevent traversal attacks."""
    name = os.path.basename(filename)
    clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', name)
    if not clean_name: clean_name = "onyx_file"
    return clean_name

# --- FILE HELPERS ---

def compress_folder(folder_path):
    """Zips a folder into a temporary file for transfer."""
    console.print(f"[yellow]📦 Compressing folder '{folder_path}'...[/yellow]")
    temp_dir = tempfile.gettempdir()
    base_name = os.path.basename(os.path.normpath(folder_path))
    output_path = os.path.join(temp_dir, f"{base_name}")
    zip_path = shutil.make_archive(output_path, 'zip', folder_path)
    return zip_path

# --- NETWORK CORE ---

async def connect_and_transfer(mode: str, code: str, filepath: str = None, is_temp: bool = False):
    # Security Warning
    if "wss://" not in SERVER_URL and "localhost" not in SERVER_URL:
        console.print("[bold red]🚨 SECURITY RISK: Insecure connection (ws://).[/bold red]")
        console.print("Onyx requires 'wss://' for remote transfers.")
        return

    room_id_hash = hashlib.sha256(code.encode()).hexdigest()[:16] # First 16 chars is enough
    
    uri = f"{SERVER_URL}{room_id_hash}"
    
    console.print(f"[dim]   (Public Room Hash: {room_id_hash})[/dim]") # Debug info
    
    # --- UX UPDATE: Extended Warning ---
    console.print(f"[bold yellow]🔌 Connecting to Onyx Relay...[/bold yellow]")
    console.print("[dim]   (If the server is sleeping, this may take up to 3 minutes to wake up)[/dim]")
    
    try:
        # TIMEOUT UPDATE: Changed from 60 to 180 seconds (3 minutes)
        async with websockets.connect(uri, ping_interval=None, open_timeout=180) as websocket:
            
            console.print("[green]✅ Connected! Waiting for peer...[/green]")
            
            # 1. SYNC
            try:
                start_signal = await websocket.recv()
                if start_signal != b"READY":
                    console.print("[red]❌ Protocol Error.[/red]")
                    return
            except websockets.exceptions.ConnectionClosed:
                console.print("[red]❌ Connection Lost.[/red]")
                return

            console.print("[bold cyan]🤝 Peer Linked. Initiating Handshake...[/bold cyan]")

            # 2. ZKP HANDSHAKE
            g = get_generator_from_pass(code)
            my_secret = int.from_bytes(os.urandom(32), 'big')
            my_public = pow(g, my_secret, P)

            await websocket.send(str(my_public).encode())
            other_public = int((await websocket.recv()).decode())
            
            session_key = derive_shared_key(code, my_secret, other_public)
            aes = AESGCM(session_key)
            
            console.print("[bold green]🔐 Secure Tunnel Established.[/bold green]")

            # 3. TRANSFER
            if mode == "send":
                await send_file(websocket, aes, filepath)
            elif mode == "receive":
                await receive_file(websocket, aes)

    except asyncio.TimeoutError:
        console.print("\n[bold red]❌ Connection Timed Out (3 mins).[/bold red]")
        console.print("The server is taking too long. Please try running the command again.")
        
    except Exception as e:
        console.print(f"[bold red]❌ Critical Error:[/bold red] {e}")
        
    finally:
        # Zero-Trace Cleanup
        if is_temp and filepath and os.path.exists(filepath):
            try: os.remove(filepath)
            except OSError: pass

async def send_file(websocket, aes, filepath):
    file_size = os.path.getsize(filepath)
    filename = os.path.basename(filepath)
    
    # Calculate Checksum
    console.print("[yellow]⏳ Calculating Integrity Checksum...[/yellow]")
    file_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            file_hash.update(chunk)
    checksum = file_hash.hexdigest()

    # Send Metadata
    metadata = f"{filename}|{file_size}|{checksum}".encode()
    nonce = os.urandom(12)
    enc_meta = aes.encrypt(nonce, metadata, None)
    await websocket.send(nonce + enc_meta)
    
    # Stream File
    with open(filepath, "rb") as f:
        with Progress() as progress:
            task = progress.add_task("[green]Uploading...", total=file_size)
            while chunk := f.read(CHUNK_SIZE):
                nonce = os.urandom(12)
                enc_chunk = aes.encrypt(nonce, chunk, None)
                msg = len(enc_chunk).to_bytes(4, 'big') + nonce + enc_chunk
                await websocket.send(msg)
                progress.update(task, advance=len(chunk))
                
    console.print("\n[bold white on green] ✨ Transfer Complete! [/bold white on green]")

async def receive_file(websocket, aes):
    data = await websocket.recv()
    nonce, ciphertext = data[:12], data[12:]
    
    try:
        dec_meta = aes.decrypt(nonce, ciphertext, None)
        raw_filename, file_size_str, sender_checksum = dec_meta.decode().split("|")
        file_size = int(file_size_str)
        filename = sanitize_filename(raw_filename)
    except:
        console.print("[red]❌ Handshake Failed! Password Mismatch?[/red]")
        return

    console.print(f"📥 Incoming: [bold]{filename}[/bold] ({file_size / (1024*1024):.2f} MB)")
    
    received_hash = hashlib.sha256()
    received_bytes = 0
    
    with open(f"downloaded_{filename}", "wb") as f:
        with Progress() as progress:
            task = progress.add_task("[cyan]Downloading...", total=file_size)
            
            while received_bytes < file_size:
                raw_msg = await websocket.recv()
                nonce = raw_msg[4:16]
                ciphertext = raw_msg[16:]
                
                chunk = aes.decrypt(nonce, ciphertext, None)
                f.write(chunk)
                received_hash.update(chunk)
                received_bytes += len(chunk)
                progress.update(task, advance=len(chunk))

    if received_hash.hexdigest() == sender_checksum:
        console.print(f"\n[bold white on green] ✅ Integrity Verified! [/bold white on green]")
    else:
        console.print(f"\n[bold white on red] ⚠️ CORRUPTION DETECTED! [/bold white on red]")

# --- CLI COMMANDS ---

@app.command()
def gen_code():
    """Generates a secure 8-word passphrase."""
    secure_words = [secrets.choice(WORDLIST) for _ in range(8)]
    code = "-".join(secure_words)
    console.print(Panel(f"[bold green]{code}[/bold green]", title="🔐 Secure Passphrase", expand=False))

@app.command()
def send(path: str = typer.Argument(..., help="Path to file or folder")):
    """Send a file or folder securely."""
    if not os.path.exists(path):
        console.print(f"[red]❌ Error: '{path}' not found.[/red]")
        return

    target_file = path
    is_temp = False

    if os.path.isdir(path):
        target_file = compress_folder(path)
        is_temp = True
    
    console.print("[dim]Enter the shared code (or generate one with 'gen-code')[/dim]")
    code = typer.prompt("🔑 Secret Code", hide_input=True)
    confirm = typer.prompt("🔑 Confirm Code", hide_input=True)
    
    if code != confirm:
        console.print("[red]❌ Codes do not match![/red]")
        if is_temp: os.remove(target_file)
        return

    asyncio.run(connect_and_transfer("send", code, target_file, is_temp))

@app.command()
def receive():
    """Receive a file securely."""
    code = typer.prompt("🔑 Secret Code", hide_input=True)
    asyncio.run(connect_and_transfer("receive", code))

@app.command()
def guide():
    """Shows a beginner's guide and cheat sheet."""
    
    # 1. Title Banner
    console.print(Panel.fit("[bold cyan]ONYX: The Zero-Knowledge Transfer Tool[/bold cyan]", border_style="cyan"))
    
    # 2. Cheat Sheet Table
    table = Table(title="Quick Reference", box=None)
    table.add_column("Goal", style="cyan", no_wrap=True)
    table.add_column("Command", style="green")
    
    table.add_row("1. Generate Password", "onyx.exe gen-code")
    table.add_row("2. Send a File", "onyx.exe send my_photo.jpg")
    table.add_row("3. Send a Folder", "onyx.exe send MyFolder")
    table.add_row("4. Receive", "onyx.exe receive")
    
    console.print(table)
    
    # 3. How It Works Section
    md = Markdown("""
    **How to use:**
    1. **Alice** (Sender) runs `onyx.exe gen-code` to get a secret phrase.
    2. **Alice** shares the phrase with **Bob** via a secure channel (Signal, verbal).
    3. **Bob** (Receiver) runs `onyx.exe receive` and enters the phrase.
    4. **Alice** runs `onyx.exe send file.txt` and enters the same phrase.
    5. The tunnel opens, file transfers, and vanishes.
    """)
    console.print(Panel(md, title="Workflow", border_style="yellow"))

if __name__ == "__main__":
    app()