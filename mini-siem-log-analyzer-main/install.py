import os
import sys
import subprocess
import shutil

REQUIREMENTS = "requirements.txt"
CONFIG_EXAMPLE = "config.example.json"
CONFIG = "config.json"


def pip_install(requirements: str) -> int:
    print("Installing dependencies...")
    return subprocess.call([sys.executable, "-m", "pip", "install", "-r", requirements])


def verify_pywin32() -> bool:
    try:
        import win32evtlog  # noqa
        print("pywin32 OK")
        return True
    except Exception as e:
        print("pywin32 import failed:", e)
        return False


def ensure_dirs():
    for d in ["data", "logs"]:
        os.makedirs(d, exist_ok=True)


def ensure_config():
    if os.path.exists(CONFIG):
        return
    if os.path.exists(CONFIG_EXAMPLE):
        shutil.copyfile(CONFIG_EXAMPLE, CONFIG)
        print(f"Created {CONFIG} from {CONFIG_EXAMPLE}.")
        return
    # Fallback: create a minimal safe config file
    with open(CONFIG, "w", encoding="utf-8") as f:
        f.write("{}\n")
    print(f"Created empty {CONFIG}.")


def main():
    ensure_dirs()
    ensure_config()
    rc = pip_install(REQUIREMENTS)
    if rc != 0:
        sys.exit(rc)
    if not verify_pywin32():
        print("pywin32 is required for Windows Event Log access.")
        sys.exit(1)
    print("Initialization complete.")


if __name__ == "__main__":
    main()

