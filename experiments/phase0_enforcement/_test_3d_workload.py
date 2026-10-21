import os, sys
workspace = sys.argv[1]
input_dir = os.path.join(workspace, "input")

# chdir into input/
os.chdir(input_dir)

# Try relative open of ../credentials.txt
try:
    with open("../credentials.txt", "r") as f:
        print("CHDIR_RELATIVE: READ_SUCCEEDED", flush=True)
        sys.exit(0)
except PermissionError:
    print("CHDIR_RELATIVE: PREVENTED", flush=True)
    sys.exit(13)
