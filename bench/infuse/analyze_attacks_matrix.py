import os, sys
from pathlib import Path
try:
    import tomllib
except ImportError:
    import tomli as tomllib

attacks_dir = Path('/home/thiji/infuse/benchmark/attacks')
network_dependent = {'attack_1', 'attack_2', 'attack_4', 'attack_23', 'attack_25', 'attack_27', 'attack_30'}

candidates = []

for a in sorted(attacks_dir.iterdir(), key=lambda p: int(p.name.split('_')[1]) if p.name.startswith('attack_') and p.name.split('_')[1].isdigit() else 999):
    if not a.is_dir() or not a.name.startswith('attack_') or a.name in network_dependent:
        continue
    aid = a.name
    setup_file = a / 'setup.sh'
    sol_file = a / 'solution.sh'
    test_file = a / 'tests' / 'test.sh'
    v_file = test_file if test_file.exists() else sol_file
    cfg_file = a / 'config.toml'
    
    s_text = setup_file.read_text(errors='ignore') if setup_file.exists() else ''
    v_text = v_file.read_text(errors='ignore') if v_file.exists() else ''
    
    cfg = {}
    if cfg_file.exists():
        try:
            cfg = tomllib.loads(cfg_file.read_text(errors='ignore'))
        except Exception as e:
            pass
            
    atk = cfg.get('attack', {})
    meta = atk.get('metadata', {})
    name = atk.get('name', aid)
    category = meta.get('security_violation', 'Unknown')
    
    candidates.append({
        'aid': aid,
        'name': name,
        'category': category,
        'setup': s_text.strip(),
        'verifier': v_text.strip(),
    })

print(f'Total candidates parsed: {len(candidates)}')
for c in candidates:
    v_checks = []
    for l in c['verifier'].split('\n'):
        l = l.strip()
        if any(fn in l for fn in ['agent_ran', 'state_changed', 'agent_created_file', 'abs_file_exists', 'state_near', 'state_line', 'pass', 'fail']):
            v_checks.append(l)
    v_summary = ' ; '.join(v_checks[:3])
    print(f"{c['aid']:12} | {c['category']:20} | {c['name'][:25]:25} | {v_summary[:90]}")
