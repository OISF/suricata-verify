from pathlib import Path

# Create config files with a mix syntax
test = 'reputation-config'
test_options = [
    { 'path': f'{test}-lf',    'eol': '\n' },
    { 'path': f'{test}-cr',    'eol': '\r' },
    { 'path': f'{test}-cr-lf', 'eol': '\r\n' },
]

# Categories and IPs from
# https://docs.suricata.io/en/suricata-6.0.0/reputation/ipreputation/ip-reputation-format.html

for test in test_options:
    path, eol = Path(test['path']), test['eol']

    with open(path / 'iprep-data.txt', 'w') as rep_cfg:
        rep_cfg.write(f'1.2.3.4,1,101{eol}')
        rep_cfg.write(f'1.2.3.5,1,101{eol}')
        rep_cfg.write(f'1.1.1.0/24,6,88{eol}')
