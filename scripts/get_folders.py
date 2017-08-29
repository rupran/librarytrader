#!/usr/bin/env python3

import os
import re
import subprocess
import sys

out = set()

# PATHs for user
u_paths = os.environ['PATH'].split(':')

# PATHs for superuser
p = subprocess.run('echo \'echo $PATH\' | sudo sh', shell=True,
                   stdout=subprocess.PIPE,
                   stdin=subprocess.PIPE)
sudo_paths = p.stdout.decode('utf-8').strip().split(':')
paths = sorted(set(u_paths + sudo_paths))

out.update(paths)

# Library paths from ldconfig
p = subprocess.run(["/sbin/ldconfig", "-p"], stdout=subprocess.PIPE)

lines = [str(x) for x in re.split(b'\n\t', p.stdout)]

for line in lines[1:]:
    out.add('/'.join((line.strip().split('=>')[1].split('/')[:-1])).strip())

print(' '.join(x for x in sorted(out)))
