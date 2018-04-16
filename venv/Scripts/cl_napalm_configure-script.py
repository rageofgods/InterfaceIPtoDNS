#!C:\Users\e.hohlov\PycharmProjects\InterfaceIPtoDNS\venv\Scripts\python.exe
# EASY-INSTALL-ENTRY-SCRIPT: 'napalm==2.3.0','console_scripts','cl_napalm_configure'
__requires__ = 'napalm==2.3.0'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(
        load_entry_point('napalm==2.3.0', 'console_scripts', 'cl_napalm_configure')()
    )
