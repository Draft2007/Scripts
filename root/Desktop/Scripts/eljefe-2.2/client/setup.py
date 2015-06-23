from distutils.core import setup
import py2exe, sys, os
sys.path.append(".")

sys.argv.append('py2exe')

setup(
    options = {'py2exe': {"dll_excludes":[ "mswsock.dll", "powrprof.dll" ], 
               'bundle_files': 1, 'compressed': True}},
    windows = [{'script': "ElJefeService.py",
				'dest_base': "ElJefeService32" }],
    zipfile = None,
)   
