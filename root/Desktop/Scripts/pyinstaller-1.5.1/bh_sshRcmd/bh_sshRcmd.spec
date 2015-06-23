# -*- mode: python -*-
a = Analysis([os.path.join(HOMEPATH,'support/_mountzlib.py'), os.path.join(HOMEPATH,'support/useUnicode.py'), '/usr/local/tools/bh_sshRcmd.py'],
             pathex=['/usr/local/tools/pyinstaller-1.5.1'])
pyz = PYZ(a.pure)
exe = EXE( pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name=os.path.join('dist', 'bh_sshRcmd'),
          debug=False,
          strip=False,
          upx=True,
          console=1 )
app = BUNDLE(exe,
             name=os.path.join('dist', 'bh_sshRcmd.app'))
