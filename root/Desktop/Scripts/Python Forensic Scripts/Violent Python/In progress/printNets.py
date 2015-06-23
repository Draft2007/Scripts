from _winreg import *

def printNets():
    net = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
    key = OpenKey(HKEY_LOCAL_MACHINE, net)
    print '\n[*] Networks You have Joined.'
    for i in range(100):
        try:
            guid = EnumKey(key, i)
            print guid
        except:
            print "This whole thing is fucked..."
            break

def main():
    printNets()

if __name__ == "__main__":
    main()
            