import scapy.all as scapy
import json
from datetime import datetime
import signal
import sys

# create empty json and convert it to dict
xJson =  '{}'
logs = json.loads(xJson)

# get local ip
localIp = scapy.get_if_addr(scapy.conf.iface)

# create key with local ip
logs[localIp] = {"sentCount": 0, "recvCount": 0, "UnsureSentOrRecv": 0}


# save data into file, so that later you can check ips
def saveDataToTxt(data, filename):
    f = open(filename, "w")
    data = json.dumps(data, indent=2)
    f.write(data)
    f.close()

# handles exit process
def signal_handle(sig, frame):
    date = datetime.today().strftime('%Y-%m-%d-%H-%M-%S')
    saveDataToTxt(logs, date+".txt")
    print('exiting...')
    print("You have sent: {0}, recv: {1}, unsure sent/recv: {2}".format(logs[localIp]["sentCount"], logs[localIp]["recvCount"], logs[localIp]["UnsureSentOrRecv"]))
    sys.exit(0)


def handleIp(ip, type):
    try:
        if ip in logs:
            logs[ip][type] = (logs[ip][type] +1)
        else:
            logs[ip] = {"sentCount": 0, "recvCount": 0, "UnsureSentOrRecv": 0}
            logs[ip][type] = (logs[ip][type] +1)
    except:
        print("error")
        

# this ignores message from messages from router 
def handlePacket(packet):
    if (packet.haslayer(scapy.IP)):
        if(packet[scapy.IP].src == localIp):
            logs[localIp]["sentCount"] = (logs[localIp]["sentCount"] +1)
            handleIp(packet[scapy.IP].dst, "sentCount")
            print("sent")
        elif(packet[scapy.IP].dst == localIp):
            logs[localIp]["recvCount"] = (logs[localIp]["recvCount"] +1)
            handleIp(packet[scapy.IP].src, "recvCount")
            print("recv")
        else:
            logs[localIp]["UnsureSentOrRecv"] = (logs[localIp]["UnsureSentOrRecv"] +1)
            handleIp(packet[scapy.IP].src, "UnsureSentOrRecv")
            handleIp(packet[scapy.IP].dst, "UnsureSentOrRecv")



        print("src: {0}, dst: {1}".format(packet[scapy.IP].src, packet[scapy.IP].dst))


signal.signal(signal.SIGINT, signal_handle)

scapy.sniff(store=False, prn=handlePacket)