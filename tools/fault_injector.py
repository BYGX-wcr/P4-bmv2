import sys
import socket

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Too few arguments, destination addr and port are required!")
    dstAddr = sys.argv[1]
    dstPort = int(sys.argv[2])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
        sk.connect((dstAddr, dstPort))

        cmdStr = input("Type in command: ")
        sk.sendall(str.encode(cmdStr, encoding="utf-8"))

