#!/usr/bin/env python
#
# TrimPCAP 1.3
#
# Trims capture files (PCAP and PCAP-NG) by truncating flows to a desired max size
#
# Created by: Erik Hjelmvik, NETRESEC
# Open Source License: GPLv2
#
#
# Usage: ./trimpcap.py 8192 somefile1.pcap somefile2.pcap
# Usage: ./trimpcap.py 100000 *.pcap
#
# ==DEPENDENCIES==
# python 2.6 or 2.7
# pip install dpkt
# pip install repoze.lru
#
# On Debian/Ubuntu you can also do:
# apt install python-dpkt python-repoze.lru
#
# ==CHANGE LOG==
# TrimPCAP 1.3
# * Relocated variable declaration of src, dst and proto to outside the try clause.
#   Thanks to Mike McDargh for reporting the bug and providing a fix!
#
# TrimPCAP 1.2
# * Fixed snaplength bug to ensure generated pcap files have the same snaplength as the source file.
#   Thanks Phil Hagen for reporting the bug and providing a fix!
#
# TrimPCAP 1.1
# * Added a strategy to handle fragmented IP packets.
#   Thanks to Mark Eldridge for notifying us about this bug!
#
import dpkt
import socket
import sys
import os
from repoze.lru import LRUCache

#change this variable to False if you prefer to keep the *.trimmed files rather than overwriting the original capture files
OVERWRITE_SOURCE = False


def inet_to_str(ip_addr):
    try:
        return socket.inet_ntop(socket.AF_INET, ip_addr)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, ip_addr)

def get_fivetuple_from_ip(ip):
    src = ""
    dst = ""
    proto = 0
    try:
        src = inet_to_str(ip.src) + ":"
        dst = inet_to_str(ip.dst) + ":"
        if ip is not None:
            proto = ip.p
            if ip.offset == 0 and (ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_UDP):
                src += str(ip.data.sport)
                dst += str(ip.data.dport)
    except dpkt.dpkt.NeedData:
        pass
    except AttributeError:
        pass
    if src < dst:
        # tcp_192.168.1.1-192.168.1.22
        return str(proto) + "_" + src + "-" + dst
    else:
        return str(proto) + "_" + dst + "-" + src

def get_fivetuple(buf, pcap, pcap_file):
    
    if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
        sll = dpkt.sll.SLL(buf)
        return get_fivetuple_from_ip(sll.data)
    elif pcap.datalink() == dpkt.pcap.DLT_IEEE802 or pcap.datalink() == dpkt.pcap.DLT_EN10MB:
        try:
            ethernet = dpkt.ethernet.Ethernet(buf)
            if ethernet.type == dpkt.ethernet.ETH_TYPE_IP:
                return get_fivetuple_from_ip(ethernet.data)
            else:
                return None
        except dpkt.UnpackError as e:
            return None
    elif pcap.datalink() == dpkt.pcap.DLT_RAW or pcap.datalink() == dpkt.pcap.DLT_LOOP:
        #Raw IP only supported for ETH_TYPE 0x0c. Type 0x65 is not supported by DPKT
        return get_fivetuple_from_ip(dpkt.ip.IP(buf))
    elif pcap.datalink() == dpkt.pcap.DLT_NULL:
        frame = dpkt.loopback.Loopback(buf)
        return get_fivetuple_from_ip(frame.data)
    else:
        print >> sys.stderr, "unknown datalink in " + pcap_file
        exit

def trim(flist, flowmaxbytes):
    cache = LRUCache(10000)
    trimmed_bytes = 0
    for pcap_file in flist:
        with open(pcap_file, "rb") as f:
            try:
                if pcap_file.endswith("pcapng"):
                    pcap = dpkt.pcapng.Reader(f)
                else:
                    pcap = dpkt.pcap.Reader(f)

                snaplen = pcap.snaplen

                with open(pcap_file + ".trimmed", "wb") as trimmed:
                    if pcap_file.endswith("pcapng"):
                        pcap_out = dpkt.pcapng.Writer(trimmed, snaplen=snaplen)
                    else:
                        pcap_out = dpkt.pcap.Writer(trimmed, snaplen=snaplen)
                    for ts, buf in pcap:
                        fivetuple = get_fivetuple(buf, pcap, pcap_file)
                        #print fivetuple
                        bytes = len(buf)
                        if not cache.get(fivetuple) is None:
                            bytes += cache.get(fivetuple)
                        cache.put(fivetuple, bytes)
                        if bytes < flowmaxbytes:
                            pcap_out.writepkt(buf, ts)
                        else:
                            trimmed_bytes += len(buf)
            except dpkt.dpkt.NeedData: pass
            except ValueError: pass
        if OVERWRITE_SOURCE and os.path.exists(pcap_file + ".trimmed"):
            os.rename(pcap_file + ".trimmed", pcap_file)
    return trimmed_bytes



USAGE_MESSAGE = 'Usage: %s <max_bytes_per_flow> <pcap_file(s)>' % sys.argv[0]
if len(sys.argv) < 3:
    sys.exit(USAGE_MESSAGE)
else:
    flist = list()
    try:
        flowmaxbytes = int(sys.argv[1])
        print "Trimming capture files to max " + str(flowmaxbytes) + " bytes per flow."
        source_bytes = 0
        for file in sys.argv[2:]:
            if not os.path.exists(file):
                print "ERROR: File " + file + " does not exist!"
            else:
                flist.append(file)
                source_bytes += os.path.getsize(file)
        trimmed_bytes = trim(flist, flowmaxbytes)
        if source_bytes > 0:
            print "Dataset reduced by " + "{0:.2f}".format(trimmed_bytes * 100.0 / source_bytes) +  "% = " + str(trimmed_bytes) + " bytes"
        else:
            sys.exit(USAGE_MESSAGE)
    except ValueError:
        sys.exit(USAGE_MESSAGE)
