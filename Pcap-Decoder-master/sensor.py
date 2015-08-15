import dpkt, json

def numIP2strIP(ip):
    '''
    this function convert decimal ip to dot notation
    '''
    l = [str((ip >> 8*n) % 256) for n in range(4)]
    l.reverse()
    return ".".join(l)
    
def numIP2strIPv6(ip):
    '''
    this function adds ':' to the ipv6 hex address
    '''
    ipv6 = ':'.join([ip[i:i+4] for i in range(0, len(ip), 4)])        
    return ipv6

# Open Pcap    Then transform Pcap to py__dict__
f = open('ios.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

pktCounter = 0

# Read pcap
for ts, buf in pcap:

    pktCounter += 1

    try:
        ether = dpkt.ethernet.Ethernet(buf)
                        
        # Mac address
        smac = ether.src.encode("hex")
        dmac = ether.dst.encode("hex")
        srcmac = ':'.join([smac[i:i+2] for i in range(0, len(smac), 2)])
        dstmac = ':'.join([dmac[i:i+2] for i in range(0, len(dmac), 2)])
        
        # Ports
        tcp = ether.data.data
        srcport = tcp.sport
        dstport = tcp.dport
        
        # Protocol
        prot = ether.data.p
        
        # Packet Size
        sizeP = len(buf)
        
        # Layer 3 Packet
        ethDict = ether.__dict__
        cutBrack = str(ethDict).strip('{))}')
        grablayer = cutBrack.split('data=', 1)[1]
        formatType = grablayer.replace('(', ', ', 1)
        removeDat = formatType.split(', data=', 1)[0]
        
        layertype = removeDat.split(', ', 1)
     
        # Determine IP type to convert and run proper code
        if ether.type == dpkt.ethernet.ETH_TYPE_IP:
                   
            srcip = numIP2strIP(int(ether.data.src.encode('hex'), 16))
            dstip = numIP2strIP(int(ether.data.dst.encode('hex'), 16))
            
            packet = {
                'Packet: #%s Size: %s' %(pktCounter, sizeP): {
                    'Ethernet': {
                        'Src MAC': srcmac,
                        'Dest MAC': dstmac,
                        'Type': 'Ipv4',
                        'Packet': layertype
                    },
                    'IP': {
                        'Src IP': srcip,
                        'Dest IP': dstip,   
                        'Ttl': ether.data.ttl,
                        'Length': ether.data.len,
                        'Tos': ether.data.tos,
                        'Id': ether.data.id,
                        'Off': ether.data.off,
                        'Sum': ether.data.sum,
                        'Prot': ether.data.p
                    },
                },
            }
            
        else:
        
            srcip = numIP2strIPv6(ether.data.src.encode('hex'))
            dstip = numIP2strIPv6(ether.data.dst.encode('hex'))
            
            packet = {
                'Packet: #%s Size: %s' %(pktCounter, sizeP): {
                    'Ethernet': {
                        'Source MAC': srcmac,
                        'Destination MAC': dstmac,
                        'Type': 'Ipv6',
                        'Packet': layertype
                    },
                    'IP': {
                        'Source IP': srcip,
                        'Dest IP': dstip,   
                        'hlim': ether.ip6.hlim,
                        'Length': ether.ip6.plen,
                        'Flow': ether.ip6.v_fc_flow,
                        'Prot': ether.ip6.nxt
                    },
                },
            }
        
        dictionary = dict(packet)
        
        # Json Dump
        # packetdump = json.dumps(dictionary, indent = 4, sort_keys = False)
        if pktCounter == 100:

            for each in  packet.items():
                # raw_pk = each[0]    #Orignal Package Size and Order
                raw_pkdict = each[1]
                # print  raw_pkdict
                Ethernet = raw_pkdict['Ethernet']
                Application = Ethernet['Packet']
                IP = raw_pkdict['IP']

                print  IP
                print  'Source:',IP['Src IP'],'-->','Target:',IP['Dest IP']
                print  Application

                # App_prot= Application[0]
                App_attr_list = Application[1]
                print  App_attr_list.split(', ')




        # Write Json to the File
        # fsock = open("Parsing_JSON.txt", "a")
        # fsock.write(packetdump)
        # fsock.close()

        # print packetdump
        # print "Packet Data: %s" %(ether.data.data.data)

    except AttributeError:
        pass