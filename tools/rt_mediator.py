import threading
from pyroute2 import IPRoute
from runtime_CLI import RuntimeAPI
from runtime_CLI import get_parser, thrift_connect, load_json_config

class MonitorThread(threading.Thread):
    "The thread monitors netlink messages and update the forwarding table of the bmv2 switch accordingly"
    def __init__(self, runtime):
        threading.Thread.__init__(self)
        assert (type(runtime) == RuntimeAPI)
        self.runtime = runtime

    def run(self):
        ip = IPRoute()
        ip.bind()
        handleDict = dict()
        while True:
            message = ip.get()[0]
            if message['event'] == 'RTM_NEWROUTE':
                # add a new route entry to the ipv4 route table of p4 switch
                print("New RTM_NEWROUTE msg: ", message)
                # define all fields in an entry
                action = "ipv4_forward"
                srcAddr = '0.0.0.0'
                srcMask = '0.0.0.0'
                dstAddr = str()
                dstMaskLen = str(message['dst_len'])
                next_hop = str()
                egress_port = str()

                # parse attrs
                attrs = message['attrs']
                for field in attrs:
                    if field[0] == 'RTA_DST':
                        dstAddr = field[1]
                    elif field[0] == 'RTA_SRC':
                        srcAddr = field[1]
                    elif field[0] == 'RTA_GATEWAY':
                        next_hop = field[1]
                    elif field[0] == 'RTA_OIF':
                        device_name = ip.get_links(field[1])[0].get_attr('IFLA_IFNAME')
                        device_name = str(device_name).split('-')
                        port_name = device_name[1] if len(device_name) > 1 else device_name[0]
                        egress_port = int(port_name[3:])
                entry = 'Ipv4_FIB' + ' ' + action + ' ' + srcAddr + '&&&' + srcMask + ' ' + dstAddr + '/' + dstMaskLen + " => " + next_hop + ' ' + str(egress_port)
                print("Add an entry: " + entry)
                handle = self.runtime.do_table_add(entry)
                handleDict[dstAddr + '/' + dstMaskLen] = handle
            elif message['event'] == 'RTM_DELROUTE':
                # delete an existing route entry to the ipv4 route table of p4 switch
                print("New RTM_DELROUTE msg: ", message)
                dstAddr = str()
                dstMaskLen = str(message['dst_len'])
                
                # parse attrs(only looking for RTA_DST)
                attrs = message['attrs']
                for field in attrs:
                    if field[0] == 'RTA_DST':
                        dstAddr = field[1]
                
                key = dstAddr + '/' + dstMaskLen
                if key not in handleDict:
                    print("Handle missing for entry: ", key)
                else:
                    print("Delete an entry: ", message)
                    handle = handleDict[key]
                    cmdLine = 'table_delete Ipv4_FIB' + ' ' + str(handle)
                    del handleDict[key]
                

if __name__ == "__main__":
    # set up runtime API for the p4 switch
    args = get_parser().parse_args()

    standard_client, mc_client = thrift_connect(
        args.thrift_ip, args.thrift_port,
        RuntimeAPI.get_thrift_services(args.pre)
    )

    load_json_config(standard_client, args.json)
    main_runtime = RuntimeAPI(args.pre, standard_client, mc_client)

    # create monitor thread
    mt = MonitorThread(main_runtime)
    mt.start()