"""
ACS Dataplane Qos tests
"""

import time
import math
import logging
import ptf.packet as scapy
import socket
import ptf.dataplane as dataplane
import sai_base_test
from ptf.testutils import *
from ptf.mask import Mask
from switch_mlnx import *

# Counters
EGRESS_DROP = 0
INGRESS_DROP = 1
PFC_PRIO_3 = 5
PFC_PRIO_4 = 6
TRANSMITTED_OCTETS = 10
TRANSMITTED_PKTS = 11
NUM_QUEUE = 8
DSCP_TO_TC_CONFIG_FILE="/root/dscp_to_tc_map.txt"

# Constants
STOP_PORT_MAX_RATE = 1
RELEASE_PORT_MAX_RATE = 0
ECN_INDEX_IN_HEADER = 53 # Fits the ptf hex_dump_buffer() parse function
DSCP_INDEX_IN_HEADER = 52 # Fits the ptf hex_dump_buffer() parse function


class ARPpopulate(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        router_mac = self.test_params['router_mac']
        ## ARP Populate
        index = 0
        for port in ptf_ports():
            arpreq_pkt = simple_arp_packet(
                          eth_dst='ff:ff:ff:ff:ff:ff',
                          eth_src=self.dataplane.get_mac(port[0],port[1]),
                          arp_op=1,
                          ip_snd='10.0.0.%d' % (index * 2 + 1),
                          ip_tgt='10.0.0.%d' % (index * 2),
                          hw_snd=self.dataplane.get_mac(port[0], port[1]),
                          hw_tgt='ff:ff:ff:ff:ff:ff')
            send_packet(self, port[1], arpreq_pkt)
            index += 1

class ReleaseAllPorts(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client, RELEASE_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        for port in sai_port_list:
            self.client.sai_thrift_set_port_attribute(port, attr)

class DscpMappingPB(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        expect_results = [0] * NUM_QUEUE
        switch_init(self.client)
        
        router_mac = self.test_params['router_mac']        
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        exp_ip_id = 101
        exp_ttl = 63

        ## Clear Switch Counters
        sai_thrift_clear_all_counters(self.client)

        file = open(DSCP_TO_TC_CONFIG_FILE, 'r')
        if not file:
            self.fail("Not found DSCP to TC map config file")
        dscp_to_tc_dic = eval(file.readline()).values()[0]
        for dscp, queue in dscp_to_tc_dic.items():
            expect_results[int(queue)] += 1

        ## DSCP Mapping test
        try:
            for dscp in range(0,64):
                tos = dscp << 2
                pkt = simple_tcp_packet(eth_dst=router_mac,
                                        eth_src=src_port_mac,
                                        ip_src=src_port_ip,
                                        ip_dst=dst_port_ip,
                                        ip_tos=tos,
                                        ip_id=exp_ip_id,
                                        ip_ttl=64)

                testutils.send_packet(self, src_port_id, pkt)

                dscp_received = False

                while not dscp_received:
                    result = self.dataplane.poll(device_number=0, port_number=dst_port_id, timeout=3)
                    if isinstance(result, self.dataplane.PollFailure):
                        self.fail("Expected packet was not received on port %d.\n%s"
                            % (dst_port_id, result.format()))
                    recv_pkt = scapy.Ether(result.packet)

                    # Verify dscp flag
                    try:
                        dscp_received = recv_pkt.payload.tos == tos and recv_pkt.payload.src == src_port_ip and recv_pkt.payload.dst == dst_port_ip and \
                            recv_pkt.payload.ttl == exp_ttl and recv_pkt.payload.id == exp_ip_id
                    except AttributeError:
                        continue

            ## Read Counters
            port_results, queue_results = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])

            for queue_index in range(NUM_QUEUE):
                assert(queue_results[queue_index] == expect_results[queue_index])

        finally:
            print "END OF TEST"

#This test is to measure the Xoff threshold, and buffer limit
class PFCtest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.client)
        
        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        pg = int(self.test_params['pg']) + 2 #The pfc counter index starts from index 2
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        max_buffer_size = int(self.test_params['buffer_max_size'])
        max_queue_size = int(self.test_params['queue_max_size']) 
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        
        # Prepare TCP packet data
        tos = dscp << 2
        tos |= ecn
        ttl = 64        
        default_packet_length = 72
        # Calculate the max number of packets which port buffer can consists
        # Increase the number of packets on 25% for a oversight of translating packet size to cells
        pkts_max = (max_buffer_size / default_packet_length + 1) * 1.3
            
        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        # Close DST port
        sched_prof_id = sai_thrift_create_scheduler_profile(self.client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

        #send packets
        try:
            src_port_index = -1
            pkts_bunch_size = 70 # Number of packages to send to DST port
            pkts_count = 0 # Total number of shipped packages
            port_pg_counter = 0
            
            # Send the packets untill PFC counter will be trigerred or max pkts reached
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
            while port_pg_counter == 0 and pkts_count < pkts_max:
                testutils.send_packet(self, src_port_id, pkt, pkts_bunch_size)
                pkts_count += pkts_bunch_size
                time.sleep(1)

                drop_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
                assert (drop_counters[EGRESS_DROP] == 0)
                
                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
                port_pg_counter = port_counters[pg]

            assert(port_counters[pg] != 0)
            assert(port_counters[EGRESS_DROP] == 0)
            assert(port_counters[INGRESS_DROP] == 0)
            
            # Send the packages till ingress drop on src port
            pkts_bunch_size = 70
            # Increase the number of packets on 25% for a oversight of translating packet size to cells
            pkts_max = ((max_buffer_size + max_queue_size) / default_packet_length) * 1.3
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
            ingress_drop = port_counters[INGRESS_DROP]
            while ingress_drop == 0 and pkts_count < pkts_max:
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                                        eth_dst=router_mac,
                                        eth_src=src_port_mac,
                                        ip_src=src_port_ip,
                                        ip_dst=dst_port_ip,
                                        ip_tos=tos,
                                        ip_ttl=ttl)
                testutils.send_packet(self, src_port_id, pkt, pkts_bunch_size)
                pkts_count += pkts_bunch_size
                time.sleep(2)
                
                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])

                ingress_drop = port_counters[INGRESS_DROP]
                egress_drop = port_counters[EGRESS_DROP]

            assert(egress_drop == 0)
            assert(ingress_drop != 0)
            assert(port_counters[pg] != 0)

        finally:
            # RELEASE PORT
            sched_prof_id = sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id],attr)
            print "END OF TEST"

class PFCXonTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.client)
        last_pfc_counter = 0
        recv_port_counters = []
        transmit_port_counters = []
        
        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        max_buffer_size = int(self.test_params['buffer_max_size'])
        pg = int(self.test_params['pg']) + 2 #The pfc counter index starts from index 2        
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)

        #STOP PORT FUNCTION
        sched_prof_id = sai_thrift_create_scheduler_profile(self.client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        try:
            tos = dscp << 2
            tos |= ecn
            ttl=64
            default_packet_length = 72
            # Calculate the max number of packets which port buffer can consists
            pkts_max = (max_buffer_size / default_packet_length) * 1.3
            pkts_bunch_size = 70 # Number of packages to send to DST port
            pkts_count = 0 # Total number of shipped packages
            port_pg_counter = 0
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
            
            # Send the packets untill PFC counter will be trigerred or max pkts reached
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)            
            while port_pg_counter == 0 and pkts_count < pkts_max:                
                testutils.send_packet(self, src_port_id, pkt, pkts_bunch_size)
                pkts_count += pkts_bunch_size
                time.sleep(8)
                
                recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
                port_pg_counter = recv_port_counters[pg]

            assert(recv_port_counters[pg] != 0)
            assert(recv_port_counters[EGRESS_DROP] == 0)
            assert(recv_port_counters[INGRESS_DROP] == 0)

            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id],attr)            
            time.sleep(10)
            
            # After release, send the packets and verify if no drops on port
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
            last_pfc_counter = recv_port_counters[pg]
            non_xoff_pkts_num = pkts_count - pkts_bunch_size
            testutils.send_packet(self, src_port_id, pkt, non_xoff_pkts_num)
            time.sleep(5)

            # Read Counters
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
            transmit_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
                
            assert (recv_port_counters[EGRESS_DROP] == 0)
            assert (recv_port_counters[INGRESS_DROP] == 0)
            assert (recv_port_counters[pg] != 0)
            assert (transmit_port_counters[TRANSMITTED_PKTS] != 0)
            assert (recv_port_counters[pg] == last_pfc_counter)

        finally:
            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id],attr)
            print "END OF TEST"

class DscpEcnSend(sai_base_test.ThriftInterfaceDataPlane):
    def predictTx(self, min, max, num_pkts, max_drop_probability):
        tx = 0
        for i in range(min, num_pkts):
            drop = float(tx) / (max - min) # drop probability 0..1
            if drop > 1.0:
                drop = 1.0
            else:
                drop = drop * max_drop_probability / 100.0
            rnd = float(int(os.urandom(8).encode('hex'), 16)) / ((1 << 64) - 1) # random number between 0 and 1
            if rnd > drop:
                tx += 1
        return min + tx

    def runTest(self):
        time.sleep(5)
        switch_init(self.client)

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        cell_size = int(self.test_params['cell_size'])
        ecn_tolerance_prc = int(self.test_params['ecn_tolerance'])

        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)

        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        src_port_info_list = [(src_port_id, src_port_ip, src_port_mac)]
        logging.info('source port info: %d %s %s' % (src_port_id, src_port_ip, src_port_mac))

        if 'more_src_ports' in self.test_params.keys():
            more_src_ports = int((self.test_params['more_src_ports']))
            for i in range(more_src_ports):
                src_port_id = int(self.test_params['src_port_{}_id'.format(i + 2)])
                src_port_ip = self.test_params['src_port_{}_ip'.format(i + 2)]
                src_port_mac = self.dataplane.get_mac(0, src_port_id)
                src_port_info_list.append((src_port_id, src_port_ip, src_port_mac))
                logging.info('%d-th source port info: %d %s %s' % (i+2, src_port_id, src_port_ip, src_port_mac))

        if 'max_drop_probability' in self.test_params.keys():
            max_drop_probability = int(self.test_params['max_drop_probability'])
        else:
            max_drop_probability = 100
        logging.info('max drop probability is %d' % max_drop_probability)

        num_of_src_ports = len(src_port_info_list)
        num_of_pkts = int(self.test_params['num_of_pkts'])
        num_of_pkts_perport = num_of_pkts / num_of_src_ports
        packet_length = cell_size - 20 # to be within one cell
        logging.info('original num_of_pkts: %d' % num_of_pkts)
        if ecn == 1:
            # scapy(ptf?) cannot capture more than 1023 packets.
            packet_length = min(cell_size * (num_of_pkts_perport / 125), 9000)
            num_of_pkts_perport = 125
            num_of_pkts = num_of_pkts_perport * num_of_src_ports

        green_min_limit = int(self.test_params['green_min_limit'])
        green_max_limit = int(self.test_params['green_max_limit'])
        green_min_limit_cells = int(math.ceil(float(green_min_limit) / 64 / cell_size) * 64)
        green_max_limit_cells = int(math.ceil(float(green_max_limit) / 64 / cell_size) * 64)

        logging.info("WRED min/max (cells): %d, %d" % (green_min_limit_cells, green_max_limit_cells))

        cells_per_packet = int(math.ceil(float(packet_length) / cell_size))

        logging.info('num_of_pkts: %d' % num_of_pkts)
        logging.info('packet_length: %d' % packet_length)
        logging.info('cells_per_packet: %d' % cells_per_packet)

        # Close DST port
        sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], STOP_PORT_MAX_RATE)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        try:
            tos = dscp << 2
            tos |= ecn
            ttl = 64
            for src_port_id, src_port_ip, src_port_mac in src_port_info_list:
                pkt = simple_tcp_packet(pktlen=packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
                send_packet(self, src_port_id, pkt, num_of_pkts_perport)
                time.sleep(1)

            # Set receiving socket buffers to some big value
            for p in self.dataplane.ports.values():
                p.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 41943040)
            # Set the dataplane qlen
            self.dataplane.set_qlen(num_of_pkts)
            logging.info("Setting dataplane qlen to {}".format(num_of_pkts))

            # RELEASE PORT
            sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], RELEASE_PORT_MAX_RATE)

            # if (ecn == 1) - capture and parse all incoming packets
            marked_cnt = 0
            not_marked_cnt = 0
            if (ecn == 1):
                cnt = 0
                for i in xrange(num_of_pkts):
                    (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=0, port_number=dst_port_id, timeout=0.2)
                    if rcv_pkt is not None:
                        cnt += 1
                        pkt_str = hex_dump_buffer(rcv_pkt)
                        # Count marked and not marked amount of packets
                        if ( (int(pkt_str[ECN_INDEX_IN_HEADER], 16) & 0x03)  == 1 ):
                            not_marked_cnt += 1
                        elif ( (int(pkt_str[ECN_INDEX_IN_HEADER], 16) & 0x03) == 3 ):
                            #assert (not_marked_cnt == 0)
                            marked_cnt += 1
                    else:  # Received less packets then expected
                        logging.info("Warning: sent %d but captured %d" % (num_of_pkts, cnt))
                        break

                logging.info("    Received packets:   %d" % cnt)
                logging.info("    ECN non-marked pkts:%d" % not_marked_cnt)
                logging.info("    ECN marked pkts:    %d" % marked_cnt)

            time.sleep(5)
            # Read Counters
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
            logging.info("DST port counters (port %d):" %  dst_port_id)
            logging.info(port_counters)
            logging.info(queue_counters)

            expected_tx_cells = self.predictTx(green_min_limit_cells, green_max_limit_cells,
                                               num_of_pkts*cells_per_packet,
                                               max_drop_probability)
            tolerance = float(expected_tx_cells) * ecn_tolerance_prc / 100
            limit_max = expected_tx_cells + tolerance
            limit_min = expected_tx_cells - tolerance

            if (ecn == 0):
                actual_tx_cells = port_counters[TRANSMITTED_PKTS] * cells_per_packet
                logging.info('Tolerance +/- (cells): %d (%d%%)' % (tolerance, ecn_tolerance_prc))
                logging.info('port_counters[TRANSMITTED_PKTS]: %d' % port_counters[TRANSMITTED_PKTS])
                logging.info('port_counters[TRANSMITTED_OCTETS]: %d' % port_counters[TRANSMITTED_OCTETS])
                logging.info("Actually transmitted  (cells): %d" % actual_tx_cells)
                logging.info("Expected to be transmitted  (cells): %d" % expected_tx_cells)
                logging.info("Expected in range (cells): %d <= %d <= %d" % (limit_min, actual_tx_cells, limit_max))
                assert (actual_tx_cells >= limit_min)
                assert (actual_tx_cells <= limit_max)
            elif (ecn == 1):
                actual_not_marked_cells = not_marked_cnt * cells_per_packet
                logging.info('Tolerance +/- (cells): %d (%d%%)' % (tolerance, ecn_tolerance_prc))
                logging.info("Actually not marked  (cells): %d" % actual_not_marked_cells)
                logging.info("Expected not marked  (cells): %d" % expected_tx_cells)
                logging.info("Expected in range    (cells): %d <= %d <= %d" % (limit_min, actual_not_marked_cells, limit_max))
                logging.info("Drops ingress:%d, egress %d" % (port_counters[INGRESS_DROP], port_counters[EGRESS_DROP]))
                assert (actual_not_marked_cells >= limit_min)
                assert (actual_not_marked_cells <= limit_max)
                assert (port_counters[INGRESS_DROP] == 0)
                assert (port_counters[EGRESS_DROP] == 0)

        finally:
            # RELEASE PORT
            sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], RELEASE_PORT_MAX_RATE)
            logging.info("END OF TEST")

class WRRtest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)        
        
        # Parse input parameters
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']       
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)
        default_packet_length = 1500
        exp_ip_id = 110
        queue_0_num_of_pkts = int(self.test_params['q0_num_of_pkts'])
        queue_1_num_of_pkts = int(self.test_params['q1_num_of_pkts'])
        queue_3_num_of_pkts = int(self.test_params['q3_num_of_pkts'])
        queue_4_num_of_pkts = int(self.test_params['q4_num_of_pkts'])

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets to each queue based on dscp field
        try:
            for i in range(0, queue_0_num_of_pkts):
                dscp = 0
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                            eth_dst=router_mac,
                            eth_src=src_port_mac,
                            ip_src=src_port_ip,
                            ip_dst=dst_port_ip,
                            ip_tos=tos,
                            ip_id=exp_ip_id,
                            ip_ttl=64)
                send_packet(self, src_port_id, pkt)

            for i in range(0, queue_1_num_of_pkts):
                dscp = 8
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                            eth_dst=router_mac,
                            eth_src=src_port_mac,
                            ip_src=src_port_ip,
                            ip_dst=dst_port_ip,
                            ip_tos=tos,
                            ip_id=exp_ip_id,
                            ip_ttl=64)
                send_packet(self, src_port_id, pkt)

            for i in range(0, queue_3_num_of_pkts):
                dscp = 3
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                            eth_dst=router_mac,
                            eth_src=src_port_mac,
                            ip_src=src_port_ip,
                            ip_dst=dst_port_ip,
                            ip_tos=tos,
                            ip_id=exp_ip_id,
                            ip_ttl=64)
                send_packet(self, src_port_id, pkt)

            for i in range(0, queue_4_num_of_pkts):
                dscp = 4
                tos = dscp << 2
                tos |= ecn
                pkt = simple_tcp_packet(pktlen=default_packet_length,
                            eth_dst=router_mac,
                            eth_src=src_port_mac,
                            ip_src=src_port_ip,
                            ip_dst=dst_port_ip,
                            ip_tos=tos,
                            ip_id=exp_ip_id,
                            ip_ttl=64)
                send_packet(self, src_port_id, pkt)

            # Set receiving socket buffers to some big value
            for p in self.dataplane.ports.values():
                p.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 41943040)

            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

            cnt = 0
            pkts = []
            recv_pkt = scapy.Ether()

            while recv_pkt:
                received = self.dataplane.poll(device_number=0, port_number=dst_port_id, timeout=2)
                if isinstance(received, self.dataplane.PollFailure):
                    recv_pkt = None
                    break
                recv_pkt = scapy.Ether(received.packet)

                try:
                    if recv_pkt.payload.src == src_port_ip and recv_pkt.payload.dst == dst_port_ip and recv_pkt.payload.id == exp_ip_id:
                        cnt += 1
                        pkts.append(recv_pkt)
                except AttributeError:
                    continue

            queue_pkt_counters = [0,0,0,0,0,0,0,0,0]
            queue_num_of_pkts  = [queue_0_num_of_pkts, 0, 0, queue_3_num_of_pkts, queue_4_num_of_pkts, 0, 0, 0, 0, queue_1_num_of_pkts]
            total_pkts = 0
            limit = int(self.test_params['limit'])

            diff_list = []

            for pkt_to_inspect in pkts:
                dscp_of_pkt = pkt_to_inspect.payload.tos >> 2
                total_pkts += 1

                # Count packet oredering

                queue_pkt_counters[dscp_of_pkt] += 1
                if queue_pkt_counters[dscp_of_pkt] == queue_num_of_pkts[dscp_of_pkt]:
                     diff_list.append((dscp_of_pkt, (queue_0_num_of_pkts+queue_1_num_of_pkts+queue_3_num_of_pkts+queue_4_num_of_pkts) - total_pkts))

                print queue_pkt_counters

            print "Difference for each dscp"
            print diff_list
            print "Limit is %d" % limit

            for dscp, diff in diff_list:
                assert diff < limit, "Difference for %d is %d which exceeds limit %d" % (dscp, diff, limit)

            # Read Counters
            print "DST port counters: "
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
            print port_counters
            print queue_counters

        finally:
            # RELEASE PORT
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client, RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)

class LossyQueueTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        
        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        max_buffer_size = int(self.test_params['buffer_max_size'])
        headroom_size = int(self.test_params['headroom_size'])
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        dst_port_2_id = int(self.test_params['dst_port_2_id'])
        dst_port_2_ip = self.test_params['dst_port_2_ip']
        dst_port_2_mac = self.dataplane.get_mac(0, dst_port_2_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)

        #STOP PORT FUNCTION
        sched_prof_id=sai_thrift_create_scheduler_profile(self.client, STOP_PORT_MAX_RATE)
        attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
        attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)
        self.client.sai_thrift_set_port_attribute(port_list[dst_port_2_id], attr)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        try:
            tos = dscp << 2
            tos |= ecn
            ttl=64
            default_packet_length = 64
            # Calculate the max number of packets which port buffer can consists
            pkts_max = (max_buffer_size / default_packet_length) * 1.25
            pkts_bunch_size = 200 # Number of packages to send to DST port
            pkts_count = 0 # Total number of shipped packages
            egress_drop_counter = 0
            recv_port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
            
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
            # Send packets till egress drop or max number of packages is reached
            while egress_drop_counter == 0 and pkts_count < pkts_max:
                testutils.send_packet(self, src_port_id, pkt, pkts_bunch_size)
                pkts_count += pkts_bunch_size
                time.sleep(5)
                
                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
                egress_drop_counter = port_counters[EGRESS_DROP]
            
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
            assert (port_counters[EGRESS_DROP] != 0)

            # Send N packets to another port to fill the headroom and check if no drops
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_2_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
            no_drop_pkts_max = headroom_size / default_packet_length * 0.9

            if no_drop_pkts_max > 0:
                testutils.send_packet(self, src_port_id, pkt, no_drop_pkts_max)
                time.sleep(5)
            
                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_id])
                assert (port_counters[EGRESS_DROP] != 0)
            
                port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[dst_port_2_id])
                assert (port_counters[EGRESS_DROP] == 0)
            
            port_counters, queue_counters = sai_thrift_read_port_counters(self.client, port_list[src_port_id])            
            assert (port_counters[INGRESS_DROP] == 0)

        finally:
            # RELEASE PORTS
            sched_prof_id=sai_thrift_create_scheduler_profile(self.client,RELEASE_PORT_MAX_RATE)
            attr_value = sai_thrift_attribute_value_t(oid=sched_prof_id)
            attr = sai_thrift_attribute_t(id=SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID, value=attr_value)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_id], attr)
            self.client.sai_thrift_set_port_attribute(port_list[dst_port_2_id], attr)

class BufferUtilizationTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        time.sleep(5)
        switch_init(self.client)

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        buffer_headroom = int(self.test_params['buffer_headroom'])
        buffer_alpha = float(self.test_params['buffer_alpha'])
        buffer_pool_size = int(self.test_params['buffer_pool_size'])
        buffer_utilization_tolerance = int(self.test_params['buffer_utilization_tolerance'])
        cell_size = int(self.test_params['cell_size'])
        default_port_mtu = int(self.test_params['default_port_mtu'])
        packet_send_rate = int(self.test_params['packet_send_rate'])
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)

        logging.info('Buffer headroom: %d' % buffer_headroom)
        logging.info('Buffer pool size: %d' % buffer_pool_size)
        logging.info('Buffer alpha: %d' % buffer_alpha)
        logging.info('Port MTU: %d' % default_port_mtu)
        logging.info('Cell size: %d' % cell_size)
        logging.info('Packet send rate: %d' % packet_send_rate)

        # Prepare TCP packet data
        tos = dscp << 2
        tos |= ecn
        ttl = 64

        # NOTE: below calculation of buffer max packets capacity assumes
        # packet length is less than the cell size. Specificaly it assumes
        # one packet can fit into one cell
        default_packet_length = 72

        assert default_packet_length < cell_size, "Packet length should be less than the cell size"

        # calculate the exact max packets number that buffer can hold
        cell_size = float(cell_size)
        mtu_cells = math.ceil(default_port_mtu / cell_size)
        headroom_cells = math.ceil(buffer_headroom / cell_size)
        pool_cells = math.ceil(math.ceil(buffer_pool_size / cell_size) * (buffer_alpha / (buffer_alpha + 1)))
        buffer_max_pkts_capacity = (headroom_cells - mtu_cells + pool_cells)

        # Send a bit more packets to see whether drops appear after reached max buffer utilization
        pkts_max = buffer_max_pkts_capacity + 1

        logging.info('Max packets buffer capacity - %d, max packets to send - %d' % (buffer_max_pkts_capacity, pkts_max))

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        # Close DST port
        sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], STOP_PORT_MAX_RATE)

        #send packets
        try:
            pkts_bunch_size = packet_send_rate # Number of packages to send to DST port
            pkts_count = 0 # Total number of shipped packages
            ingress_drop_counter = 0

            # Send the packets untill PFC counter will be trigerred or max pkts reached
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)
            while ingress_drop_counter == 0 and pkts_count < pkts_max:
                testutils.send_packet(self, src_port_id, pkt, pkts_bunch_size)
                pkts_count += pkts_bunch_size
                time.sleep(1)

                port_counters, _ = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
                ingress_drop_counter = port_counters[INGRESS_DROP]

                logging.info('Sent %d packets, total packet sent %d, ingress drops %d' % (pkts_bunch_size, pkts_count, ingress_drop_counter))

            # wait for INGRESS_DROP counter to be updated
            time.sleep(7)

            port_counters, _ = sai_thrift_read_port_counters(self.client, port_list[src_port_id])
            ingress_drop_counter = port_counters[INGRESS_DROP]

            buffer_utilization = pkts_count - ingress_drop_counter
            logging.info("Result: Buffer utilization %d, calculated %d" % (buffer_utilization, buffer_max_pkts_capacity))

            # Utilization should be within 3-4 MTU (generic for SCP and SPC2)
            assert not (buffer_utilization + buffer_utilization_tolerance*mtu_cells) < buffer_max_pkts_capacity, "Buffer is under utilized"
            assert not (buffer_utilization - buffer_utilization_tolerance*mtu_cells) > buffer_max_pkts_capacity, "Buffer is over utilized"

        finally:
            # RELEASE PORT
            sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], RELEASE_PORT_MAX_RATE)

class PGHeadroomWatermarkTest(sai_base_test.ThriftInterfaceDataPlane):  

    def runTest(self):
        time.sleep(5)
        switch_init(self.client)

        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        buffer_headroom = int(self.test_params['buffer_headroom'])
        buffer_alpha = float(self.test_params['buffer_alpha'])
        buffer_pool_size = int(self.test_params['buffer_pool_size'])
        buffer_xon = int(self.test_params['buffer_xon'])
        cell_size = int(self.test_params['cell_size'])
        num_of_pkts = int(self.test_params['num_of_pkts'])
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)

        logging.info('Buffer headroom: %d' % buffer_headroom)
        logging.info('Buffer pool size: %d' % buffer_pool_size)
        logging.info('Buffer alpha: %d' % buffer_alpha)
        logging.info('Cell size: %d' % cell_size)

        # calculate the exact max packets number that buffer can hold
        cell_size = float(cell_size)
        xon_cells = int(math.ceil(buffer_xon / cell_size))
        headroom_cells = math.ceil(buffer_headroom / cell_size)
        pool_cells = math.ceil(math.ceil(buffer_pool_size / cell_size) * (buffer_alpha / (buffer_alpha + 1)))

        # Close DST port
        sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], STOP_PORT_MAX_RATE)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        try:
            tos = dscp << 2
            tos |= ecn
            ttl=64
            default_packet_length = 64

            q_wm_res, pg_shared_wm_res, pg_headroom_wm_res = sai_thrift_read_port_watermarks(self.client, port_list[src_port_id])
            
            logging.info("Pre-test watermark\nShared:{}\nHeadroom{}".format(pg_shared_wm_res, pg_headroom_wm_res))
            assert pg_headroom_wm_res[dscp] == 0, "PG headroom WM is not zero at the beginning of the test!"
            # Send the packets untill PFC counter will be trigerred or max pkts reached
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)

            testutils.send_packet(self, src_port_id, pkt, num_of_pkts + xon_cells)

            q_wm_res, pg_shared_wm_res, pg_headroom_wm_res = sai_thrift_read_port_watermarks(self.client, port_list[src_port_id])
            
            logging.info("Post-test watermark\nShared:{}\nHeadroom{}".format(pg_shared_wm_res, pg_headroom_wm_res))

            expected_wm = num_of_pkts*cell_size
            assert pg_headroom_wm_res[dscp] == expected_wm, "Priority-group headroom WM is not what is expected! {} != {}".format(pg_headroom_wm_res[dscp], expected_wm)

        finally:
            # RELEASE PORTS
            sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], RELEASE_PORT_MAX_RATE)


class QSharedWatermarkTest(sai_base_test.ThriftInterfaceDataPlane):  
    def runTest(self):
        time.sleep(5)
        switch_init(self.client)
        
        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        buffer_headroom = int(self.test_params['buffer_headroom'])
        buffer_alpha = float(self.test_params['buffer_alpha'])
        buffer_pool_size = int(self.test_params['buffer_pool_size'])
        cell_size = int(self.test_params['cell_size'])
        num_of_pkts = int(self.test_params['num_of_pkts'])
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        src_port_mac = self.dataplane.get_mac(0, src_port_id)

        # Close DST port
        sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], STOP_PORT_MAX_RATE)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        try:
            tos = dscp << 2
            tos |= ecn
            ttl=64
            default_packet_length = 64

            
            q_wm_res, _, _ = sai_thrift_read_port_watermarks(self.client, port_list[dst_port_id])
            logging.info("Pre-test watermark\nShared:{}".format(q_wm_res))
            assert q_wm_res[dscp] == 0, "Queue shared WM is not zero at the beginning of the test!"

            # Send the packets untill PFC counter will be trigerred or max pkts reached
            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)

            testutils.send_packet(self, src_port_id, pkt, num_of_pkts)
            
            q_wm_res, _, _ = sai_thrift_read_port_watermarks(self.client, port_list[dst_port_id])
            logging.info("Post-test watermark\nShared:{}".format(q_wm_res))

            expected_wm = num_of_pkts*cell_size

            assert q_wm_res[dscp] == expected_wm, "Queue shared WM is not what is expected! {} != {}".format(q_wm_res[dscp], expected_wm)

        finally:
            # RELEASE PORTS
            sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], RELEASE_PORT_MAX_RATE)

class PGSharedWatermarkTest(sai_base_test.ThriftInterfaceDataPlane):

    def runTest(self):
        time.sleep(5)
        switch_init(self.client)
        
        # Parse input parameters
        dscp = int(self.test_params['dscp'])
        ecn = int(self.test_params['ecn'])
        router_mac = self.test_params['router_mac']
        buffer_headroom = int(self.test_params['buffer_headroom'])
        buffer_alpha = float(self.test_params['buffer_alpha'])
        buffer_pool_size = int(self.test_params['buffer_pool_size'])
        buffer_xon = 192*96*1000  #int(self.test_params['buffer_xon'])
        cell_size = int(self.test_params['cell_size'])
        num_of_pkts = int(self.test_params['num_of_pkts'])
        default_port_mtu = int(self.test_params['default_port_mtu'])
        cell_size = int(self.test_params['cell_size'])
        dst_port_id = int(self.test_params['dst_port_id'])
        dst_port_ip = self.test_params['dst_port_ip']
        src_port_id = int(self.test_params['src_port_id'])
        src_port_ip = self.test_params['src_port_ip']
        dst_port_mac = self.dataplane.get_mac(0, dst_port_id)
        src_port_mac = self.dataplane.get_mac(0, src_port_id)


        cell_size = float(cell_size)
        mtu_cells = math.ceil(default_port_mtu / cell_size)
        headroom_cells = math.ceil(buffer_headroom / cell_size)
        xon_cells = math.ceil(buffer_xon / cell_size)
        pool_cells = math.ceil(math.ceil(buffer_pool_size / cell_size) * (buffer_alpha / (buffer_alpha + 1)))
        buffer_max_pkts_capacity = (headroom_cells - mtu_cells + pool_cells)

        logging.info('Cell size: %d' % cell_size)
        logging.info('Buffer alpha: %d' % buffer_alpha)
        logging.info('MTU cells: {} / {}'.format(mtu_cells, mtu_cells*cell_size))
        logging.info('Headroom cells: {} / {}'.format(headroom_cells, headroom_cells*cell_size))
        logging.info('Pool cells: {} / {}'.format(pool_cells, pool_cells*cell_size))
        logging.info('Buffer max cap: {} / {}'.format(buffer_max_pkts_capacity, buffer_max_pkts_capacity*cell_size))

        # Close DST port
        sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], STOP_PORT_MAX_RATE)

        # Clear Counters
        sai_thrift_clear_all_counters(self.client)

        #send packets
        try:
            tos = dscp << 2
            tos |= ecn
            ttl=64
            default_packet_length = 64

            q_wm_res, pg_shared_wm_res, pg_headroom_wm_res = sai_thrift_read_port_watermarks(self.client, port_list[src_port_id])            
            logging.info("Pre-test watermark\nShared:{}\nHeadroom{}".format(pg_shared_wm_res, pg_headroom_wm_res))
            assert pg_shared_wm_res[dscp] == 0, "PG shared WM is not zero at the beginning of the test!"

            pkt = simple_tcp_packet(pktlen=default_packet_length,
                                    eth_dst=router_mac,
                                    eth_src=src_port_mac,
                                    ip_src=src_port_ip,
                                    ip_dst=dst_port_ip,
                                    ip_tos=tos,
                                    ip_ttl=ttl)

            pkts_bunch_size = int(num_of_pkts)

            testutils.send_packet(self, src_port_id, pkt, pkts_bunch_size)

            q_wm_res, pg_shared_wm_res, pg_headroom_wm_res = sai_thrift_read_port_watermarks(self.client, port_list[src_port_id])            
            logging.info("Post-test watermark\nShared:{}\nHeadroom{}".format(pg_shared_wm_res, pg_headroom_wm_res))

            expected_wm = num_of_pkts*cell_size

            assert pg_shared_wm_res[dscp] == expected_wm, "PG shared WM is not what is expected! {} != {}".format(pg_shared_wm_res[dscp], expected_wm)

        finally:
            # RELEASE PORTS
            sai_thrift_set_port_shaper(self.client, port_list[dst_port_id], RELEASE_PORT_MAX_RATE)
