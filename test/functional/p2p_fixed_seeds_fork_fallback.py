#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fixed seeds are added for every reachable network when no fork-capable outbound peers turn up.

The usual fixed-seed fallback only loads seeds for a network whose addrman is empty, so a node with an
addrman full of peers that cannot serve the chain past the BLAKE2b hard fork never loads them. After
FIXED_SEEDS_FORK_FALLBACK_DELAY with fewer than two fork-capable full outbound peers, the node adds
them once. Regtest has no fixed seeds, so this checks when the fallback fires, not what it adds.
"""
import time

from test_framework.messages import NODE_BLAKE2B, NODE_NETWORK, NODE_WITNESS
from test_framework.netutil import UNREACHABLE_PROXY_ARG
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework

FALLBACK_MSG = "fixed seeds from reachable networks as fewer than 2 fork-capable outbound peers were found"
STALE = NODE_NETWORK | NODE_WITNESS
FORK = NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B


class FixedSeedsForkFallbackTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.disable_autoconnect = False

    def start_with_mocktime(self, extra=()):
        now = int(time.time())
        with self.nodes[0].assert_debug_log(expected_msgs=["opencon thread start"], timeout=10):
            self.start_node(0, extra_args=["-fixedseeds=1", f"-mocktime={now}", UNREACHABLE_PROXY_ARG, *extra])
        return now

    def run_test(self):
        node = self.nodes[0]
        self.stop_node(0)

        self.log.info("Disabled with -fixedseeds=0")
        now = int(time.time())
        with node.assert_debug_log(expected_msgs=["opencon thread start"], timeout=10):
            self.start_node(0, extra_args=["-fixedseeds=0", f"-mocktime={now}", UNREACHABLE_PROXY_ARG])
        with node.assert_debug_log(expected_msgs=[], unexpected_msgs=[FALLBACK_MSG], timeout=3):
            node.setmocktime(now + 3 * 60)
            time.sleep(2)
        self.stop_node(0)

        self.log.info("Addrman holds only addresses without NODE_BLAKE2B and no fork-capable peer connects")
        now = self.start_with_mocktime()
        for i in range(50):
            node.addpeeraddress(f"1.{i}.1.1", 8333, False, STALE)
        with node.assert_debug_log(expected_msgs=[], unexpected_msgs=[FALLBACK_MSG], timeout=3):
            node.setmocktime(now + 60)
            time.sleep(2)
        self.log.info("Not before the delay; fires once it has passed")
        with node.assert_debug_log(expected_msgs=[f"Added 0 {FALLBACK_MSG}"], timeout=10):
            node.setmocktime(now + 2 * 60 + 1)
        self.log.info("Only once")
        with node.assert_debug_log(expected_msgs=[], unexpected_msgs=[FALLBACK_MSG], timeout=3):
            node.setmocktime(now + 10 * 60)
            time.sleep(2)
        self.stop_node(0)

        self.log.info("Two fork-capable full outbound peers: no fallback")
        now = self.start_with_mocktime()
        for i in range(2):
            node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=i, connection_type="outbound-full-relay", services=FORK)
        with node.assert_debug_log(expected_msgs=[], unexpected_msgs=[FALLBACK_MSG], timeout=3):
            node.setmocktime(now + 3 * 60)
            time.sleep(2)
        self.log.info("Losing them later fires it")
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        with node.assert_debug_log(expected_msgs=[f"Added 0 {FALLBACK_MSG}"], timeout=10):
            node.setmocktime(now + 4 * 60)


if __name__ == '__main__':
    FixedSeedsForkFallbackTest(__file__).main()
