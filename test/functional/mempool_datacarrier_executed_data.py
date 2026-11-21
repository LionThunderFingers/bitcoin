#!/usr/bin/env python3
# Copyright (c) The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Executed-data accounting for the datacarrier limit.

A spend is charged for the bytes of its stack and code that the script execution did not use, so
payload can no longer ride in key slots that CHECKMULTISIG never reaches, in pushes that a NIP
consumes, in witness items that are dropped, or in branches that do not run.

Every node but the last two runs real Knots defaults (-corepolicy=0 -acceptnonstdtxn=0). The test
framework otherwise adds -corepolicy to every node, which turns the counting off. Nodes 1 to 3 only
lower -datacarriersize, to pin a charge between two limits (Knots caps the setting at 83, so a larger
charge is told apart only by being rejected). Node 4 has -datacarrierexecuted=0 and so behaves as the
verified-key recount alone, which is what the attack rows are accepted by. Node 5 has -corepolicy=1.

Set DATACARRIER_SOFT=1 to collect failures instead of stopping at the first, which is how the
negative control is run on a build that lacks this accounting. Set DATACARRIER_BASE=1 to leave out
the option that build does not know.
"""
import hashlib
import os
from random import randbytes

from test_framework.crypto.ripemd160 import ripemd160
from test_framework.key import (
    ECKey,
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    ser_string_vector,
)
from test_framework.script import (
    CScript,
    LegacySignatureHash,
    OP_0,
    OP_1,
    OP_16,
    OP_2,
    OP_2DROP,
    OP_2SWAP,
    OP_3,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_CHECKSIGVERIFY,
    OP_DEPTH,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_NOP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_GREATERTHANOREQUAL,
    OP_HASH160,
    OP_IF,
    OP_IFDUP,
    OP_NIP,
    OP_NOTIF,
    OP_NUMEQUAL,
    OP_OVER,
    OP_ROT,
    OP_SHA256,
    OP_SIZE,
    OP_SWAP,
    OP_TOALTSTACK,
    OP_TRUE,
    OP_VERIFY,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
    hash160,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.script_util import (
    key_to_p2sh_p2wpkh_script,
    key_to_p2wpkh_script,
    keyhash_to_p2pkh_script,
    script_to_p2sh_p2wsh_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet

FUNDING = 100_000
REJECT = "txn-datacarrier-exceeded"
# -datacarriersize of nodes 0 to 3. Knots caps it at 83.
LIMITS = [83, 0, 33, 66]
WITNESS_CAP = 1650  # -maxscriptsize at Knots defaults, for the whole witness stack of an input
SCRIPTSIG_CAP = 1650  # MAX_STANDARD_SCRIPTSIG_SIZE
SOFT = bool(os.environ.get("DATACARRIER_SOFT"))
BASE = bool(os.environ.get("DATACARRIER_BASE"))


def sha256(b):
    return hashlib.sha256(b).digest()


def nz(n):
    """n random bytes, the first one nonzero. A single byte is never one a script push of it would write as an
    opcode (1 to 16, or 0x81), so pushing it is minimal, as the standard flags require."""
    first = 1 + randbytes(1)[0] % 200
    if n == 1 and (first <= 16 or first == 0x81):
        first += 0x20
    return bytes([first]) + randbytes(n - 1)


def cs(n):
    return 1 if n < 253 else 3


def wlen(items):
    return cs(len(items)) + sum(cs(len(x)) + len(x) for x in items)


def seeded_key(i):
    k = ECKey()
    k.set(sha256(b"pr2 executed data key %d" % i), True)
    return k


class ExecutedDataTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 6
        defaults = ["-corepolicy=0", "-acceptnonstdtxn=0"]
        self.extra_args = [defaults] + [defaults + [f"-datacarriersize={n}"] for n in LIMITS[1:]]
        # The recount without this accounting: what the attack rows must be accepted by.
        self.extra_args.append(defaults if BASE else defaults + ["-datacarrierexecuted=0"])
        self.extra_args.append(["-corepolicy=1"])
        self.failures = []

    # ---- bookkeeping ----

    def verdict(self, name, ok, detail=""):
        self.log.info(f"RESULT|{name}|{'OK' if ok else 'FAIL'}|{detail}")
        if not ok:
            self.failures.append((name, detail))
            if not SOFT:
                raise AssertionError(f"{name}: {detail}")

    def accept(self, node, tx):
        return node.testmempoolaccept([tx.serialize().hex()])[0]

    def check(self, tx, charge, what, control="accept"):
        """charge is the number of bytes the spend is charged (pinned by the limits of nodes 0 to 3, so
        up to 83), or None for 'more than 83', which every default node rejects with the datacarrier
        reason. control is what the node without this accounting does: 'accept' or 'reject'."""
        ok = True
        detail = []
        for n, limit in enumerate(LIMITS):
            res = self.accept(self.nodes[n], tx)
            should_accept = charge is not None and charge <= limit
            if should_accept:
                good = res['allowed']
            else:
                good = (not res['allowed']) and res['reject-reason'] == REJECT
            if not good:
                ok = False
                detail.append(f"node{n} limit {limit}: expected {'accept' if should_accept else 'reject'}, got {res}")
        res = self.accept(self.nodes[4], tx)
        if (control == 'accept') != res['allowed']:
            ok = False
            detail.append(f"without the accounting: expected {control}, got {res}")
        if self.accept(self.nodes[5], tx)['allowed'] is not True and control == 'accept':
            ok = False
            detail.append("-corepolicy should not count it")
        self.verdict(what + (f" (charge {charge})" if charge is not None else " (rejected)"), ok, "; ".join(detail))
        return tx

    # ---- building blocks ----

    def newkey(self):
        k = ECKey()
        k.generate()
        return k

    @staticmethod
    def pub(k):
        return k.get_pubkey().get_bytes()

    @staticmethod
    def fake_key():
        return b'\x02' + randbytes(32)

    def p2wsh_sig(self, key, script, tx, i):
        return key.sign_ecdsa(SegwitV0SignatureHash(script, tx, i, SIGHASH_ALL, FUNDING)) + bytes([SIGHASH_ALL])

    def legacy_sig(self, key, script, tx, i):
        return key.sign_ecdsa(LegacySignatureHash(script, tx, i, SIGHASH_ALL)[0]) + bytes([SIGHASH_ALL])

    def fund(self, spk):
        f = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=spk, amount=FUNDING)
        return COutPoint(int(f['txid'], 16), f['sent_vout'])

    def spend_many(self, specs, locktime=0, mature=0):
        """Fund every spec and return an unmined tx spending all of them.

        A spec has 'spk', 'stack' (a function of the tx and input index giving the witness), and
        optionally 'script_sig' (same, giving the scriptSig) and 'sequence'."""
        outpoints = [self.fund(s['spk']) for s in specs]
        self.generate(self.wallet, 1 + mature, sync_fun=self.sync_blocks)
        tx = CTransaction()
        tx.version = 2
        tx.nLockTime = locktime
        tx.vin = [CTxIn(op, nSequence=s.get('sequence', 0xffffffff)) for op, s in zip(outpoints, specs)]
        tx.vout = [CTxOut(FUNDING * len(specs) - 10_000 * len(specs), script_to_p2wsh_script(CScript([OP_TRUE])))]
        tx.wit.vtxinwit = [CTxInWitness() for _ in specs]
        for i, s in enumerate(specs):
            if 'stack' in s:
                stack = s['stack'](tx, i)
                size = len(ser_string_vector(stack))
                assert size <= WITNESS_CAP, f"input {i}: witness is {size} bytes, over {WITNESS_CAP}"
                tx.wit.vtxinwit[i].scriptWitness.stack = stack
            if 'script_sig' in s:
                sig = s['script_sig'](tx, i)
                assert len(sig) <= SCRIPTSIG_CAP, f"input {i}: scriptSig is {len(sig)} bytes"
                tx.vin[i].scriptSig = sig
        return tx

    def wsh(self, script, stack, sequence=0xffffffff):
        return {'spk': script_to_p2wsh_script(script), 'stack': lambda tx, i: stack(tx, i) + [bytes(script)], 'sequence': sequence}

    def spend(self, script, stack, sequence=0xffffffff, locktime=0, mature=0):
        return self.spend_many([self.wsh(script, stack, sequence)], locktime=locktime, mature=mature)

    def p2sh(self, redeem, items, sequence=0xffffffff):
        """items is a function of (tx, i) giving the pushes before the redeemScript."""
        return {'spk': script_to_p2sh_script(redeem),
                'script_sig': lambda tx, i: CScript(items(tx, i) + [bytes(redeem)]),
                'sequence': sequence}

    def tap(self, leaf, stack, internal=None, sequence=0xffffffff):
        """A tapscript spend of one leaf. stack is a function of (tx, i, sighash) giving the items below the leaf."""
        internal = internal or compute_xonly_pubkey(generate_privkey())[0]
        t = taproot_construct(internal, [("leaf", leaf)])
        info = t.leaves["leaf"]
        control = bytes([info.version | t.negflag]) + t.internal_pubkey + info.merklebranch

        def wit(tx, i):
            utxo = [CTxOut(FUNDING, t.scriptPubKey)]
            return stack(tx, i, TaprootSignatureHash(tx, utxo, 0, i, scriptpath=True, leaf_script=leaf)) + [bytes(leaf), control]
        return {'spk': t.scriptPubKey, 'stack': wit, 'sequence': sequence}

    def fit(self, build_script, items_fn, size=256):
        """Garbage push sizes, `size` bytes each while the whole witness stack stays within the cap, then one filler."""
        chunks = []
        while wlen(items_fn(build_script(chunks + [size]))) <= WITNESS_CAP:
            chunks.append(size)
        for s in range(size - 1, 0, -1):
            if s in (33, 65):
                continue
            if wlen(items_fn(build_script(chunks + [s]))) <= WITNESS_CAP:
                chunks.append(s)
                break
        return chunks

    # ---- the channels that nothing counted before ----

    def attacks(self):
        self.log.info("Attack rows: each inside the witness cap, rejected at real defaults, accepted without the accounting")
        K = self.newkey()
        pub = self.pub(K)

        # CHECKMULTISIG tail garbage: the key slots under the matched key are never examined. The odd push
        # rule (#422) has counted these slots as data since 29.4.3, so the node without this accounting
        # rejects it as well; the row stays to show the two agree.
        chunks = self.fit(lambda ch: CScript([1] + [nz(c) for c in ch] + [pub, len(ch) + 1, OP_CHECKMULTISIG]), lambda sc: [b'', b'\x30' * 73, bytes(sc)])
        script = CScript([1] + [nz(c) for c in chunks] + [pub, len(chunks) + 1, OP_CHECKMULTISIG])
        self.check(self.spend(script, lambda tx, i: [b'', self.p2wsh_sig(K, script, tx, i)]), None, f"tail garbage in CHECKMULTISIG key slots ({sum(chunks)} bytes)", control="reject")

        # Executed but useless: <data> OP_NIP.
        chunks = self.fit(lambda ch: CScript([pub, OP_CHECKSIG] + sum([[nz(c), OP_NIP] for c in ch], [])), lambda sc: [b'\x30' * 73, bytes(sc)])
        script = CScript([pub, OP_CHECKSIG] + sum([[nz(c), OP_NIP] for c in chunks], []))
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), None, f"P2WSH NIP chain ({sum(chunks)} bytes)")

        # The same in tapscript.
        xpriv = generate_privkey()
        xonly = compute_xonly_pubkey(xpriv)[0]
        leaf = CScript([xonly, OP_CHECKSIG] + sum([[nz(256), OP_NIP] for _ in range(5)], []))
        self.check(self.spend_many([self.tap(leaf, lambda tx, i, h: [sign_schnorr(xpriv, h)])]), None, "tapscript NIP chain (1280 bytes)")

        # Dropped witness items: 18 x 80 (the standard limit of a P2WSH stack item).
        script = CScript([OP_2DROP] * 9 + [pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)] + [randbytes(80) for _ in range(18)]), None, "18 dropped witness items of 80 bytes")

        # What PR1 leaves of the jasonsopko live shape: its 14 script keys are charged by the verified-key
        # recount, so keep only what it cannot see: junk items and 14 witness-supplied fake keys with empty signatures.
        junk = 4
        script = CScript([OP_2DROP] * (junk // 2) + [OP_CHECKSIG, OP_DROP] * 14 + [pub, OP_CHECKSIG])

        def jason(tx, i):
            pairs = []
            for _ in range(14):
                pairs += [b'', self.fake_key()]
            return [self.p2wsh_sig(K, script, tx, i)] + pairs + [randbytes(72) for _ in range(junk)]
        self.check(self.spend(script, jason), None, "jasonsopko remainder: junk items and 14 witness-supplied fake keys")

        # P2SH scriptSig junk pushes, consumed by OP_2DROP at the front of the redeemScript.
        redeem = CScript([OP_2DROP] * 3 + [pub, OP_CHECKSIG])
        self.check(self.spend_many([self.p2sh(redeem, lambda tx, i: [self.legacy_sig(K, redeem, tx, i)] + [nz(250) for _ in range(6)])]), None, "P2SH scriptSig junk pushes (1500 bytes)")

        # An untaken, scriptSig-chosen branch of a P2SH redeemScript. Like the junk pushes above, this is a
        # legacy spend in a transaction with no witness at all (the datacarrier recount of -datacarrierfullcount
        # alone skips such a transaction, so only the executed-data accounting can charge it), and the static
        # count cannot see it, since the guard is not a constant.
        redeem = CScript([OP_IF, nz(200), nz(200), OP_ENDIF, pub, OP_CHECKSIG])
        tx = self.check(self.spend_many([self.p2sh(redeem, lambda tx, i: [self.legacy_sig(K, redeem, tx, i), b''])]), None, "P2SH untaken branch with 400 bytes of pushes, no witness")
        assert not any(vin.scriptWitness.stack for vin in tx.wit.vtxinwit), "this row must be a transaction with no witness"

        # An untaken witness-chosen branch.
        script = CScript([OP_IF] + [nz(250) for _ in range(5)] + [OP_ENDIF, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), b'']), None, "untaken branch with 1250 bytes of pushes")

        # <d> OP_SHA256 OP_DROP.
        script = CScript([nz(200), OP_SHA256, OP_DROP, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), None, "<d> SHA256 DROP")

        # An oversized preimage: 80 bytes charge 48, so three of them are over.
        pres = [nz(80) for _ in range(3)]
        script = CScript(sum([[OP_SHA256, sha256(p), OP_EQUALVERIFY] for p in pres], []) + [pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)] + pres[::-1]), None, "three oversized preimages of 80 bytes")
        pres = [nz(33) for _ in range(6)]
        script = CScript(sum([[OP_SHA256, sha256(p), OP_EQUALVERIFY] for p in pres], []) + [pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)] + pres[::-1]), None, "six preimages of 33 bytes")

        # Comparisons that check nothing.
        d = nz(200)
        script = CScript([d, OP_DUP, OP_EQUALVERIFY, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), None, "<d> DUP EQUALVERIFY")
        script = CScript([d, d, OP_EQUALVERIFY, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), None, "<d> <d> EQUALVERIFY, both in the script")
        a = nz(80)
        script = CScript([OP_EQUALVERIFY, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), a, a]), None, "witness against witness equality")

        # A raw value that only has to be true: one byte of it is used.
        script = CScript([nz(80), OP_VERIFY, nz(80), OP_VERIFY, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), None, "two <80B> VERIFY")

        # An altstack leftover.
        script = CScript([nz(200), OP_TOALTSTACK, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), None, "altstack leftover")

        # SIZE is the only use of the data.
        script = CScript([nz(200), OP_SIZE, 200, OP_EQUALVERIFY, OP_DROP, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), None, "SIZE-only use")

        # Untaken typed hash slots: three are free, the rest are data.
        hs = [sha256(randbytes(8)) for _ in range(8)]
        script = CScript([OP_IF] + sum([[OP_SHA256, h, OP_EQUALVERIFY] for h in hs], []) + [OP_ENDIF, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), b'']), None, "8 untaken hash slots")

        # <4B> OP_NIP runs: 16 charge 78, 17 charge 83, 18 are over.
        for n, charge in ((16, 78), (17, 83), (18, None)):
            script = CScript([pub, OP_CHECKSIG] + sum([[nz(4), OP_NIP] for _ in range(n)], []))
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), charge, f"{n} runs of <4B> NIP", control="accept")

    # ---- boundaries ----

    def boundaries(self):
        self.log.info("Boundary rows")
        K = self.newkey()
        pub = self.pub(K)

        # A preimage of 32 bytes is free, 33 costs its extra byte, 80 costs 48.
        for size, charge in ((32, 0), (33, 1), (80, 48)):
            p = nz(size)
            script = CScript([OP_SHA256, sha256(p), OP_EQUALVERIFY, pub, OP_CHECKSIG])
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), p]), charge, f"preimage of {size} bytes")

        # A raw condition of 1 byte against 2 on P2SH, which has no MINIMALIF.
        redeem = CScript([OP_IF, pub, OP_ELSE, pub, OP_ENDIF, OP_CHECKSIG])
        for cond, charge in ((b'\x11', 0), (b'\x11\x00', 1), (b'\x11\x00\x00', 2)):
            self.check(self.spend_many([self.p2sh(redeem, lambda tx, i: [self.legacy_sig(K, redeem, tx, i), cond])]), charge, f"P2SH IF condition of {len(cond)} bytes")

        # Lock allowance: three executed locks are free, a fourth is data.
        for n, charge in ((3, 0), (4, 65)):
            pres = [nz(32) for _ in range(n)]
            script = CScript(sum([[OP_SHA256, sha256(p), OP_EQUALVERIFY] for p in pres], []) + [pub, OP_CHECKSIG])
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)] + pres[::-1]), charge, f"{n} executed hash locks")
        # Untaken typed slots draw from the same three.
        for n, charge in ((3, 0), (4, 33)):
            hs = [sha256(randbytes(8)) for _ in range(n)]
            script = CScript([OP_IF] + sum([[OP_SHA256, h, OP_EQUALVERIFY] for h in hs], []) + [OP_ENDIF, pub, OP_CHECKSIG])
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), b'']), charge, f"{n} untaken hash slots")
        # Two executed and two untaken: the second untaken slot is over.
        pres = [nz(32) for _ in range(2)]
        hs = [sha256(randbytes(8)) for _ in range(2)]
        script = CScript(sum([[OP_SHA256, sha256(p), OP_EQUALVERIFY] for p in pres], [])
                         + [OP_IF] + sum([[OP_SHA256, h, OP_EQUALVERIFY] for h in hs], []) + [OP_ENDIF, pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), b''] + pres[::-1]), 33, "2 executed and 2 untaken hash locks")

        # Minimal numbers of 5 bytes in a branch that does not run carry ~4.9 bytes of payload each. Three are
        # inside the untaken-number budget (16 bytes), every further one is charged in full (push opcode and 5).
        def num5():
            return randbytes(4) + bytes([1 + randbytes(1)[0] % 0x7f])
        for n, charge in ((3, 0), (4, 6), (10, 42), (254, None)):
            nums = [num5() for _ in range(n)]
            script = CScript([OP_IF] + nums + [OP_ENDIF, pub, OP_CHECKSIG])
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), b'']), charge, f"{n} untaken 5-byte numbers")
        # The original shape: the key check runs, the numbers sit in the ELSE.
        nums = [num5() for _ in range(254)]
        script = CScript([OP_IF, pub, OP_CHECKSIG, OP_ELSE] + nums + [OP_ENDIF])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), b'\x01']), None, "254 untaken 5-byte numbers in the ELSE of IF <pk> CHECKSIG")
        # Opcodes that do not run name a byte each: 80 are free, the rest are charged.
        for n, charge in ((80, 0), (81, 1), (190, None)):
            script = CScript([OP_IF] + [OP_NOP] * n + [OP_ENDIF, pub, OP_CHECKSIG])
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), b'']), charge, f"{n} untaken opcode bytes")

        # A data source of exactly the remaining limit against one over: <x> NIP leaves x as the final
        # top, which uses one byte of it.
        for size, charge in ((34, 33), (35, 34)):
            script = CScript([pub, OP_CHECKSIG, nz(size), OP_NIP])
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), charge, f"data source of {size} bytes, limit 33")

        # Sources of every interesting size. A dropped witness item costs its length; a hashed and dropped script
        # push costs its length and its push opcode and length. (A tapscript or P2WSH stack item is capped at 80
        # bytes by standardness, so the larger sizes are script pushes, which RDTS caps at 256.)
        for size in (0, 1, 16, 17, 127, 128, 255, 256):
            push = nz(size) if size else b''
            script = CScript([push, OP_SHA256, OP_DROP, pub, OP_CHECKSIG])
            overhead = 1 if size <= 75 else (2 if size <= 255 else 3)
            charge = size + overhead if size else 0
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)]), None if charge > 83 else charge, f"hashed and dropped push of {size} bytes")
        for size in (1, 16, 17, 80):
            script = CScript([OP_DROP, pub, OP_CHECKSIG])
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), nz(size)]), size, f"dropped witness item of {size} bytes")
        # Many empty items are free.
        script = CScript([OP_2DROP] * 45 + [pub, OP_CHECKSIG])
        self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i)] + [b'' for _ in range(90)]), 0, "90 empty witness items")
        # The same push sizes in a branch that does not run, and as a dropped item. Pushes of 0 or 1 byte are numbers, inside
        # the untaken-number budget, so they are free. A push of n bytes is charged its length and its push opcode (1 byte
        # up to 75, 2 to 255), so 75 and 76 sit at 76 and 78, and 255 and 256 are over the limit. A P2WSH witness item is
        # capped at 80 bytes and a tapscript item at 80 by standardness, and a script push at 256 by RDTS, so the sizes
        # above are P2SH scriptSig items. (A tapscript OP_IF is banned by RDTS, so there is no tapscript untaken row.)
        def mini(size):
            # a one-byte push of 1 to 16 or 0x81 is not minimal, and a script that pushes it fails MINIMALDATA
            return bytes([0x20 + randbytes(1)[0] % 0x50]) + randbytes(size - 1) if size else b''
        for size in (0, 1, 16, 17, 75, 76, 255, 256):
            push = mini(size)
            overhead = 1 if size <= 75 else (2 if size <= 255 else 3)
            charge = 0 if size <= 1 else size + overhead
            script = CScript([OP_IF, push, OP_ENDIF, pub, OP_CHECKSIG])
            self.check(self.spend(script, lambda tx, i: [self.p2wsh_sig(K, script, tx, i), b'']), None if charge > 83 else charge, f"untaken push of {size} bytes, P2WSH")
            self.check(self.spend_many([self.p2sh(script, lambda tx, i: [self.legacy_sig(K, script, tx, i), b''])]), None if charge > 83 else charge, f"untaken push of {size} bytes, P2SH")
        drop = CScript([OP_DROP, pub, OP_CHECKSIG])
        for size in (0, 75, 76):
            item = mini(size)
            self.check(self.spend(drop, lambda tx, i: [self.p2wsh_sig(K, drop, tx, i), item]), size, f"dropped witness item of {size} bytes")
        for size in (0, 1, 16, 17, 75, 76, 255, 256):
            item = mini(size)
            self.check(self.spend_many([self.p2sh(drop, lambda tx, i: [self.legacy_sig(K, drop, tx, i), item])]), None if size > 83 else size, f"dropped P2SH scriptSig item of {size} bytes")
        # A redeemScript of 513 bytes is code.
        keys = [self.newkey() for _ in range(15)]
        redeem = CScript([15] + [self.pub(k) for k in keys] + [15, OP_CHECKMULTISIG])
        assert len(redeem) > 500
        self.check(self.spend_many([self.p2sh(redeem, lambda tx, i: [b''] + [self.legacy_sig(k, redeem, tx, i) for k in keys])]), 0, f"P2SH 15-of-15 with a redeemScript of {len(redeem)} bytes")

    # ---- honest spends ----

    def honest(self):
        self.log.info("Honest rows: accepted at defaults with no charge")
        # P2WPKH, P2TR key path, P2SH-P2WPKH, P2PKH.
        k = self.newkey()
        code = keyhash_to_p2pkh_script(hash160(self.pub(k)))
        self.check(self.spend_many([{'spk': key_to_p2wpkh_script(self.pub(k)), 'stack': lambda tx, i: [
            k.sign_ecdsa(SegwitV0SignatureHash(code, tx, i, SIGHASH_ALL, FUNDING)) + bytes([SIGHASH_ALL]), self.pub(k)]}]), 0, "P2WPKH")
        spk = key_to_p2sh_p2wpkh_script(self.pub(k))
        self.check(self.spend_many([{'spk': spk,
                                     'script_sig': lambda tx, i: CScript([bytes(CScript([OP_0, hash160(self.pub(k))]))]),
                                     'stack': lambda tx, i: [k.sign_ecdsa(SegwitV0SignatureHash(code, tx, i, SIGHASH_ALL, FUNDING)) + bytes([SIGHASH_ALL]), self.pub(k)]}]), 0, "P2SH-P2WPKH")
        self.check(self.spend_many([{'spk': CScript([OP_DUP, OP_HASH160, hash160(self.pub(k)), OP_EQUALVERIFY, OP_CHECKSIG]),
                                     'script_sig': lambda tx, i: CScript([self.legacy_sig(k, CScript([OP_DUP, OP_HASH160, hash160(self.pub(k)), OP_EQUALVERIFY, OP_CHECKSIG]), tx, i), self.pub(k)])}]), 0, "P2PKH")
        priv = generate_privkey()
        internal = compute_xonly_pubkey(priv)[0]
        t = taproot_construct(internal)
        tweaked = tweak_add_privkey(priv, t.tweak)
        self.check(self.spend_many([{'spk': t.scriptPubKey, 'stack': lambda tx, i: [sign_schnorr(tweaked, TaprootSignatureHash(tx, [CTxOut(FUNDING, t.scriptPubKey)], 0, i))]}]), 0, "taproot key path")

        # CHECKMULTISIG, P2WSH and P2SH.
        for m, n, signers in ((1, 1, None), (2, 3, None), (3, 5, None), (11, 15, None), (12, 12, None), (15, 15, None)):
            keys = [self.newkey() for _ in range(n)]
            script = CScript([m] + [self.pub(x) for x in keys] + [n, OP_CHECKMULTISIG])
            self.check(self.spend(script, lambda tx, i: [b''] + [self.p2wsh_sig(keys[j], script, tx, i) for j in range(m)]), 0, f"P2WSH {m}-of-{n}")
        for m, n in ((2, 3), (15, 15)):
            keys = [self.newkey() for _ in range(n)]
            redeem = CScript([m] + [self.pub(x) for x in keys] + [n, OP_CHECKMULTISIG])
            self.check(self.spend_many([self.p2sh(redeem, lambda tx, i: [b''] + [self.legacy_sig(keys[j], redeem, tx, i) for j in range(m)])]), 0, f"P2SH {m}-of-{n}")
        keys = [self.newkey() for _ in range(3)]
        inner = CScript([2] + [self.pub(x) for x in keys] + [3, OP_CHECKMULTISIG])
        self.check(self.spend_many([{'spk': script_to_p2sh_p2wsh_script(inner),
                                     'script_sig': lambda tx, i: CScript([bytes(CScript([OP_0, sha256(bytes(inner))]))]),
                                     'stack': lambda tx, i: [b'', self.p2wsh_sig(keys[0], inner, tx, i), self.p2wsh_sig(keys[1], inner, tx, i), bytes(inner)]}]), 0, "P2SH-P2WSH 2-of-3")

        # Tapscript multi_a.
        for kk, n in ((2, 3), (13, 13), (12, 14)):
            privs = [generate_privkey() for _ in range(n)]
            xs = [compute_xonly_pubkey(p)[0] for p in privs]
            leaf = CScript([xs[0], OP_CHECKSIG] + sum([[x, OP_CHECKSIGADD] for x in xs[1:]], []) + [kk, OP_NUMEQUAL])
            self.check(self.spend_many([self.tap(leaf, lambda tx, i, h: [sign_schnorr(privs[j], h) if j < kk else b'' for j in reversed(range(n))])]), 0, f"multi_a {kk}-of-{n}")

        self.bolt3()
        self.other_honest()
        self.corpus_shapes()

    def bolt3(self):
        """The scripts of BOLT 3, typed in from the text of the specification (not fetched here, so a
        transcription: the text itself was not available to this run)."""
        self.log.info("BOLT 3")
        rev, local_delayed, remote_htlc, local_htlc, funding = (self.newkey() for _ in range(5))
        delay = 10
        cltv = 100
        rev_h = hash160(self.pub(rev))
        preimage = nz(32)
        payment_h = ripemd160(sha256(preimage))

        # to_local, and the output of a second-level HTLC transaction, which has the same script.
        to_local = CScript([OP_IF, self.pub(rev), OP_ELSE, delay, OP_CHECKSEQUENCEVERIFY, OP_DROP, self.pub(local_delayed), OP_ENDIF, OP_CHECKSIG])
        for name in ("to_local", "second-level HTLC output"):
            self.check(self.spend(to_local, lambda tx, i: [self.p2wsh_sig(rev, to_local, tx, i), b'\x01']), 0, f"{name}, revocation")
            self.check(self.spend(to_local, lambda tx, i: [self.p2wsh_sig(local_delayed, to_local, tx, i), b''], sequence=delay, mature=delay), 0, f"{name}, delayed")

        for anchors in (False, True):
            tail = [1, OP_CHECKSEQUENCEVERIFY, OP_DROP] if anchors else []
            seq = 1 if anchors else 0xfffffffe
            tag = "anchors " if anchors else ""
            offered = CScript([OP_DUP, OP_HASH160, rev_h, OP_EQUAL, OP_IF, OP_CHECKSIG, OP_ELSE,
                               self.pub(remote_htlc), OP_SWAP, OP_SIZE, 32, OP_EQUAL, OP_NOTIF,
                               OP_DROP, 2, OP_SWAP, self.pub(local_htlc), 2, OP_CHECKMULTISIG,
                               OP_ELSE, OP_HASH160, payment_h, OP_EQUALVERIFY, OP_CHECKSIG, OP_ENDIF] + tail + [OP_ENDIF])
            self.check(self.spend(offered, lambda tx, i: [self.p2wsh_sig(rev, offered, tx, i), self.pub(rev)]), 0, f"{tag}offered HTLC, revocation")
            self.check(self.spend(offered, lambda tx, i: [self.p2wsh_sig(remote_htlc, offered, tx, i), preimage], sequence=seq), 0, f"{tag}offered HTLC, remote with the preimage")
            self.check(self.spend(offered, lambda tx, i: [b'', self.p2wsh_sig(remote_htlc, offered, tx, i), self.p2wsh_sig(local_htlc, offered, tx, i), b''], sequence=seq), 0, f"{tag}offered HTLC, timeout through the second level")

            received = CScript([OP_DUP, OP_HASH160, rev_h, OP_EQUAL, OP_IF, OP_CHECKSIG, OP_ELSE,
                                self.pub(remote_htlc), OP_SWAP, OP_SIZE, 32, OP_EQUAL, OP_IF,
                                OP_HASH160, payment_h, OP_EQUALVERIFY, 2, OP_SWAP, self.pub(local_htlc), 2, OP_CHECKMULTISIG,
                                OP_ELSE, OP_DROP, cltv, OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_CHECKSIG, OP_ENDIF] + tail + [OP_ENDIF])
            self.check(self.spend(received, lambda tx, i: [self.p2wsh_sig(rev, received, tx, i), self.pub(rev)]), 0, f"{tag}received HTLC, revocation")
            self.check(self.spend(received, lambda tx, i: [b'', self.p2wsh_sig(remote_htlc, received, tx, i), self.p2wsh_sig(local_htlc, received, tx, i), preimage], sequence=seq), 0, f"{tag}received HTLC, success through the second level")
            self.check(self.spend(received, lambda tx, i: [self.p2wsh_sig(remote_htlc, received, tx, i), b''], sequence=seq, locktime=cltv), 0, f"{tag}received HTLC, remote after the timeout")

        # option_anchors: to_remote and the anchor output, which is also swept by anyone after 16 blocks.
        to_remote = CScript([self.pub(rev), OP_CHECKSIGVERIFY, 1, OP_CHECKSEQUENCEVERIFY])
        self.check(self.spend(to_remote, lambda tx, i: [self.p2wsh_sig(rev, to_remote, tx, i)], sequence=1), 0, "to_remote with anchors")
        anchor = CScript([self.pub(funding), OP_CHECKSIG, OP_IFDUP, OP_NOTIF, OP_16, OP_CHECKSEQUENCEVERIFY, OP_ENDIF])
        self.check(self.spend(anchor, lambda tx, i: [self.p2wsh_sig(funding, anchor, tx, i)]), 0, "anchor, signed by the funding key")
        self.check(self.spend(anchor, lambda tx, i: [b''], sequence=16, mature=16), 0, "anchor, swept with an empty signature after 16 blocks")
        # The funding output.
        a, b = self.newkey(), self.newkey()
        funding_script = CScript([2, self.pub(a), self.pub(b), 2, OP_CHECKMULTISIG])
        self.check(self.spend(funding_script, lambda tx, i: [b'', self.p2wsh_sig(a, funding_script, tx, i), self.p2wsh_sig(b, funding_script, tx, i)]), 0, "funding 2-of-2")

    def other_honest(self):
        self.log.info("Federation, vault, swap")
        # Liquid style: 11-of-15, or after a timelock 2-of-3.
        fed = [self.newkey() for _ in range(15)]
        rec = [self.newkey() for _ in range(3)]
        liquid = CScript([OP_DEPTH, 12, OP_GREATERTHANOREQUAL, OP_IF, 11] + [self.pub(k) for k in fed] + [15, OP_CHECKMULTISIG,
                          OP_ELSE, 10, OP_CHECKSEQUENCEVERIFY, OP_DROP, 2] + [self.pub(k) for k in rec] + [3, OP_CHECKMULTISIG, OP_ENDIF])
        self.check(self.spend(liquid, lambda tx, i: [b''] + [self.p2wsh_sig(fed[j], liquid, tx, i) for j in range(11)]), 0, "federation 11-of-15")
        # The recovery path keeps 15 + 1 unproven keys on the books: the verified-key recount already
        # refuses it, so what this row pins is that the accounting does not change that.
        self.check(self.spend(liquid, lambda tx, i: [b'', self.p2wsh_sig(rec[0], liquid, tx, i), self.p2wsh_sig(rec[1], liquid, tx, i)], sequence=10, mature=10), None, "federation recovery path (as without the accounting)", control="reject")

        # A vault: a delayed hot key, or two cold keys at once.
        hot, c1, c2 = self.newkey(), self.newkey(), self.newkey()
        vault = CScript([OP_IF, 10, OP_CHECKSEQUENCEVERIFY, OP_DROP, self.pub(hot), OP_CHECKSIG, OP_ELSE, 2, self.pub(c1), self.pub(c2), 2, OP_CHECKMULTISIG, OP_ENDIF])
        self.check(self.spend(vault, lambda tx, i: [self.p2wsh_sig(hot, vault, tx, i), b'\x01'], sequence=10, mature=10), 0, "vault, hot key after the delay")
        self.check(self.spend(vault, lambda tx, i: [b'', self.p2wsh_sig(c1, vault, tx, i), self.p2wsh_sig(c2, vault, tx, i), b'']), 0, "vault, cold keys")

        # Hash-locked atomic swaps with a 32 byte preimage.
        recv, refund = self.newkey(), self.newkey()
        pre = nz(32)
        swap = CScript([OP_IF, OP_SHA256, sha256(pre), OP_EQUALVERIFY, self.pub(recv), OP_CHECKSIG, OP_ELSE, 100, OP_CHECKLOCKTIMEVERIFY, OP_DROP, self.pub(refund), OP_CHECKSIG, OP_ENDIF])
        self.check(self.spend(swap, lambda tx, i: [self.p2wsh_sig(recv, swap, tx, i), pre, b'\x01']), 0, "swap, claim with the preimage")
        self.check(self.spend(swap, lambda tx, i: [self.p2wsh_sig(refund, swap, tx, i), b''], sequence=0xfffffffe, locktime=100), 0, "swap, refund")
        xp = generate_privkey()
        xo = compute_xonly_pubkey(xp)[0]
        leaf = CScript([OP_SHA256, sha256(pre), OP_EQUALVERIFY, xo, OP_CHECKSIG])
        self.check(self.spend_many([self.tap(leaf, lambda tx, i, h: [sign_schnorr(xp, h), pre])]), 0, "tapscript swap with the preimage")

    def corpus_shapes(self):
        """Honest scripts that the corpus replay of the 144 blocks found charged by an earlier version of the accounting."""
        self.log.info("Corpus-derived rows: submarine swap with key hashes, selector of key hash pairs")
        # A submarine swap: IF SIZE 32 EQUALVERIFY SHA256 <h> EQUALVERIFY DUP HASH160 <claim> ELSE <t> CLTV DROP DUP HASH160 <refund> ENDIF EQUALVERIFY CHECKSIG
        claim, refund = self.newkey(), self.newkey()
        pre = nz(32)
        swap = CScript([OP_IF, OP_SIZE, 32, OP_EQUALVERIFY, OP_SHA256, sha256(pre), OP_EQUALVERIFY, OP_DUP, OP_HASH160, hash160(self.pub(claim)),
                        OP_ELSE, 100, OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_DUP, OP_HASH160, hash160(self.pub(refund)), OP_ENDIF, OP_EQUALVERIFY, OP_CHECKSIG])
        self.check(self.spend(swap, lambda tx, i: [self.p2wsh_sig(claim, swap, tx, i), self.pub(claim), pre, b'\x01']), 0, "key-hash swap, claim")
        self.check(self.spend(swap, lambda tx, i: [self.p2wsh_sig(refund, swap, tx, i), self.pub(refund), b''], sequence=0xfffffffe, locktime=100), 0, "key-hash swap, refund")

        # A selector: every branch names two key hashes up front, the spender picks the branch with a number.
        # DUP 1 EQUAL IF DROP <h1> <h2> ELSE DUP 2 EQUAL IF DROP <h1> <h3> ELSE DUP 3 EQUAL IF DROP <h3> <h4> ELSE 4 EQUALVERIFY <h3> <h5> ENDIF ENDIF ENDIF
        # ROT HASH160 EQUALVERIFY OVER HASH160 EQUALVERIFY CHECKSIG
        ks = [self.newkey() for _ in range(5)]
        h = [hash160(self.pub(k)) for k in ks]
        sel = CScript([OP_DUP, 1, OP_EQUAL, OP_IF, OP_DROP, h[0], h[1], OP_ELSE, OP_DUP, 2, OP_EQUAL, OP_IF, OP_DROP, h[0], h[2],
                       OP_ELSE, OP_DUP, 3, OP_EQUAL, OP_IF, OP_DROP, h[2], h[3], OP_ELSE, 4, OP_EQUALVERIFY, h[2], h[4], OP_ENDIF, OP_ENDIF, OP_ENDIF,
                       OP_ROT, OP_HASH160, OP_EQUALVERIFY, OP_OVER, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG])
        for choice, (a, b) in ((1, (0, 1)), (2, (0, 2)), (3, (2, 3)), (4, (2, 4))):
            # The stack under the selector: signature, the key hashed against the first hash, the key hashed against the second.
            self.check(self.spend(sel, lambda tx, i: [self.p2wsh_sig(ks[a], sel, tx, i), self.pub(ks[a]), self.pub(ks[b]), bytes([choice])]), 0, f"selector script, branch {choice} (P2WSH)")
        # The same script behind P2SH-P2WSH, as on the corpus.
        self.check(self.spend_many([{'spk': script_to_p2sh_p2wsh_script(sel),
                                     'script_sig': lambda tx, i: CScript([bytes(script_to_p2wsh_script(sel))]),
                                     'stack': lambda tx, i: [self.p2wsh_sig(ks[0], sel, tx, i), self.pub(ks[0]), self.pub(ks[1]), b'\x01', bytes(sel)]}]), 0, "selector script (P2SH-P2WSH)")

    def miniscript_rows(self):
        """Scripts made by the miniscript implementation of the tree (src/test/miniscript_tests.cpp,
        scripts_of_the_executed_data_functional_test checks that these are what it makes), spent here with
        real signatures. K1 to K8 are seeded_key(1..8), pre1 and pre3 the preimages of H1 and H3."""
        self.log.info("Miniscript, generated by src/script/miniscript.*")
        MS = [
            "210335049a0ea93d68b915619cb80c3260f53cd17ceba0c7d332ea651a09298c7ca7ac736476a91462a37f4df923ea2fdb5066239e9c6ef36dd293a988ad5ab268",
            "210335049a0ea93d68b915619cb80c3260f53cd17ceba0c7d332ea651a09298c7ca7ac642102a36b67e00284494fd649fd7c5eb03d7e8bf933095857ac640ca2262bd1d678f2ac6782012088a82083bb6fba4955e7cfa8e9c93880df580d293a5e04f6dbf024079fe0242f6e22c88768",
            "76a914e2ef6705f4a1a536f9b47cb863aedb89fcb965c188ac736482012088a82083bb6fba4955e7cfa8e9c93880df580d293a5e04f6dbf024079fe0242f6e22c88882012088a9144173c80a0436fcfe1e6826bf35a6cafda471e248882102a36b67e00284494fd649fd7c5eb03d7e8bf933095857ac640ca2262bd1d678f2ac68",
            "210335049a0ea93d68b915619cb80c3260f53cd17ceba0c7d332ea651a09298c7ca7ac6b76a91462a37f4df923ea2fdb5066239e9c6ef36dd293a988ac6c936b76a914e2ef6705f4a1a536f9b47cb863aedb89fcb965c188ac6c936b76a914370f0b5e29b1b202897b5198bcfb5049a795411788ac6c936b76a914c9032d1155c557d015a5f8e443414c68e6df99e788ac6c936b76a914014cfbf386a4bdc517d6373cb19419bece989f0388ac6c935287",
            "210335049a0ea93d68b915619cb80c3260f53cd17ceba0c7d332ea651a09298c7ca7ac6b76a91462a37f4df923ea2fdb5066239e9c6ef36dd293a988ac6c936b76a914e2ef6705f4a1a536f9b47cb863aedb89fcb965c188ac6c936b76a914370f0b5e29b1b202897b5198bcfb5049a795411788ac6c936b76a914c9032d1155c557d015a5f8e443414c68e6df99e788ac6c936b76a914014cfbf386a4bdc517d6373cb19419bece989f0388ac6c936b76a9144ec255e3dee3f7adbfcfa2b058aa8f0d95bd9f2188ac6c936b76a914cf42b7ef36628b9431d4ac522de6f20be3fa865388ac6c935287",
            "53210335049a0ea93d68b915619cb80c3260f53cd17ceba0c7d332ea651a09298c7ca72102a36b67e00284494fd649fd7c5eb03d7e8bf933095857ac640ca2262bd1d678f221024e94e6664a502077fa1d8a70d7a7a4e26957fb702cd7df752d313658a42d27452102dbbea9cf8350896daf74e047997a36951ca17f6875ad3dce9ada893abb15b48621032c12499e669f390968839f55b88c7d5700bcc7b32e13b0eb83f6136c2e45423855ae736452210335049a0ea93d68b915619cb80c3260f53cd17ceba0c7d332ea651a09298c7ca72102a36b67e00284494fd649fd7c5eb03d7e8bf933095857ac640ca2262bd1d678f221024e94e6664a502077fa1d8a70d7a7a4e26957fb702cd7df752d313658a42d274553af5ab268",
        ]
        keys = {i: seeded_key(i) for i in range(1, 9)}
        pub = {i: self.pub(k) for i, k in keys.items()}
        pre1, pre3 = sha256(b"pr2 preimage 1"), sha256(b"pr2 preimage 3")
        scripts = [CScript(bytes.fromhex(h)) for h in MS]

        def sig(i, script, tx, n):
            return self.p2wsh_sig(keys[i], script, tx, n)

        def run(idx, name, items, **kw):
            script = scripts[idx]
            self.check(self.spend(script, lambda tx, n: items(script, tx, n), **kw), 0, name)

        run(0, "or_d(pk, and_v(v:pkh, older)), first branch", lambda sc, tx, n: [sig(1, sc, tx, n)])
        run(0, "or_d(pk, and_v(v:pkh, older)), second branch", lambda sc, tx, n: [sig(2, sc, tx, n), pub[2], b''], sequence=10, mature=10)
        run(1, "andor(pk, sha256, pk), X and Y", lambda sc, tx, n: [pre1, sig(1, sc, tx, n)])
        run(1, "andor(pk, sha256, pk), Z", lambda sc, tx, n: [sig(2, sc, tx, n), b''])
        run(2, "or_d(pkh, and_v(sha256, and_v(hash160, pk))), pkh branch", lambda sc, tx, n: [sig(3, sc, tx, n), pub[3]])
        run(2, "or_d(pkh, and_v(sha256, and_v(hash160, pk))), two hash fragments", lambda sc, tx, n: [sig(2, sc, tx, n), pre3, pre1, b'', pub[3]])
        run(3, "thresh 2 of pk and 5 pkh, four pkh unsigned", lambda sc, tx, n:
            sum([[b'', pub[j]] for j in (6, 5, 4, 3)], []) + [sig(2, sc, tx, n), pub[2], sig(1, sc, tx, n)])
        run(4, "thresh 2 of pk and 7 pkh, six pkh unsigned", lambda sc, tx, n:
            sum([[b'', pub[j]] for j in (8, 7, 6, 5, 4, 3)], []) + [sig(2, sc, tx, n), pub[2], sig(1, sc, tx, n)])
        run(5, "decaying multisig, 3-of-5", lambda sc, tx, n: [b'', sig(1, sc, tx, n), sig(2, sc, tx, n), sig(3, sc, tx, n)])
        run(5, "decaying multisig, 2-of-3 after the delay", lambda sc, tx, n: [b'', sig(1, sc, tx, n), sig(2, sc, tx, n), b'', b'', b'', b''], sequence=10, mature=10)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 130)
        self.honest()
        self.miniscript_rows()
        self.boundaries()
        self.attacks()
        if self.failures:
            self.log.info("FAILED ROWS: %d" % len(self.failures))
            for name, detail in self.failures:
                self.log.info(f"  FAIL {name}: {detail}")
            if not SOFT:
                raise AssertionError("rows failed")


if __name__ == '__main__':
    ExecutedDataTest(__file__).main()
