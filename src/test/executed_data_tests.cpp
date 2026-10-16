// Copyright (c) The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/executed_data.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(executed_data_tests, BasicTestingSetup)

namespace {
using valtype = std::vector<unsigned char>;
using Ledger = ExecutedDataTracer::Ledger;

//! Every signature that is not empty verifies, so what a spend uses is decided by the script alone.
class TruthChecker : public BaseSignatureChecker
{
public:
    bool CheckECDSASignature(const valtype& sig, const valtype&, const CScript&, SigVersion, SighashRules = SighashRules::LEGACY) const override { return !sig.empty(); }
    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char>, SigVersion, ScriptExecutionData&, ScriptError* = nullptr, SighashRules = SighashRules::LEGACY) const override { return !sig.empty(); }
    bool CheckLockTime(const CScriptNum&) const override { return true; }
    bool CheckSequence(const CScriptNum&) const override { return true; }
};

struct Traced {
    bool ok{false};
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    Ledger ledger;
};

const unsigned int FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS};

valtype Bytes(size_t n, unsigned char seed)
{
    valtype v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<unsigned char>(seed + i);
    return v;
}
valtype Key(unsigned char seed)
{
    valtype k{Bytes(33, seed)};
    k[0] = 0x02;
    return k;
}
valtype XKey(unsigned char seed) { return Bytes(32, seed); }
//! A signature with a valid DER and hashtype encoding, which is all the policy flags look at.
valtype Sig() { return {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01}; }
valtype Schnorr() { return Bytes(64, 0x40); }
valtype Sha256(const valtype& v)
{
    valtype out(32);
    CSHA256().Write(v.data(), v.size()).Finalize(out.data());
    return out;
}
valtype Hash160(const valtype& v)
{
    valtype out(20);
    CHash160().Write(v).Finalize(out);
    return out;
}

//! Run one script the way the interpreter runs a witness script, over the given initial stack.
Traced TraceEval(ScriptRunKind kind, SigVersion sigversion, const CScript& script, std::vector<valtype> stack, unsigned int flags = FLAGS)
{
    Traced t;
    const TruthChecker truth;
    VerifiedKeys keys;
    SigCheckLog log;
    ExecutedDataTracer tracer{&log};
    const KeyRecordingSignatureChecker checker{truth, keys, &log, &tracer};
    ScriptExecutionData execdata;
    execdata.m_validation_weight_left = 1000000;
    execdata.m_validation_weight_left_init = true;
    tracer.SetRunKind(kind);
    t.ok = EvalScript(stack, script, flags, checker, sigversion, execdata, &t.err);
    t.ledger = tracer.Finish();
    return t;
}
Traced TraceWsh(const CScript& script, std::vector<valtype> stack, unsigned int flags = FLAGS)
{
    return TraceEval(ScriptRunKind::WITNESS_V0_SCRIPT, SigVersion::WITNESS_V0, script, std::move(stack), flags);
}
Traced TraceTap(const CScript& script, std::vector<valtype> stack, unsigned int flags = FLAGS)
{
    return TraceEval(ScriptRunKind::TAPSCRIPT, SigVersion::TAPSCRIPT, script, std::move(stack), flags);
}

//! A whole spend: scriptSig, scriptPubKey, P2SH and witness runs.
Traced TraceSpend(const CScript& script_sig, const CScript& script_pub_key, const CScriptWitness& witness, unsigned int flags = FLAGS)
{
    Traced t;
    const TruthChecker truth;
    VerifiedKeys keys;
    SigCheckLog log;
    ExecutedDataTracer tracer{&log};
    const KeyRecordingSignatureChecker checker{truth, keys, &log, &tracer};
    t.ok = VerifyScript(script_sig, script_pub_key, &witness, flags, checker, &t.err);
    t.ledger = tracer.Finish();
    return t;
}

CScript Wsh(const CScript& script)
{
    return CScript() << OP_0 << Sha256(valtype(script.begin(), script.end()));
}

#define REQUIRE_TRACED(t) \
    BOOST_REQUIRE_MESSAGE((t).ok, ScriptErrorString((t).err)); \
    BOOST_REQUIRE_MESSAGE(!(t).ledger.failed, (t).ledger.fail_reason)

//! Index of the first source of this kind with this length.
size_t FindSource(const Ledger& l, ExecutedDataTracer::SourceKind kind, uint32_t len)
{
    for (size_t i = 0; i < l.sources.size(); ++i) {
        if (l.sources[i].kind == kind && l.sources[i].len == len) return i;
    }
    BOOST_FAIL("no such source");
    return 0;
}
} // namespace

// ---- the channels that nothing counted before ----------------------------------------------

BOOST_AUTO_TEST_CASE(checkmultisig_tail_garbage)
{
    // 1 <junk> <K> 2 CHECKMULTISIG: the key slot below the matched key is never examined.
    const valtype junk{Bytes(256, 7)};
    const CScript script = CScript() << OP_1 << junk << Key(1) << OP_2 << OP_CHECKMULTISIG;
    const auto t = TraceWsh(script, {{}, Sig()});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 256U);
}

BOOST_AUTO_TEST_CASE(checkmultisig_maps_signatures_to_slots)
{
    // 2-of-3 with two signatures: the last two keys are checked, the first one never is.
    const CScript script = CScript() << OP_2 << Key(1) << Key(2) << Key(3) << OP_3 << OP_CHECKMULTISIG;
    const auto t = TraceWsh(script, {{}, Sig(), Sig()});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);                    // keys belong to the unproven-key budget
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(/*exclude_key_shaped=*/false), 33U); // only the unexamined key is not credited
    uint32_t uncredited_keys{0};
    for (size_t s = 0; s < t.ledger.sources.size(); ++s) {
        if (t.ledger.IsKeyShaped(s) && t.ledger.credited[s] == 0) ++uncredited_keys;
    }
    BOOST_CHECK_EQUAL(uncredited_keys, 1U);
}

BOOST_AUTO_TEST_CASE(checkmultisig_failed_pair_advances_key_only)
{
    // The checker refuses the first signature; the second key then takes it.
    class PickyChecker : public TruthChecker
    {
    public:
        bool CheckECDSASignature(const valtype& sig, const valtype& key, const CScript&, SigVersion, SighashRules = SighashRules::LEGACY) const override { return !sig.empty() && key[1] != 4; }
    };
    const PickyChecker picky;
    VerifiedKeys keys;
    SigCheckLog log;
    ExecutedDataTracer tracer{&log};
    const KeyRecordingSignatureChecker checker{picky, keys, &log, &tracer};
    const CScript script = CScript() << OP_1 << Key(1) << Key(2) << Key(3) << OP_3 << OP_CHECKMULTISIG;
    std::vector<valtype> stack{{}, Sig()};
    ScriptError err;
    tracer.SetRunKind(ScriptRunKind::WITNESS_V0_SCRIPT);
    BOOST_REQUIRE(EvalScript(stack, script, FLAGS, checker, SigVersion::WITNESS_V0, &err));
    const auto l = tracer.Finish();
    BOOST_REQUIRE_MESSAGE(!l.failed, l.fail_reason);
    BOOST_CHECK_EQUAL(log.calls.size(), 2U);
    // Key 3 was tried and failed; key 2 verified. Key 1 was not reached.
    BOOST_CHECK_EQUAL(l.TotalDataBytes(/*exclude_key_shaped=*/false), 66U);
}

BOOST_AUTO_TEST_CASE(executed_but_useless_pushes)
{
    // <K> CHECKSIG, then <junk> NIP twice: both pushes execute and neither is used, except that the last
    // one stays as the final top, which a boolean test needs one byte of.
    const CScript script = CScript() << Key(1) << OP_CHECKSIG << Bytes(256, 1) << OP_NIP << Bytes(256, 2) << OP_NIP;
    const auto t = TraceWsh(script, {Sig()});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 256U + 255U);
}

BOOST_AUTO_TEST_CASE(tapscript_executed_but_useless)
{
    const CScript script = CScript() << XKey(1) << OP_CHECKSIG << Bytes(200, 1) << OP_NIP << Bytes(200, 2) << OP_NIP;
    const auto t = TraceTap(script, {Schnorr()});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 200U + 199U);
}

BOOST_AUTO_TEST_CASE(dropped_witness_items)
{
    const CScript script = CScript() << OP_2DROP << OP_2DROP << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig(), Bytes(80, 1), Bytes(80, 2), Bytes(80, 3), Bytes(80, 4)});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 320U);
}

BOOST_AUTO_TEST_CASE(hashed_and_dropped_constant)
{
    // <d> SHA256 DROP: a hash that nothing compares is no use.
    const CScript script = CScript() << Bytes(32, 9) << OP_SHA256 << OP_DROP << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig()});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 32U);
}

BOOST_AUTO_TEST_CASE(tautologies_earn_nothing)
{
    {
        // <d> DUP EQUALVERIFY
        const CScript script = CScript() << Bytes(32, 9) << OP_DUP << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG;
        const auto t = TraceWsh(script, {Sig()});
        REQUIRE_TRACED(t);
        BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 32U);
    }
    {
        // <d> <d> EQUALVERIFY with both in the script
        const CScript script = CScript() << Bytes(32, 9) << Bytes(32, 9) << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG;
        const auto t = TraceWsh(script, {Sig()});
        REQUIRE_TRACED(t);
        BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 64U);
    }
    {
        // witness against witness
        const CScript script = CScript() << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG;
        const auto t = TraceWsh(script, {Sig(), Bytes(32, 5), Bytes(32, 5)});
        REQUIRE_TRACED(t);
        BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 64U);
    }
}

BOOST_AUTO_TEST_CASE(raw_value_decides_for_one_byte)
{
    // <80B> VERIFY
    const CScript script = CScript() << Bytes(80, 9) << OP_VERIFY << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig()});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 79U);
}

BOOST_AUTO_TEST_CASE(condition_boundary_one_byte_vs_two)
{
    // No MINIMALIF, as in legacy and P2SH scripts.
    const unsigned int flags{FLAGS & ~SCRIPT_VERIFY_MINIMALIF};
    const CScript script = CScript() << OP_IF << OP_ENDIF << Key(1) << OP_CHECKSIG;
    const auto one = TraceWsh(script, {Sig(), {1}}, flags);
    REQUIRE_TRACED(one);
    BOOST_CHECK_EQUAL(one.ledger.TotalDataBytes(), 0U);
    const auto two = TraceWsh(script, {Sig(), {1, 1}}, flags);
    REQUIRE_TRACED(two);
    BOOST_CHECK_EQUAL(two.ledger.TotalDataBytes(), 1U);
    const auto big = TraceWsh(script, {Sig(), Bytes(40, 1)}, flags);
    REQUIRE_TRACED(big);
    BOOST_CHECK_EQUAL(big.ledger.TotalDataBytes(), 39U);
}

BOOST_AUTO_TEST_CASE(altstack_leftover)
{
    const CScript script = CScript() << Bytes(64, 9) << OP_TOALTSTACK << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig()});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 64U);
}

BOOST_AUTO_TEST_CASE(altstack_round_trip_keeps_taint)
{
    // The preimage goes to the alt stack and back before the hash lock.
    const valtype pre{Bytes(32, 1)};
    const CScript script = CScript() << OP_TOALTSTACK << OP_FROMALTSTACK << OP_SHA256 << Sha256(pre) << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig(), pre});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
}

BOOST_AUTO_TEST_CASE(size_only_use_earns_nothing)
{
    // SIZE <40> EQUALVERIFY DROP: only the length of the item was looked at.
    const CScript script = CScript() << OP_SIZE << 40 << OP_EQUALVERIFY << OP_DROP << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig(), Bytes(40, 1)});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 40U);
}

BOOST_AUTO_TEST_CASE(untaken_branch_is_not_executed)
{
    const CScript script = CScript() << OP_IF << Bytes(64, 9) << OP_ENDIF << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig(), {}});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
    // Nothing is known of the 64 bytes by the tracer: they are in no source, and their offset never executed.
    for (const auto& s : t.ledger.sources) BOOST_CHECK(s.len != 64);
    const auto& executed = t.ledger.runs.back().executed;
    BOOST_CHECK(std::find(executed.begin(), executed.end(), 1U) == executed.end()); // offset 1 is the push
    BOOST_CHECK(std::find(executed.begin(), executed.end(), 0U) != executed.end()); // the IF
}

// ---- locks ------------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(hash_lock_boundaries)
{
    for (const size_t len : {size_t{32}, size_t{33}, size_t{80}}) {
        const valtype pre{Bytes(len, 1)};
        const CScript script = CScript() << OP_SHA256 << Sha256(pre) << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG;
        const auto t = TraceWsh(script, {Sig(), pre});
        REQUIRE_TRACED(t);
        // A preimage is free up to 32 bytes, and so is the hash it was checked against.
        BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), len - 32);
    }
}

BOOST_AUTO_TEST_CASE(lock_allowance_three_vs_four)
{
    auto run = [](size_t locks) {
        CScript script;
        std::vector<valtype> stack{Sig()};
        for (size_t i = locks; i-- > 0;) stack.push_back(Bytes(32, static_cast<unsigned char>(i)));
        for (size_t i = 0; i < locks; ++i) script << OP_SHA256 << Sha256(Bytes(32, static_cast<unsigned char>(i))) << OP_EQUALVERIFY;
        script << Key(1) << OP_CHECKSIG;
        auto t = TraceWsh(script, stack);
        BOOST_REQUIRE_MESSAGE(t.ok && !t.ledger.failed, t.ledger.fail_reason);
        return t.ledger;
    };
    BOOST_CHECK_EQUAL(run(2).TotalDataBytes(), 0U);
    BOOST_CHECK_EQUAL(run(3).TotalDataBytes(), 0U);
    BOOST_CHECK_EQUAL(run(3).lock_slots_left, 0U);
    // The fourth lock gets no credit for its preimage and none for its hash.
    BOOST_CHECK_EQUAL(run(4).TotalDataBytes(), 64U);
    BOOST_CHECK_EQUAL(run(6).TotalDataBytes(), 192U);
}

BOOST_AUTO_TEST_CASE(same_source_in_several_locks_counts_once)
{
    // DUP HASH160 <a> EQUAL IF ... ELSE HASH160 <b> EQUALVERIFY ENDIF on one 32-byte item: two locks, one source.
    const valtype pre{Bytes(32, 1)};
    const CScript script = CScript() << OP_DUP << OP_HASH160 << Hash160(Bytes(32, 99)) << OP_EQUAL << OP_IF << OP_DROP << OP_ELSE
                                     << OP_HASH160 << Hash160(pre) << OP_EQUALVERIFY << OP_ENDIF << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig(), pre});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
    BOOST_CHECK_EQUAL(t.ledger.lock_slots_used, 1U);
}

BOOST_AUTO_TEST_CASE(small_lock_is_exempt)
{
    const valtype c{1, 2, 3, 4};
    const CScript script = CScript() << c << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig(), c});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
    BOOST_CHECK_EQUAL(t.ledger.lock_slots_used, 0U);
    BOOST_CHECK_EQUAL(t.ledger.small_credit_used, 8U);
}

BOOST_AUTO_TEST_CASE(large_constant_against_tiny_witness_is_not_free)
{
    // <1B> <32B payload> EQUAL NOTIF ENDIF: the exemption is only for two small sides. A false comparison
    // that steers a branch credits like a true one, so each of these spends a slot of the allowance.
    auto run = [](size_t n) {
        CScript script;
        std::vector<valtype> stack{Sig()};
        for (size_t i = 0; i < n; ++i) {
            stack.push_back({static_cast<unsigned char>(i)});
            script << Bytes(32, static_cast<unsigned char>(100 + i)) << OP_EQUAL << OP_NOTIF << OP_ENDIF;
        }
        script << Key(1) << OP_CHECKSIG;
        auto t = TraceWsh(script, stack);
        BOOST_REQUIRE_MESSAGE(t.ok && !t.ledger.failed, t.ledger.fail_reason);
        return t.ledger;
    };
    BOOST_CHECK_EQUAL(run(3).TotalDataBytes(), 0U);
    BOOST_CHECK_EQUAL(run(3).lock_slots_used, 3U);
    // Past the allowance the payload constant is data again.
    BOOST_CHECK_EQUAL(run(4).TotalDataBytes(), 33U);
}

BOOST_AUTO_TEST_CASE(false_lock_result_dropped_earns_nothing)
{
    const valtype pre{Bytes(32, 1)};
    const CScript script = CScript() << OP_SHA256 << Sha256(pre) << OP_EQUAL << OP_DROP << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig(), pre});
    REQUIRE_TRACED(t);
    // The comparison result never reaches a decision.
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 64U);
}

BOOST_AUTO_TEST_CASE(size_then_hash_lock_miniscript_style)
{
    // SIZE <32> EQUALVERIFY SHA256 <h> EQUALVERIFY: the size test credits only its constant.
    const valtype pre{Bytes(32, 1)};
    const CScript script = CScript() << OP_SIZE << 32 << OP_EQUALVERIFY << OP_SHA256 << Sha256(pre) << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig(), pre});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
    BOOST_CHECK_EQUAL(t.ledger.lock_slots_used, 1U);
}

BOOST_AUTO_TEST_CASE(pending_credit_survives_add)
{
    // [pre, sig]: SWAP SHA256 <h> EQUAL SWAP <K> CHECKSIG ADD 2 EQUAL: a thresh-style sum of two fragments.
    const valtype pre{Bytes(32, 1)};
    const CScript head = CScript() << OP_SWAP << OP_SHA256 << Sha256(pre) << OP_EQUAL << OP_SWAP << Key(1) << OP_CHECKSIG << OP_ADD << OP_2 << OP_EQUAL;
    const auto kept = TraceWsh(head, {pre, Sig()});
    REQUIRE_TRACED(kept);
    BOOST_CHECK_EQUAL(kept.ledger.TotalDataBytes(), 0U);
    // The same, with the sum thrown away before it decides anything.
    const CScript thrown = CScript(head) << OP_DROP << OP_1;
    const auto dropped = TraceWsh(thrown, {pre, Sig()});
    REQUIRE_TRACED(dropped);
    BOOST_CHECK_EQUAL(dropped.ledger.TotalDataBytes(), 64U);
}

BOOST_AUTO_TEST_CASE(multi_a_count_is_not_a_lock)
{
    // multi_a 12-of-14 with three hash locks: the NUMEQUAL on the sum must not use up a slot.
    CScript script;
    std::vector<valtype> stack;
    for (size_t i = 0; i < 3; ++i) stack.push_back(Bytes(32, static_cast<unsigned char>(i)));
    for (size_t i = 0; i < 3; ++i) script << OP_SHA256 << Sha256(Bytes(32, static_cast<unsigned char>(2 - i))) << OP_EQUALVERIFY;
    // Sigs: the first key's signature is the deepest on the stack after the preimages are gone.
    std::vector<valtype> sigs;
    for (int i = 0; i < 14; ++i) sigs.push_back(i < 12 ? Schnorr() : valtype{});
    std::vector<valtype> full;
    for (auto it = sigs.rbegin(); it != sigs.rend(); ++it) full.push_back(*it);
    for (const auto& s : stack) full.push_back(s);
    script << XKey(0) << OP_CHECKSIG;
    for (unsigned char i = 1; i < 14; ++i) script << XKey(i) << OP_CHECKSIGADD;
    script << 12 << OP_NUMEQUAL;
    const auto t = TraceTap(script, full);
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
    BOOST_CHECK_EQUAL(t.ledger.lock_slots_used, 3U);
}

// ---- honest spends -----------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(honest_p2wpkh)
{
    const valtype pk{Key(1)};
    CScriptWitness w;
    w.stack = {Sig(), pk};
    const auto t = TraceSpend(CScript(), CScript() << OP_0 << Hash160(pk), w);
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(/*exclude_key_shaped=*/false), 0U);
}

BOOST_AUTO_TEST_CASE(honest_p2wsh_one_of_one)
{
    const CScript script = CScript() << Key(1) << OP_CHECKSIG;
    CScriptWitness w;
    w.stack = {Sig(), valtype(script.begin(), script.end())};
    const auto t = TraceSpend(CScript(), Wsh(script), w);
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(/*exclude_key_shaped=*/false), 0U);
    // The witnessScript is not a source.
    for (const auto& s : t.ledger.sources) BOOST_CHECK(s.len != script.size());
}

BOOST_AUTO_TEST_CASE(honest_p2sh_multisig_redeem_script_is_code)
{
    CScript redeem = CScript() << OP_2;
    for (unsigned char i = 1; i <= 15; ++i) redeem << Key(i);
    redeem << CScript::EncodeOP_N(15) << OP_CHECKMULTISIG;
    const CScript script_sig = CScript() << OP_0 << Sig() << Sig() << valtype(redeem.begin(), redeem.end());
    const CScript spk = CScript() << OP_HASH160 << Hash160(valtype(redeem.begin(), redeem.end())) << OP_EQUAL;
    const auto t = TraceSpend(script_sig, spk, CScriptWitness());
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
    const size_t r = FindSource(t.ledger, ExecutedDataTracer::SourceKind::SCRIPTSIG_PUSH, static_cast<uint32_t>(redeem.size()));
    BOOST_CHECK(t.ledger.sources[r].code);
    BOOST_CHECK_EQUAL(t.ledger.DataBytes(r), 0U);
}

BOOST_AUTO_TEST_CASE(honest_p2sh_p2wsh)
{
    const CScript script = CScript() << OP_SHA256 << Sha256(Bytes(32, 1)) << OP_EQUALVERIFY << Key(1) << OP_CHECKSIG;
    const CScript program = Wsh(script);
    const CScript script_sig = CScript() << valtype(program.begin(), program.end());
    const CScript spk = CScript() << OP_HASH160 << Hash160(valtype(program.begin(), program.end())) << OP_EQUAL;
    CScriptWitness w;
    w.stack = {Sig(), Bytes(32, 1), valtype(script.begin(), script.end())};
    const auto t = TraceSpend(script_sig, spk, w);
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
}

BOOST_AUTO_TEST_CASE(honest_bolt3_anchor)
{
    // <pk> CHECKSIG IFDUP NOTIF 16 CSV ENDIF, swept with an empty signature after 16 blocks, and with a real one.
    const CScript script = CScript() << Key(1) << OP_CHECKSIG << OP_IFDUP << OP_NOTIF << OP_16 << OP_CHECKSEQUENCEVERIFY << OP_ENDIF;
    for (const bool signed_spend : {false, true}) {
        const auto t = TraceWsh(script, {signed_spend ? Sig() : valtype{}});
        REQUIRE_TRACED(t);
        BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
        // The key is a script push of the kind PR1's budget owns, and it was not credited when the signature was empty.
        const size_t key = FindSource(t.ledger, ExecutedDataTracer::SourceKind::SCRIPT_PUSH, 33);
        BOOST_CHECK(t.ledger.IsKeyShaped(key));
        BOOST_CHECK_EQUAL(t.ledger.credited[key], signed_spend ? 33U : 0U);
    }
}

BOOST_AUTO_TEST_CASE(honest_p2pkh)
{
    const valtype pk{Key(1)};
    const CScript spk = CScript() << OP_DUP << OP_HASH160 << Hash160(pk) << OP_EQUALVERIFY << OP_CHECKSIG;
    const auto t = TraceSpend(CScript() << Sig() << pk, spk, CScriptWitness());
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(/*exclude_key_shaped=*/false), 0U);
}

BOOST_AUTO_TEST_CASE(tapscript_if_when_reduced_data_expires)
{
    // On this chain OP_IF is banned in tapscript, but not once the reduced data rules expire. The untaken
    // branch must still be left out, and a taken one counted.
    const unsigned int flags{FLAGS & ~REDUCED_DATA_VERIFY_FLAGS};
    const CScript script = CScript() << OP_IF << Bytes(70, 9) << OP_DROP << OP_ENDIF << XKey(1) << OP_CHECKSIG;
    const auto untaken = TraceTap(script, {Schnorr(), {}}, flags);
    REQUIRE_TRACED(untaken);
    BOOST_CHECK_EQUAL(untaken.ledger.TotalDataBytes(), 0U);
    for (const auto& s : untaken.ledger.sources) BOOST_CHECK(s.len != 70);
    const auto taken = TraceTap(script, {Schnorr(), {1}}, flags);
    REQUIRE_TRACED(taken);
    BOOST_CHECK_EQUAL(taken.ledger.TotalDataBytes(), 70U);
}

BOOST_AUTO_TEST_CASE(honest_tapscript_multi_a_13_of_13)
{
    CScript script = CScript() << XKey(0) << OP_CHECKSIG;
    for (unsigned char i = 1; i < 13; ++i) script << XKey(i) << OP_CHECKSIGADD;
    script << OP_13 << OP_NUMEQUAL;
    const auto t = TraceTap(script, std::vector<valtype>(13, Schnorr()));
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(/*exclude_key_shaped=*/false), 0U);
}

BOOST_AUTO_TEST_CASE(tapscript_unsigned_keys_are_key_budget_not_data)
{
    CScript script = CScript() << XKey(0) << OP_CHECKSIG;
    for (unsigned char i = 1; i < 14; ++i) script << XKey(i) << OP_CHECKSIGADD;
    script << 12 << OP_NUMEQUAL;
    std::vector<valtype> stack{{}, {}};
    for (int i = 0; i < 12; ++i) stack.push_back(Schnorr());
    const auto t = TraceTap(script, stack);
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(/*exclude_key_shaped=*/false), 64U);
}

BOOST_AUTO_TEST_CASE(unsigned_witness_supplied_key_pays_the_difference)
{
    // pk_h with an empty signature: the key is hashed against the program (32 bytes credit), the rest is data.
    const valtype pk{Key(1)};
    const CScript script = CScript() << OP_DUP << OP_HASH160 << Hash160(pk) << OP_EQUALVERIFY << OP_CHECKSIG;
    const auto t = TraceWsh(script, {{}, pk});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 1U);
    const auto signed_spend = TraceWsh(script, {Sig(), pk});
    REQUIRE_TRACED(signed_spend);
    BOOST_CHECK_EQUAL(signed_spend.ledger.TotalDataBytes(), 0U);
}

BOOST_AUTO_TEST_CASE(timelocks_and_picks_credit_small_values)
{
    const CScript script = CScript() << int64_t{500000} << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_0 << OP_PICK << OP_DROP << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, {Sig()});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
}

BOOST_AUTO_TEST_CASE(small_credit_budget_is_bounded)
{
    // Forty 4-byte numbers, added in pairs and thrown away: each operand is credited, but only up to the budget.
    CScript script;
    std::vector<valtype> stack{Sig()};
    for (int i = 0; i < 40; ++i) stack.push_back({1, 2, 3, static_cast<unsigned char>(i + 1)});
    for (int i = 0; i < 20; ++i) script << OP_ADD << OP_DROP;
    script << Key(1) << OP_CHECKSIG;
    const auto t = TraceWsh(script, stack);
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.small_credit_used, ExecutedDataTracer::SMALL_CREDIT_BUDGET);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 40U * 4 - ExecutedDataTracer::SMALL_CREDIT_BUDGET);
}

// ---- the model must hold for every script -----------------------------------------------------

BOOST_AUTO_TEST_CASE(random_scripts_never_break_the_model)
{
    static const opcodetype OPS[] = {
        OP_0, OP_1, OP_2, OP_3, OP_16, OP_1NEGATE, OP_NOP, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY,
        OP_TOALTSTACK, OP_FROMALTSTACK, OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP, OP_IFDUP,
        OP_DEPTH, OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK, OP_SIZE,
        OP_EQUAL, OP_EQUALVERIFY, OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL, OP_ADD, OP_SUB,
        OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
        OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX, OP_WITHIN, OP_RIPEMD160, OP_SHA1, OP_SHA256,
        OP_HASH160, OP_HASH256, OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD,
        OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY,
    };
    static const size_t SIZES[] = {0, 1, 1, 2, 4, 20, 32, 33, 64};
    const SigVersion versions[] = {SigVersion::BASE, SigVersion::WITNESS_V0, SigVersion::TAPSCRIPT};
    const ScriptRunKind kinds[] = {ScriptRunKind::SCRIPTPUBKEY, ScriptRunKind::WITNESS_V0_SCRIPT, ScriptRunKind::TAPSCRIPT};
    size_t completed{0};
    for (int i = 0; i < 20000; ++i) {
        CScript script;
        const size_t n = 1 + m_rng.randrange(30);
        for (size_t j = 0; j < n; ++j) {
            if (m_rng.randrange(4) == 0) {
                valtype item(SIZES[m_rng.randrange(std::size(SIZES))]);
                for (auto& b : item) b = static_cast<unsigned char>(m_rng.randrange(3));
                script << item;
            } else {
                script << OPS[m_rng.randrange(std::size(OPS))];
            }
        }
        std::vector<valtype> stack;
        for (size_t j = m_rng.randrange(8); j > 0; --j) {
            valtype item(SIZES[m_rng.randrange(std::size(SIZES))]);
            for (auto& b : item) b = static_cast<unsigned char>(m_rng.randrange(3));
            stack.push_back(std::move(item));
        }
        const size_t v = m_rng.randrange(3);
        // SCRIPTPUBKEY runs continue a stack, so these are given a witness-style start to keep things simple.
        const ScriptRunKind kind = v == 0 ? ScriptRunKind::WITNESS_V0_SCRIPT : kinds[v];
        const auto t = TraceEval(kind, versions[v], script, stack, m_rng.randbits(8) == 0 ? FLAGS & ~SCRIPT_VERIFY_NULLFAIL : FLAGS);
        BOOST_REQUIRE_MESSAGE(!t.ledger.failed, t.ledger.fail_reason + " script " + ScriptToAsmStr(script));
        completed += t.ok;
    }
    BOOST_CHECK_GT(completed, 100U);
}

BOOST_AUTO_TEST_SUITE_END()
