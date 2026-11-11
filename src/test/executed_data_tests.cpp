// Copyright (c) The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/executed_data.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
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

//! What the policy path adds for one input of a spend, with the tracer's trace of it (or none).
struct Charged {
    size_t static_counted;
    ExecutedDataCharge extra;
};
Charged ChargeSpend(const CScript& script_sig, const CScript& spk, const CScriptWitness& witness, bool traced = true)
{
    const Traced t = TraceSpend(script_sig, spk, witness);
    BOOST_REQUIRE_MESSAGE(t.ok, ScriptErrorString(t.err));
    BOOST_REQUIRE_MESSAGE(!t.ledger.failed, t.ledger.fail_reason);
    CTxIn txin;
    txin.scriptSig = script_sig;
    txin.scriptWitness = witness;
    const CScript script{GetScriptForTransactionInput(spk, txin).first};
    DatacarrierRanges ranges;
    const auto dcb = script.DatacarrierBytes(0, &witness, /*dead_branches=*/::g_reject_dead_branches, /*verified_keys=*/nullptr, /*reached_normal_return=*/nullptr, &ranges);
    InputTrace trace;
    trace.status = InputTrace::Status::TRACED;
    trace.ledger = t.ledger;
    return {dcb.second, ExecutedDataBytes(txin, spk, traced ? &trace : nullptr, ranges, dcb.second)};
}
//! <c> (<c> ADD)* then 2DUP EQUALVERIFY, repeated: one constant made of many pushes, and many locks on it.
//! The witness value the locks compare with is returned in value.
CScript ManyConstantLocks(size_t constants, size_t locks, valtype& value)
{
    const valtype unit{0x11}; // 17: the smallest one-byte push that is minimal as a push
    CScript script;
    script << unit;
    int64_t sum{17};
    for (size_t i = 1; i < constants; ++i) {
        script << unit << OP_ADD;
        sum += 17;
    }
    for (size_t i = 0; i < locks; ++i) script << OP_2DUP << OP_EQUALVERIFY;
    value = CScriptNum(sum).getvch();
    return script;
}

CScriptWitness Wit(std::vector<valtype> items, const CScript& script)
{
    CScriptWitness w;
    w.stack = std::move(items);
    w.stack.emplace_back(script.begin(), script.end());
    return w;
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

BOOST_AUTO_TEST_CASE(many_locks_sharing_many_constants_dedup_is_cheap)
{
    // The worst case for merging the constants of the lock records of one source: a constant accumulated from
    // hundreds of pushes, compared with the same witness value again and again, so every record carries every
    // constant. A P2WSH script is held down by the 201 opcode limit; a tapscript has no such limit, so a
    // script of a few thousand bytes can hold thousands of records each naming thousands of constants.
    auto measure = [&](bool tap, size_t constants, size_t locks) {
        valtype value;
        const CScript script{ManyConstantLocks(constants, locks, value)};
        const auto start{std::chrono::steady_clock::now()};
        const Traced t{tap ? TraceTap(script, {value}) : TraceWsh(script, {value})};
        const auto ms{std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()};
        REQUIRE_TRACED(t);
        BOOST_TEST_MESSAGE("shape tap=" << tap << " constants=" << constants << " locks=" << locks
                                        << " script=" << script.size() << " sources=" << t.ledger.sources.size()
                                        << " total=" << t.ledger.TotalDataBytes()
                                        << " lock_slots_used=" << t.ledger.lock_slots_used
                                        << " small_credit_used=" << t.ledger.small_credit_used
                                        << " ms=" << ms);
        BOOST_CHECK_LT(ms, 2000); // a guard against a quadratic creeping back in, loose enough for a slow machine
        return t.ledger;
    };
    // A P2WSH shape: 133 OP_ADDs and 33 locks fill the 201 opcode limit. 134 one-byte constants and a
    // two-byte witness value, of which the small-value budget credits 64 bytes.
    const Ledger wsh{measure(false, 134, 33)};
    BOOST_CHECK_EQUAL(wsh.sources.size(), 135U);
    BOOST_CHECK_EQUAL(wsh.TotalDataBytes(), 134U + 2U - ExecutedDataTracer::SMALL_CREDIT_BUDGET);
    BOOST_CHECK_EQUAL(wsh.lock_slots_used, 0U);
    BOOST_CHECK_EQUAL(wsh.small_credit_used, ExecutedDataTracer::SMALL_CREDIT_BUDGET);

    // The tapscript shape, 9999 bytes: 1667 records of 2222 constants each. Same accounting, and the
    // merge must not cost a scan of the group per constant of every record.
    const Ledger tap{measure(true, 2222, 1667)};
    BOOST_CHECK_EQUAL(tap.sources.size(), 2223U);
    BOOST_CHECK_EQUAL(tap.TotalDataBytes(), 2222U + 3U - ExecutedDataTracer::SMALL_CREDIT_BUDGET);
    BOOST_CHECK_EQUAL(tap.lock_slots_used, 0U);
    BOOST_CHECK_EQUAL(tap.small_credit_used, ExecutedDataTracer::SMALL_CREDIT_BUDGET);
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

BOOST_AUTO_TEST_CASE(honest_submarine_swap)
{
    // IF SIZE 32 EQUALVERIFY SHA256 <h> EQUALVERIFY DUP HASH160 <claim> ELSE <timeout> CLTV DROP DUP HASH160 <refund> ENDIF EQUALVERIFY CHECKSIG
    // as it is on the corpus: the refund hash of the branch that does not run follows HASH160 and waits for EQUALVERIFY after ENDIF.
    const valtype preimage{Bytes(32, 3)}, claim_key{Key(4)}, refund_key{Key(5)};
    const CScript script = CScript() << OP_IF << OP_SIZE << valtype{32} << OP_EQUALVERIFY << OP_SHA256 << Sha256(preimage) << OP_EQUALVERIFY
                                     << OP_DUP << OP_HASH160 << Hash160(claim_key) << OP_ELSE << CScriptNum(0x6ad1ee00).getvch() << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                                     << OP_DUP << OP_HASH160 << Hash160(refund_key) << OP_ENDIF << OP_EQUALVERIFY << OP_CHECKSIG;
    const auto claim = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), claim_key, preimage, {1}}, script));
    BOOST_CHECK_EQUAL(claim.extra.bytes, 0U);
    const auto refund = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), refund_key, {}}, script));
    BOOST_CHECK_EQUAL(refund.extra.bytes, 0U);
}

BOOST_AUTO_TEST_CASE(honest_selector_of_key_hash_pairs)
{
    // DUP 1 EQUAL IF DROP <h1> <h2> ELSE DUP 2 EQUAL IF DROP <h1> <h3> ELSE ... ENDIF ENDIF ROT HASH160 EQUALVERIFY OVER HASH160 EQUALVERIFY CHECKSIG
    // (P2SH-P2WSH on the corpus): every branch pushes its two key hashes up front, so the three branches
    // that do not run hold six pushes of 20 bytes that no HASH160 precedes.
    const valtype k1{Key(1)}, k2{Key(2)};
    CScript script = CScript() << OP_DUP << OP_1 << OP_EQUAL << OP_IF << OP_DROP << Hash160(k1) << Hash160(k2);
    for (unsigned char b = 2; b <= 3; ++b) {
        script << OP_ELSE << OP_DUP << CScriptNum(b).getvch() << OP_EQUAL << OP_IF << OP_DROP << Bytes(20, b) << Bytes(20, static_cast<unsigned char>(b + 10));
    }
    script << OP_ELSE << CScriptNum(4).getvch() << OP_EQUALVERIFY << Bytes(20, 4) << Bytes(20, 14);
    for (int i = 0; i < 3; ++i) script << OP_ENDIF;
    script << OP_ROT << OP_HASH160 << OP_EQUALVERIFY << OP_OVER << OP_HASH160 << OP_EQUALVERIFY << OP_CHECKSIG;
    const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), k1, k2, {1}}, script));
    BOOST_CHECK_EQUAL(c.extra.bytes, 0U);
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
    // pk_h with an empty signature: the key is named by its hash, which takes the whole key out of the data.
    const valtype pk{Key(1)};
    const CScript script = CScript() << OP_DUP << OP_HASH160 << Hash160(pk) << OP_EQUALVERIFY << OP_CHECKSIG;
    const auto t = TraceWsh(script, {{}, pk});
    REQUIRE_TRACED(t);
    BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
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

BOOST_AUTO_TEST_CASE(nop_between_key_and_checksig_is_still_a_key)
{
    // An x-only push is a key only because a signature check opcode claims it, and an opcode that leaves
    // the stack as it found it does not stop it doing so. The static counting of unproven keys looks through
    // those no-ops (IsStackNeutralNop in script/script.cpp), so the tracer must too, or a key is charged as
    // data on top of the budget that already owns it.
    // The signature is empty, so the check fails without NULLFAIL and the key earns no credit of its own:
    // what keeps it out of the data count is its shape alone.
    for (const int nops : {0, 1, 3}) {
        CScript script = CScript() << XKey(1);
        for (int i = 0; i < nops; ++i) script << OP_NOP;
        script << OP_CHECKSIG << OP_NOT;
        const auto t = TraceTap(script, {{}});
        REQUIRE_TRACED(t);
        const size_t key{FindSource(t.ledger, ExecutedDataTracer::SourceKind::SCRIPT_PUSH, 32)};
        BOOST_CHECK(t.ledger.IsKeyShaped(key));
        BOOST_CHECK_EQUAL(t.ledger.credited[key], 0U);
        BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 0U);
        BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(/*exclude_key_shaped=*/false), 32U);
    }
    // A push of 32 bytes that no signature check claims is data, no-ops or not.
    for (const int nops : {0, 2}) {
        CScript script = CScript() << XKey(1);
        for (int i = 0; i < nops; ++i) script << OP_NOP;
        script << OP_DROP << OP_1;
        const auto t = TraceTap(script, {});
        REQUIRE_TRACED(t);
        const size_t key{FindSource(t.ledger, ExecutedDataTracer::SourceKind::SCRIPT_PUSH, 32)};
        BOOST_CHECK(!t.ledger.IsKeyShaped(key));
        BOOST_CHECK_EQUAL(t.ledger.TotalDataBytes(), 32U);
    }
}

// ---- the charge one input gets, with the static rules and this accounting sharing one ledger ------

BOOST_AUTO_TEST_CASE(accounting_tail_garbage_is_charged_with_its_push)
{
    const CScript script = CScript() << OP_1 << Bytes(256, 7) << Key(1) << OP_2 << OP_CHECKMULTISIG;
    const auto c = ChargeSpend(CScript(), Wsh(script), Wit({{}, Sig()}, script));
    BOOST_CHECK_EQUAL(c.static_counted, 0U);
    BOOST_CHECK_EQUAL(c.extra.bytes, 256U + 3U); // the data and the PUSHDATA2 opcode and length
    BOOST_CHECK(!c.extra.untraceable && !c.extra.conservative);
}

BOOST_AUTO_TEST_CASE(accounting_envelope_is_counted_once)
{
    // OP_FALSE OP_IF <data> OP_ENDIF is counted whole by the static rule; the push inside it never runs.
    const CScript script = CScript() << OP_FALSE << OP_IF << Bytes(200, 7) << OP_ENDIF << Key(1) << OP_CHECKSIG;
    const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig()}, script));
    BOOST_CHECK_GT(c.static_counted, 200U);
    BOOST_CHECK_EQUAL(c.extra.bytes, 0U);
}

BOOST_AUTO_TEST_CASE(accounting_drop_run_is_counted_once_and_covered)
{
    // <data> OP_DROP, and a run of pushes dropped together: the static rule counts them, and so must this
    // accounting (the assertion that it covers them), without adding them a second time.
    const CScript one = CScript() << Bytes(200, 7) << OP_DROP << Key(1) << OP_CHECKSIG;
    const auto c1 = ChargeSpend(CScript(), Wsh(one), Wit({Sig()}, one));
    BOOST_CHECK_GT(c1.static_counted, 200U);
    BOOST_CHECK_GE(c1.extra.total, c1.static_counted);
    BOOST_CHECK_EQUAL(c1.extra.bytes, 0U);

    const CScript run = CScript() << Bytes(100, 1) << Bytes(100, 2) << OP_2DROP << Key(1) << OP_CHECKSIG;
    const auto c2 = ChargeSpend(CScript(), Wsh(run), Wit({Sig()}, run));
    BOOST_CHECK_GT(c2.static_counted, 200U);
    BOOST_CHECK_GE(c2.extra.total, c2.static_counted);
    BOOST_CHECK_EQUAL(c2.extra.bytes, 0U);
}

BOOST_AUTO_TEST_CASE(accounting_dropped_witness_items_are_charged)
{
    // 18 items of 80 bytes dropped at the front, which the static rules cannot see.
    CScript script;
    for (int i = 0; i < 9; ++i) script << OP_2DROP;
    script << Key(1) << OP_CHECKSIG;
    std::vector<valtype> items{Sig()};
    for (int i = 0; i < 18; ++i) items.push_back(Bytes(80, static_cast<unsigned char>(i)));
    const auto c = ChargeSpend(CScript(), Wsh(script), Wit(items, script));
    BOOST_CHECK_EQUAL(c.extra.bytes, 18U * 80U);
}

BOOST_AUTO_TEST_CASE(accounting_untaken_branch_data)
{
    // A witness-chosen branch that does not run: its push is data in full, opcode and length included.
    const CScript script = CScript() << OP_IF << Bytes(100, 7) << OP_SHA256 << OP_DROP << OP_ENDIF << Key(1) << OP_CHECKSIG;
    const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), {}}, script));
    BOOST_CHECK_EQUAL(c.extra.bytes, 102U); // 100 bytes, PUSHDATA1 and its length
}

BOOST_AUTO_TEST_CASE(accounting_untaken_hash_slots_three_free_fourth_charged)
{
    for (const int slots : {3, 4}) {
        CScript script = CScript() << OP_IF;
        for (int i = 0; i < slots; ++i) script << OP_SHA256 << Bytes(32, static_cast<unsigned char>(i)) << OP_EQUALVERIFY;
        script << OP_ENDIF << Key(1) << OP_CHECKSIG;
        const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), {}}, script));
        BOOST_CHECK_EQUAL(c.extra.bytes, slots == 3 ? 0U : 33U);
    }
}

BOOST_AUTO_TEST_CASE(accounting_untaken_key_hashes_ten_free_eleventh_charged)
{
    // Keys named by their hash share the allowance of the executed pk_h locks. The hash may follow HASH160,
    // wait for it after a merge of branches (a submarine swap), or be pushed up front (a selector script).
    for (const int slots : {10, 11}) {
        CScript script = CScript() << OP_IF;
        for (int i = 0; i < slots; ++i) script << OP_HASH160 << Bytes(20, static_cast<unsigned char>(i)) << OP_EQUALVERIFY;
        script << OP_ENDIF << Key(1) << OP_CHECKSIG;
        const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), {}}, script));
        BOOST_CHECK_EQUAL(c.extra.bytes, slots == 10 ? 0U : 21U);
    }
    // 20 byte pushes in a script that never hashes are not key hashes.
    CScript plain = CScript() << OP_IF << Bytes(20, 1) << OP_EQUAL << OP_DROP << OP_ENDIF << Key(1) << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(ChargeSpend(CScript(), Wsh(plain), Wit({Sig(), {}}, plain)).extra.bytes, 21U);
}

BOOST_AUTO_TEST_CASE(accounting_untaken_keys_and_numbers_are_free)
{
    // The unproven-key budget owns untaken keys; small minimal numbers are free.
    const CScript script = CScript() << OP_IF << Key(2) << XKey(3) << OP_CHECKSIG << Bytes(5, 1) << OP_DROP << OP_ENDIF << Key(1) << OP_CHECKSIG;
    const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), {}}, script));
    BOOST_CHECK_EQUAL(c.extra.bytes, 0U);
}

BOOST_AUTO_TEST_CASE(accounting_nop_between_untaken_key_and_checksig_is_not_charged_twice)
{
    // The same lockstep in code that never ran: the static rules count the x-only push under the unproven
    // key budget because a checksig claims it across the no-op, so this accounting must not charge it again.
    // OP_CHECKSEQUENCEVERIFY (OP_NOP3) is one of those no-ops: it reads the top of the stack and leaves it.
    const CScript plain = CScript() << OP_IF << XKey(2) << OP_CHECKSIG << OP_ENDIF << Key(1) << OP_CHECKSIG;
    const auto base = ChargeSpend(CScript(), Wsh(plain), Wit({Sig(), {}}, plain));
    BOOST_CHECK_EQUAL(base.extra.bytes, 0U);
    BOOST_CHECK_GE(base.extra.total, base.static_counted);

    for (const opcodetype nop : {OP_NOP, OP_CHECKSEQUENCEVERIFY, OP_CHECKLOCKTIMEVERIFY, OP_NOP10}) {
        const CScript script = CScript() << OP_IF << XKey(2) << nop << OP_CHECKSIG << OP_ENDIF << Key(1) << OP_CHECKSIG;
        const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), {}}, script));
        // At most the no-op's own byte more than the shape without it, and that byte is inside the
        // untaken opcode budget here, so in fact nothing.
        BOOST_CHECK_LE(c.extra.bytes, base.extra.bytes + 1U);
        BOOST_CHECK_EQUAL(c.extra.bytes, 0U);
        BOOST_CHECK_GE(c.extra.total, c.static_counted);
    }

    // An opcode that is not stack neutral does hide the key, and then it is data in full with its push.
    const CScript hidden = CScript() << OP_IF << XKey(2) << OP_DUP << OP_CHECKSIG << OP_ENDIF << Key(1) << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(ChargeSpend(CScript(), Wsh(hidden), Wit({Sig(), {}}, hidden)).extra.bytes, 33U);
}

BOOST_AUTO_TEST_CASE(accounting_untaken_small_numbers_are_budgeted)
{
    // Minimal numbers of 5 bytes carry almost 5 bytes of payload each, so code that never ran may hold only a
    // small budget of them for free (UNTAKEN_NUMBER_BUDGET, 16 bytes): three, and the fourth is charged in full.
    for (const int count : {3, 4, 254}) {
        CScript script = CScript() << OP_IF;
        for (int i = 0; i < count; ++i) script << Bytes(5, static_cast<unsigned char>(1 + i % 100));
        script << OP_ENDIF << Key(1) << OP_CHECKSIG;
        const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), {}}, script));
        BOOST_CHECK_EQUAL(c.extra.bytes, count <= 3 ? 0U : static_cast<uint64_t>(count - 3) * 6U);
    }
    // Numbers of 6 bytes were never free: the static rules count them, so nothing is left for the accounting.
    const CScript six = CScript() << OP_IF << Bytes(6, 1) << OP_DROP << OP_ENDIF << Key(1) << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(ChargeSpend(CScript(), Wsh(six), Wit({Sig(), {}}, six)).extra.bytes, 0U);
}

BOOST_AUTO_TEST_CASE(accounting_untaken_opcode_bytes_are_budgeted)
{
    // Opcodes that never ran name a byte each. 80 are free (UNTAKEN_OPCODE_BUDGET), the rest are charged.
    for (const int count : {80, 81, 190}) {
        CScript script = CScript() << OP_IF;
        for (int i = 0; i < count; ++i) script << OP_NOP;
        script << OP_ENDIF << Key(1) << OP_CHECKSIG;
        const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), {}}, script));
        BOOST_CHECK_EQUAL(c.extra.bytes, count <= 80 ? 0U : static_cast<uint64_t>(count - 80));
    }
}

BOOST_AUTO_TEST_CASE(accounting_static_ranges_do_not_spend_the_untaken_budgets)
{
    // The budgets for code that never ran are per input, and an OP_FALSE OP_IF envelope is as large as the
    // script likes. Its bytes are counted by the static rule already, so they must not spend those budgets:
    // otherwise an envelope exhausts them and the honest untaken branch beside it, whose bytes no rule has
    // counted, is charged in full for the privilege.
    auto charge = [&](const CScript& dead, const CScript& honest) {
        CScript script;
        if (!dead.empty()) {
            script << OP_FALSE << OP_IF << Bytes(200, 7);
            script.insert(script.end(), dead.begin(), dead.end());
            script << OP_ENDIF;
        }
        script << OP_IF;
        script.insert(script.end(), honest.begin(), honest.end());
        script << OP_ENDIF << Key(1) << OP_CHECKSIG;
        const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), {}}, script));
        // Without an envelope this accounting covers the static count. With one it falls exactly two bytes
        // short: the static envelope range includes the OP_FALSE OP_IF that opens it, and those two bytes
        // are flow control that ran, which this accounting never calls data.
        if (dead.empty()) {
            BOOST_CHECK_GE(c.extra.total, c.static_counted);
        } else {
            BOOST_CHECK_GE(c.extra.total + 2, c.static_counted);
        }
        return c;
    };
    auto repeat = [&](size_t n, const CScript& unit) {
        CScript out;
        for (size_t i = 0; i < n; ++i) out.insert(out.end(), unit.begin(), unit.end());
        return out;
    };

    // UNTAKEN_OPCODE_BUDGET: 80 no-ops in the dead region, 90 in the honest branch. Ten of the honest
    // ninety are over the budget whether the envelope is there or not.
    {
        const CScript nop = CScript() << OP_NOP;
        const auto alone = charge(CScript(), repeat(90, nop));
        BOOST_CHECK_EQUAL(alone.extra.bytes, 90U - ExecutedDataTracer::UNTAKEN_OPCODE_BUDGET);
        BOOST_CHECK_EQUAL(charge(repeat(80, nop), repeat(90, nop)).extra.bytes, alone.extra.bytes);
    }
    // UNTAKEN_NUMBER_BUDGET: three 5-byte numbers in the dead region, four in the honest branch.
    {
        auto numbers = [&](size_t n, unsigned char seed) {
            CScript out;
            for (size_t i = 0; i < n; ++i) out << Bytes(5, static_cast<unsigned char>(seed + i));
            return out;
        };
        const auto alone = charge(CScript(), numbers(4, 1));
        BOOST_CHECK_EQUAL(alone.extra.bytes, 6U); // three are free, the fourth is charged with its push
        BOOST_CHECK_EQUAL(charge(numbers(3, 40), numbers(4, 1)).extra.bytes, alone.extra.bytes);
    }
    // The ten slots for keys named by their hash: ten pk_h in the dead region, two in the honest branch.
    {
        auto hashes = [&](size_t n, unsigned char seed) {
            CScript out;
            for (size_t i = 0; i < n; ++i) out << OP_HASH160 << Bytes(20, static_cast<unsigned char>(seed + i)) << OP_EQUALVERIFY;
            return out;
        };
        const auto alone = charge(CScript(), hashes(2, 1));
        BOOST_CHECK_EQUAL(alone.extra.bytes, 0U);
        BOOST_CHECK_EQUAL(charge(hashes(10, 40), hashes(2, 1)).extra.bytes, alone.extra.bytes);
    }
    // And the three hash-lock slots: three 32-byte digests in the dead region, one in the honest branch.
    {
        auto digests = [&](size_t n, unsigned char seed) {
            CScript out;
            for (size_t i = 0; i < n; ++i) out << OP_SHA256 << Bytes(32, static_cast<unsigned char>(seed + i)) << OP_EQUALVERIFY;
            return out;
        };
        const auto alone = charge(CScript(), digests(1, 1));
        BOOST_CHECK_EQUAL(alone.extra.bytes, 0U);
        BOOST_CHECK_EQUAL(charge(digests(3, 40), digests(1, 1)).extra.bytes, alone.extra.bytes);
    }
}

BOOST_AUTO_TEST_CASE(accounting_not_followed_is_charged_conservatively)
{
    // A preimage and a signature: the signature-shaped item is free, the preimage is data.
    const valtype preimage{Bytes(32, 9)};
    const CScript script = CScript() << OP_SHA256 << Sha256(preimage) << OP_EQUAL;
    const CScriptWitness w{Wit({preimage}, script)};
    const auto traced = ChargeSpend(CScript(), Wsh(script), w);
    BOOST_CHECK_EQUAL(traced.extra.bytes, 0U); // credited by its lock
    const auto untraced = ChargeSpend(CScript(), Wsh(script), w, /*traced=*/false);
    BOOST_CHECK(untraced.extra.conservative);
    BOOST_CHECK_EQUAL(untraced.extra.bytes, 32U);

    CScriptWitness sig_like;
    sig_like.stack = {Bytes(70, 1), Bytes(64, 2), Bytes(63, 3), {}, valtype(script.begin(), script.end())};
    CTxIn txin;
    txin.scriptWitness = sig_like;
    const auto none = ExecutedDataBytes(txin, Wsh(script), nullptr, DatacarrierRanges{}, 0);
    BOOST_CHECK(none.conservative);
    BOOST_CHECK_EQUAL(none.bytes, 63U); // the script is code, 64 and 70 byte items look like signatures
}

BOOST_AUTO_TEST_CASE(accounting_conservative_charge_per_script_type)
{
    CTxIn txin;
    // P2WPKH: nothing is charged, its key and signature are implied by the output.
    txin.scriptWitness.stack = {Bytes(71, 1), Key(1)};
    BOOST_CHECK_EQUAL(ExecutedDataBytes(txin, CScript() << OP_0 << Hash160(Key(1)), nullptr, DatacarrierRanges{}, 0).bytes, 0U);
    // P2PKH likewise.
    CTxIn legacy;
    legacy.scriptSig = CScript() << Bytes(71, 1) << Key(1);
    BOOST_CHECK_EQUAL(ExecutedDataBytes(legacy, CScript() << OP_DUP << OP_HASH160 << Hash160(Key(1)) << OP_EQUALVERIFY << OP_CHECKSIG, nullptr, DatacarrierRanges{}, 0).bytes, 0U);
    // Taproot key path: one signature. Script path: the leaf and control block are code, the rest is data.
    CTxIn key_path;
    key_path.scriptWitness.stack = {Bytes(64, 1)};
    const CScript tr = CScript() << OP_1 << Bytes(32, 5);
    BOOST_CHECK_EQUAL(ExecutedDataBytes(key_path, tr, nullptr, DatacarrierRanges{}, 0).bytes, 0U);
    CTxIn script_path;
    script_path.scriptWitness.stack = {Bytes(50, 1), Bytes(30, 2), Bytes(100, 3), Bytes(33, 4)};
    BOOST_CHECK_EQUAL(ExecutedDataBytes(script_path, tr, nullptr, DatacarrierRanges{}, 0).bytes, 80U);
    // An anchor output spent with nothing.
    BOOST_CHECK_EQUAL(ExecutedDataBytes(CTxIn{}, CScript() << OP_1 << valtype{0x4e, 0x73}, nullptr, DatacarrierRanges{}, 0).bytes, 0U);
}

BOOST_AUTO_TEST_CASE(accounting_failed_model_is_flagged_and_charged)
{
    InputTrace trace;
    trace.status = InputTrace::Status::TRACED;
    trace.ledger.failed = true;
    trace.ledger.fail_reason = "test";
    CTxIn txin;
    txin.scriptWitness.stack = {Bytes(32, 1), Bytes(10, 2)};
    const auto c = ExecutedDataBytes(txin, CScript() << OP_0 << Bytes(32, 5), &trace, DatacarrierRanges{}, 0);
    BOOST_CHECK(c.untraceable && c.conservative);
    BOOST_CHECK_EQUAL(c.bytes, 32U);
}

BOOST_AUTO_TEST_CASE(accounting_static_owned_input_is_not_added_to)
{
    DatacarrierRanges owned;
    owned.whole_input = true;
    CTxIn txin;
    txin.scriptWitness.stack = {Bytes(300, 1), Bytes(10, 2)};
    BOOST_CHECK_EQUAL(ExecutedDataBytes(txin, CScript() << OP_1 << Bytes(32, 5), nullptr, owned, 0).bytes, 0U);
}

BOOST_AUTO_TEST_CASE(accounting_unsigned_pk_h_has_its_own_allowance)
{
    // n times <sig> <key> DUP HASH160 <hash> EQUALVERIFY CHECKSIG DROP, every signature empty: the unsigned
    // pk_h of a miniscript thresh. Ten are free, as ten unproven keys are, and the eleventh is data with its hash.
    for (const int n : {1, 4, 6, 10, 11}) {
        CScript script;
        std::vector<valtype> items;
        for (int i = n; i >= 1; --i) {
            items.push_back({});
            items.push_back(Key(static_cast<unsigned char>(i)));
        }
        for (int i = 1; i <= n; ++i) script << OP_DUP << OP_HASH160 << Hash160(Key(static_cast<unsigned char>(i))) << OP_EQUALVERIFY << OP_CHECKSIG << OP_DROP;
        script << OP_1;
        const auto c = ChargeSpend(CScript(), Wsh(script), Wit(items, script));
        BOOST_CHECK_EQUAL(c.extra.bytes, n <= 10 ? 0U : 54U); // the key, and its 20 byte hash with its push opcode
    }
}

BOOST_AUTO_TEST_CASE(accounting_tapscript_untaken_branch_with_reduced_data_off)
{
    // On this chain a tapscript has no untaken code, since OP_IF is banned. Once the reduced data rules expire
    // it has, and an untaken push is data in full there exactly as in a P2WSH script.
    const unsigned int flags{FLAGS & ~REDUCED_DATA_VERIFY_FLAGS};
    const CScript script = CScript() << OP_IF << Bytes(70, 9) << OP_SHA256 << OP_DROP << OP_ENDIF << XKey(1) << OP_CHECKSIG;
    for (const bool taken : {false, true}) {
        const auto t = TraceTap(script, {Schnorr(), taken ? valtype{1} : valtype{}}, flags);
        REQUIRE_TRACED(t);
        InputTrace trace;
        trace.status = InputTrace::Status::TRACED;
        trace.ledger = t.ledger;
        const auto c = ExecutedDataBytes(CTxIn{}, CScript(), &trace, DatacarrierRanges{}, 0);
        BOOST_CHECK_EQUAL(c.bytes, 71U); // 70 bytes and the push opcode, whether it ran or not
    }
}

BOOST_AUTO_TEST_CASE(accounting_empty_witness_item_is_a_source)
{
    // The timeout path of a BOLT 3 HTLC compares an empty item with the hash of the revocation key. The empty
    // item is the spender's, so the comparison is a lock and the 20 byte constant is credited; if the empty
    // item counted as a constant, the comparison would check nothing and the hash would be data.
    const CScript script = CScript() << OP_DUP << OP_HASH160 << Hash160(Key(9)) << OP_EQUAL << OP_IF << OP_CHECKSIG << OP_ELSE << OP_DROP << Key(1) << OP_CHECKSIG << OP_ENDIF;
    const auto c = ChargeSpend(CScript(), Wsh(script), Wit({Sig(), {}}, script));
    BOOST_CHECK_EQUAL(c.extra.bytes, 0U);
    // And an empty scriptSig push (OP_0) in a P2SH spend is a source the same way.
    const CScript redeem = CScript() << OP_DUP << OP_HASH160 << Hash160(Key(9)) << OP_EQUAL << OP_IF << OP_CHECKSIG << OP_ELSE << OP_DROP << Key(1) << OP_CHECKSIG << OP_ENDIF;
    const CScript spk = GetScriptForDestination(ScriptHash(redeem));
    BOOST_CHECK_EQUAL(ChargeSpend(CScript() << Sig() << OP_0 << valtype(redeem.begin(), redeem.end()), spk, CScriptWitness()).extra.bytes, 0U);
}

BOOST_AUTO_TEST_CASE(accounting_honest_spends_pay_nothing)
{
    // P2WSH 1-of-1, the anchor swept after 16 blocks with an empty signature, P2SH 3-of-5, P2SH-P2WSH.
    const CScript one = CScript() << OP_1 << Key(1) << OP_1 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(ChargeSpend(CScript(), Wsh(one), Wit({{}, Sig()}, one)).extra.bytes, 0U);

    const CScript anchor = CScript() << Key(1) << OP_CHECKSIG << OP_IFDUP << OP_NOTIF << OP_16 << OP_CHECKSEQUENCEVERIFY << OP_ENDIF;
    for (const bool signed_spend : {false, true}) {
        BOOST_CHECK_EQUAL(ChargeSpend(CScript(), Wsh(anchor), Wit({signed_spend ? Sig() : valtype{}}, anchor)).extra.bytes, 0U);
    }

    const CScript multisig = CScript() << OP_3 << Key(1) << Key(2) << Key(3) << Key(4) << Key(5) << OP_5 << OP_CHECKMULTISIG;
    const CScript p2sh = GetScriptForDestination(ScriptHash(multisig));
    const CScript sig_script = CScript() << OP_0 << Sig() << Sig() << Sig() << valtype(multisig.begin(), multisig.end());
    BOOST_CHECK_EQUAL(ChargeSpend(sig_script, p2sh, CScriptWitness()).extra.bytes, 0U);

    const CScript wsh_inner = CScript() << OP_1 << Key(1) << OP_1 << OP_CHECKMULTISIG;
    const CScript program = Wsh(wsh_inner);
    const CScript nested = GetScriptForDestination(ScriptHash(program));
    BOOST_CHECK_EQUAL(ChargeSpend(CScript() << valtype(program.begin(), program.end()), nested, Wit({{}, Sig()}, wsh_inner)).extra.bytes, 0U);

    const valtype pk{Key(1)};
    BOOST_CHECK_EQUAL(ChargeSpend(CScript() << Sig() << pk, CScript() << OP_DUP << OP_HASH160 << Hash160(pk) << OP_EQUALVERIFY << OP_CHECKSIG, CScriptWitness()).extra.bytes, 0U);
}

BOOST_AUTO_TEST_CASE(accounting_does_not_depend_on_the_input_cache)
{
    // With traces given, the input cache of the static pass is neither filled nor read: the executed-data
    // accounting needs the ranges of the full counting pass of every input. So the result is the same
    // with no cache, an empty one, one a static pass filled, and one holding nonsense.
    const CScript envelope = CScript() << OP_FALSE << OP_IF << Bytes(100, 3) << OP_ENDIF << Key(1) << OP_CHECKSIG;
    const CScript dropping = CScript() << OP_DROP << Key(2) << OP_CHECKSIG;
    const CScriptWitness envelope_witness{Wit({Sig()}, envelope)};
    const CScriptWitness dropping_witness{Wit({Sig(), Bytes(80, 5)}, dropping)};
    const CScript spks[] = {Wsh(envelope), Wsh(dropping)};
    const CScriptWitness* witnesses[] = {&envelope_witness, &dropping_witness};

    CCoinsView dummy;
    CCoinsViewCache view{&dummy};
    CMutableTransaction mtx;
    std::vector<InputTrace> traces;
    for (size_t i{0}; i < 2; ++i) {
        const COutPoint prevout{Txid::FromUint256(uint256{static_cast<unsigned char>(i + 1)}), 0};
        view.AddCoin(prevout, Coin{CTxOut{COIN, spks[i]}, 1, false}, true);
        mtx.vin.emplace_back(prevout);
        mtx.vin.back().scriptWitness = *witnesses[i];
        const Traced t = TraceSpend(CScript(), spks[i], *witnesses[i]);
        REQUIRE_TRACED(t);
        InputTrace trace;
        trace.status = InputTrace::Status::TRACED;
        trace.ledger = t.ledger;
        traces.push_back(std::move(trace));
    }
    mtx.vout.emplace_back(COIN, CScript() << OP_TRUE);
    const CTransaction tx{mtx};

    const std::vector<VerifiedKeys> verified{VerifiedKeys{Key(1)}, VerifiedKeys{Key(2)}};
    const auto same = [](const std::vector<DatacarrierInputCache>& a, const std::vector<DatacarrierInputCache>& b) {
        return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](const DatacarrierInputCache& x, const DatacarrierInputCache& y) {
            return x.first == y.first && x.second == y.second && x.normal == y.normal;
        });
    };

    std::vector<DatacarrierInputCache> filled;
    const auto static_only{DatacarrierBytes(tx, view, /*verified_keys=*/nullptr, &filled)};
    BOOST_REQUIRE_EQUAL(filled.size(), 2U);

    for (const std::vector<VerifiedKeys>* keys : {static_cast<const std::vector<VerifiedKeys>*>(nullptr), &verified}) {
        bool untraceable{false};
        const auto baseline{DatacarrierBytes(tx, view, keys, /*input_cache=*/nullptr, &traces, &untraceable)};
        BOOST_CHECK(!untraceable);
        // Not vacuous: the dropped witness item is charged on top of the static count.
        BOOST_CHECK_GT(baseline.second, static_only.second);

        std::vector<DatacarrierInputCache> empty;
        std::vector<DatacarrierInputCache> prefilled{filled};
        std::vector<DatacarrierInputCache> nonsense(2, DatacarrierInputCache{9999, 9999, true});
        for (std::vector<DatacarrierInputCache>* cache : {&empty, &prefilled, &nonsense}) {
            const std::vector<DatacarrierInputCache> before{*cache};
            bool untraceable_cached{false};
            const auto with_cache{DatacarrierBytes(tx, view, keys, cache, &traces, &untraceable_cached)};
            BOOST_CHECK(with_cache == baseline);
            BOOST_CHECK_EQUAL(untraceable_cached, untraceable);
            BOOST_CHECK(same(*cache, before)); // neither filled nor modified
        }
    }
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
