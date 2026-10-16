// Copyright (c) The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/executed_data.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/script_observer.h>
#include <util/check.h>

#include <cstdint>
#include <vector>

namespace {
std::vector<std::vector<unsigned char>> ConsumeStack(FuzzedDataProvider& provider)
{
    std::vector<std::vector<unsigned char>> stack;
    LIMITED_WHILE(provider.ConsumeBool(), 20)
    {
        stack.push_back(ConsumeRandomLengthByteVector(provider, 80));
    }
    return stack;
}

void CheckLedger(const ExecutedDataTracer::Ledger& l)
{
    // Whatever the script did, the model must hold, and the ledger must be consistent with itself.
    Assert(!l.failed);
    Assert(l.credited.size() == l.sources.size());
    uint64_t data{0};
    for (size_t s = 0; s < l.sources.size(); ++s) {
        Assert(l.credited[s] <= l.sources[s].len);
        data += l.DataBytes(s, /*exclude_key_shaped=*/false);
    }
    Assert(l.TotalDataBytes(/*exclude_key_shaped=*/false) == data);
    Assert(l.TotalDataBytes(/*exclude_key_shaped=*/true) <= data);
    Assert(l.lock_slots_used + l.lock_slots_left == ExecutedDataTracer::LOCK_ALLOWANCE);
    Assert(l.small_credit_used <= ExecutedDataTracer::SMALL_CREDIT_BUDGET);
}
} // namespace

/** The shadow stacks of ExecutedDataTracer agree with the real ones for every script the interpreter runs. */
FUZZ_TARGET(executed_data_trace)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    std::vector<bool> answers;
    LIMITED_WHILE(provider.ConsumeBool(), 16) answers.push_back(provider.ConsumeBool());
    unsigned int flags{provider.ConsumeIntegral<unsigned int>()};
    // VerifyScript asserts on these combinations.
    if (flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    if (flags & SCRIPT_VERIFY_WITNESS) flags |= SCRIPT_VERIFY_P2SH;

    const test::ListSignatureChecker list_checker{answers};
    VerifiedKeys keys;
    SigCheckLog log;
    ExecutedDataTracer tracer{&log};
    const KeyRecordingSignatureChecker checker{list_checker, keys, &log, &tracer};

    if (provider.ConsumeBool()) {
        const CScript script{ConsumeScript(provider)};
        auto stack{ConsumeStack(provider)};
        const SigVersion sigversion{provider.PickValueInArray({SigVersion::BASE, SigVersion::WITNESS_V0, SigVersion::TAPSCRIPT})};
        ScriptExecutionData execdata;
        execdata.m_validation_weight_left = provider.ConsumeIntegralInRange<int64_t>(0, 5000);
        execdata.m_validation_weight_left_init = true;
        tracer.SetRunKind(provider.PickValueInArray({ScriptRunKind::WITNESS_V0_SCRIPT, ScriptRunKind::WITNESS_V0_KEYHASH, ScriptRunKind::TAPSCRIPT}));
        (void)EvalScript(stack, script, flags, checker, sigversion, execdata);
    } else {
        const CScript script_sig{ConsumeScript(provider)};
        const CScript script_pub_key{ConsumeScript(provider, /*maybe_p2wsh=*/true)};
        CScriptWitness witness;
        witness.stack = ConsumeStack(provider);
        (void)VerifyScript(script_sig, script_pub_key, &witness, flags, checker, nullptr);
        auto ledger{tracer.Finish()};
        CheckLedger(ledger);

        // The policy accounting on top of the same trace: it must cover what the static rules count, never
        // fail the model, and give the same answer when asked twice.
        CTxIn txin;
        txin.scriptSig = script_sig;
        txin.scriptWitness = witness;
        const CScript script = GetScriptForTransactionInput(script_pub_key, txin).first;
        DatacarrierRanges ranges;
        const auto dcb = script.DatacarrierBytes(0, &witness, /*dead_branches=*/::g_reject_dead_branches, /*verified_keys=*/nullptr, /*reached_normal_return=*/nullptr, &ranges);
        InputTrace trace;
        trace.status = provider.PickValueInArray({InputTrace::Status::TRACED, InputTrace::Status::TRACED, InputTrace::Status::NOT_RUN, InputTrace::Status::TOO_LARGE, InputTrace::Status::LOG_OVERFLOW});
        trace.ledger = std::move(ledger);
        const auto charge = ExecutedDataBytes(txin, script_pub_key, &trace, ranges, dcb.second);
        const auto again = ExecutedDataBytes(txin, script_pub_key, &trace, ranges, dcb.second);
        Assert(charge.bytes == again.bytes && charge.total == again.total);
        Assert(!charge.untraceable);
        if (charge.conservative) {
            // Charged as if nothing was followed: at most the stack sources of the input.
            Assert(charge.bytes <= TraceableInputBytes(txin));
        } else if (!trace.ledger.runs.empty() && !trace.ledger.failed) {
            // The accounting covers what the static rules count only for shapes they recognise, which a random
            // script is not. What must hold for any script is that the part outside the static ranges is part of the whole.
            Assert(charge.bytes <= charge.total);
            if (ranges.counted.empty() && !ranges.whole_input) Assert(charge.bytes == charge.total);
        }
        return;
    }
    CheckLedger(tracer.Finish());
}
