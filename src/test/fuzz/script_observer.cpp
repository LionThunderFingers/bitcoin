// Copyright (c) The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
    LIMITED_WHILE(provider.ConsumeBool(), 12)
    {
        stack.push_back(ConsumeRandomLengthByteVector(provider, 80));
    }
    return stack;
}
} // namespace

/** The interpreter gives the same result, error and stacks whether or not it is observed. */
FUZZ_TARGET(script_observer)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    std::vector<bool> answers;
    LIMITED_WHILE(provider.ConsumeBool(), 16) answers.push_back(provider.ConsumeBool());
    unsigned int flags{provider.ConsumeIntegral<unsigned int>()};
    // VerifyScript asserts on these combinations.
    if (flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    if (flags & SCRIPT_VERIFY_WITNESS) flags |= SCRIPT_VERIFY_P2SH;

    if (provider.ConsumeBool()) {
        // One EvalScript run.
        const CScript script{ConsumeScript(provider)};
        const auto initial{ConsumeStack(provider)};
        const SigVersion sigversion{provider.PickValueInArray({SigVersion::BASE, SigVersion::WITNESS_V0, SigVersion::TAPSCRIPT})};
        const int64_t weight{provider.ConsumeIntegralInRange<int64_t>(0, 5000)};

        ScriptExecutionData plain_data, observed_data;
        plain_data.m_validation_weight_left = observed_data.m_validation_weight_left = weight;
        plain_data.m_validation_weight_left_init = observed_data.m_validation_weight_left_init = true;

        auto plain_stack{initial};
        ScriptError plain_err;
        const test::ListSignatureChecker plain_checker{answers};
        const bool plain_ok{EvalScript(plain_stack, script, flags, plain_checker, sigversion, plain_data, &plain_err)};

        auto observed_stack{initial};
        ScriptError observed_err;
        test::CountingScriptObserver observer;
        const test::ListSignatureChecker inner_checker{answers};
        const test::ObservedSignatureChecker observed_checker{inner_checker, observer};
        const bool observed_ok{EvalScript(observed_stack, script, flags, observed_checker, sigversion, observed_data, &observed_err)};

        Assert(plain_ok == observed_ok);
        Assert(plain_err == observed_err);
        Assert(plain_stack == observed_stack);
        Assert(plain_data.m_codeseparator_pos == observed_data.m_codeseparator_pos);
        Assert(plain_data.m_validation_weight_left == observed_data.m_validation_weight_left);
        Assert(observer.contract_ok);
        Assert(observer.ended_runs == (plain_ok ? 1U : 0U));
    } else {
        // A whole spend: scriptSig, scriptPubKey, P2SH and witness runs.
        const CScript script_sig{ConsumeScript(provider)};
        const CScript script_pub_key{ConsumeScript(provider, /*maybe_p2wsh=*/true)};
        CScriptWitness witness;
        witness.stack = ConsumeStack(provider);

        ScriptError plain_err;
        const test::ListSignatureChecker plain_checker{answers};
        const bool plain_ok{VerifyScript(script_sig, script_pub_key, &witness, flags, plain_checker, &plain_err)};

        ScriptError observed_err;
        test::CountingScriptObserver observer;
        const test::ListSignatureChecker inner_checker{answers};
        const test::ObservedSignatureChecker observed_checker{inner_checker, observer};
        const bool observed_ok{VerifyScript(script_sig, script_pub_key, &witness, flags, observed_checker, &observed_err)};

        Assert(plain_ok == observed_ok);
        Assert(plain_err == observed_err);
        Assert(observer.contract_ok);
    }
}
