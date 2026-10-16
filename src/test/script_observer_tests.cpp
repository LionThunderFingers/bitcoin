// Copyright (c) The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/random.h>
#include <test/util/script_observer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <iterator>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(script_observer_tests, BasicTestingSetup)

namespace {
//! Answers signature checks from a fixed pattern, so two runs over the same script agree.
class PatternChecker : public BaseSignatureChecker
{
    mutable size_t m_pos{0};

public:
    bool Answer() const { return (m_pos++ % 3) != 1; }
    bool CheckECDSASignature(const std::vector<unsigned char>&, const std::vector<unsigned char>&, const CScript&, SigVersion, SighashRules = SighashRules::LEGACY) const override { return Answer(); }
    bool CheckSchnorrSignature(Span<const unsigned char>, Span<const unsigned char>, SigVersion, ScriptExecutionData&, ScriptError* = nullptr, SighashRules = SighashRules::LEGACY) const override { return Answer(); }
    bool CheckLockTime(const CScriptNum&) const override { return true; }
    bool CheckSequence(const CScriptNum&) const override { return true; }
};

const opcodetype OPS[] = {
    OP_0, OP_1, OP_2, OP_3, OP_16, OP_1NEGATE, OP_NOP, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY,
    OP_TOALTSTACK, OP_FROMALTSTACK, OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP, OP_IFDUP,
    OP_DEPTH, OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK, OP_SIZE,
    OP_EQUAL, OP_EQUALVERIFY, OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL, OP_ADD, OP_SUB,
    OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
    OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX, OP_WITHIN, OP_RIPEMD160, OP_SHA1, OP_SHA256,
    OP_HASH160, OP_HASH256, OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD,
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_RETURN,
};

std::vector<unsigned char> RandomItem(FastRandomContext& rng)
{
    static const size_t sizes[] = {0, 1, 1, 2, 4, 20, 32, 33, 64, 72};
    std::vector<unsigned char> item(sizes[rng.randrange(std::size(sizes))]);
    for (auto& b : item) b = static_cast<unsigned char>(rng.randrange(4));
    return item;
}

CScript RandomScript(FastRandomContext& rng)
{
    CScript script;
    const size_t n = 1 + rng.randrange(24);
    for (size_t i = 0; i < n; ++i) {
        if (rng.randrange(4) == 0) {
            script << RandomItem(rng);
        } else {
            script << OPS[rng.randrange(std::size(OPS))];
        }
    }
    return script;
}
} // namespace

BOOST_AUTO_TEST_CASE(observer_does_not_change_eval_script)
{
    // Same script, stack and flags, once without and once with an observer: result, error and
    // final stack must agree, in all three signature versions.
    const SigVersion versions[] = {SigVersion::BASE, SigVersion::WITNESS_V0, SigVersion::TAPSCRIPT};
    size_t observed_ops{0};
    for (int i = 0; i < 20000; ++i) {
        const CScript script{RandomScript(m_rng)};
        std::vector<std::vector<unsigned char>> initial;
        const size_t items = m_rng.randrange(6);
        for (size_t j = 0; j < items; ++j) initial.push_back(RandomItem(m_rng));
        const unsigned int flags = static_cast<unsigned int>(m_rng.randbits(20)) & ~SCRIPT_VERIFY_P2SH;
        const SigVersion sigversion = versions[m_rng.randrange(std::size(versions))];

        ScriptExecutionData plain_data, observed_data;
        plain_data.m_validation_weight_left = observed_data.m_validation_weight_left = 100000;
        plain_data.m_validation_weight_left_init = observed_data.m_validation_weight_left_init = true;

        auto plain_stack{initial};
        ScriptError plain_err;
        const PatternChecker plain_checker;
        const bool plain_ok = EvalScript(plain_stack, script, flags, plain_checker, sigversion, plain_data, &plain_err);

        auto observed_stack{initial};
        ScriptError observed_err;
        test::CountingScriptObserver observer;
        const PatternChecker inner_checker;
        const test::ObservedSignatureChecker observed_checker{inner_checker, observer};
        const bool observed_ok = EvalScript(observed_stack, script, flags, observed_checker, sigversion, observed_data, &observed_err);

        BOOST_REQUIRE_EQUAL(plain_ok, observed_ok);
        BOOST_REQUIRE_EQUAL(plain_err, observed_err);
        BOOST_REQUIRE(plain_stack == observed_stack);
        BOOST_REQUIRE_EQUAL(plain_data.m_codeseparator_pos, observed_data.m_codeseparator_pos);
        BOOST_REQUIRE_EQUAL(plain_data.m_validation_weight_left, observed_data.m_validation_weight_left);
        BOOST_REQUIRE(observer.contract_ok);
        BOOST_REQUIRE_EQUAL(observer.runs, 1U);
        BOOST_REQUIRE_EQUAL(observer.ended_runs, plain_ok ? 1U : 0U);
        // Every op that began and did not raise an error has a matching AfterOp.
        BOOST_REQUIRE(observer.after_ops == observer.ops || (!plain_ok && observer.after_ops + 1 == observer.ops));
        observed_ops += observer.ops;
    }
    BOOST_CHECK_GT(observed_ops, 20000U);
}

BOOST_AUTO_TEST_CASE(no_observer_by_default)
{
    BOOST_CHECK(BaseSignatureChecker().GetObserver() == nullptr);
    const PatternChecker inner;
    BOOST_CHECK(DeferringSignatureChecker(inner).GetObserver() == nullptr);
    test::CountingScriptObserver observer;
    BOOST_CHECK(test::ObservedSignatureChecker(inner, observer).GetObserver() == &observer);
    // A deferring wrapper around an observed checker passes the observer on.
    const test::ObservedSignatureChecker observed{inner, observer};
    const BaseSignatureChecker& as_base{observed};
    BOOST_CHECK(DeferringSignatureChecker{as_base}.GetObserver() == &observer);
}

BOOST_AUTO_TEST_CASE(observer_sees_executed_and_flow_control_ops_only)
{
    // OP_0 OP_IF <5> OP_ENDIF OP_1: the push inside the untaken branch is not reported, the IF and ENDIF are.
    const CScript script = CScript() << OP_0 << OP_IF << std::vector<unsigned char>{5} << OP_ENDIF << OP_1;
    std::vector<std::vector<unsigned char>> stack;
    test::CountingScriptObserver observer;
    const PatternChecker inner;
    const test::ObservedSignatureChecker checker{inner, observer};
    BOOST_REQUIRE(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE));
    BOOST_CHECK_EQUAL(observer.ops, 4U);          // OP_0, IF, ENDIF, OP_1
    BOOST_CHECK_EQUAL(observer.executed_ops, 3U); // the IF itself ran, ENDIF is flow control reached with exec false
    BOOST_CHECK(observer.contract_ok);
}

BOOST_AUTO_TEST_SUITE_END()
