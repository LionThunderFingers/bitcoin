// Copyright (c) The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_SCRIPT_OBSERVER_H
#define BITCOIN_TEST_UTIL_SCRIPT_OBSERVER_H

#include <script/interpreter.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace test {

/** An observer that only counts, and checks that the interpreter keeps to the call order that
 *  ScriptObserver documents. */
class CountingScriptObserver : public ScriptObserver
{
    bool m_in_run{false};
    bool m_op_open{false};
    size_t m_last_end{0};
    size_t m_script_size{0};

public:
    size_t runs{0};
    size_t ended_runs{0};
    size_t ops{0};
    size_t executed_ops{0};
    size_t after_ops{0};
    bool contract_ok{true};

    void BeginRun(const CScript& script, SigVersion, unsigned int, const std::vector<std::vector<unsigned char>>&) override
    {
        // A run that failed has no EndRun, but then the whole spend has failed with it.
        m_in_run = true;
        m_op_open = false;
        m_last_end = 0;
        m_script_size = script.size();
        ++runs;
    }
    void BeforeOp(opcodetype, size_t start, size_t end, const std::vector<unsigned char>&, bool exec, const std::vector<std::vector<unsigned char>>&, const std::vector<std::vector<unsigned char>>&) override
    {
        if (!m_in_run || m_op_open || start < m_last_end || end < start || end > m_script_size) contract_ok = false;
        m_op_open = true;
        m_last_end = end;
        ++ops;
        if (exec) ++executed_ops;
    }
    void AfterOp(const std::vector<std::vector<unsigned char>>&, const std::vector<std::vector<unsigned char>>&) override
    {
        if (!m_in_run || !m_op_open) contract_ok = false;
        m_op_open = false;
        ++after_ops;
    }
    void EndRun(const std::vector<std::vector<unsigned char>>&) override
    {
        if (!m_in_run || m_op_open) contract_ok = false;
        m_in_run = false;
        ++ended_runs;
    }
};

/** Hands an observer to the interpreter and otherwise defers to the checker underneath. */
class ObservedSignatureChecker : public DeferringSignatureChecker
{
    ScriptObserver& m_observer;

public:
    ObservedSignatureChecker(const BaseSignatureChecker& checker, ScriptObserver& observer) : DeferringSignatureChecker(checker), m_observer(observer) {}
    ScriptObserver* GetObserver() const override { return &m_observer; }
};

} // namespace test

#endif // BITCOIN_TEST_UTIL_SCRIPT_OBSERVER_H
