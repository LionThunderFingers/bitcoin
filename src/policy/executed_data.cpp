// Copyright (c) The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/executed_data.h>

#include <logging.h>
#include <serialize.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <utility>

namespace {
using valtype = std::vector<unsigned char>;

//! Thrown inside the tracer when its model of the stacks cannot be right. Never leaves it.
struct ModelError {
    std::string what;
};

//! A cheap fingerprint of a stack element, for the tracer to check its model against the interpreter with.
//! It reads eight bytes per step: the tracer calls it for every op of every input of a transaction it has not
//! accepted yet. It is not a security hash, a collision only hides a model error that the length and the
//! other elements would very likely show too.
uint64_t HashBytes(const valtype& v)
{
    uint64_t h{0xcbf29ce484222325ULL ^ v.size()};
    size_t i{0};
    for (; i + 8 <= v.size(); i += 8) {
        uint64_t w;
        std::memcpy(&w, v.data() + i, 8);
        h = (h ^ w) * 0x9E3779B97F4A7C15ULL;
        h ^= h >> 32;
    }
    for (; i < v.size(); ++i) {
        h = (h ^ v[i]) * 0x100000001b3ULL;
    }
    return h ^ (h >> 29);
}

//! Little endian sign-and-magnitude, as CScriptNum reads it. False if too long to be a count.
bool DecodeNum(const valtype& v, int64_t& out)
{
    if (v.size() > 8) return false;
    uint64_t r{0};
    for (size_t i = 0; i < v.size(); ++i) r |= static_cast<uint64_t>(v[i]) << (8 * i);
    if (!v.empty() && (v.back() & 0x80)) {
        r &= ~(static_cast<uint64_t>(0x80) << (8 * (v.size() - 1)));
        out = -static_cast<int64_t>(r);
    } else {
        out = static_cast<int64_t>(r);
    }
    return true;
}

uint32_t Cap(uint32_t len, uint32_t cap) { return std::min(len, cap); }

//! Mirror of IsStackNeutralNop in script/script.cpp, which the static counting of unproven keys uses to
//! carry a key across the opcodes that leave the stack as they found it. The two must stay in lockstep:
//! where the static rules see a key and this does not, a key is charged as data on top of the budget that
//! already owns it. It is wider than IsNoOp on purpose, since OP_CHECKLOCKTIMEVERIFY (OP_NOP2) and
//! OP_CHECKSEQUENCEVERIFY (OP_NOP3) read the top of the stack but leave it there. Every opcode it takes is
//! a single byte, so a raw script byte can be tested against it.
bool IsStackNeutralNop(unsigned int opcode)
{
    return opcode == OP_NOP || (opcode >= OP_NOP1 && opcode <= OP_NOP10);
}

bool IsInitialKind(ExecutedDataTracer::SourceKind k)
{
    return k == ExecutedDataTracer::SourceKind::SCRIPTSIG_PUSH || k == ExecutedDataTracer::SourceKind::WITNESS_ITEM;
}
} // namespace

// ---- BitSet -------------------------------------------------------------------------------

void ExecutedDataTracer::BitSet::Set(size_t i)
{
    if (m_words.size() <= i / 64) m_words.resize(i / 64 + 1, 0);
    m_words[i / 64] |= uint64_t{1} << (i % 64);
}

bool ExecutedDataTracer::BitSet::Test(size_t i) const
{
    return i / 64 < m_words.size() && (m_words[i / 64] >> (i % 64)) & 1;
}

void ExecutedDataTracer::BitSet::Or(const BitSet& other)
{
    if (m_words.size() < other.m_words.size()) m_words.resize(other.m_words.size(), 0);
    for (size_t i = 0; i < other.m_words.size(); ++i) m_words[i] |= other.m_words[i];
}

bool ExecutedDataTracer::BitSet::None() const
{
    return std::all_of(m_words.begin(), m_words.end(), [](uint64_t w) { return w == 0; });
}

size_t ExecutedDataTracer::BitSet::Count() const
{
    size_t n{0};
    for (uint64_t w : m_words) n += static_cast<size_t>(__builtin_popcountll(w));
    return n;
}

void ExecutedDataTracer::BitSet::AndNot(const BitSet& other)
{
    for (size_t i = 0; i < m_words.size() && i < other.m_words.size(); ++i) m_words[i] &= ~other.m_words[i];
}

// ---- Ledger -------------------------------------------------------------------------------

bool ExecutedDataTracer::Ledger::IsKeyShaped(size_t s) const
{
    const Source& src{sources.at(s)};
    if (src.kind != SourceKind::SCRIPT_PUSH || !src.chargeable) return false;
    if (src.len == 33 || src.len == 65) return true;
    if (src.len != 32) return false;
    const valtype& script{runs.at(src.run).script};
    // src.end is an opcode boundary, and every stack-neutral no-op is one byte, so this walks opcodes.
    size_t at{src.end};
    while (at < script.size() && IsStackNeutralNop(script[at])) ++at;
    if (at >= script.size()) return false;
    const unsigned char next{script[at]};
    return next == OP_CHECKSIG || next == OP_CHECKSIGVERIFY || next == OP_CHECKSIGADD;
}

uint32_t ExecutedDataTracer::Ledger::DataBytes(size_t s, bool exclude_key_shaped) const
{
    const Source& src{sources.at(s)};
    if (!src.chargeable || src.code) return 0;
    if (exclude_key_shaped && IsKeyShaped(s)) return 0;
    return src.len - std::min(src.len, credited.at(s));
}

uint64_t ExecutedDataTracer::Ledger::TotalDataBytes(bool exclude_key_shaped) const
{
    uint64_t total{0};
    for (size_t s = 0; s < sources.size(); ++s) total += DataBytes(s, exclude_key_shaped);
    return total;
}

ExecutedDataTracer::Ledger ExecutedDataTracer::Finish(uint32_t lock_allowance) const
{
    Ledger l;
    l.failed = m_failed;
    l.fail_reason = m_fail_reason;
    l.sources = m_sources;
    l.runs = m_runs;
    l.credited.assign(m_sources.size(), 0);
    for (size_t s = 0; s < m_sources.size(); ++s) {
        if (m_verified[s]) l.credited[s] = m_sources[s].len;
    }
    if (m_failed) return l;

    auto grant = [&](uint32_t s, uint32_t amount) { l.credited[s] = std::max(l.credited[s], Cap(amount, m_sources[s].len)); };

    // Group the live locks by their witness-side source: a source credited by several locks counts once.
    struct Group {
        BitSet constants;
        bool all_true{true};
        bool key_hash{true};
    };
    std::map<uint32_t, Group> groups;
    m_live.ForEach([&](size_t r) {
        const LockRecord& rec{m_records[r]};
        Group& g{groups[rec.src]};
        // A set union, so merging a record costs the group's size and not the group's size per constant:
        // a script may lock one value against one accumulated constant thousands of times.
        g.constants.Or(rec.constants);
        g.all_true = g.all_true && rec.true_result;
        g.key_hash = g.key_hash && rec.key_hash;
    });

    std::vector<std::pair<uint32_t, uint32_t>> small; // source, credit, from groups that fit in a few bytes
    std::vector<std::pair<uint32_t, uint32_t>> ranked; // value, source
    std::vector<uint32_t> key_locks;
    for (const auto& [s, g] : groups) {
        if (m_sources[s].code) continue;
        bool tiny{m_sources[s].len <= 4};
        g.constants.ForEach([&](size_t c) { tiny = tiny && m_sources[c].len <= 4; });
        if (tiny) {
            small.emplace_back(s, m_sources[s].len);
            g.constants.ForEach([&](size_t c) { small.emplace_back(static_cast<uint32_t>(c), m_sources[c].len); });
            continue;
        }
        if (g.all_true && m_verified[s]) {
            // The value is a key that really signed: what it was compared with is its own hash.
            g.constants.ForEach([&](size_t c) { grant(static_cast<uint32_t>(c), LOCK_CREDIT_CAP); });
            continue;
        }
        bool all_20{true};
        g.constants.ForEach([&](size_t c) { all_20 = all_20 && m_sources[c].len == 20; });
        if (g.key_hash && all_20) {
            key_locks.push_back(s);
            continue;
        }
        uint32_t value{Cap(m_sources[s].len, LOCK_CREDIT_CAP)};
        g.constants.ForEach([&](size_t c) { value += Cap(m_sources[c].len, LOCK_CREDIT_CAP); });
        ranked.emplace_back(value, s);
    }
    // Keys named by their hash have an allowance of their own, in source order, which is the same set of
    // sources whatever order the script ran in.
    for (size_t i = 0; i < key_locks.size() && i < KEY_LOCK_ALLOWANCE; ++i) {
        grant(key_locks[i], m_sources[key_locks[i]].len);
        groups[key_locks[i]].constants.ForEach([&](size_t c) { grant(static_cast<uint32_t>(c), LOCK_CREDIT_CAP); });
    }
    l.key_lock_slots_left = KEY_LOCK_ALLOWANCE - static_cast<uint32_t>(std::min<size_t>(key_locks.size(), KEY_LOCK_ALLOWANCE));
    // The largest credits win, so the outcome does not depend on the order the locks ran in.
    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) { return a.first != b.first ? a.first > b.first : a.second < b.second; });
    for (size_t i = 0; i < ranked.size() && i < lock_allowance; ++i) {
        const uint32_t s{ranked[i].second};
        grant(s, LOCK_CREDIT_CAP);
        groups[s].constants.ForEach([&](size_t c) { grant(static_cast<uint32_t>(c), LOCK_CREDIT_CAP); });
        ++l.lock_slots_used;
    }
    l.lock_slots_left = lock_allowance - l.lock_slots_used;


    // Small values, in source order, until the per-input budget is gone.
    std::vector<uint32_t> want(m_sources.size(), 0);
    for (size_t s = 0; s < m_sources.size(); ++s) want[s] = m_small_credit[s];
    for (const auto& [s, credit] : small) want[s] = std::max(want[s], Cap(credit, m_sources[s].len));
    for (size_t s = 0; s < m_sources.size(); ++s) {
        if (want[s] <= l.credited[s]) continue;
        const uint32_t increase{want[s] - l.credited[s]};
        if (l.small_credit_used + increase > SMALL_CREDIT_BUDGET) continue;
        l.small_credit_used += increase;
        l.credited[s] = want[s];
    }
    return l;
}

// ---- tracer -------------------------------------------------------------------------------

void ExecutedDataTracer::Fail(const std::string& reason)
{
    if (m_failed) return;
    m_failed = true;
    m_fail_reason = reason;
}

uint32_t ExecutedDataTracer::NewSource(SourceKind kind, bool chargeable, uint32_t index, uint32_t offset, uint32_t end, uint32_t len, uint32_t overhead)
{
    if (m_sources.size() >= MAX_SOURCES) throw ModelError{"too many sources"};
    Source s;
    s.kind = kind;
    s.chargeable = chargeable;
    s.run = m_run_index;
    s.index = index;
    s.offset = offset;
    s.end = end;
    s.len = len;
    s.overhead = overhead;
    m_sources.push_back(s);
    m_verified.push_back(0);
    m_small_credit.push_back(0);
    return static_cast<uint32_t>(m_sources.size() - 1);
}

ExecutedDataTracer::Elem ExecutedDataTracer::Pop(Stack& s)
{
    if (s.empty()) throw ModelError{"shadow stack underflow"};
    Elem e{std::move(s.back())};
    s.pop_back();
    return e;
}

void ExecutedDataTracer::Join(Elem& into, const Elem& e)
{
    into.content.Or(e.content);
    into.length.Or(e.length);
    into.pending.Or(e.pending);
}

ExecutedDataTracer::Elem ExecutedDataTracer::Derived(const Elem* a, const Elem* b, const Elem* c)
{
    Elem r;
    for (const Elem* e : {a, b, c}) {
        if (e) Join(r, *e);
    }
    r.length.AndNot(r.content);
    return r;
}

void ExecutedDataTracer::SmallCredit(uint32_t s, uint32_t cap)
{
    m_small_credit[s] = std::max(m_small_credit[s], Cap(m_sources[s].len, cap));
}

void ExecutedDataTracer::DirectCredit(const Elem& e, uint32_t cap)
{
    // An aggregate says nothing about any one of its parts, so only a value that depends on a
    // single source can credit it.
    if (e.content.Count() != 1) return;
    e.content.ForEach([&](size_t s) { SmallCredit(static_cast<uint32_t>(s), cap); });
}

void ExecutedDataTracer::FullCredit(const Elem& e)
{
    // Only an untouched source is a signature or key that was really checked.
    if (e.form == Form::SOURCE) m_verified[e.src] = 1;
}

void ExecutedDataTracer::Decide(const Elem& e)
{
    e.pending.ForEach([&](size_t r) { m_live.Set(r); });
    if (e.result) return;
    // A raw value that decides a branch or a VERIFY needs one byte at most.
    e.content.ForEach([&](size_t s) { SmallCredit(static_cast<uint32_t>(s), 1); });
}

bool ExecutedDataTracer::IsConst(const Elem& e) const
{
    if (!e.length.None() || e.content.None()) return false;
    bool all_push{true};
    e.content.ForEach([&](size_t s) { all_push = all_push && m_sources[s].kind == SourceKind::SCRIPT_PUSH; });
    return all_push;
}

bool ExecutedDataTracer::SingleInitial(const Elem& e) const
{
    return e.length.None() && e.content.Count() == 1 && (e.form == Form::SOURCE || e.form == Form::HASHED) &&
           IsInitialKind(m_sources[e.src].kind);
}

bool ExecutedDataTracer::HasInitial(const Elem& e) const
{
    bool any{false};
    auto check = [&](size_t s) { any = any || IsInitialKind(m_sources[s].kind); };
    e.content.ForEach(check);
    e.length.ForEach(check);
    return any;
}

void ExecutedDataTracer::Verify(const Stack& shadow, const Real& real, size_t window, const char* what)
{
    if (shadow.size() != real.size()) throw ModelError{std::string{"depth mismatch after "} + what};
    const size_t from{shadow.size() > window ? shadow.size() - window : 0};
    for (size_t i = from; i < shadow.size(); ++i) {
        if (shadow[i].len != real[i].size() || shadow[i].hash != HashBytes(real[i])) {
            throw ModelError{std::string{"value mismatch after "} + what};
        }
    }
}

void ExecutedDataTracer::BeginRun(const CScript& script, SigVersion sigversion, unsigned int flags, const Real& stack)
{
    if (m_failed) return;
    try {
        m_kind = m_next_kind;
        m_next_kind = ScriptRunKind::SCRIPTSIG;
        m_flags = flags;
        switch (m_kind) {
        case ScriptRunKind::SCRIPTSIG:
        case ScriptRunKind::REDEEMSCRIPT:
        case ScriptRunKind::WITNESS_V0_SCRIPT:
        case ScriptRunKind::TAPSCRIPT:
            m_run_chargeable = true;
            break;
        case ScriptRunKind::SCRIPTPUBKEY:
        case ScriptRunKind::WITNESS_V0_KEYHASH:
            m_run_chargeable = false;
            break;
        }
        m_runs.push_back(Run{m_kind, sigversion, valtype(script.begin(), script.end()), {}});
        m_run_index = static_cast<uint32_t>(m_runs.size() - 1);
        m_alt.clear();
        switch (m_kind) {
        case ScriptRunKind::SCRIPTSIG:
            if (!stack.empty()) throw ModelError{"scriptSig run starts with items"};
            m_stack.clear();
            m_snapshot_valid = false;
            m_scriptsig_pushes = 0;
            break;
        case ScriptRunKind::SCRIPTPUBKEY:
        case ScriptRunKind::REDEEMSCRIPT:
            // These continue on the stack the previous run left, which has to be the one we followed.
            Verify(m_stack, stack, SIZE_MAX, "run boundary");
            break;
        case ScriptRunKind::WITNESS_V0_SCRIPT:
        case ScriptRunKind::WITNESS_V0_KEYHASH:
        case ScriptRunKind::TAPSCRIPT:
            m_stack.clear();
            for (size_t i = 0; i < stack.size(); ++i) {
                const uint32_t len{static_cast<uint32_t>(stack[i].size())};
                const uint32_t overhead{len < 253 ? 1U : 3U};
                Elem e;
                {
                    // An empty item is a source too. It holds no bytes, but a script that compares it with
                    // a constant is checking what the spender supplied, not another constant of its own.
                    const uint32_t s{NewSource(SourceKind::WITNESS_ITEM, true, static_cast<uint32_t>(i), 0, 0, len, overhead)};
                    e.content.Set(s);
                    e.src = s;
                    e.form = Form::SOURCE;
                }
                e.len = len;
                e.hash = HashBytes(stack[i]);
                m_stack.push_back(std::move(e));
            }
            break;
        }
    } catch (const ModelError& e) {
        Fail(e.what);
    } catch (...) {
        Fail("exception");
    }
}

void ExecutedDataTracer::BeforeOp(opcodetype opcode, size_t start, size_t end, const valtype&, bool exec, const Real& stack, const Real& altstack)
{
    if (m_failed) return;
    m_op = opcode;
    m_exec = exec;
    m_start = start;
    m_end = end;
    m_pre_size = stack.size();
    m_pre_alt_size = altstack.size();
    m_calls_mark = m_calls ? m_calls->calls.size() : 0;
    m_pre_ok = false;
    m_window = 8;
    m_roll_slot = SIZE_MAX;
    if (exec) {
        try {
            m_runs.back().executed.push_back(static_cast<uint32_t>(start));
            if ((opcode == OP_PICK || opcode == OP_ROLL) && !stack.empty()) {
                m_pre_ok = DecodeNum(stack.back(), m_pre_n) && m_pre_n >= 0 && m_pre_n < 1000;
                // The elements between the top and the one that moves are not touched, whatever their number:
                // hashing them all for every op made a deep OP_ROLL cost the stack, and a script may roll
                // hundreds of times. Check the top and the slot the rolled element left, and the whole stack
                // at the end of the run.
                if (m_pre_ok && opcode == OP_ROLL && static_cast<size_t>(m_pre_n) + 2 <= stack.size()) {
                    m_roll_slot = stack.size() - 2 - static_cast<size_t>(m_pre_n);
                }
            } else if ((opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY) && !stack.empty()) {
                m_pre_ok = DecodeNum(stack.back(), m_pre_n) && m_pre_n >= 0 && m_pre_n <= MAX_PUBKEYS_PER_MULTISIG &&
                           stack.size() >= static_cast<size_t>(m_pre_n) + 2 &&
                           DecodeNum(stack[stack.size() - 2 - static_cast<size_t>(m_pre_n)], m_pre_m) && m_pre_m >= 0 && m_pre_m <= m_pre_n &&
                           stack.size() >= static_cast<size_t>(m_pre_n + m_pre_m) + 3;
            }
        } catch (...) {
            Fail("exception");
        }
    }
}

void ExecutedDataTracer::AfterOp(const Real& stack, const Real& altstack)
{
    if (m_failed) return;
    try {
        if (m_exec) Apply(stack);
        if (m_stack.size() != stack.size() || m_alt.size() != altstack.size()) {
            throw ModelError{"depth mismatch after " + GetOpName(m_op)};
        }
        Verify(m_stack, stack, m_window, GetOpName(m_op).c_str());
        if (m_roll_slot < stack.size() && m_roll_slot < m_stack.size()) {
            if (m_stack[m_roll_slot].len != stack[m_roll_slot].size() || m_stack[m_roll_slot].hash != HashBytes(stack[m_roll_slot])) {
                throw ModelError{"value mismatch after OP_ROLL"};
            }
        }
        if (!m_alt.empty()) {
            const Elem& top{m_alt.back()};
            if (top.len != altstack.back().size() || top.hash != HashBytes(altstack.back())) throw ModelError{"altstack value mismatch"};
        }
    } catch (const ModelError& e) {
        Fail(e.what);
    } catch (...) {
        Fail("exception");
    }
}

void ExecutedDataTracer::EndRun(const Real& stack)
{
    if (m_failed) return;
    try {
        Verify(m_stack, stack, SIZE_MAX, "run end");
        if (m_kind == ScriptRunKind::REDEEMSCRIPT) {
            // A P2SH-wrapped witness program is a commitment, like a scriptPubKey, not script the spender wrote.
            int version;
            std::vector<unsigned char> program;
            if (CScript(m_runs.back().script.begin(), m_runs.back().script.end()).IsWitnessProgram(version, program)) {
                for (Source& src : m_sources) {
                    if (src.run == m_run_index && src.kind == SourceKind::SCRIPT_PUSH) src.chargeable = false;
                }
            }
        }
        // The caller of the interpreter reads the top of every run but the scriptSig as a boolean.
        if (m_kind != ScriptRunKind::SCRIPTSIG && !m_stack.empty()) Decide(m_stack.back());
    } catch (const ModelError& e) {
        Fail(e.what);
    } catch (...) {
        Fail("exception");
    }
}

void ExecutedDataTracer::P2SHStackCopied()
{
    if (m_failed) return;
    try {
        m_snapshot = m_stack;
        m_snapshot_valid = true;
    } catch (...) {
        Fail("exception");
    }
}

void ExecutedDataTracer::P2SHRedeemScriptPopped()
{
    if (m_failed) return;
    if (!m_snapshot_valid || m_snapshot.empty()) {
        Fail("no scriptSig stack to take the P2SH redeem script from");
        return;
    }
    // The redeemScript is code: the scriptPubKey run hashes it, and it is never a stack source. An empty
    // one is not a source at all (OP_0), and can only be a script that fails.
    if (m_snapshot.back().form == Form::SOURCE) m_sources[m_snapshot.back().src].code = true;
    m_stack = std::move(m_snapshot);
    m_stack.pop_back();
    m_snapshot_valid = false;
}

void ExecutedDataTracer::TaprootKeyPathSpend(const valtype& sig)
{
    if (m_failed) return;
    try {
        m_stack.clear();
        m_alt.clear();
        const uint32_t len{static_cast<uint32_t>(sig.size())};
        const uint32_t s{NewSource(SourceKind::WITNESS_ITEM, true, 0, 0, 0, len, len < 253 ? 1U : 3U)};
        if (m_calls && !m_calls->overflow && !m_calls->calls.empty()) {
            const SigCheckCall& c{m_calls->calls.back()};
            if (c.ok && c.sig == sig) m_verified[s] = 1;
        }
    } catch (const ModelError& e) {
        Fail(e.what);
    } catch (...) {
        Fail("exception");
    }
}

void ExecutedDataTracer::Equality(bool numeric, bool verify, const Real& stack)
{
    Elem b{Pop(m_stack)};
    Elem a{Pop(m_stack)};
    Elem r{Derived(&a, &b, nullptr)};
    r.result = true;
    const bool a_const{IsConst(a)}, b_const{IsConst(b)};
    const bool lock{(a_const && SingleInitial(b)) || (b_const && SingleInitial(a))};
    if (lock) {
        const Elem& konst{a_const ? a : b};
        const Elem& other{a_const ? b : a};
        LockRecord rec;
        rec.src = other.src;
        rec.constants = konst.content;
        // The real result is on the stack when the comparison does not verify; otherwise it held.
        rec.key_hash = other.key_hash;
        rec.true_result = verify || (!stack.empty() && stack.back().size() == 1 && stack.back()[0] == 1);
        m_records.push_back(std::move(rec));
        r.pending.Set(m_records.size() - 1);
    } else {
        // Not a lock: no allowance is spent, but a constant that a witness-derived value is compared
        // with (a count, a SIZE test) is a small value like any other.
        if (a_const != b_const) {
            const Elem& konst{a_const ? a : b};
            const Elem& other{a_const ? b : a};
            if (HasInitial(other)) konst.content.ForEach([&](size_t s) { SmallCredit(static_cast<uint32_t>(s), 4); });
        }
        if (numeric) {
            DirectCredit(a, 4);
            DirectCredit(b, 4);
        }
        // A value built from no source at all, OP_0 to OP_16 or OP_1NEGATE, is no constant of the kind a lock
        // compares against, but a spender-chosen selector tested against one (DUP 1 EQUAL IF) is as much a
        // small value as a count is.
        const bool a_empty{a.content.None() && a.length.None()}, b_empty{b.content.None() && b.length.None()};
        if (a_empty != b_empty) DirectCredit(a_empty ? b : a, 4);
    }
    if (verify) {
        Decide(r);
    } else {
        m_stack.push_back(std::move(r));
    }
}

void ExecutedDataTracer::CreditChecked(const Elem& sig, const Elem& key)
{
    if (!m_calls) throw ModelError{"no signature check log"};
    if (m_calls->overflow) throw ModelError{"signature check log overflow"};
    const size_t n{m_calls->calls.size() - m_calls_mark};
    if (n > 1) throw ModelError{"more than one signature check for a single check opcode"};
    if (n == 1) {
        const SigCheckCall& c{m_calls->calls[m_calls_mark]};
        if (c.sig.size() != sig.len || HashBytes(c.sig) != sig.hash || c.key.size() != key.len || HashBytes(c.key) != key.hash) {
            throw ModelError{"signature check operands are not the stack slots"};
        }
        if (c.ok) {
            FullCredit(sig);
            FullCredit(key);
        }
    }
}

void ExecutedDataTracer::CheckSig(opcodetype opcode)
{
    Elem key{Pop(m_stack)};
    Elem sig{Pop(m_stack)};
    CreditChecked(sig, key);
    Elem r{Derived(&sig, &key, nullptr)};
    r.result = true;
    if (opcode == OP_CHECKSIGVERIFY) {
        Decide(r);
    } else {
        m_stack.push_back(std::move(r));
    }
}

void ExecutedDataTracer::CheckSigAdd()
{
    Elem key{Pop(m_stack)};
    Elem num{Pop(m_stack)};
    Elem sig{Pop(m_stack)};
    CreditChecked(sig, key);
    DirectCredit(num, 4);
    m_stack.push_back(Derived(&sig, &num, &key));
}

void ExecutedDataTracer::CheckMultisig(opcodetype opcode)
{
    if (!m_pre_ok) throw ModelError{"multisig counts did not parse"};
    if (!m_calls) throw ModelError{"no signature check log"};
    if (m_calls->overflow) throw ModelError{"signature check log overflow"};
    const size_t n{static_cast<size_t>(m_pre_n)};
    const size_t m{static_cast<size_t>(m_pre_m)};
    const size_t total{n + m + 3};
    if (m_stack.size() < total) throw ModelError{"shadow stack too small for multisig"};
    const size_t top{m_stack.size() - 1};
    // Top first: the key count, the keys from the last one pushed, the signature count, the signatures, the dummy.
    auto key_at = [&](size_t j) -> const Elem& { return m_stack[top - 1 - j]; };
    auto sig_at = [&](size_t k) -> const Elem& { return m_stack[top - 2 - n - k]; };
    // The interpreter pairs signatures with keys by walking both from the top, advancing the key on
    // every call and the signature only when the call succeeded. Replay that from the logged results.
    size_t isig{0}, ikey{0};
    for (size_t i = m_calls_mark; i < m_calls->calls.size(); ++i) {
        const SigCheckCall& c{m_calls->calls[i]};
        if (isig >= m || ikey >= n) throw ModelError{"more multisig checks than slots"};
        const Elem& sig{sig_at(isig)};
        const Elem& key{key_at(ikey)};
        if (c.sig.size() != sig.len || HashBytes(c.sig) != sig.hash || c.key.size() != key.len || HashBytes(c.key) != key.hash) {
            throw ModelError{"multisig check operands are not the stack slots"};
        }
        if (c.ok) {
            FullCredit(sig);
            FullCredit(key);
            ++isig;
        }
        ++ikey;
    }
    DirectCredit(m_stack[top], 4);
    DirectCredit(m_stack[top - 1 - n], 4);
    Elem r;
    for (size_t i = 0; i < total; ++i) Join(r, m_stack[m_stack.size() - 1 - i]);
    r.length.AndNot(r.content);
    r.result = true;
    m_stack.resize(m_stack.size() - total);
    if (opcode == OP_CHECKMULTISIGVERIFY) {
        Decide(r);
    } else {
        m_stack.push_back(std::move(r));
    }
}

void ExecutedDataTracer::Apply(const Real& stack)
{
    Stack& s{m_stack};
    auto need = [&](size_t k) {
        if (s.size() < k) throw ModelError{"shadow stack too small for " + GetOpName(m_op)};
    };
    const opcodetype op{m_op};
    bool derived_top{false};

    if (op <= OP_PUSHDATA4) {
        if (stack.empty()) throw ModelError{"push without a result"};
        const valtype& data{stack.back()};
        Elem e;
        // An empty push in a scriptSig is a source for the same reason an empty witness item is.
        if (!data.empty() || m_kind == ScriptRunKind::SCRIPTSIG) {
            const uint32_t len{static_cast<uint32_t>(data.size())};
            const uint32_t overhead{static_cast<uint32_t>(m_end - m_start) - len};
            const bool in_sig{m_kind == ScriptRunKind::SCRIPTSIG};
            const uint32_t index{in_sig ? m_scriptsig_pushes++ : 0};
            const uint32_t src{NewSource(in_sig ? SourceKind::SCRIPTSIG_PUSH : SourceKind::SCRIPT_PUSH, m_run_chargeable, index,
                                         static_cast<uint32_t>(m_start), static_cast<uint32_t>(m_end), len, overhead)};
            e.content.Set(src);
            e.src = src;
            e.form = Form::SOURCE;
        }
        s.push_back(std::move(e));
        derived_top = true;
    } else {
        switch (op) {
        case OP_1NEGATE: case OP_1: case OP_2: case OP_3: case OP_4: case OP_5: case OP_6: case OP_7: case OP_8:
        case OP_9: case OP_10: case OP_11: case OP_12: case OP_13: case OP_14: case OP_15: case OP_16:
        case OP_DEPTH:
            s.emplace_back();
            derived_top = true;
            break;
        case OP_NOP: case OP_NOP1: case OP_NOP4: case OP_NOP5: case OP_NOP6: case OP_NOP7: case OP_NOP8:
        case OP_NOP9: case OP_NOP10: case OP_CODESEPARATOR: case OP_ELSE: case OP_ENDIF:
            break;
        case OP_CHECKLOCKTIMEVERIFY:
            // Without the flag it is a NOP and looks at nothing.
            if (m_flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) {
                need(1);
                DirectCredit(s.back(), 5);
            }
            break;
        case OP_CHECKSEQUENCEVERIFY:
            if (m_flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) {
                need(1);
                DirectCredit(s.back(), 5);
            }
            break;
        case OP_IF: case OP_NOTIF: case OP_VERIFY: {
            Elem c{Pop(s)};
            Decide(c);
            break;
        }
        case OP_TOALTSTACK:
            m_alt.push_back(Pop(s));
            break;
        case OP_FROMALTSTACK:
            s.push_back(Pop(m_alt));
            break;
        case OP_2DROP:
            need(2);
            s.pop_back();
            s.pop_back();
            break;
        case OP_DROP:
            need(1);
            s.pop_back();
            break;
        case OP_2DUP:
            need(2);
            s.push_back(s[s.size() - 2]);
            s.push_back(s[s.size() - 2]);
            break;
        case OP_3DUP:
            need(3);
            s.push_back(s[s.size() - 3]);
            s.push_back(s[s.size() - 3]);
            s.push_back(s[s.size() - 3]);
            break;
        case OP_2OVER:
            need(4);
            s.push_back(s[s.size() - 4]);
            s.push_back(s[s.size() - 4]);
            break;
        case OP_2ROT: {
            need(6);
            Elem x1{s[s.size() - 6]}, x2{s[s.size() - 5]};
            s.erase(s.end() - 6, s.end() - 4);
            s.push_back(std::move(x1));
            s.push_back(std::move(x2));
            break;
        }
        case OP_2SWAP:
            need(4);
            std::swap(s[s.size() - 4], s[s.size() - 2]);
            std::swap(s[s.size() - 3], s[s.size() - 1]);
            break;
        case OP_IFDUP:
            need(1);
            // Whether it duplicated is read off the real stack, never worked out again here.
            if (stack.size() == s.size() + 1) s.push_back(s.back());
            break;
        case OP_DUP:
            need(1);
            s.push_back(s.back());
            break;
        case OP_NIP:
            need(2);
            s.erase(s.end() - 2);
            break;
        case OP_OVER:
            need(2);
            s.push_back(s[s.size() - 2]);
            break;
        case OP_PICK:
        case OP_ROLL: {
            if (!m_pre_ok) throw ModelError{"pick depth did not parse"};
            Elem depth{Pop(s)};
            DirectCredit(depth, 4);
            const size_t n{static_cast<size_t>(m_pre_n)};
            if (n >= s.size()) throw ModelError{"pick beyond the shadow stack"};
            Elem x{s[s.size() - 1 - n]};
            if (op == OP_ROLL) s.erase(s.end() - 1 - static_cast<std::ptrdiff_t>(n));
            s.push_back(std::move(x));
            break;
        }
        case OP_ROT:
            need(3);
            std::swap(s[s.size() - 3], s[s.size() - 2]);
            std::swap(s[s.size() - 2], s[s.size() - 1]);
            break;
        case OP_SWAP:
            need(2);
            std::swap(s[s.size() - 2], s[s.size() - 1]);
            break;
        case OP_TUCK: {
            need(2);
            Elem top{s.back()};
            s.insert(s.end() - 2, std::move(top));
            break;
        }
        case OP_SIZE: {
            need(1);
            Elem r;
            r.length = s.back().content;
            r.length.Or(s.back().length);
            r.pending = s.back().pending;
            s.push_back(std::move(r));
            derived_top = true;
            break;
        }
        case OP_EQUAL:
            Equality(false, false, stack);
            derived_top = true;
            break;
        case OP_EQUALVERIFY:
            Equality(false, true, stack);
            break;
        case OP_NUMEQUAL:
            Equality(true, false, stack);
            derived_top = true;
            break;
        case OP_NUMEQUALVERIFY:
            Equality(true, true, stack);
            break;
        case OP_1ADD: case OP_1SUB: case OP_NEGATE: case OP_ABS: case OP_NOT: case OP_0NOTEQUAL: {
            Elem a{Pop(s)};
            Elem r{Derived(&a, nullptr, nullptr)};
            if (op == OP_NOT || op == OP_0NOTEQUAL) {
                r.result = a.result;
            } else {
                DirectCredit(a, 4);
            }
            s.push_back(std::move(r));
            derived_top = true;
            break;
        }
        case OP_ADD: case OP_SUB: case OP_BOOLAND: case OP_BOOLOR: case OP_NUMNOTEQUAL: case OP_LESSTHAN:
        case OP_GREATERTHAN: case OP_LESSTHANOREQUAL: case OP_GREATERTHANOREQUAL: case OP_MIN: case OP_MAX: {
            Elem b{Pop(s)};
            Elem a{Pop(s)};
            Elem r{Derived(&a, &b, nullptr)};
            if (op == OP_BOOLAND || op == OP_BOOLOR) {
                r.result = a.result && b.result;
            } else {
                DirectCredit(a, 4);
                DirectCredit(b, 4);
                r.result = op != OP_ADD && op != OP_SUB && op != OP_MIN && op != OP_MAX;
            }
            s.push_back(std::move(r));
            derived_top = true;
            break;
        }
        case OP_WITHIN: {
            Elem c{Pop(s)};
            Elem b{Pop(s)};
            Elem a{Pop(s)};
            Elem r{Derived(&a, &b, &c)};
            DirectCredit(a, 4);
            DirectCredit(b, 4);
            DirectCredit(c, 4);
            r.result = true;
            s.push_back(std::move(r));
            derived_top = true;
            break;
        }
        case OP_RIPEMD160: case OP_SHA1: case OP_SHA256: case OP_HASH160: case OP_HASH256: {
            Elem a{Pop(s)};
            Elem r{Derived(&a, nullptr, nullptr)};
            if (a.form == Form::SOURCE) {
                r.form = Form::HASHED;
                r.src = a.src;
                r.key_hash = op == OP_HASH160 && (m_sources[a.src].len == 33 || m_sources[a.src].len == 65);
            }
            s.push_back(std::move(r));
            derived_top = true;
            break;
        }
        case OP_CHECKSIG: case OP_CHECKSIGVERIFY:
            CheckSig(op);
            derived_top = op == OP_CHECKSIG;
            break;
        case OP_CHECKSIGADD:
            CheckSigAdd();
            derived_top = true;
            break;
        case OP_CHECKMULTISIG: case OP_CHECKMULTISIGVERIFY:
            CheckMultisig(op);
            derived_top = op == OP_CHECKMULTISIG;
            break;
        default:
            throw ModelError{"opcode without a model: " + GetOpName(op)};
        }
    }

    if (derived_top && !s.empty() && !stack.empty()) {
        // A value the interpreter computed: take its length and hash from the real stack, where it ended up.
        s.back().len = static_cast<uint32_t>(stack.back().size());
        s.back().hash = HashBytes(stack.back());
    }
    // A moved element has to still be what it was: AfterOp compares the top of the shadow with the real stack.
}

// ---- accounting ---------------------------------------------------------------------------

namespace {
//! Items of this many bytes look like signatures to the static count, and are the one thing an
//! input that was not followed is not charged for.
bool LooksLikeSignature(size_t size) { return size >= 64 && size <= 73; }

//! The push opcodes and their data of a script that is meant to be push-only. False on anything else.
bool ParsePushes(const CScript& script, std::vector<valtype>& out)
{
    CScript::const_iterator it{script.begin()};
    opcodetype op;
    valtype data;
    while (it < script.end()) {
        if (!script.GetOp(it, op, data) || op > OP_16) return false;
        out.push_back(op == OP_0 || (op >= OP_1 && op <= OP_16) || op == OP_1NEGATE ? valtype{} : data);
    }
    return true;
}

/**
 * What an input is charged when nothing could be said about which of its bytes were used: every
 * stack source byte, except items that look like signatures. The script itself, the redeemScript,
 * the control block and the annex are code. The implicit keys of P2PKH and P2WPKH are free, since
 * nothing else can be done with them there.
 */
uint64_t ConservativeInputBytes(const CTxIn& txin, const CScript& spent_script_pub_key)
{
    uint64_t total{0};
    auto charge = [&](size_t size) { if (!LooksLikeSignature(size)) total += size; };

    std::vector<valtype> pushes;
    if (!ParsePushes(txin.scriptSig, pushes)) {
        // An executable scriptSig is all script, and the static rules count what they recognise in it.
        pushes.clear();
    }
    CScript program_script{spent_script_pub_key};
    int version{0};
    std::vector<unsigned char> program;
    const bool p2sh{spent_script_pub_key.IsPayToScriptHash()};
    if (p2sh && !pushes.empty()) {
        program_script = CScript{pushes.back().begin(), pushes.back().end()};
        pushes.pop_back();
    }
    const bool p2pkh{spent_script_pub_key.size() == 25 && spent_script_pub_key[0] == OP_DUP && spent_script_pub_key[1] == OP_HASH160 &&
                     spent_script_pub_key[2] == 20 && spent_script_pub_key[23] == OP_EQUALVERIFY && spent_script_pub_key[24] == OP_CHECKSIG};
    for (size_t i = 0; i < pushes.size(); ++i) {
        // The public key of a P2PKH spend is implied by the output it spends.
        if (p2pkh && i + 1 == pushes.size() && (pushes[i].size() == 33 || pushes[i].size() == 65)) continue;
        charge(pushes[i].size());
    }

    auto stack{txin.scriptWitness.stack};
    if (stack.empty()) return total;
    if (program_script.IsWitnessProgram(version, program)) {
        if (version == 0 && program.size() == WITNESS_V0_KEYHASH_SIZE) {
            // P2WPKH: a signature and the key the program commits to.
            for (size_t i = 0; i + 1 < stack.size(); ++i) charge(stack[i].size());
            return total;
        }
        if (version == 0 && program.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            stack.pop_back(); // the witnessScript
        } else if (version == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
            if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) stack.pop_back();
            if (stack.size() >= 2) {
                stack.pop_back(); // the control block
                stack.pop_back(); // the leaf script
            }
        }
    }
    for (const valtype& item : stack) charge(item.size());
    return total;
}

bool IsFreeNumber(const valtype& data)
{
    if (data.size() > 5) return false;
    try {
        (void)CScriptNum(data, /*fRequireMinimal=*/true, /*nMaxNumSize=*/5);
    } catch (const scriptnum_error&) {
        return false;
    }
    return true;
}

struct ScriptOp {
    size_t begin;
    size_t end;
    opcodetype opcode;
    valtype data;
};

bool InRanges(const std::vector<std::pair<size_t, size_t>>& ranges, size_t offset)
{
    return std::any_of(ranges.begin(), ranges.end(), [&](const auto& r) { return offset >= r.first && offset < r.second; });
}
} // namespace

size_t TraceableInputBytes(const CTxIn& txin)
{
    size_t size{txin.scriptSig.size()};
    for (const auto& item : txin.scriptWitness.stack) size += item.size() + GetSizeOfCompactSize(item.size());
    return size;
}

ExecutedDataCharge ExecutedDataBytes(const CTxIn& txin, const CScript& spent_script_pub_key, const InputTrace* trace, const DatacarrierRanges& static_ranges, size_t static_counted)
{
    ExecutedDataCharge charge;
    // The static rule recognised the whole input and counted all of it.
    if (static_ranges.whole_input) return charge;

    if (!trace || trace->status != InputTrace::Status::TRACED) {
        charge.conservative = true;
        charge.bytes = ConservativeInputBytes(txin, spent_script_pub_key);
        return charge;
    }
    const ExecutedDataTracer::Ledger& l{trace->ledger};
    if (l.failed) {
        charge.conservative = charge.untraceable = true;
        charge.bytes = ConservativeInputBytes(txin, spent_script_pub_key);
        LogWarning("Executed-data accounting could not follow an input (%s); charging it conservatively\n", l.fail_reason);
        return charge;
    }
    if (l.runs.empty()) {
        // Nothing went through the interpreter (an OP_SUCCESS leaf, an unknown witness version, an
        // anchor output), so there is no trace to read. That is not the same as nothing to charge.
        charge.conservative = true;
        charge.bytes = ConservativeInputBytes(txin, spent_script_pub_key);
        return charge;
    }

    // The run whose script the static rules looked at: the witness script or leaf, else the redeemScript,
    // else the scriptSig of a spend that has neither.
    int static_run{-1};
    for (size_t r = 0; r < l.runs.size(); ++r) {
        if (l.runs[r].kind == ScriptRunKind::WITNESS_V0_SCRIPT || l.runs[r].kind == ScriptRunKind::TAPSCRIPT) static_run = static_cast<int>(r);
    }
    for (size_t r = 0; static_run < 0 && r < l.runs.size(); ++r) {
        if (l.runs[r].kind == ScriptRunKind::REDEEMSCRIPT) static_run = static_cast<int>(r);
    }
    for (size_t r = 0; static_run < 0 && r < l.runs.size(); ++r) {
        if (l.runs[r].kind == ScriptRunKind::SCRIPTSIG) static_run = static_cast<int>(r);
    }
    auto counted_by_static = [&](uint32_t run, uint32_t offset) {
        return static_cast<int>(run) == static_run && InRanges(static_ranges.counted, offset);
    };

    uint64_t outside{0}, total{0};

    // The stack sources no check used.
    for (size_t s = 0; s < l.sources.size(); ++s) {
        const uint32_t data{l.DataBytes(s)};
        if (data == 0) continue;
        const auto& src{l.sources[s]};
        // The push opcode and length of a push nothing used at all are part of the payload's envelope.
        uint64_t bytes{data};
        if (l.credited[s] == 0 && src.kind != ExecutedDataTracer::SourceKind::WITNESS_ITEM) {
            bytes += src.overhead;
            // A push that is dropped right away takes the drop with it, as the static envelope rule does.
            const valtype& script{l.runs[src.run].script};
            if (src.kind == ExecutedDataTracer::SourceKind::SCRIPT_PUSH && src.end < script.size() &&
                (script[src.end] == OP_DROP || script[src.end] == OP_2DROP)) {
                ++bytes;
            }
        }
        total += bytes;
        if (src.kind != ExecutedDataTracer::SourceKind::WITNESS_ITEM && counted_by_static(src.run, src.offset)) continue;
        outside += bytes;
    }

    // The pushes in code that never ran.
    uint32_t slots_left{l.lock_slots_left};
    uint32_t key_slots_left{l.key_lock_slots_left};
    uint32_t number_bytes_left{ExecutedDataTracer::UNTAKEN_NUMBER_BUDGET};
    uint32_t opcode_bytes_left{ExecutedDataTracer::UNTAKEN_OPCODE_BUDGET};
    for (size_t r = 0; r < l.runs.size(); ++r) {
        const auto& run{l.runs[r]};
        if (run.kind != ScriptRunKind::REDEEMSCRIPT && run.kind != ScriptRunKind::WITNESS_V0_SCRIPT && run.kind != ScriptRunKind::TAPSCRIPT) continue;
        const CScript script{run.script.begin(), run.script.end()};
        int v{0};
        std::vector<unsigned char> prog;
        // The redeemScript of a nested witness program is a push of the program, which belongs to the witness.
        if (run.kind == ScriptRunKind::REDEEMSCRIPT && script.IsWitnessProgram(v, prog)) continue;

        std::vector<ScriptOp> ops;
        {
            CScript::const_iterator it{script.begin()};
            while (it < script.end()) {
                ScriptOp op;
                op.begin = static_cast<size_t>(it - script.begin());
                if (!script.GetOp(it, op.opcode, op.data)) {
                    // Cannot happen for a script that ran, since the interpreter reads all of it.
                    op.end = script.size();
                    op.opcode = OP_INVALIDOPCODE;
                    ops.push_back(std::move(op));
                    break;
                }
                op.end = static_cast<size_t>(it - script.begin());
                ops.push_back(std::move(op));
            }
        }
        // A constant that waits for a hash opcode further on is as typed as one that follows it: branches merge
        // before the comparison, and a script may push all its hashes first. Only a script that hashes at all can
        // hold such a constant.
        bool hashes160{false}, hashes256{false};
        for (const ScriptOp& op : ops) {
            if (op.opcode == OP_HASH160 || op.opcode == OP_RIPEMD160) hashes160 = true;
            if (op.opcode == OP_SHA256 || op.opcode == OP_HASH256) hashes256 = true;
        }
        for (size_t i = 0; i < ops.size(); ++i) {
            const ScriptOp& op{ops[i]};
            if (std::binary_search(run.executed.begin(), run.executed.end(), static_cast<uint32_t>(op.begin))) continue;
            const bool broken{op.opcode == OP_INVALIDOPCODE};
            const uint64_t bytes{op.end - op.begin};
            if (!broken && (op.opcode > OP_PUSHDATA4 || op.data.empty())) {
                // Not a push, or an empty one. The opcodes of a branch that never ran are not free: a run of them
                // names a byte each. Flow control is structure, not payload. An honest branch fits the allowance.
                const bool flow{op.opcode == OP_IF || op.opcode == OP_NOTIF || op.opcode == OP_ELSE || op.opcode == OP_ENDIF};
                if (flow) continue;
                if (opcode_bytes_left >= bytes) {
                    opcode_bytes_left -= static_cast<uint32_t>(bytes);
                    continue;
                }
                total += bytes;
                if (!counted_by_static(static_cast<uint32_t>(r), static_cast<uint32_t>(op.begin))) outside += bytes;
                continue;
            }
            bool data{true};
            if (!broken) {
                // As on the executed side, a stack-neutral no-op between a key and the opcode that spends
                // it does not hide the key: the static counting looks through the same ones.
                size_t j{i + 1};
                while (j < ops.size() && IsStackNeutralNop(ops[j].opcode)) ++j;
                const opcodetype next{j < ops.size() ? ops[j].opcode : OP_INVALIDOPCODE};
                const size_t n{op.data.size()};
                if (n == 33 || n == 65 || (n == 32 && (next == OP_CHECKSIG || next == OP_CHECKSIGVERIFY || next == OP_CHECKSIGADD))) {
                    data = false; // a key: the unproven-key budget owns it
                } else if (IsFreeNumber(op.data) && number_bytes_left >= n) {
                    // A minimal number of up to 5 bytes carries almost its length in free-form payload, so the
                    // untaken ones are free only up to a small budget, like the executed small values.
                    number_bytes_left -= static_cast<uint32_t>(n);
                    data = false;
                } else if (n == 20 && hashes160 && key_slots_left > 0) {
                    --key_slots_left; // a key named by its hash: shares the allowance of the executed pk_h locks
                    data = false;
                } else if (n == 32 && hashes256 && slots_left > 0) {
                    --slots_left;
                    data = false;
                }
            }
            if (!data) continue;
            total += bytes;
            if (counted_by_static(static_cast<uint32_t>(r), static_cast<uint32_t>(op.begin))) continue;
            outside += bytes;
        }
    }

    if (total < static_counted) {
        // The static rules counted bytes that this accounting does not call data (flow control inside an
        // envelope, say). They stay counted: the charge is the static count plus what lies outside it.
        LogDebug(BCLog::MEMPOOL, "Executed-data accounting covers %u bytes where the static count has %u\n", total, static_counted);
    }
    charge.bytes = outside;
    charge.total = total;
    return charge;
}
