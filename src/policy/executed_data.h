// Copyright (c) The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_EXECUTED_DATA_H
#define BITCOIN_POLICY_EXECUTED_DATA_H

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * Follows what one input's script does with the data it was given, to find out which bytes of
 * the spend were used and which only travelled along.
 *
 * It is a ScriptObserver, so it only watches: the interpreter never reads anything back from it.
 * It keeps a shadow of the main stack and the alt stack. Every shadow element knows, as exact
 * bitsets over the input's sources, which sources its value was computed from. A source is a
 * scriptSig push, a witness item, or a push that executed in script code. The script itself
 * (a P2WSH witnessScript, a P2SH redeemScript, a tapscript leaf and its control block) is code,
 * not a source: it is hashed against its commitment outside the interpreter.
 *
 * What counts as used is described in Finish(). The tracer fails closed. If its model of the
 * stacks ever disagrees with the real ones, Failed() is set and nothing in the ledger can be
 * trusted; callers must then treat every source as data. The failure has its own reason so that
 * a model bug does not hide behind an ordinary datacarrier rejection.
 *
 * One tracer is for one input, and for one VerifyScript call. Not thread safe.
 */
class ExecutedDataTracer final : public ScriptObserver
{
public:
    enum class SourceKind : uint8_t {
        SCRIPTSIG_PUSH, //!< a push in the scriptSig, which is the initial stack of a P2SH or legacy spend
        WITNESS_ITEM,   //!< an item of the witness stack, other than the script, control block and annex
        SCRIPT_PUSH,    //!< a push that executed in some script
    };

    struct Source {
        SourceKind kind;
        //! False for what is not part of the spending transaction (scriptPubKey and implied scripts).
        bool chargeable;
        //! True for the P2SH redeemScript, which is code that the scriptSig carries.
        bool code{false};
        uint32_t run;      //!< index into Ledger::runs of the run it was pushed in (SCRIPT_PUSH, SCRIPTSIG_PUSH)
        uint32_t index;    //!< push ordinal in the scriptSig, or witness stack index
        uint32_t offset;   //!< script offset of the push opcode (SCRIPT_PUSH, SCRIPTSIG_PUSH)
        uint32_t end;      //!< script offset after the push (SCRIPT_PUSH, SCRIPTSIG_PUSH)
        uint32_t len;      //!< length of the pushed value
        uint32_t overhead; //!< bytes around the value: push opcode and length, or the witness item length prefix
    };

    struct Run {
        ScriptRunKind kind;
        SigVersion sigversion;
        std::vector<unsigned char> script;
        //! Offsets of the opcodes that executed, ascending. Everything else in script never ran.
        std::vector<uint32_t> executed;
    };

    struct Ledger {
        //! True if the tracer's model broke. Nothing else here can be trusted then.
        bool failed{false};
        std::string fail_reason;
        std::vector<Source> sources;
        std::vector<Run> runs;
        //! Bytes of each source that something used, never more than its length.
        std::vector<uint32_t> credited;
        //! Lock allowance slots in use by executed locks, and left over for untaken typed slots.
        uint32_t lock_slots_used{0};
        uint32_t lock_slots_left{0};
        //! Slots of the allowance for keys named by their hash (KEY_LOCK_ALLOWANCE) that executed locks left unused.
        //! Untaken pushes of the size of a HASH160 draw on them.
        uint32_t key_lock_slots_left{0};
        //! Small-value credit bytes spent, out of the per-input budget.
        uint32_t small_credit_used{0};

        //! True if source s is a push that PR1's unproven-key budget owns: a chargeable script push
        //! of 33 or 65 bytes, or 32 bytes followed by a signature-check opcode.
        bool IsKeyShaped(size_t s) const;
        //! Length minus credited bytes for source s, or 0 if it is not charged (not chargeable,
        //! code, or key-shaped when exclude_key_shaped).
        uint32_t DataBytes(size_t s, bool exclude_key_shaped = true) const;
        //! Sum of DataBytes over all sources. Overheads are not included.
        uint64_t TotalDataBytes(bool exclude_key_shaped = true) const;
    };

    //! Locks (comparisons that check a witness-supplied value against a constant) that may spend
    //! their credit for free in one input, counting distinct credited sources.
    static constexpr uint32_t LOCK_ALLOWANCE{3};
    //! Locks of the form <key> HASH160 <20 byte hash> EQUAL, the pk_h of miniscript, that may take their
    //! credit apart from LOCK_ALLOWANCE. An honest thresh can hold many keys it does not sign with, and
    //! each is named by a hash. Ten matches the unproven public keys one input may carry for free (PR1).
    static constexpr uint32_t KEY_LOCK_ALLOWANCE{10};
    //! A hash lock credits at most this much of its witness-side source and of each constant.
    static constexpr uint32_t LOCK_CREDIT_CAP{32};
    //! Total bytes of small-value credit (counts, lock times, depths, raw conditions, numeric
    //! operands) one input may use. Calibrate on the corpus.
    static constexpr uint32_t SMALL_CREDIT_BUDGET{64};
    //! Bytes of minimal small numbers (up to 5 bytes) that code which never ran may hold for free in one input.
    //! Beyond it they are charged: a 5 byte number carries almost 5 bytes of payload.
    static constexpr uint32_t UNTAKEN_NUMBER_BUDGET{16};
    //! Bytes of non-push, non-flow opcodes that code which never ran may hold for free in one input. An honest
    //! untaken branch is a few dozen opcodes; the 201 opcode limit caps the rest at about 190 bytes.
    static constexpr uint32_t UNTAKEN_OPCODE_BUDGET{80};
    //! Signature-check calls and logged sources the tracer is willing to follow.
    static constexpr size_t MAX_SOURCES{20000};

    /** @param[in] calls  The ordered signature-check calls of this input, as the recorder logs them.
     *                    The tracer reads it and never writes. May be null if no checker logs. */
    explicit ExecutedDataTracer(const SigCheckLog* calls) : m_calls{calls} {}

    bool Failed() const { return m_failed; }
    const std::string& FailReason() const { return m_fail_reason; }

    /** Summarise what happened. Cheap enough to call once per input. Untaken typed hash slots draw
     *  from the same allowance, after the executed locks have been ranked: they get lock_slots_left. */
    Ledger Finish(uint32_t lock_allowance = LOCK_ALLOWANCE) const;

    // ScriptObserver
    void SetRunKind(ScriptRunKind kind) override { m_next_kind = kind; }
    void BeginRun(const CScript& script, SigVersion sigversion, unsigned int flags, const std::vector<std::vector<unsigned char>>& stack) override;
    void BeforeOp(opcodetype opcode, size_t start, size_t end, const std::vector<unsigned char>& push_data, bool exec, const std::vector<std::vector<unsigned char>>& stack, const std::vector<std::vector<unsigned char>>& altstack) override;
    void AfterOp(const std::vector<std::vector<unsigned char>>& stack, const std::vector<std::vector<unsigned char>>& altstack) override;
    void EndRun(const std::vector<std::vector<unsigned char>>& stack) override;
    void P2SHStackCopied() override;
    void P2SHRedeemScriptPopped() override;
    void TaprootKeyPathSpend(const std::vector<unsigned char>& sig) override;

private:
    class BitSet
    {
        std::vector<uint64_t> m_words;

    public:
        void Set(size_t i);
        bool Test(size_t i) const;
        void Or(const BitSet& other);
        bool None() const;
        size_t Count() const;
        //! Remove the bits that are also set in other.
        void AndNot(const BitSet& other);
        template <typename F>
        void ForEach(F&& f) const
        {
            for (size_t w = 0; w < m_words.size(); ++w) {
                uint64_t bits{m_words[w]};
                while (bits) {
                    const int b{__builtin_ctzll(bits)};
                    f(w * 64 + static_cast<size_t>(b));
                    bits &= bits - 1;
                }
            }
        }
    };

    static constexpr uint32_t NO_SOURCE{0xFFFFFFFFU};

    enum class Form : uint8_t {
        OTHER,  //!< anything computed
        SOURCE, //!< exactly one source, only ever moved
        HASHED, //!< a single hash opcode applied to one source
    };

    struct Elem {
        //! Sources whose value this element depends on, and sources that only its length depends on.
        //! The two are disjoint: content wins.
        BitSet content;
        BitSet length;
        //! Lock records whose credit is pending on this element reaching a decision.
        BitSet pending;
        uint32_t src{NO_SOURCE}; //!< for SOURCE and HASHED
        Form form{Form::OTHER};
        //! The result of a comparison or a signature check, as opposed to a raw value.
        bool result{false};
        //! HASHED by HASH160 from a source of the length of a public key: the shape of a pk_h.
        bool key_hash{false};
        //! Length and hash of the real value, used to check pure moves.
        uint32_t len{0};
        uint64_t hash{0};
    };

    struct LockRecord {
        uint32_t src;                   //!< the single witness-side source
        std::vector<uint32_t> constants; //!< sources of the constant side
        bool true_result;               //!< the comparison held
        bool key_hash;                  //!< the witness side is HASH160 of a key-sized source
    };

    using Stack = std::vector<Elem>;
    using Real = std::vector<std::vector<unsigned char>>;

    void Fail(const std::string& reason);
    uint32_t NewSource(SourceKind kind, bool chargeable, uint32_t index, uint32_t offset, uint32_t end, uint32_t len, uint32_t overhead);
    Elem Pop(Stack& s);
    void Apply(const Real& stack);
    void SmallCredit(uint32_t s, uint32_t cap);
    void DirectCredit(const Elem& e, uint32_t cap);
    void FullCredit(const Elem& e);
    void Decide(const Elem& e);
    bool IsConst(const Elem& e) const;
    bool SingleInitial(const Elem& e) const;
    bool HasInitial(const Elem& e) const;
    static void Join(Elem& into, const Elem& e);
    void Equality(bool numeric, bool verify, const Real& stack);
    void CheckSig(opcodetype opcode);
    void CreditChecked(const Elem& sig, const Elem& key);
    void CheckSigAdd();
    void CheckMultisig(opcodetype opcode);
    void Verify(const Stack& shadow, const Real& real, size_t window, const char* what);
    Elem Derived(const Elem* a, const Elem* b, const Elem* c);

    const SigCheckLog* const m_calls;
    bool m_failed{false};
    std::string m_fail_reason;

    ScriptRunKind m_next_kind{ScriptRunKind::SCRIPTSIG};
    ScriptRunKind m_kind{ScriptRunKind::SCRIPTSIG};
    unsigned int m_flags{0};
    bool m_run_chargeable{false};
    uint32_t m_run_index{0};
    uint32_t m_scriptsig_pushes{0};

    std::vector<Source> m_sources;
    std::vector<Run> m_runs;
    std::vector<uint8_t> m_verified;       //!< per source: a signature verified against it
    std::vector<uint32_t> m_small_credit;  //!< per source: largest small-value credit it received
    std::vector<LockRecord> m_records;
    BitSet m_live;                          //!< lock records whose result reached a decision

    Stack m_stack;
    Stack m_alt;
    Stack m_snapshot;
    bool m_snapshot_valid{false};

    // State captured before the opcode that is running.
    opcodetype m_op{OP_NOP};
    bool m_exec{false};
    size_t m_start{0};
    size_t m_end{0};
    size_t m_calls_mark{0};
    size_t m_pre_size{0};
    size_t m_pre_alt_size{0};
    int64_t m_pre_n{0};  //!< PICK/ROLL depth, or CHECKMULTISIG key count
    int64_t m_pre_m{0};  //!< CHECKMULTISIG signature count
    bool m_pre_ok{false};
    size_t m_window{8};
    size_t m_roll_slot{SIZE_MAX}; //!< the slot an OP_ROLL took its element from, to be checked after the op
};

/** What the policy script check could tell about one input. */
struct InputTrace {
    enum class Status : uint8_t {
        NOT_RUN,      //!< nothing was observed: the script execution cache answered, or this is not a policy check
        TRACED,       //!< the tracer followed the input
        TOO_LARGE,    //!< the input carries more than MAX_TRACED_INPUT_BYTES, so it was not followed
        LOG_OVERFLOW, //!< the input made more signature checks than the recorder keeps
    };
    Status status{Status::NOT_RUN};
    ExecutedDataTracer::Ledger ledger;
};

//! The most scriptSig and witness bytes of one input that the tracer will follow, however large
//! -maxscriptsize is set. Past it the input is charged as if untraced.
static constexpr size_t MAX_TRACED_INPUT_BYTES{10000};

/** Serialized size of the scriptSig and the witness of an input, the measure MAX_TRACED_INPUT_BYTES is against. */
size_t TraceableInputBytes(const CTxIn& txin);

/** What the executed-data accounting adds to the static data count of one input. */
struct ExecutedDataCharge {
    //! Data bytes not already counted by the static rules: the second member of DatacarrierBytes.
    uint64_t bytes{0};
    //! All the bytes this accounting calls data, including those inside ranges the static rules counted.
    //! At least the static count for every shape the static rules recognise (tested).
    uint64_t total{0};
    //! The tracer's model broke. The bytes are then the conservative charge, and the caller rejects
    //! with txn-datacarrier-untraceable unless that is ignored.
    bool untraceable{false};
    //! The input was not followed, so bytes is the conservative charge.
    bool conservative{false};
};

/**
 * The data bytes of one input that the static rules did not count: every byte of every stack source
 * that no check used, up to the credits of ExecutedDataTracer, plus the pushes in code that never ran
 * that are not keys, small numbers or one of the few hash slots the allowance covers. A byte inside
 * a range the static rule counted is paid for by that rule alone.
 *
 * An input that was not followed (no trace, too large, a log that overflowed, a script that ran no
 * interpreter at all) is charged conservatively: every stack source byte except items that look
 * like signatures. A trace whose model failed is charged the same way and flagged.
 *
 * @param[in] static_counted  The second member the static rules returned for this input, for the check
 *                            that this accounting covers at least what they cover.
 */
ExecutedDataCharge ExecutedDataBytes(const CTxIn& txin, const CScript& spent_script_pub_key, const InputTrace* trace, const DatacarrierRanges& static_ranges, size_t static_counted);

#endif // BITCOIN_POLICY_EXECUTED_DATA_H
