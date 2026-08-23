# account-abstraction-guard

Drop-in Foundry security checks for the **ERC-4337 / ERC-7702 account-abstraction** footguns — the
smart-account and paymaster mistakes that end in a drained account or a full takeover. Same
discipline as [v4-hookguard](https://github.com/dngr2/v4-hookguard): every check ships a correct
**and** a deliberately-broken reference, so it is proven to bite.

Account abstraction is the newest surface every wallet now has: ERC-7702 is live on mainnet, and
custom accounts, session keys, and paymasters are proliferating. The bugs here are catastrophic and
invisible to a happy-path test. Depends only on `forge-std`.

## Install

```bash
forge install dngr2/account-abstraction-guard
```

## Checks

### 1. execute() access control  ✅ available

**The account-drain footgun.** A smart account's `execute(target, value, data)` runs an arbitrary
call *from the account*. If it isn't gated to the EntryPoint (or the owner), anyone calls it
directly and drains the account — moves its ETH/tokens or approves themselves. The account still
validates UserOps correctly through the EntryPoint; the ungated direct `execute` path is the bug.

```solidity
import {ExecuteAuthCheck} from "account-abstraction-guard/src/checks/ExecuteAuthCheck.sol";

contract MyAccountSecurity is ExecuteAuthCheck {
    function test_executeGated() public {
        assertExecuteGated(IExecutable(address(myAccount)));
    }
}
```

`assertExecuteGated` verifies **effect**: it runs an arbitrary call as a stranger through the account
and asserts it didn't execute. The reference pair proves it — a stranger drains the ungated account's
10 ETH; the gated one rejects everyone but the EntryPoint/owner.

### 2. UserOp signature validation  ✅ available

**The account-takeover footgun.** An account whose `validateUserOp` returns success without truly
checking the signature over `userOpHash` lets any bundler execute ANY UserOp for it — arbitrary
calldata, full control. It passes a happy-path test (the owner's own op validates); only a *wrong*
signature exposes it.

```solidity
import {UserOpSignatureCheck} from "account-abstraction-guard/src/checks/UserOpSignatureCheck.sol";

contract MyAccountSig is UserOpSignatureCheck {
    function test_sigValidated() public {
        assertValidatesSignature(IAccount(address(myAccount)), ownerPrivateKey);
    }
}
```

`assertValidatesSignature` signs a UserOp with the owner key (must validate → 0), then tampers one
byte and asserts the account returns `SIG_VALIDATION_FAILED`. The reference pair proves it: the
no-signature account validates a forged UserOp; the correct one rejects a non-owner signature.

### 3. Paymaster safety  ✅ available

**The three ways a paymaster gets drained or griefed.** A paymaster pays gas for other people's
user ops, and three implementation mistakes turn that into a loss: `validatePaymasterUserOp` not
gated to the EntryPoint (anyone drives sponsorship logic), `validatePaymasterUserOp` sponsoring an
unbounded `maxCost` (one crafted op drains the whole EntryPoint deposit), and a `postOp` that can
revert (the EntryPoint calls it to settle, so a failing user op griefs the paymaster and can brick
settlement). All three pass a happy-path test where the owner sponsors their own well-formed op.

```solidity
import {PaymasterSafetyCheck} from "account-abstraction-guard/src/checks/PaymasterSafetyCheck.sol";

contract MyPaymasterSecurity is PaymasterSafetyCheck {
    function test_paymasterSafe() public {
        assertPaymasterSafe(IPaymaster(address(myPaymaster)));
    }
}
```

`assertPaymasterSafe` drives each property directly and names the offender: it validates as a
stranger (gating), offers an absurd `maxCost` as the EntryPoint (bounds), and calls `postOp` in
both `opSucceeded` and `opReverted` modes (no-revert). The reference set proves each flag bites —
a distinct broken paymaster for gating, bounds, and griefing, plus a safe one that passes all three.

### 4. Replay protection on a signed relayed path  ✅ available

**The relayed-account footgun.** The EntryPoint's 2D nonce protects the standard `validateUserOp`
flow — but 7702 delegates and modular accounts also expose a direct, off-chain-signed path
(`executeWithSig`-style) for gasless/relayed actions that bypasses it. That path must consume a nonce
itself. An account that verifies the owner's signature but never records the nonce lets any relayer
resubmit the same signed payload again and again: a signed "send 1 ETH" becomes "send it every
block". The owner signed once; a happy-path test that relays once never sees it.

```solidity
import {ReplayProtectionCheck, IRelayExecutable} from "account-abstraction-guard/src/checks/ReplayProtectionCheck.sol";

contract MyAccountReplay is ReplayProtectionCheck {
    function test_noReplay() public {
        assertNoReplay(IRelayExecutable(address(myAccount)), ownerKey, address(counterTarget));
    }
}
```

`assertNoReplay` relays a signed op once (it must take effect), relays the identical payload again,
and asserts the second has no effect. The reference pair proves it: the nonce-consuming account runs
the op exactly once; the one that skips the nonce runs the same signed op twice.

## Roadmap (grant milestones)

The four shipped checks are the foundation. The suite this grows into:

5. **Session-key scoping & ERC-7702 delegate context** — a session key / 7702 delegate is bounded
   to its intended permissions and can't be driven by an unauthorized caller (the class of bug in
   real 7702 wallets and the ENS smart-account session design).

## Why

Account abstraction is an Ethereum Foundation priority and the fastest-growing wallet surface. Shared,
drop-in checks turn each AA footgun into a red CI check for every team shipping an account or
paymaster. MIT, no token, no fees.

Built by **dngr2**, extending [invariant-kit](https://github.com/dngr2/invariant-kit),
[v4-hookguard](https://github.com/dngr2/v4-hookguard), and
[superchain-interop-guard](https://github.com/dngr2/superchain-interop-guard).
