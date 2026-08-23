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

## Roadmap (grant milestones)

1. **Paymaster safety** — `validatePaymasterUserOp` must bound what it sponsors and be gated to the
   EntryPoint; `postOp` must not revert (griefing). Good/broken paymaster references.
2. **Nonce / replay** — the account uses the EntryPoint's 2D nonce; a UserOp can't be replayed.
3. **Session-key scoping & ERC-7702 delegate context** — a session key / 7702 delegate is bounded
   to its intended permissions and can't be driven by an unauthorized caller (the class of bug in
   real 7702 wallets and the ENS smart-account session design).

## Why

Account abstraction is an Ethereum Foundation priority and the fastest-growing wallet surface. Shared,
drop-in checks turn each AA footgun into a red CI check for every team shipping an account or
paymaster. MIT, no token, no fees.

Built by **dngr2**, extending [invariant-kit](https://github.com/dngr2/invariant-kit),
[v4-hookguard](https://github.com/dngr2/v4-hookguard), and
[superchain-interop-guard](https://github.com/dngr2/superchain-interop-guard).
