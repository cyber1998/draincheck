// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Draincheck Authors
pragma solidity 0.8.30;

interface IERC20Like {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @title MiniPermit2
/// @notice MINIMAL TEST STAND-IN for the Draincheck sandbox. NOT a Permit2 implementation:
///         it only has the SignatureTransfer witness path (permitWitnessTransferFrom) that
///         the x402 `upto` scheme uses. No AllowanceTransfer, no batch transfers, no
///         ERC-1271. Never deploy it anywhere but a local anvil chain.
/// @dev Same EIP-712 domain ("Permit2", chainId, verifyingContract), same type strings and
///      the same unordered nonce bitmap as canonical Permit2, so payloads signed for it
///      match the x402 `upto` spec. Draincheck installs it at the canonical Permit2 address
///      with anvil_setCode, so there is no constructor or immutable. Only EOA signatures.
contract MiniPermit2 {
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    // Slot 0: owner => word position => bitmap of used nonces.
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("Permit2");
    bytes32 public constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    string public constant PERMIT_WITNESS_TRANSFER_FROM_TYPEHASH_STUB =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";
    uint256 private constant HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    event UnorderedNonceInvalidation(address indexed owner, uint256 word, uint256 mask);

    error SignatureExpired(uint256 signatureDeadline);
    error InvalidAmount(uint256 maxAmount);
    error InvalidNonce();
    error InvalidSigner();
    error InvalidSignatureLength();
    error TransferFailed();

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, block.chainid, address(this)));
    }

    function permitWitnessTransferFrom(
        PermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata signature
    ) external {
        if (block.timestamp > permit.deadline) revert SignatureExpired(permit.deadline);
        uint256 requested = transferDetails.requestedAmount;
        if (requested > permit.permitted.amount) revert InvalidAmount(permit.permitted.amount);

        bytes32 typeHash = keccak256(abi.encodePacked(PERMIT_WITNESS_TRANSFER_FROM_TYPEHASH_STUB, witnessTypeString));
        bytes32 tokenPermissionsHash =
            keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permit.permitted.token, permit.permitted.amount));
        bytes32 structHash =
            keccak256(abi.encode(typeHash, tokenPermissionsHash, msg.sender, permit.nonce, permit.deadline, witness));

        _useUnorderedNonce(owner, permit.nonce);
        if (_recover(keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)), signature) != owner) {
            revert InvalidSigner();
        }
        if (!IERC20Like(permit.permitted.token).transferFrom(owner, transferDetails.to, requested)) {
            revert TransferFailed();
        }
    }

    function invalidateUnorderedNonces(uint256 wordPos, uint256 mask) external {
        nonceBitmap[msg.sender][wordPos] |= mask;
        emit UnorderedNonceInvalidation(msg.sender, wordPos, mask);
    }

    function _useUnorderedNonce(address from, uint256 nonce) internal {
        uint256 wordPos = nonce >> 8;
        uint256 bit = 1 << (nonce & 0xff);
        uint256 flipped = nonceBitmap[from][wordPos] ^= bit;
        if (flipped & bit == 0) revert InvalidNonce();
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) revert InvalidSignatureLength();
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (uint256(s) > HALF_N || (v != 27 && v != 28)) revert InvalidSigner();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSigner();
        return signer;
    }
}
