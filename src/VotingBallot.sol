// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "src/library/ECDSA.sol";

contract VotingBallot {
    using ECDSA for bytes32;

    struct Ballot {
        address voter;
        uint256 proposalId;
        uint256 vote;
    }

    bytes32 public constant BALLOT_TYPEHASH = keccak256(
        "Ballot(address voter,uint256 proposalId,uint256 vote)"
    );

    bytes32 public DOMAIN_SEPARATOR;

    // Mapping to store votes by proposal ID
    mapping(uint256 => uint256) public proposalVotes;
    // Mapping to track whether an address has voted on a proposal
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    // Event to emit when a vote is cast
    event VoteCast(address indexed voter, uint256 proposalId, uint256 vote);

    /**
     * @dev Constructor that initializes the domain separator for EIP-712.
     */
    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("VotingBallotTest")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @dev Hashes the ballot using the Ballot type hash and the ballot data.
     * @param ballot The Ballot struct to hash.
     * @return The keccak256 hash of the ballot.
     */
    function hashBallot(Ballot memory ballot) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                BALLOT_TYPEHASH,
                ballot.voter,
                ballot.proposalId,
                ballot.vote
            )
        );
    }

    /**
     * @dev Hashes the EIP-712 message for the ballot.
     * @param ballot The Ballot struct to hash.
     * @return The keccak256 hash of the EIP-712 message.
     */
    function hashEIP712Message(Ballot memory ballot) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                hashBallot(ballot)
            )
        );
    }

    /**
     * @dev Verifies the signature of the ballot.
     * @param ballot The Ballot struct to verify.
     * @param signature The signature to verify.
     * @return True if the signature is valid, false otherwise.
     */
    function verify(Ballot memory ballot, bytes memory signature) public view returns (bool) {
        bytes32 digest = hashEIP712Message(ballot);
        address signer = digest.recover(signature);
        return signer == ballot.voter;
    }

    /**
     * @dev Allows a user to cast a vote.
     * @param ballot The Ballot struct containing the vote information.
     * @param signature The signature to verify the ballot.
     */
    function castVote(Ballot memory ballot, bytes memory signature) public {
        require(verify(ballot, signature), "Invalid signature");
        require(!hasVoted[ballot.proposalId][ballot.voter], "Voter has already voted");

        hasVoted[ballot.proposalId][ballot.voter] = true;
        proposalVotes[ballot.proposalId] += ballot.vote;
        emit VoteCast(ballot.voter, ballot.proposalId, ballot.vote);
    }

    /**
     * @dev Returns the total votes for a given proposal.
     * @param proposalId The ID of the proposal to query.
     * @return The total number of votes for the proposal.
     */
    function getVotes(uint256 proposalId) public view returns (uint256) {
        return proposalVotes[proposalId];
    }
}
