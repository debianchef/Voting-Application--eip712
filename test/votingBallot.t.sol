// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {Vote} from "src/vote.sol";
import "forge-std/Test.sol";
import {VotingBallot} from "src/VotingBallot.sol";
import "forge-std/Script.sol";

contract VotingBallotTest is Test {
    VotingBallot votingBallot;
    Vote castVote;
    address voter1;
    address voter2;
    address voter3;
    address voter4;
    uint256 proposalId = 1;
    uint256 vote = 1;

    // Private keys
    uint256 privateKey1;
    uint256 privateKey2;
    uint256 privateKey3;
    uint256 privateKey4;
    
    // RPC URL
    string rpcUrl;

    function setUp() public {
        // Load environment variables
        privateKey1 = vm.envUint("PRIVATE_KEY1");
        privateKey2 = vm.envUint("PRIVATE_KEY2");
        privateKey3 = vm.envUint("PRIVATE_KEY3");
        privateKey4 = vm.envUint("PRIVATE_KEY4");
        rpcUrl = vm.envString("RPC_URL");

        // Initialize contract and addresses
        votingBallot = new VotingBallot();
        castVote = new Vote(address(votingBallot));
        voter1 = vm.addr(privateKey1);
        voter2 = vm.addr(privateKey2);
        voter3 = vm.addr(privateKey3);
        voter4 = vm.addr(privateKey4);

        // Set up RPC URL
        vm.createSelectFork(rpcUrl);
    }

    function testHashBallot() public {
        VotingBallot.Ballot memory ballot = VotingBallot.Ballot({
            voter: voter1,
            proposalId: proposalId,
            vote: vote
        });

        bytes32 ballotTypeHash = votingBallot.BALLOT_TYPEHASH();
        bytes32 ballotHash = keccak256(
            abi.encode(
                ballotTypeHash,
                ballot.voter,
                ballot.proposalId,
                ballot.vote
            )
        );

        bytes32 domainSeparator = votingBallot.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                ballotHash
            )
        );

        assertEq(votingBallot.hashEIP712Message(ballot), digest);
    }

    function testVerify() public {
        VotingBallot.Ballot memory ballot = VotingBallot.Ballot({
            voter: voter1,
            proposalId: proposalId,
            vote: vote
        });

        bytes32 digest = votingBallot.hashEIP712Message(ballot);
        emit log_bytes32(digest); // Debug print the digest

        // Generate signature using the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey1, digest);
        emit log_bytes32(r); // Debug print r
        emit log_bytes32(s); // Debug print s
        emit log_uint(v);    // Debug print v

        bytes memory signature = abi.encodePacked(r, s, v);

        // Manually recover the signer address
        address recoveredSigner = ecrecover(digest, v, r, s);
        emit log_address(recoveredSigner); // Debug print the recovered address

        // Check if the recovered signer is the expected voter
        assertEq(recoveredSigner, voter1);

        // Verify the signature using the contract function
        assertTrue(votingBallot.verify(ballot, signature));
    }

    function testCastVote() public {
        // Voter 1 casts a vote
        VotingBallot.Ballot memory ballot1 = VotingBallot.Ballot({
            voter: voter1,
            proposalId: proposalId,
            vote: vote
        });

        bytes32 digest1 = votingBallot.hashEIP712Message(ballot1);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey1, digest1);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);

        castVote.castVote(ballot1, signature1);

        // Voter 2 casts a vote
        VotingBallot.Ballot memory ballot2 = VotingBallot.Ballot({
            voter: voter2,
            proposalId: proposalId,
            vote: vote
        });

        bytes32 digest2 = votingBallot.hashEIP712Message(ballot2);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey2, digest2);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);

        castVote.castVote(ballot2, signature2);

        // Voter 3 casts a vote
        VotingBallot.Ballot memory ballot3 = VotingBallot.Ballot({
            voter: voter3,
            proposalId: proposalId,
            vote: vote
        });

        bytes32 digest3 = votingBallot.hashEIP712Message(ballot3);
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(privateKey3, digest3);
        bytes memory signature3 = abi.encodePacked(r3, s3, v3);

        castVote.castVote(ballot3, signature3);

        // Voter 4 casts a vote
        VotingBallot.Ballot memory ballot4 = VotingBallot.Ballot({
            voter: voter4,
            proposalId: proposalId,
            vote: vote
        });

        bytes32 digest4 = votingBallot.hashEIP712Message(ballot4);
        (uint8 v4, bytes32 r4, bytes32 s4) = vm.sign(privateKey4, digest4);
        bytes memory signature4 = abi.encodePacked(r4, s4, v4);

        castVote.castVote(ballot4, signature4);

        // Check total votes
        uint256 totalVotes = votingBallot.getVotes(proposalId);
        assertEq(totalVotes, 4 * vote);
    }

    function testPreventDoubleVoting() public {
        // Voter 1 casts a vote
        VotingBallot.Ballot memory ballot1 = VotingBallot.Ballot({
            voter: voter1,
            proposalId: proposalId,
            vote: vote
        });

        bytes32 digest1 = votingBallot.hashEIP712Message(ballot1);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey1, digest1);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);

        castVote.castVote(ballot1, signature1);

        // Voter 1 tries to cast another vote
        vm.expectRevert("Voter has already voted");
        castVote.castVote(ballot1, signature1);

        // Check total votes should still be 1
        uint256 totalVotes = votingBallot.getVotes(proposalId);
        assertEq(totalVotes, vote);
    }
}
