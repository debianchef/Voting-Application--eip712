// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {VotingBallot} from "src/VotingBallot.sol";


contract Vote {
    VotingBallot votingBallot;

    constructor(address _votingBallot) {
        votingBallot = VotingBallot(_votingBallot);
    }

    function castVote(VotingBallot.Ballot memory ballot, bytes memory signature) public {
       return  votingBallot.castVote(ballot, signature);
    }
}
