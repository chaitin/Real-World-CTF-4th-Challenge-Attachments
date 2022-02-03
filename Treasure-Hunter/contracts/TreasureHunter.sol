pragma solidity >=0.8.0 <0.9.0;

import {SMT} from "./SparseMerkleTree.sol";

contract TreasureHunter {
    bytes32 public root;
    SMT.Mode public smtMode = SMT.Mode.WhiteList;
    bool public solved = false;

    mapping(address => bool) public haveKey;
    mapping(address => bool) public haveTreasureChest;

    event FindKey(address indexed _from);
    event PickupTreasureChest(address indexed _from);
    event OpenTreasureChest(address indexed _from);

    constructor() public {
        root = SMT.init();
        _init();
    }

    function _init() internal {
        address[] memory hunters = new address[](8);
        hunters[0] = 0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e;
        hunters[1] = 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45;
        hunters[2] = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
        hunters[3] = 0x6B3595068778DD592e39A122f4f5a5cF09C90fE2;
        hunters[4] = 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B;
        hunters[5] = 0xc00e94Cb662C3520282E6f5717214004A7f26888;
        hunters[6] = 0xD533a949740bb3306d119CC777fa900bA034cd52;
        hunters[7] = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

        SMT.Leaf[] memory nextLeaves = new SMT.Leaf[](8);
        SMT.Leaf[] memory prevLeaves = new SMT.Leaf[](8);
        for (uint8 i = 0; i < hunters.length; i++) {
            nextLeaves[i] = SMT.Leaf({key: hunters[i], value: 1});
            prevLeaves[i] = SMT.Leaf({key: hunters[i], value: 0});
        }

        bytes32[] memory proof = new bytes32[](22);
        proof[0] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[1] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[2] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[3] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[4] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[5] = 0x0000000000000000000000000000000000000000000000000000000000000095;
        proof[6] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[7] = 0x0000000000000000000000000000000000000000000000000000000000000099;
        proof[8] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[9] = 0x000000000000000000000000000000000000000000000000000000000000009e;
        proof[10] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[11] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[12] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[13] = 0x000000000000000000000000000000000000000000000000000000000000004c;
        proof[14] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[15] = 0x000000000000000000000000000000000000000000000000000000000000009b;
        proof[16] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[17] = 0x000000000000000000000000000000000000000000000000000000000000009c;
        proof[18] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[19] = 0x000000000000000000000000000000000000000000000000000000000000009e;
        proof[20] = 0x0000000000000000000000000000000000000000000000000000000000000048;
        proof[21] = 0x000000000000000000000000000000000000000000000000000000000000009f;

        root = SMT.update(proof, nextLeaves, prevLeaves, root);
    }

    function enter(bytes32[] memory _proofs) public {
        require(haveKey[msg.sender] == false);
        root = SMT.updateSingleTarget(_proofs, msg.sender, root, SMT.Method.Insert);
    }

    function leave(bytes32[] memory _proofs) public {
        require(haveTreasureChest[msg.sender] == false);
        root = SMT.updateSingleTarget(_proofs, msg.sender, root, SMT.Method.Delete);
    }

    function findKey(bytes32[] memory _proofs) public {
        require(smtMode == SMT.Mode.BlackList, "not blacklist mode");
        address[] memory targets = new address[](1);
        targets[0] = msg.sender;
        require(SMT.verifyByMode(_proofs, targets, root, smtMode), "hunter has fallen into a trap");
        haveKey[msg.sender] = true;
        smtMode = SMT.Mode.WhiteList;
        emit FindKey(msg.sender);
    }

    function pickupTreasureChest(bytes32[] memory _proofs) public {
        require(smtMode == SMT.Mode.WhiteList, "not whitelist mode");
        address[] memory targets = new address[](1);
        targets[0] = msg.sender;
        require(
            SMT.verifyByMode(_proofs, targets, root, smtMode),
            "hunter hasn't found the treasure chest"
        );
        haveTreasureChest[msg.sender] = true;
        smtMode = SMT.Mode.BlackList;
        emit PickupTreasureChest(msg.sender);
    }

    function openTreasureChest() public {
        require(haveKey[msg.sender] && haveTreasureChest[msg.sender]);
        solved = true;
        emit OpenTreasureChest(msg.sender);
    }

    function isSolved() public view returns (bool) {
        return solved;
    }
}
