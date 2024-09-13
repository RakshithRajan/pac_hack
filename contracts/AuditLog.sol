// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract AuditLog {
    struct Log {
        string userId;
        string hash;
        string action;
        string timestamp;
    }

    Log[] public logs;

    event LogCreated(string indexed userId, string indexed hash, string action, string timestamp);

    function addLog(string memory _userId, string memory _hash, string memory _action, string memory _timestamp) public {
        logs.push(Log(_userId, _hash, _action, _timestamp));
        
        emit LogCreated(_userId, _hash, _action, _timestamp);
    }

    function getLogs() public view returns (Log[] memory) {
        return logs;
    }

    function getLogsCount() public view returns (uint) {
        return logs.length;
    }

    function getUserLogs(string memory _userId) public view returns (Log[] memory) {
        uint count = 0;
        for (uint i = 0; i < logs.length; i++) {
            if (keccak256(abi.encodePacked(logs[i].userId)) == keccak256(abi.encodePacked(_userId))) {
                count++;
            }
        }

        Log[] memory userLogs = new Log[](count);
        uint index = 0;
        for (uint i = 0; i < logs.length; i++) {
            if (keccak256(abi.encodePacked(logs[i].userId)) == keccak256(abi.encodePacked(_userId))) {
                userLogs[index] = logs[i];
                index++;
            }
        }

        return userLogs;
    }
}