// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract AuditLog {
    struct Log {
        string hash;
        string action;
        string timestamp;
    }

    Log[] public logs;

    event LogCreated(string indexed hash, string action, string timestamp);

    function addLog(string memory _hash, string memory _action, string memory _timestamp) public {
        logs.push(Log(_hash, _action, _timestamp));
        
        emit LogCreated(_hash, _action, _timestamp);
    }

    function getLogs() public view returns (Log[] memory) {
        return logs;
    }

    function getLogsCount() public view returns (uint) {
        return logs.length;
    }
}