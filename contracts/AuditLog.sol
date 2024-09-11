// contracts/AuditLog.sol
pragma solidity ^0.8.0;

contract AuditLog {
    struct Log {
        address user;
        string hash;
        string action;
        string timestamp;
    }

    Log[] public logs;

    event LogCreated(address indexed user, string hash, string action, string timestamp);

    function addLog(string memory _hash, string memory _action, string memory _timestamp) public {
        logs.push(Log(msg.sender, _hash, _action, _timestamp));
        emit LogCreated(msg.sender, _hash, _action, _timestamp);
    }

    function getLogs() public view returns (Log[] memory) {
        return logs;
    }
}
