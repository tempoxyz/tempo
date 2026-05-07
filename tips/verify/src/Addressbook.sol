// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title Addressbook
/// @notice Per-user address book: each `msg.sender` owns an independent
///         namespace of name → address entries.  Only the owner can create,
///         update, or delete entries in their own book.
contract Addressbook {

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event EntrySet(address indexed owner, string name, address addr);
    event EntryRemoved(address indexed owner, string name);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error EmptyName();
    error EntryNotFound(string name);

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// owner → name → address
    mapping(address => mapping(string => address)) private _entries;

    /// owner → ordered list of names (for enumeration)
    mapping(address => string[]) private _names;

    /// owner → name → index+1 in _names (0 means not present)
    mapping(address => mapping(string => uint256)) private _nameIndex;

    /*//////////////////////////////////////////////////////////////
                            MUTATIVE
    //////////////////////////////////////////////////////////////*/

    /// @notice Add or update a name → address entry in the caller's book.
    /// @param name  Human-readable label (must be non-empty).
    /// @param addr  The address to associate with `name`.
    function set(string calldata name, address addr) external {
        if (bytes(name).length == 0) revert EmptyName();

        _entries[msg.sender][name] = addr;

        // Track the name for enumeration if it's new.
        if (_nameIndex[msg.sender][name] == 0) {
            _names[msg.sender].push(name);
            _nameIndex[msg.sender][name] = _names[msg.sender].length; // 1-indexed
        }

        emit EntrySet(msg.sender, name, addr);
    }

    /// @notice Remove an entry from the caller's book.
    /// @param name  The label to remove.
    function remove(string calldata name) external {
        uint256 idx = _nameIndex[msg.sender][name];
        if (idx == 0) revert EntryNotFound(name);

        delete _entries[msg.sender][name];

        // Swap-and-pop to keep enumeration array compact.
        uint256 lastIdx = _names[msg.sender].length;
        if (idx != lastIdx) {
            string memory lastName = _names[msg.sender][lastIdx - 1];
            _names[msg.sender][idx - 1] = lastName;
            _nameIndex[msg.sender][lastName] = idx;
        }
        _names[msg.sender].pop();
        delete _nameIndex[msg.sender][name];

        emit EntryRemoved(msg.sender, name);
    }

    /*//////////////////////////////////////////////////////////////
                              VIEW
    //////////////////////////////////////////////////////////////*/

    /// @notice Resolve a name in a given owner's book.
    function get(address owner, string calldata name) external view returns (address) {
        return _entries[owner][name];
    }

    /// @notice Return how many entries an owner has.
    function count(address owner) external view returns (uint256) {
        return _names[owner].length;
    }

    /// @notice Return all names in an owner's book.
    function listNames(address owner) external view returns (string[] memory) {
        return _names[owner];
    }

    /// @notice Return all entries (names + addresses) for an owner.
    function listAll(address owner)
        external
        view
        returns (string[] memory names, address[] memory addrs)
    {
        names = _names[owner];
        addrs = new address[](names.length);
        for (uint256 i; i < names.length; ++i) {
            addrs[i] = _entries[owner][names[i]];
        }
    }

}
