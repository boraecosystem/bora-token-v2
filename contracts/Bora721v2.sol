// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0)

pragma solidity 0.8.9;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

// import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol"; // for publicMint using Merkle Tree

interface IERC20 {
    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// Deploy : Optimizer : 50
// contract BORA721Core is ERC721, ERC721Enumerable, ERC721URIStorage, Pausable, Ownable, AccessControl, ReentrancyGuard {
contract Bora721v2 is ERC721, ERC721Enumerable, ERC721URIStorage, Pausable, Ownable, AccessControl, ReentrancyGuard {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant SYSTEM_ROLE = keccak256("SYSTEM_ROLE");

    using Strings for string;

    string private _name; // Token name
    string private _symbol; // Token symbol
    string private _baseURIextended = ""; // Base URI
    string private _contractURI = ""; // Contract URI for Contract Information
    string public tokenURISuffix = ".json"; // The suffix for the token URL, e.g. ".json".

    mapping(uint256 => string) private _tokenURIs; // (Optional) mapping for individual token URIs | Allows updating token URIs for individual token IDs

    bool public revealed = true; // Reveal NFT (How Generative NFT Reveals Work — Options and Strategies for a Smooth, Secure, and Profitable Reveal Process)
    string public notRevealedURI; // Case1. display URI for all NFT when not Revealed
    uint256 public notRevealedMinTokenID = 0; // Case2. not display between notRevealedMinTokenID and notRevealedMaxTokenID
    uint256 public notRevealedMaxTokenID = 0;

    uint256 public totalMintCount = 0;

    bool public useWhitelisted = false; // enable minting for a whitelisted address
    mapping(address => bool) private _whitelist; // Case1. use internal storage for whitelist
    // bytes32 public merkleRoot; // Case2. use Merkle Tree for whitelist (public Mint)
    bool public publicMintEnabled = false;
    // Case3. if you want to use Merkle Tree for whitelist, cheak a BORA721Mint

    mapping(address => bool) private _blacklist; // Prevention of illegal user activity
    mapping(uint256 => bool) private lockedStatusByTokenId; // Use for SBT (or) To prohibit sales in the market while in use in the game

    uint256 public maxCountTokensOfOwner = 100; // Only to avoid big gas costs or listing retrieval errors

    bool private _destroyFlag = false; // for only test

    struct PublicMintInfo {
        uint256[5] _publicMintPrice; // 1 ETH = 1000000000000000000
        uint256 _antibotInterval; // To prevent bot attack, we record the last contract call block number.
        mapping(address => uint256) _lastCallBlockNumber;
    }

    PublicMintInfo private publicMintInfo;

    struct ContractInfo {
        uint256 BappNo;
        string BappName;
        string SCVersion;
    }

    ContractInfo public contractInfo;

    constructor(string memory baseURI_, string memory contractURI_, string memory name, string memory symbol) ERC721(name, symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(SYSTEM_ROLE, msg.sender);

        _baseURIextended = baseURI_; // _setBaseURI(baseURI);
        notRevealedURI = baseURI_; // _setNotRevealURI(baseURI);
        _contractURI = contractURI_;

        contractInfo.BappNo = 1000;
        contractInfo.BappName = "BORA";
        contractInfo.SCVersion = "2.1.0";

        // Setting Accont For Test

        _destroyFlag = true;

        // addAdmin(0x507c5bAAE6DD008924b8754e4101510e131303b9);
        // addAdmin(0xf58451B68870f90DB17aCFB3954806DAe47058dE);

        // grantRole(PAUSER_ROLE, 0x764a118Aa7857f56ddD272725539b65Aa04083cB);        // Admin
        // grantRole(MINTER_ROLE, 0x7080de4124d5119B6054bD35bE9749EbcCa0E577);        // System + Mint + Burn
        // grantRole(SYSTEM_ROLE, 0xF64D9d628ECcdb9381cC18d7C819F45FE0786F5D);        // System

        _baseURIextended = "qq.com/metainfo/"; // _setBaseURI(baseURI);
        _contractURI = "qq.com/contract/"; // _setBaseURI(baseURI);

        publicMintEnabled = true;
        publicMintInfo._publicMintPrice = [1 * 1e18, 2 * 1e18, 3 * 1e18, 4 * 1e18, 5 * 1e18];
        publicMintInfo._antibotInterval = 1;

        // merkleRoot = 0xdd840fd7d7d47e5bebe8316b01acd281fd81832cdf1a0a2cd3eb0795b9ac32b2;
        // ["0x999bf57501565dbd2fdcea36efa2b9aef8340a8901e3459f4a4c926275d36cdb","0x04a10bfd00977f54cc3450c9b25c9b3a502a089eba0097ba35fc33c4ea5fcb54","0x766444319ac48c8f614a103c4029b3976fc55f641375a3836cf00fa03ebb0850"]
        // Test-91 : 0xFE6242Cdc31ac8BbD70edc5123945C384fA885e6 : d3d55a97855a22f9ac131a17823ddb6519f0893c057382dffacda4ce474e1e55
        // Test-92 : 0xCa92B755e6f81922885cD720Ea0Ba0c69d9fCF5d : 133654a8df4f8d63fba8c7a447249ce9f1c1e805e3e7eb34b3a35454cc14c712
        // Test-93 : 0xE1EB0035851D962fC6E3544abB575F0fE9F0E6fD : 421e7b72bc499b23af4f9a5969320926b1ec9d01d2f16a3a222bbccd06521ff8
        // Test-94 : 0x0A918626A1644210235D4fA68d99fFf02eD09501 : f8dbfbb02126e67cb27f20807de9c700efd8f6d33c342d7971dec207ff9a88c4
        // Test-95 : 0x1d309D16820AebB042D2fef96744a89f800Ae26b : 0eaf8d0de62d26bdb4afaebff353120e26bd40762d66c0cd92ec4f3ce3f68b5a
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function safeMint(address to, uint256 tokenId) public onlyRole(MINTER_ROLE) {
        safeMintWithUri(to, tokenId, "");
    }

    function safeMintWithUri(address to, uint256 tokenId, string memory uri) public onlyRole(MINTER_ROLE) {
        _mintInternal(to, tokenId, msg.sender, false, uri);
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256 batchSize) internal override(ERC721, ERC721Enumerable) whenNotPaused checkBlacklisted(from) checkBlacklisted(to) {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
    }

    // The following functions are overrides required by Solidity.

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, ERC721Enumerable, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: caller is not token owner or approved");
        ERC721URIStorage._burn(tokenId);
    }

    // ################################## BORA ##################################

    /* ========== VIEWs ========== */

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseURIextended;
    }

    function baseURI() external view returns (string memory) {
        return _baseURI();
    }

    function contractURI() external view returns (string memory) {
        return _contractURI;
    }

    function tokenURI(uint256 tokenId) public view override(ERC721, ERC721URIStorage) returns (string memory) {
        _requireMinted(tokenId);

        // Case10. display URI for all NFT when not Revealed
        if (revealed == false) {
            return notRevealedURI;
        }

        // Case20. not display between notRevealedMinTokenID and notRevealedMaxTokenID
        if ((tokenId >= notRevealedMinTokenID) && (tokenId <= notRevealedMaxTokenID)) {
            return notRevealedURI;
        }

        string memory tokenURI_ = _tokenURIs[tokenId];
        string memory baseURI_ = _baseURI();

        // Case31. baseURI_.len = 0, tokenURI_.len = 0 : return ""                                        : If there is no base URI, no token URI
        // Case32. baseURI_.len = 0, tokenURI_.len > 0 : return tokenURI_                                 : If there is no base URI, return the token URI
        // Case33. baseURI_.len > 0, tokenURI_.len > 0 : return string(_base + tokenURI_)                 : If both are set, concatenate the baseURI and tokenURI (via abi.encodePacked).
        // Case34. baseURI_.len > 0, tokenURI_.len = 0 : return string(_base + tokenId + tokenURISuffix)  : If there is a baseURI but no tokenURI, concatenate the tokenID to the baseURI.

        if ((bytes(baseURI_).length == 0) && (bytes(tokenURI_).length == 0)) {
            // Case31
            return "";
        } else if (bytes(baseURI_).length == 0) {
            // Case32
            return tokenURI_;
        } else if (bytes(tokenURI_).length > 0) {
            // Case33
            return string(abi.encodePacked(baseURI_, tokenURI_));
        } else {
            return string(abi.encodePacked(baseURI_, Strings.toString(tokenId), tokenURISuffix));
        }
    }

    function tokenURIStorage(uint256 tokenId) external view onlySystem returns (uint256, string memory) {
        string memory tokenURI_ = _tokenURIs[tokenId];
        return (bytes(tokenURI_).length, tokenURI_);
    }

    // @dev SBT : https://eips.ethereum.org/EIPS/eip-5192

    function locked(uint256 tokenId) external view returns (bool) {
        return lockedStatusByTokenId[tokenId];
    }

    function getPublicMintInfo() external view onlySystem returns (bool, uint256[5] memory, uint256) {
        return (publicMintEnabled, publicMintInfo._publicMintPrice, publicMintInfo._antibotInterval);
    }

    function getPublicMintlastCallBlockNumber(address account) external view onlySystem returns (uint256) {
        return publicMintInfo._lastCallBlockNumber[account];
    }

    /* ========== FUNCTIONS ========== */

    function transferFrom(address from, address to, uint256 tokenId) public override whenTokenNotLocked(tokenId) {
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public override whenTokenNotLocked(tokenId) {
        super.safeTransferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public override whenTokenNotLocked(tokenId) {
        super.safeTransferFrom(from, to, tokenId, _data);
    }

    function transferMultipleTokens(address[] memory from, address[] memory to, uint256[] memory tokenIds) public {
        require(from.length == to.length && to.length == tokenIds.length, "BORA721: Input arrays must be the same length");

        for (uint256 i = 0; i < tokenIds.length; i++) {
            safeTransferFrom(from[i], to[i], tokenIds[i]);
        }
    }

    function _mintInternal(address to, uint256 tokenId, address msgSender, bool checkBotInterval, string memory uri) internal nonReentrant checkWhitelisted(to) returns (bool) {
        if (bytes(uri).length == 0) {
            _safeMint(to, tokenId);
        } else {
            _safeMint(to, tokenId);
            _setTokenURI(tokenId, uri);
        }

        incrementMintCount();

        if (checkBotInterval) {
            publicMintInfo._lastCallBlockNumber[msgSender] = block.number;
        }
        emit Mint(to, tokenId, msgSender);
        return true;
    }

    function mint(address to, uint256 tokenId) public onlyRole(MINTER_ROLE) returns (bool) {
        return _mintInternal(to, tokenId, msg.sender, false, "");
    }

    function mintWithUri(address to, uint256 tokenId, string memory uri) public onlyRole(MINTER_ROLE) returns (bool) {
        return _mintInternal(to, tokenId, msg.sender, false, uri);
    }

    function mintMultipleTokens(address[] memory to, uint256[] memory tokenIds) public returns (bool) {
        require(to.length == tokenIds.length, "BORA721: Input arrays must be the same length");
        for (uint256 i = 0; i < to.length; i++) {
            mint(to[i], tokenIds[i]);
        }
        return true;
    }

    function mintMultipleTokensWithUri(address[] memory receivers, uint256[] memory tokenIds, string[] memory uris) public returns (bool) {
        require(receivers.length == tokenIds.length && tokenIds.length == uris.length, "BORA721: Input arrays must be the same length");

        for (uint256 i = 0; i < receivers.length; i++) {
            mintWithUri(receivers[i], tokenIds[i], uris[i]);
        }
        return true;
    }

    function incrementMintCount() internal {
        totalMintCount++;
    }

    function burn(uint256 tokenId) public {
        _burn(tokenId);
        emit Burn(tokenId, _msgSender());
    }

    function burnMultipleTokens(uint256[] memory tokenIds) public returns (bool) {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            burn(tokenIds[i]);
        }
        return true;
    }

    function tokensOfOwner(address owner) external view returns (uint256[] memory) {
        uint256 count = balanceOf(owner);
        require(count <= maxCountTokensOfOwner, "BORA721: Can't get a token list. Check a maxCountTokensOfOwner!");
        uint256[] memory List = new uint256[](count);

        for (uint256 i = 0; i < count; i++) {
            List[i] = tokenOfOwnerByIndex(owner, i);
        }
        return List;
    }

    function clearApproval(uint256 tokenId) public {
        super.approve(address(0), tokenId);
    }

    function isApprovedForAll(address owner, address operator) public view override returns (bool) {
        if (operator == this.owner() || hasRole(SYSTEM_ROLE, operator)) {
            return true;
        }
        return super.isApprovedForAll(owner, operator);
    }

    /* ========== FUNCTIONS : Setting ========== */

    function setContractURI(string memory uri) external onlySystem {
        _contractURI = uri;
    }

    function setBaseURI(string memory uri) external onlySystem {
        _baseURIextended = uri;
    }

    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal virtual override {
        _requireMinted(tokenId);
        if (bytes(_tokenURI).length > 0) {
            _tokenURIs[tokenId] = _tokenURI;
        }
    }

    function setTokenURI(uint256 tokenId, string memory _tokenURI) public onlySystem {
        _setTokenURI(tokenId, _tokenURI);
    }

    function removeTokenURI(uint256 tokenId) public onlySystem {
        delete _tokenURIs[tokenId];
    }

    function setTokenURISuffix(string memory suffix) external onlySystem {
        tokenURISuffix = suffix;
    }

    function setRevealed(bool flag) external onlySystem {
        require(revealed != flag, "BORA721: revealed flag already setted.");
        revealed = flag;
    }

    function setNotRevealURI(string memory uri) external onlySystem {
        notRevealedURI = uri;
    }

    function setNotRevealedTokenIdScope(uint256 minIndex, uint256 maxIndex) external onlySystem {
        require(minIndex <= maxIndex, "BORA721: notRevealedTokenID index is the error");
        notRevealedMinTokenID = minIndex;
        notRevealedMaxTokenID = maxIndex;
    }

    function setBlacklist(address _account, bool flag) public onlySystem returns (bool) {
        _blacklist[_account] = flag;
        emit BlacklistUpdated(_account, flag, block.timestamp);
        return true;
    }

    function setMultipleBlacklist(address[] memory _accountList, bool flag) external onlySystem returns (bool) {
        for (uint256 i = 0; i < _accountList.length; i++) {
            setBlacklist(_accountList[i], flag);
        }
        return true;
    }

    function setUseWhitelisted(bool flag) external onlySystem {
        require(useWhitelisted != flag, "BORA721: Status is already set to the desired state");
        useWhitelisted = flag;
        emit UseWhitelistedStatusChanged(_msgSender(), useWhitelisted);
    }

    function setWhitelist(address _account, bool flag) public onlySystem returns (bool) {
        _whitelist[_account] = flag;
        emit WhitelistUpdated(_account, flag, block.timestamp);
        return true;
    }

    function setMultipleWhitelist(address[] memory _accountList, bool flag) external onlySystem returns (bool) {
        for (uint256 i = 0; i < _accountList.length; i++) {
            setWhitelist(_accountList[i], flag);
        }
        return true;
    }

    function setPublicMintEnabled(bool useFlag) public onlySystem returns (bool) {
        publicMintEnabled = useFlag;
        return true;
    }

    function setPublicMintConfig(uint256 _antibotInterval, uint256[5] memory _publicMintPrice) public onlySystem returns (bool) {
        publicMintInfo._antibotInterval = _antibotInterval;
        publicMintInfo._publicMintPrice = _publicMintPrice;
        return true;
    }

    function setMaxCountTokensOfOwner(uint256 _maxCount) external onlySystem returns (bool) {
        maxCountTokensOfOwner = _maxCount;
        return true;
    }

    function changeTokenLockedState(uint256 tokenId, bool flag) external onlySystem {
        _requireMinted(tokenId);
        require(lockedStatusByTokenId[tokenId] != flag, "BORA721: Locked status of token is already set to the desired state");
        lockedStatusByTokenId[tokenId] = flag;

        // if(flag) {
        //     emit Locked(tokenId); // EIP-5192: Minimal Soulbound NFTs
        // } else {
        //     emit Unlocked(tokenId); // EIP-5192: Minimal Soulbound NFTs
        // }
        emit TokenLockedStatusChanged(tokenId, flag);
    }

    /* ========== FUNCTIONS : publicMint ========== */

    // Type 1. use Mapping

    function publicMint(uint256 tokenId, uint256 kind) public payable checkWhitelisted(msg.sender) checkPublicMintCondition(msg.sender, kind, msg.value) returns (bool) {
        return publicMintWithUri(tokenId, kind, "");
    }

    function publicMintWithUri(uint256 tokenId, uint256 kind, string memory uri) public payable checkWhitelisted(msg.sender) checkPublicMintCondition(msg.sender, kind, msg.value) returns (bool) {
        return _mintInternal(msg.sender, tokenId, msg.sender, true, uri);
    }

    // Type 2. use Merkle Tree

    // function setMerkleRoot(bytes32 _merkleRoot) public onlySystem returns (bool) {
    //     merkleRoot = _merkleRoot;
    //     return true;
    // }

    // function publicMintMtree(uint256 tokenId, uint kind, bytes32[] calldata merkleProof) external payable checkBlacklisted(msg.sender) checkPublicMintCondition(msg.sender, kind, msg.value) returns (bool) {
    //     bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
    //     require(MerkleProof.verify(merkleProof, merkleRoot, leaf) == true, "BORA721: Invalid merkle proof");
    //     _mintInternal(msg.sender, tokenId, msg.sender, true, "");
    //     return true;
    // }

    // function publicMintWithUriMtree(uint256 tokenId, uint kind, string calldata uri, bytes32[] calldata merkleProof) external payable checkBlacklisted(msg.sender) checkPublicMintCondition(msg.sender, kind, msg.value) returns (bool) {
    //     bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
    //     require(MerkleProof.verify(merkleProof, merkleRoot, leaf) == true, "BORA721: Invalid merkle proof");
    //     _mintInternal(msg.sender, tokenId, msg.sender, true, uri);
    //     return true;
    // }

    /* ========== RESTRICTED FUNCTIONS ========== */

    function addAdmin(address _account) public onlyOwnerOrAdmin returns (bool) {
        require(_account != address(0), "BORA721: add admin of the zero address");
        grantRole(DEFAULT_ADMIN_ROLE, _account); // Admin
        grantRole(PAUSER_ROLE, _account); // Admin
        grantRole(MINTER_ROLE, _account); // System + Mint + Burn
        grantRole(SYSTEM_ROLE, _account); // System
        emit RoleChanged("addAdmin", _msgSender(), _account, block.timestamp);
        return true;
    }

    function renounceAdmin() public onlyOwnerOrAdmin returns (bool) {
        return revokeAdmin(_msgSender());
    }

    function revokeAdmin(address _account) public onlyOwnerOrAdmin returns (bool) {
        require(_account != owner(), "BORA721: Owner can't revoke AdminRole");
        revokeRole(PAUSER_ROLE, _account); // Admin
        revokeRole(MINTER_ROLE, _account); // System + Mint + Burn
        revokeRole(SYSTEM_ROLE, _account); // System
        revokeRole(DEFAULT_ADMIN_ROLE, _account); // Admin
        emit RoleChanged("revokeAdmin", _msgSender(), _account, block.timestamp);
        return true;
    }

    function removeAdmin(address _account) public onlyOwnerOrAdmin returns (bool) {
        // for compatibility
        return revokeAdmin(_account);
    }

    function contractBalance() external view onlySystem returns (uint256) {
        return (address(this).balance);
    }

    function contractBalance(address _tokenAddr) external view onlySystem returns (uint256, uint256) {
        return (address(this).balance, IERC20(_tokenAddr).balanceOf(address(this)));
    }

    function withdraw() external onlySystem returns (bool) {
        // This will transfer the remaining contract balance to the owner.
        // Do not remove this otherwise you will not be able to withdraw the funds.
        uint256 _balance = address(this).balance;
        require(_balance > 0, "BORA721: Don't have a balance.");
        payable(owner()).transfer(_balance);
        emit Withdraw(owner(), _balance, block.timestamp);
        return true;
    }

    function withdrawToken(address _tokenAddr) public onlySystem returns (bool) {
        uint256 _balance = IERC20(_tokenAddr).balanceOf(address(this));
        require(_balance > 0, "BORA721: Don't have a balance.");
        IERC20(_tokenAddr).transfer(owner(), _balance);
        emit WithdrawToken(_tokenAddr, owner(), _balance, block.timestamp);
        return true;
    }

    function setDestroyFlag(bool destroyFlag) public onlyOwner {
        _destroyFlag = destroyFlag;
    }

    function destroy() public onlyOwner {
        require(_destroyFlag, "BORA721: _destroyFlag is false");
        selfdestruct(payable(msg.sender));
    }

    function isTokenLocked(uint256 tokenId) external view returns (bool) {
        _requireMinted(tokenId);
        return lockedStatusByTokenId[tokenId];
    }

    function isBlacklisted(address _account) public view returns (bool) {
        return _blacklist[_account];
    }

    function isWhitelisted(address _account) public view returns (bool) {
        if (useWhitelisted) {
            return _whitelist[_account];
        }
        return true;
    }

    function isOwner() public view returns (bool) {
        return owner() == msg.sender;
    }

    function isOwnerOrAdmin() public view returns (bool) {
        return isOwner() || hasRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function isSystem() public view returns (bool) {
        return isOwnerOrAdmin() || hasRole(SYSTEM_ROLE, msg.sender);
    }

    /* ========== MODIFIER ========== */

    modifier onlyOwnerOrAdmin() {
        require(isOwnerOrAdmin(), "BORA721: Must be contract owner or have admin authority");
        _;
    }

    modifier onlySystem() {
        require(isSystem(), "BORA721: Must be system authority");
        _;
    }

    modifier checkBlacklisted(address _account) {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || !isBlacklisted(_account), "BORA721: Address is a blacklisted address");
        _;
    }

    modifier checkWhitelisted(address _account) {
        require(isWhitelisted(_account), "BORA721: Address is not a whitelisted address");
        _;
    }

    modifier whenTokenNotLocked(uint256 tokenId) {
        require(!lockedStatusByTokenId[tokenId] || isOwnerOrAdmin(), "BORA721: Token is currently locked. Caller must be the contract owner or have admin authority");
        _;
    }

    modifier checkPublicMintCondition(
        address _account,
        uint256 _kind,
        uint256 _amount
    ) {
        require(publicMintEnabled, "BORA721: The public sale is not enabled.");
        require(publicMintInfo._lastCallBlockNumber[_account] + publicMintInfo._antibotInterval < block.number, "BORA721: Bot is not allowed!");
        require(publicMintInfo._publicMintPrice[_kind] != 0, "BORA721: Invalid price!");
        require(_amount == publicMintInfo._publicMintPrice[_kind], "BORA721: Not enough Token for buy!");
        _;
    }

    /* ========== EVENTS ========== */

    event RoleChanged(string indexed role, address indexed granter, address indexed grantee, uint256 logTime);
    event WhitelistUpdated(address indexed account, bool isWhitelist, uint256 logTime);
    event BlacklistUpdated(address indexed account, bool isBlacklist, uint256 logTime);
    event Mint(address indexed mintedTo, uint256 indexed tokenId, address indexed minter);
    event Burn(uint256 indexed tokenId, address indexed burner);
    event UseWhitelistedStatusChanged(address indexed operatorAddress, bool useWhitelisted);
    event Withdraw(address indexed receiver, uint256 amount, uint256 logTime);
    event WithdrawToken(address indexed token, address indexed receiver, uint256 amount, uint256 logTime);
    //event Locked(uint256 tokenId); // EIP-5192: Minimal Soulbound NFTs
    //event Unlocked(uint256 tokenId); // EIP-5192: Minimal Soulbound NFTs
    event TokenLockedStatusChanged(uint256 indexed tokenId, bool hasBeenLocked);
}
