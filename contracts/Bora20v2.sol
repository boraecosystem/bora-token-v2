// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0)

pragma solidity 0.8.9;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";

interface IBoraV2FeeCalculate {
    // function calcAmount(uint256 amount) external view returns (uint256, uint256);
    // function calcAmount(uint256 amount, uint256 _feeRatio) external pure returns (uint256, uint256);
    function calcAmount(uint256 amount, address from, address to, bytes32 _feeInfo) external view returns (uint256, uint256, address, bool);
}

interface IBoraV2FeeDistributor {
    function distributeFees() external returns (bool);
}

contract LockedToken {
    using SafeERC20 for IERC20;
    IERC20 private _token;
    address public immutable donor;
    address public immutable beneficiary;
    uint256 public immutable releaseTime;
    bool public immutable revocable;
    address public immutable system;

    event Claim(address beneficiary, uint256 amount, uint256 releaseTime);
    event Revoke(address donor, uint256 amount);

    constructor(address pToken, address pDonor, address pBeneficiary, uint256 pReleaseTime, bool pRevocable, address pSystem) {
        // require(address(token) != address(0), "LockedToken: token is zero address");
        require(pDonor != address(0), "LockedToken: donor is zero address");
        require(pBeneficiary != address(0), "LockedToken: beneficiary is zero address");
        require(pSystem != address(0), "LockedToken: system is zero address");
        require(pReleaseTime > block.timestamp, "LockedToken: release time is before current time");

        _token = IERC20(pToken);
        donor = pDonor;
        beneficiary = pBeneficiary;
        releaseTime = pReleaseTime;
        revocable = pRevocable;
        system = pSystem;
    }

    function token() public view returns (IERC20) {
        return _token;
    }

    function balanceOf() public view returns (uint256) {
        return _token.balanceOf(address(this));
    }

    function getInfo() external view returns (address, address, uint256, bool, uint256, address) {
        return (donor, beneficiary, releaseTime, revocable, _token.balanceOf(address(this)), system);
    }

    function revoke() public {
        require(revocable, "LockedToken: tokens are not revocable");
        require((msg.sender == donor) || (msg.sender == system), "LockedToken: only donor|system can revoke");

        uint256 amount = _token.balanceOf(address(this));
        require(amount > 0, "LockedToken: no tokens to revoke");

        _token.safeTransfer(donor, amount);
        emit Revoke(donor, amount);
    }

    // claim is intended to be called by anyone after the release time, because the beneficiary is already claimed and cannot be changed.
    function claim() public {
        require(block.timestamp >= releaseTime, "LockedToken: current time is before release time");

        uint256 amount = _token.balanceOf(address(this));
        require(amount > 0, "LockedToken: no tokens to claim");

        _token.safeTransfer(beneficiary, amount);
        emit Claim(beneficiary, amount, releaseTime);
    }
}

contract Bora20v2 is ERC20, ERC20Burnable, AccessControl, Pausable, Ownable, ERC20Permit {
    using SafeERC20 for IERC20;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant SYSTEM_ROLE = keccak256("SYSTEM_ROLE");

    // bytes32 public constant CALL_TRANS = keccak256("CALL_TRANS");
    // bytes32 public constant CALL_MINT = keccak256("CALL_MINT");

    uint256 private _totalSupplyCap; // refer : ERC20Capped.sol

    mapping(address => bool) private _blacklist;
    bool public useWhitelisted = false;
    mapping(address => bool) private _whitelist;

    struct FeeStruct {
        bool isSet; // false : fee = 0, true : apply fee
        bool isInnerLogic; // Location a Fee Calculate logic : true=internal, false=external
        uint256 feeRatio; // for Internal (100% = 10000, 50% = 5000, 10% = 1000, 1% = 100, 0.1% = 10, 0.01% = 1)
        address feeCalcAddress; // for External : BoraV2FeeCalculate Smart Contract Address
        bytes32 feeCalcCallBytes; // for External : BoraV2FeeCalculate Call Command Bytes
        address feeReceiver; // Fee Receiver Address
        bool isFeeReceiverContract; // in case of the Fee Receiver Address is contract ( calls feeDistributor.distributeFees() )
        uint256 lastUpdated;
    }

    struct FeeDistStruct {
        uint256 amount;
        uint256 fee;
        address feeReceiver;
        bool isDistributor;
    }

    FeeStruct public transFeeInfo;
    FeeStruct public mintFeeInfo;

    struct TransferStruct {
        uint256 oneTimeMaxAmount; // max amount per transferation
        uint256 oneDayMaxAmount; // max transfer amount per day
        uint256 oneDayUnit; // 86400 = 1 day (for Test, 3600 = 1 hour)
        uint256 currentDay; // use block.timestamp.div(oneDayUnit) to check current day
        uint256 currentDayAmount; // transfer amount of current day
    }

    TransferStruct public transferInfo;
    TransferStruct public mintInfo;

    bool private _destroyFlag = false; // for test only!

    struct ContractInfo {
        uint256 BappNo;
        string BappName;
        string SCVersion;
    }

    ContractInfo public contractInfo;

    constructor(uint256 initialSupply, string memory name, string memory symbol) ERC20(name, symbol) ERC20Permit(name) {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender()); // Admin
        _grantRole(PAUSER_ROLE, _msgSender()); // Admin
        _grantRole(MINTER_ROLE, _msgSender()); // System + Mint + Burn
        _grantRole(SYSTEM_ROLE, _msgSender()); // System

        mintInfo.oneTimeMaxAmount = 99999999999999999999 * 10 ** decimals();
        mintInfo.oneDayMaxAmount = 99999999999999999999 * 10 ** decimals();
        mintInfo.oneDayUnit = 86400;

        transFeeInfo.isSet = false;
        mintFeeInfo.isSet = false;

        uint256 mintAmount = initialSupply > 0 ? initialSupply : 1205750000 * 10 ** decimals();
        _totalSupplyCap = mintAmount;
        _mint(_msgSender(), mintAmount);
        emit SupplyChanged("MINT", _msgSender(), mintAmount, totalSupply(), block.timestamp);

        mintInfo.oneTimeMaxAmount = 1000000 * 10 ** decimals();
        mintInfo.oneDayMaxAmount = 500000 * 10 ** decimals();
        mintInfo.currentDayAmount = 0;
        emit MintInfoChanged(_msgSender(), mintInfo.oneTimeMaxAmount, mintInfo.oneDayMaxAmount, mintInfo.oneDayUnit, block.timestamp);

        transferInfo.oneTimeMaxAmount = 1000000 * 10 ** decimals();
        transferInfo.oneDayMaxAmount = 500000 * 10 ** decimals();
        transferInfo.oneDayUnit = 86400;
        transferInfo.currentDayAmount = 0;
        emit TransferInfoChanged(_msgSender(), transferInfo.oneTimeMaxAmount, transferInfo.oneDayMaxAmount, transferInfo.oneDayUnit, block.timestamp);

        contractInfo.BappNo = 1000;
        contractInfo.BappName = name;
        contractInfo.SCVersion = "2.1.0";

        // Setting Account For Test

        // addAdmin(0x507c5bAAE6DD008924b8754e4101510e131303b9);
        // addAdmin(0xf58451B68870f90DB17aCFB3954806DAe47058dE);

        // grantRole(PAUSER_ROLE, 0x764a118Aa7857f56ddD272725539b65Aa04083cB);        // Admin
        // grantRole(MINTER_ROLE, 0x7080de4124d5119B6054bD35bE9749EbcCa0E577);        // System + Mint + Burn
        // grantRole(SYSTEM_ROLE, 0xF64D9d628ECcdb9381cC18d7C819F45FE0786F5D);        // System

        // transfer(0x507c5bAAE6DD008924b8754e4101510e131303b9, 100 * 10**18);
        // transfer(0xf58451B68870f90DB17aCFB3954806DAe47058dE, 100 * 10**18);
        // transfer(0x764a118Aa7857f56ddD272725539b65Aa04083cB, 100 * 10**18);
        // transfer(0x7080de4124d5119B6054bD35bE9749EbcCa0E577, 100 * 10**18);
        // transfer(0xF64D9d628ECcdb9381cC18d7C819F45FE0786F5D, 100 * 10**18);
        // transfer(0xA68a0b5b8F0521c8f9B39feC45FF1C39D3Be5259, 100 * 10**18);

        // _destroyFlag = true;
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function transferInternal(address from, address to, uint256 amount) private whenNotPaused returns (bool) {
        if (!transFeeInfo.isSet) {
            // if transFeeInfo is not setted
            _transfer(from, to, amount);
        } else {
            FeeDistStruct memory _feeDist = _calcFeeDistribution(transFeeInfo, amount, from, to);
            _transfer(from, to, _feeDist.amount);

            if (_feeDist.fee > 0) {
                _transfer(from, _feeDist.feeReceiver, _feeDist.fee);
                // if (Address.isContract(transFeeInfo.feeReceiver)) {
                //     IBoraV2FeeDistributor(transFeeInfo.feeReceiver).distributeFees();
                // }
                if (_feeDist.isDistributor) {
                    require(IBoraV2FeeDistributor(_feeDist.feeReceiver).distributeFees(), "BORA: failed to distribute fees");
                }
            }
        }
        return true;
    }

    function transfer(address to, uint256 amount) public override whenNotPaused checkWhitelisted(to) returns (bool) {
        return transferInternal(_msgSender(), to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override whenNotPaused checkWhitelisted(to) returns (bool) {
        _spendAllowance(from, _msgSender(), amount);
        return transferInternal(from, to, amount);
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) checkBlacklisted(to) {
        require(totalSupply() + amount <= totalSupplyCap(), "ERC20Capped: totalSupplyCap exceeded"); // refer : ERC20Capped.sol

        FeeDistStruct memory _feeDist;
        uint256 _nowDatetime = block.timestamp;

        if (!mintFeeInfo.isSet) {
            // if mintFeeInfo is not setted
            _feeDist.amount = amount;
            _mint(to, _feeDist.amount);
        } else {
            _feeDist = _calcFeeDistribution(mintFeeInfo, amount, _msgSender(), to);
            _mint(to, _feeDist.amount);

            if (_feeDist.fee > 0) {
                _mint(_feeDist.feeReceiver, _feeDist.fee);
                emit SupplyChanged("MINT", _feeDist.feeReceiver, _feeDist.fee, totalSupply(), _nowDatetime);
                if (_feeDist.isDistributor) {
                    IBoraV2FeeDistributor(_feeDist.feeReceiver).distributeFees();
                }
            }
        }
        emit SupplyChanged("MINT", to, _feeDist.amount, totalSupply(), _nowDatetime);
    }

    function burnBySystem(address account, uint256 amount) public onlyRole(SYSTEM_ROLE) {
        _burn(account, amount);
        emit SupplyChanged("BURN", account, amount, totalSupply(), block.timestamp);
    }

    function burn(uint256 amount) public override onlyRole(MINTER_ROLE) {
        ERC20Burnable.burn(amount);
        emit SupplyChanged("BURN", _msgSender(), amount, totalSupply(), block.timestamp);
    }

    function burnFrom(address account, uint256 amount) public override onlyRole(MINTER_ROLE) {
        ERC20Burnable.burnFrom(account, amount);
        emit SupplyChanged("BURN.FROM", account, amount, totalSupply(), block.timestamp);
    }

    /**
     * @dev Hook that is called before any transfer of tokens. This includes minting and burning. (+ transferFrom())
     *
     * Calling conditions:
     * - transfer : _beforeTokenTransfer(from, to, amount);  [when `from` and `to` are both non-zero]
     * - mint     : _beforeTokenTransfer(address(0), account, amount);
     * - burn     : _beforeTokenTransfer(account, address(0), amount);
     *
     * override : ERC20Pausable.sol
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override whenNotPaused checkBlacklisted(from) {
        super._beforeTokenTransfer(from, to, amount);

        if (to != address(0)) {
            TransferStruct storage _transferInfo = from != address(0) ? transferInfo : mintInfo;
            require(amount <= _transferInfo.oneTimeMaxAmount, "BORA: one time transfer limit exceeded");
            _checkDayMaxAmount(_transferInfo, amount);
            //"BORA: Can't transfer any more !! (oneDayMaxAmount)");
        }
    }

    /* ========== VIEWS ========== */
    function _calcFeeDistribution(FeeStruct memory feeInfo, uint256 amount, address from, address to) internal view returns (FeeDistStruct memory feeDist) {
        if (feeInfo.isSet) {
            if (feeInfo.isInnerLogic) {
                // (feeInfo.isSet=true && feeInfo.isInnerLogic=true) : use a internal logic
                (feeDist.amount, feeDist.fee) = _calcAmount(amount, feeInfo.feeRatio);
                feeDist.feeReceiver = feeInfo.feeReceiver;
                feeDist.isDistributor = feeInfo.isFeeReceiverContract;
            } else {
                // (feeInfo.isSet=true && feeInfo.isInnerLogic=false) : use a external logic
                (feeDist.amount, feeDist.fee, feeDist.feeReceiver, feeDist.isDistributor) = IBoraV2FeeCalculate(feeInfo.feeCalcAddress).calcAmount(amount, from, to, feeInfo.feeCalcCallBytes);
            }
        } else {
            feeDist.amount = amount;
        }

        return feeDist;
    }

    function _calcAmount(uint256 amount, uint256 feeRatio) internal pure returns (uint256, uint256) {
        uint256 _fee = (amount * feeRatio) / 10000;
        uint256 _amount = amount - _fee;
        return (_amount, _fee);
    }

    function _checkDayMaxAmount(TransferStruct storage _limit, uint256 amount) internal {
        uint256 nowDayTime = block.timestamp / _limit.oneDayUnit;
        if (_limit.currentDay != nowDayTime) {
            _limit.currentDay = nowDayTime;
            _limit.currentDayAmount = 0;
        }
        uint256 checkAmount = _limit.currentDayAmount + amount;
        require(checkAmount <= _limit.oneDayMaxAmount, "BORA: one day transfer limit exceeded");
        _limit.currentDayAmount = checkAmount;
    }

    function isWhitelisted(address _account) public view returns (bool) {
        if (useWhitelisted) {
            return _whitelist[_account];
        }
        return true;
    }

    function isBlacklisted(address account) public view returns (bool) {
        return _blacklist[account];
    }

    function setUseWhitelisted(bool flag) external onlyRole(SYSTEM_ROLE) {
        require(useWhitelisted != flag, "BORA: Status is already set to the desired state");
        useWhitelisted = flag;
        emit UseWhitelistedStatusChanged(_msgSender(), useWhitelisted);
    }

    function setWhitelist(address _account, bool flag) public onlyRole(SYSTEM_ROLE) returns (bool) {
        _whitelist[_account] = flag;
        emit WhitelistUpdated(_account, flag, block.timestamp);
        return true;
    }

    function setMultipleWhitelist(address[] memory _accountList, bool flag) external onlyRole(SYSTEM_ROLE) returns (bool) {
        for (uint256 i = 0; i < _accountList.length; i++) {
            setWhitelist(_accountList[i], flag);
        }
        return true;
    }

    function totalSupplyCap() public view returns (uint256) {
        return _totalSupplyCap;
    }

    function utilDiffTime(uint256 _checkTimestamp) public view returns (uint256, uint256) {
        require(_checkTimestamp > block.timestamp, "BORA: checkTime is before current time");
        uint256 nowDayTime = block.timestamp;
        uint256 chkDayTime = _checkTimestamp;
        uint256 nowDay = nowDayTime / 86400;
        uint256 chkDay = chkDayTime / 86400;
        return (chkDay - nowDay, chkDayTime - nowDayTime);
    }

    function utilDiffTime2(uint256 _timestamp1, uint256 _timestamp2) external pure returns (uint256, uint256) {
        require(_timestamp2 >= _timestamp1, "BORA: _timestamp2 is before _timestamp1");
        uint256 chkDay1 = _timestamp1 / 86400;
        uint256 chkDay2 = _timestamp2 / 86400;
        return (chkDay2 - chkDay1, _timestamp2 - _timestamp1);
    }

    function utilUnitConvert(uint256 _value) external pure returns (uint256, uint256, uint256) {
        return (_value, _value * 10 ** 9, _value * 10 ** 18);
    }

    function tokenLockInfo(LockedToken _lockToken) external view returns (address, address, address, uint256, bool, uint256, uint256) {
        uint256 _diffDay;
        (_diffDay, ) = utilDiffTime(_lockToken.releaseTime());
        return (address(_lockToken.token()), _lockToken.donor(), _lockToken.beneficiary(), _lockToken.releaseTime(), _lockToken.revocable(), _lockToken.balanceOf(), _diffDay);
    }

    /* ========== FUNCTIONS ========== */

    function multiTransfers(address[] memory recipients, uint256[] memory amount) public returns (bool) {
        require(recipients.length == amount.length, "BORA: Input arrays must be the same length");
        for (uint256 i = 0; i < recipients.length; i++) {
            require(transfer(recipients[i], amount[i]), "BORA: failed to transfer");
        }
        return true;
    }

    function multiTransferFroms(address[] memory senders, address[] memory recipients, uint256[] memory amount) public returns (bool) {
        require(senders.length == recipients.length && recipients.length == amount.length, "BORA: Input arrays must be the same length");
        for (uint256 i = 0; i < senders.length; i++) {
            require(transferFrom(senders[i], recipients[i], amount[i]), "BORA: failed to transfer");
        }
        return true;
    }

    function tokenLock(address _donor, address _beneficiary, uint256 _amount, uint256 _duration, uint256 _durationUnit, bool _revocable) public onlyRole(SYSTEM_ROLE) returns (LockedToken) {
        uint256 releaseTime = block.timestamp + (_duration * _durationUnit);
        LockedToken lockedToken = new LockedToken(address(this), _donor, _beneficiary, releaseTime, _revocable, address(this));
        transferInternal(_msgSender(), address(lockedToken), _amount);
        emit TokenLock(address(lockedToken), _donor, _beneficiary, lockedToken.balanceOf(), releaseTime, _revocable, address(this), block.timestamp);
        return lockedToken;
    }

    function tokenLockClaim(LockedToken _lockToken) public {
        _lockToken.claim();
    }

    function multiTokenLockClaim(LockedToken[] memory _lockToken) external {
        for (uint256 i = 0; i < _lockToken.length; i++) {
            tokenLockClaim(_lockToken[i]);
        }
    }

    function tokenLockRevoke(LockedToken _lockToken) public onlyRole(SYSTEM_ROLE) {
        _lockToken.revoke();
    }

    function multiTokenLockRevoke(LockedToken[] memory _lockToken) external onlyRole(SYSTEM_ROLE) {
        for (uint256 i = 0; i < _lockToken.length; i++) {
            tokenLockRevoke(_lockToken[i]);
        }
    }

    /* ========== FUNCTIONS : Setting ========== */

    function setMintInfo(uint256 _oneTimeMaxAmount, uint256 _oneDayMaxAmount, uint256 _oneDayUnit) external onlyRole(SYSTEM_ROLE) returns (bool) {
        mintInfo.oneTimeMaxAmount = _oneTimeMaxAmount;
        mintInfo.oneDayMaxAmount = _oneDayMaxAmount;
        mintInfo.oneDayUnit = _oneDayUnit;
        emit MintInfoChanged(_msgSender(), _oneTimeMaxAmount, _oneDayMaxAmount, _oneDayUnit, block.timestamp);
        return true;
    }

    function setTransferInfo(uint256 _oneTimeMaxAmount, uint256 _oneDayMaxAmount, uint256 _oneDayUnit) external onlyRole(SYSTEM_ROLE) returns (bool) {
        transferInfo.oneTimeMaxAmount = _oneTimeMaxAmount;
        transferInfo.oneDayMaxAmount = _oneDayMaxAmount;
        transferInfo.oneDayUnit = _oneDayUnit;
        emit TransferInfoChanged(_msgSender(), _oneTimeMaxAmount, _oneDayMaxAmount, _oneDayUnit, block.timestamp);
        return true;
    }

    function setContractInfo(uint256 _bappNo, string calldata _bappName, string calldata _scVersion) external onlyRole(SYSTEM_ROLE) returns (bool) {
        contractInfo.BappNo = _bappNo;
        contractInfo.BappName = _bappName;
        contractInfo.SCVersion = _scVersion;
        return true;
    }

    function setBlacklist(address _account, bool _isBlacklist) external onlyRole(SYSTEM_ROLE) returns (bool) {
        _blacklist[_account] = _isBlacklist;
        emit BlacklistUpdated(_account, _isBlacklist, block.timestamp);
        return true;
    }

    function setTotalSupplyCap(uint256 _supplyCap) external onlyRole(SYSTEM_ROLE) returns (bool) {
        _totalSupplyCap = _supplyCap;
        emit CapChanged(_msgSender(), _supplyCap, block.timestamp);
        return true;
    }

    function setFeeInfoForTransfer(bool _isSet, bool _isInnerLogic, uint256 _feeRatio, address _feeCalcAddress, bytes32 _feeCalcCallBytes, address _feeReceiver, bool _isFeeReceiverContract) external onlyRole(SYSTEM_ROLE) returns (bool) {
        require(_feeRatio <= 5000, "BORA: Check a fee ratio (0~5000, 50%)");
        transFeeInfo.isSet = _isSet; // false : fee = 0, true : apply fee
        transFeeInfo.isInnerLogic = _isInnerLogic; // Location a Fee Calculate logic : true=internal, false=external
        transFeeInfo.feeRatio = _feeRatio; // for Internal (100% = 10000, 50% = 5000, 10% = 1000, 1% = 100, 0.1% = 10, 0.01% = 1)
        transFeeInfo.feeCalcAddress = _feeCalcAddress; // for External : BoraV2FeeCalculate Smart Contract Address
        transFeeInfo.feeCalcCallBytes = _feeCalcCallBytes; // for External : BoraV2FeeCalculate Call Command Bytes
        transFeeInfo.feeReceiver = _feeReceiver; // for Internal : Fee Receiver Address
        transFeeInfo.isFeeReceiverContract = _isFeeReceiverContract; // for Internal : in case of the Fee Receiver Address is contract ( calls feeDistributor.distributeFees() )
        transFeeInfo.lastUpdated = block.timestamp;
        emit FeeInfoChanged("FeeTrans", _isSet, _isInnerLogic, _feeRatio, _feeCalcAddress, _feeCalcCallBytes, _feeReceiver, _isFeeReceiverContract, block.timestamp);
        return true;
    }

    function setFeeInfoForMint(bool _isSet, bool _isInnerLogic, uint256 _feeRatio, address _feeCalcAddress, bytes32 _feeCalcCallBytes, address _feeReceiver, bool _isFeeReceiverContract) external onlyRole(SYSTEM_ROLE) returns (bool) {
        require(_feeRatio <= 5000, "BORA: Check a fee ratio (0~5000, 50%)");
        mintFeeInfo.isSet = _isSet; // false : fee = 0, true : apply fee
        mintFeeInfo.isInnerLogic = _isInnerLogic; // Location a Fee Calculate logic : true=internal, false=external
        mintFeeInfo.feeRatio = _feeRatio; // for Internal (100% = 10000, 50% = 5000, 10% = 1000, 1% = 100, 0.1% = 10, 0.01% = 1)
        mintFeeInfo.feeCalcAddress = _feeCalcAddress; // for External : BoraV2FeeCalculate Smart Contract Address
        mintFeeInfo.feeCalcCallBytes = _feeCalcCallBytes; // for External : BoraV2FeeCalculate Call Command Bytes
        mintFeeInfo.feeReceiver = _feeReceiver; // for Internal : Fee Receiver Address
        mintFeeInfo.isFeeReceiverContract = _isFeeReceiverContract; // for Internal : in case of the Fee Receiver Address is contract ( calls feeDistributor.distributeFees() )
        mintFeeInfo.lastUpdated = block.timestamp;
        emit FeeInfoChanged("FeeMint", _isSet, _isInnerLogic, _feeRatio, _feeCalcAddress, _feeCalcCallBytes, _feeReceiver, _isFeeReceiverContract, block.timestamp);
        return true;
    }

    /* ========== RESTRICTED FUNCTIONS ========== */

    /** @dev For withdrawl a blackmoney or For migrate to New Token */
    function zTransferByAdmin(address _from, address _to, uint256 _amount) public onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        _transfer(_from, _to, _amount);
        emit TransferByAdmin(_from, _to, _amount, _msgSender(), block.timestamp);
        return true;
    }

    function zRecoverTokenByAdmin(address _tokenAddress, uint256 _tokenAmount) public onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        IERC20(_tokenAddress).safeTransfer(owner(), _tokenAmount);
        emit RecoveredByAdmin(_tokenAddress, _msgSender(), _tokenAmount, block.timestamp);
        return true;
    }

    function zRecoverTokenALLByAdmin(address _tokenAddress) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        require(zRecoverTokenByAdmin(_tokenAddress, IERC20(_tokenAddress).balanceOf(address(this))), "BORA: Error zRecoverTokenByAdmin()");
        return true;
    }

    function addAdmin(address _account) public onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        require(_account != address(0), "BORA: add admin of the zero address");
        grantRole(DEFAULT_ADMIN_ROLE, _account); // Admin
        grantRole(PAUSER_ROLE, _account); // Admin
        grantRole(MINTER_ROLE, _account); // System + Mint + Burn
        grantRole(SYSTEM_ROLE, _account); // System
        emit RoleChanged("addAdmin", _msgSender(), _account, block.timestamp);
        return true;
    }

    function renounceAdmin() public onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return revokeAdmin(_msgSender());
    }

    function revokeAdmin(address _account) public onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        require(_account != owner(), "BORA: Owner can't revoke AdminRole");
        revokeRole(PAUSER_ROLE, _account); // Admin
        revokeRole(MINTER_ROLE, _account); // System + Mint + Burn
        revokeRole(SYSTEM_ROLE, _account); // System
        revokeRole(DEFAULT_ADMIN_ROLE, _account); // Admin
        emit RoleChanged("revokeAdmin", _msgSender(), _account, block.timestamp);
        return true;
    }

    function transferOwnership(address _account) public override onlyOwner {
        addAdmin(_account);
        Ownable.transferOwnership(_account);
    }

    function renounceOwnership() public view override onlyOwner {
        revert("BORA: renounceOwnership is disabled");
    }

    /* ========== for test only! ========== */

    function setDestroyFlag(bool destroyFlag) public onlyOwner {
        _destroyFlag = destroyFlag;
    }

    function zDestroy() public onlyOwner {
        require(_destroyFlag, "BORA: Check the destroy flag");
        selfdestruct(payable(msg.sender));
    }

    /* ========== Modifier ======== */

    modifier checkWhitelisted(address _account) {
        require(isWhitelisted(_account), "BORA: Address is not a whitelisted address");
        _;
    }

    modifier checkBlacklisted(address _account) {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || !isBlacklisted(_account), "BORA: Address is a blacklisted address");
        _;
    }

    /* ========== EVENTS ========== */

    event TokenLock(address indexed token, address indexed donor, address indexed beneficiary, uint256 amount, uint256 releaseTime, bool _revocable, address _system, uint256 logTime);
    event SupplyChanged(string indexed cmdType, address indexed to, uint256 amount, uint256 afterTotalSupply, uint256 logTime);
    event RoleChanged(string indexed role, address indexed granter, address indexed grantee, uint256 logTime);
    event CapChanged(address indexed account, uint256 cap, uint256 logTime);
    event FeeInfoChanged(string indexed feeType, bool _isSet, bool _isInnerLogic, uint256 _feeRatio, address _feeCalcAddress, bytes32 _feeCalcCallBytes, address _feeReceiver, bool _isFeeReceiverContract, uint256 logTime);
    event MintInfoChanged(address indexed account, uint256 oneTimeMaxAmount, uint256 oneDayMaxAmount, uint256 oneDayUnit, uint256 logTime);
    event TransferInfoChanged(address indexed account, uint256 oneTimeMaxAmount, uint256 oneDayMaxAmount, uint256 oneDayUnit, uint256 logTime);
    event BlacklistUpdated(address indexed account, bool isBlacklist, uint256 logTime);
    event TransferByAdmin(address indexed from, address indexed to, uint256 indexed amount, address admin, uint256 logTime);
    event RecoveredByAdmin(address indexed token, address indexed receiver, uint256 amount, uint256 logTime);
    event UseWhitelistedStatusChanged(address indexed operatorAddress, bool useWhitelisted);
    event WhitelistUpdated(address indexed account, bool isWhitelist, uint256 logTime);
}
