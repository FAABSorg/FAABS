/***************************************************************************
 *    ________     ___ ___         ________     _______
 *   | ______/    /   |   \       |  _____ \   / ______\
 *   | |         / /| | |\ \      | |     \ | | /
 *   | |____    / /_| | |_\ \     | |_____/ | | \______
 *   |  ____|  / ___  |  ___ \    |  _____ <   \______ \
 *   | |      / /   | | |   \ \   | |     \ |         \ |
 *   | |     / /    | | |    \ \  | |_____/ |   ______/ |
 *   |_|    /_/     |_|_|     \_\ |________/   \_______/
 *
 * Firearms Accountability Auditability Blockchain Solution
 *
 * (c) 2019 FAABS.org
 * Jim Zubov <jz@FAABS.org>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * @title FAAlicense
 * @dev FAABS License Class contract
 * @dev A separate instance of FAAlicense is to be created for each type
 * @dev of license record. A single instance of FAAlicense holds the
 * @dev information about all licenses of the specific class that are issued
 * @dev to multiple license holders by multiple issuers.
 ***************************************************************************/

pragma solidity ^0.5.3;

contract FAAlicense is FAAbase {
  /********************
   * @dev The Configurator address. Set to the contract creator on deployment.
   *      Set to 0 once configuring is finalized.
   ********************/
    address public configurator;

  /********************
   * @dev Alphanumeric code of the license class
   ********************/
    string public code;

  /********************
   * @dev Human readable name of the license class
   ********************/
    string public name;

  /********************
   * @dev Human readable description of the license class
   ********************/
    string public description;

  /********************
   * @dev Delegate License. A holder of a valid Delegate License issued by Issuer can issue and revoke
   * @dev licenses on the behalf of the Issuer.
   ********************/
    FAAlicense delegateLicense;
    
  /********************
   * @dev License status bucket.
   * @param issuedBy address The issuer's address
   * @param validSince uint48 Timestamp
   * @param validUntil uint48 Timestamp
   ********************/
    struct Tstatus {
	address issuedBy;
	uint48 validSince;
	uint48 validUntil;
    }
    
  /********************
   * @dev Trust chain bucket.
   * @param license FAAlicense A license the Issuer is required to hold
   * @param count uint96 Number of required valid licenses the Issuer should hold,
   *                     if issuedBy == 0
   * @param issuedBy address Match the issuer of Issuer's license, 0 to match any
   ********************/
    struct Trequire {
	FAAlicense license;
	uint96 count;
	address issuedBy;
    }

  /********************
   * @dev Required trust chain for a license issuer.
   * @dev (trustChain[0][0] && trustChain[0][1] && ...) ||
   * @dev (trustChain[1][0] && trustChain[1][1] && ...) || ...
   ********************/
    Trequire[][] public requiredChain;
    
  /********************
   * @dev Issued licenses.
   * @param key address The key is a License Derived Address (LDA), produced by derive()
   *                    or by its client-side equivalent. The LDA facilitates the anonymity
   *                    of each license record. It is not possible to derive the license
   *                    holder address from the LDA, thus it is not possible to trace any
   *                    other license of different classes held by the license holder
   *                    as long as the license holder address is kept confidential, is
   *                    not published on the blockchain or supplied by other means.
   *                    Citizen license holders are expected to keep their addresses
   *                    semi-private, share the addresses only with concerned parties
   *                    and with the government agencies.
   * @param value Tstatus[] An array of validity status buckets for different dates
   *                        and/or for different issuers.
   ********************/
    mapping (address => Tstatus[]) public licenses;
    
  /********************
   * @dev Constructor.
   * @param _code string    Alphanumeric code of the License Class
   * @param _name string    Human readable name of the License Class
   * @param _desc string    Human readable description
   * @param _delegate address The Delegate License Class. A holder of a
   *                          Delegate License is authorized to issue licenses
   *                          on the behalf of the Delegate License issuer.
   ********************/
    constructor(string memory _code, string memory _name, string memory _desc, address _delegate) public {
	configurator = msg.sender;
	code = _code;
	name = _name;
	description = _desc;
	delegateLicense = FAAlicense(_delegate);
    }
    
  /********************
   * @dev Produce an anonymous License Derived Address LDA), unique for the license
   * @dev holder's address and the license class.
   * @dev SECURITY NOTE:
   * @dev This function is to be called on the smart contract  in case if the
   * @dev license holder's address is already published on the blockchain, such as
   * @dev public authorities, government or business entities. For citizen license
   * @dev holders, a client-side off-blockchain equivalent of this function to be
   * @dev used, to preserve the license holder's privacy.
   * @param _addr address License holder's address
   * @return address License Derived Address (LDA)
   ********************/
    function derive(address _addr) public view returns (address _lda) {
	_lda = address(ripemd160(abi.encodePacked(address(this), _addr)));
    }
    
  /********************
   * @dev Add trust chain buckets.
   * @param _chain address[] License class addresses required for an issuer of
   *                         'this' license class to hold.
   *                         Use duplicate entries to require multiple licenses
   *                         of the same class, with matching _by[] == 0.
   *                         Use an empty array to finalize the setup.
   * @param _by address[] Required issuers of the matching entries in _chain,
   *                      0 - match ny issuer
   ********************/
    function addRequiredChain(address[] memory _chain, address[] memory _by) public {
	require (msg.sender == configurator);
	if (_chain.length == 0) {
	    configurator = address(0);
	    return;
	}
	uint i = requiredChain.length++;
	for (uint j = 0; j < _chain.length; j++) {
	    uint k;
	    for (k = 0; k < requiredChain[i].length; k++) {
		if (address(requiredChain[i][k].license) == _chain[j] && requiredChain[i][k].issuedBy == _by[j]) {
		    requiredChain[i][k].count++;
		    break;
		}
	    }
	    if (k == requiredChain[i].length) {
		requiredChain[i].length++;
		requiredChain[i][k].license = FAAlicense(_chain[j]);
		requiredChain[i][k].issuedBy = _by[j];
		requiredChain[i][k].count = 1;
	    }
	}
    }
    
  /********************
   * @dev Validate the license, granted by any valid issuer.
   * @param _addr address License holder's address [see security notes on derive()]
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @return bool True if valid
   ********************/
    function valid(address _addr, uint _when) public view returns (bool ok) {
	ok = validR(derive(_addr), address(0), _when, new address[](0));
    }
    
  /********************
   * @dev Validate the license, granted by a specific issuer.
   * @param _addr address License holder's address [see security notes on derive()]
   * @param _by address Issuer's address, 0 to match any
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @return bool True if valid
   ********************/
    function validBy(address _addr, address _by, uint _when) public view returns (bool ok) {
	ok = validR(derive(_addr), _by, _when, new address[](0));
    }
    
  /********************
   * @dev Validate the license using LDA, granted by a specific issuer.
   * @param _lda address License Derived Address (LDA)
   * @param _by address Issuer's address, 0 to match any
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @return bool True if valid
   ********************/
    function validD(address _lda, address _by, uint _when) public view returns (bool ok) {
	ok = validR(_lda, _by, _when, new address[](0));
    }
    
  /********************
   * @dev Validate the license using LDA, granted by a specific issuer, recursion safe
   * @param _lda address License Derived Address (LDA)
   * @param _by address Issuer's address, 0 to match any
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @param _checked address[] LDAs of checked licenses, to be passed to checkChainR()
   * @return bool True if valid
   ********************/
    function validR(address _lda, address _by, uint _when, address[] memory _checked) public view returns (bool ok) {
	if (_when == 0) _when = now;
	for (uint i = 0; i < licenses[_lda].length; i++) {
	    if (licenses[_lda][i].validSince <= _when && licenses[_lda][i].validUntil > _when
	     && (_by == address(0) || _by == licenses[_lda][i].issuedBy) && checkChainR(derive(licenses[_lda][i].issuedBy), _when, _checked)) return true;
	}
	return false;
    }

  /********************
   * @dev Count licenses issued to a specific license holder by different issuers.
   * @param _addr address License holder's address [see security notes on derive()]
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @return uint Number of valid licenses
   ********************/
    function count(address _addr, uint _when) public view returns (uint ct) {
	ct = countR(derive(_addr), _when, new address[](0));
    }
    
  /********************
   * @dev Count licenses issued to a specific license holder by different issuers,
   * @dev using LDA.
   * @param _lda address License Derived Address (LDA)
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @return uint Number of valid licenses
   ********************/
    function countD(address _lda, uint _when) public view returns (uint ct) {
	ct = countR(_lda, _when, new address[](0));
    }
    
  /********************
   * @dev Count licenses issued to a specific license holder by different issuers,
   * @dev using LDA, recursion safe.
   * @param _lda address License Derived Address (LDA)
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @param _checked address[] LDAs of checked licenses, to be passed to checkChainR()
   * @return uint Number of valid licenses
   ********************/
    function countR(address _lda, uint _when, address[] memory _checked) public view returns (uint ct) {
	if (_when == 0) _when = now;
	ct = 0;
	for (uint i = 0; i < licenses[_lda].length; i++) {
	    if (licenses[_lda][i].validSince <= _when && licenses[_lda][i].validUntil > _when && checkChainR(derive(licenses[_lda][i].issuedBy), _when, _checked)) ct++;
	}
    }

  /********************
   * @dev Check the Issuer's trust chain.
   * @dev It's generally safe to pass the Issuer's license address to the
   * @dev blockchain call, since the Issuer's address is already recorded
   * @dev on the blockchain (Tstatus.issuedBy)
   * @param _addr address Issuer's address
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @return bool True if the chain is valid
   ********************/
    function checkChain(address _addr, uint _when) public view returns (bool ok) {
	ok = checkChainR(derive(_addr), _when, new address[](0));
    }

  /********************
   * @dev Check the Issuer's trust chain using Issuer's LDA.
   * @param _lda address Issuer's License Derived Address (LDA)
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @return bool True if the chain is valid
   ********************/
    function checkChainD(address _lda, uint _when) public view returns (bool ok) {
	ok = checkChainR(_lda, _when, new address[](0));
    }
    
  /********************
   * @dev Check the Issuer's trust chain using Issuer's LDA, recursion safe
   * @param _lda address Issuer's License Derived Address (LDA)
   * @param _when uint Timestamp to validate the license at, 0 for now
   * @param _checked address[] An array of checked LDAs, to prevent infinite
   *                           recursion on self-issued or cyclic licenses
   * @return bool True if the chain is valid
   ********************/
    function checkChainR(address _lda, uint _when, address[] memory _checked) public view returns (bool ok) {
	if (_when == 0) _when = now;
	ok = true;
	address[] memory checked2 = new address[](_checked.length + 1);
	uint i;
	for (i = 0; i < _checked.length; i++) if ((checked2[i] = _checked[i]) == _lda) return true;
	checked2[i] = _lda;
	for (i = 0; i < requiredChain.length; i++) {
	    ok = true;
	    for (uint j = 0; j < requiredChain[i].length; j++) {
		if (requiredChain[i][j].issuedBy == address(0) ?
		    requiredChain[i][j].license.validR(_lda, requiredChain[i][j].issuedBy, _when, checked2) :
		    requiredChain[i][j].license.countR(_lda, _when, checked2) < requiredChain[i][j].count) {
		    ok = false;
		    break;
		}
	    }
	    if (ok) break;
	}
    }
    
  /********************
   * @dev Issue a license, valid within a specific date range.
   * @dev Requires a service fee of at least 100% of prepaid gas.
   * @param _addr address License holder's address [see security notes on derive()]
   * @param _by address Issuer's address. The caller must either be the issuer,
   *                    or hold a valid delegateLicense granted by the issuer.
   * @param _since uint Timestamp - valid since
   * @param _until uint Timestamp - valid until. If the date range overlaps with
   *                    another range previously issued by the same issuer to the
   *                    license holder, the ranges are merged.
   * @param _ref string An optional public reference, such as license number
   *                    or a code of jurisdiction / agency.
   ********************/
    function issue(address _addr, address _by, uint _since, uint _until, string memory _ref) public payable {
	issueD(derive(_addr), _by, _since, _until, _ref);
    }
    
  /********************
   * @dev Issue a license, valid within a specific date range, using LDA.
   * @dev Requires a service fee of at least 100% of prepaid gas.
   * @param _lda address License Derived Address (LDA)
   * @param _by address Issuer's address. The caller must either be the issuer,
   *                    or hold a valid delegateLicense granted by the issuer.
   * @param _since uint Timestamp - valid since
   * @param _until uint Timestamp - valid until. If the date range overlaps with
   *                    another range previously issued by the same issuer to the
   *                    license holder, the ranges are merged.
   * @param _ref string An optional public reference, such as license number
   *                    or a code of jurisdiction / agency.
   ********************/
    function issueD(address _lda, address _by, uint _since, uint _until, string memory _ref) public payable {
	_serviceFee(100);
	require (configurator == address(0));
	require (_by == msg.sender || delegateLicense.validBy(msg.sender, _by, now));
	if (_since < now) _since = now;
	require (_until > _since);
	require (checkChain(msg.sender, now));
	_setRef(msg.sender, _lda, _ref);
	uint absorbed = uint(-1);
	uint i;
	for (i = 0; i < licenses[_lda].length; i++) {
	    if (licenses[_lda][i].issuedBy == _by && licenses[_lda][i].validSince <= _until && licenses[_lda][i].validUntil >= _since) {
		if (absorbed == uint(-1)) {
		    if (licenses[_lda][i].validSince > _since) licenses[_lda][i].validSince = uint48(_since);
		    if (licenses[_lda][i].validUntil < _until) licenses[_lda][i].validUntil = uint48(_until);
		    absorbed = i;
		} else {
		    if (licenses[_lda][i].validSince < licenses[_lda][absorbed].validSince) licenses[_lda][absorbed].validSince = licenses[_lda][i].validSince;
		    if (licenses[_lda][i].validUntil > licenses[_lda][absorbed].validUntil) licenses[_lda][absorbed].validUntil = licenses[_lda][i].validUntil;
		    for (uint j = i + 1; j < licenses[_lda].length; j++) licenses[_lda][j - 1] = licenses[_lda][j];
		    licenses[_lda].length--;
		    i--;
		}
	    }
	}
	if (absorbed == uint(-1)) {
	    licenses[_lda].length++;
	    licenses[_lda][i].issuedBy = _by;
	    licenses[_lda][i].validSince = uint48(_since);
	    licenses[_lda][i].validUntil = uint48(_until);
	}
    }
    
  /********************
   * @dev Revoke a license, for a specific date range or indefinitely.
   * @dev Requires a service fee of at least 100% of prepaid gas.
   * @param _addr address License holder's address [see security notes on derive()]
   * @param _by address Issuer's address. The caller must either be the issuer,
   *                    or hold a valid delegateLicense granted by the issuer.
   * @param _since uint Timestamp - revoke since
   * @param _until uint Timestamp - revoke until. 0 to revoke indefinitely.
   *                    The date ranges of the license previously issued by the
   *                    specified issuer will be accordingly adjusted, removed
   *                    or split, to exclude the specified date range
   ********************/
    function revoke(address _addr, address _by, uint _since, uint _until) public payable {
	revokeD(derive(_addr), _by, _since, _until);
    }
    
  /********************
   * @dev Revoke a license, for a specific date range or indefinitely, using LDA.
   * @dev Requires a service fee of at least 100% of prepaid gas.
   * @param _lda address License Derived Address (LDA)
   * @param _by address Issuer's address. The caller must either be the issuer,
   *                    or hold a valid delegateLicense granted by the issuer.
   * @param _since uint Timestamp - revoke since
   * @param _until uint Timestamp - revoke until. 0 to revoke indefinitely.
   *                    The date ranges of the license previously issued by the
   *                    specified issuer will be accordingly adjusted, removed
   *                    or split, to exclude the specified date range
   ********************/
    function revokeD(address _lda, address _by, uint _since, uint _until) public payable {
	_serviceFee(100);
	require (configurator == address(0));
	require (_by == msg.sender || delegateLicense.validBy(msg.sender, _by, now));
	if (_since < now) _since = now;
	require (_until == 0 || _until > _since);
	require (checkChain(msg.sender, now));
	for (uint i = 0; i < licenses[_lda].length; i++) {
	    if (licenses[_lda][i].issuedBy == _by && (_until == 0 || licenses[_lda][i].validSince <= _until) && licenses[_lda][i].validUntil >= _since) {
		if (_until != 0 && licenses[_lda][i].validUntil > _until) {
		    if (licenses[_lda][i].validSince >= _since) {
			licenses[_lda][i].validSince = uint48(_until);
		    } else {
			for (uint j = licenses[_lda].length++; j > i; j--) licenses[_lda][j] = licenses[_lda][j - 1];
			licenses[_lda][i].validUntil = uint48(_since);
			licenses[_lda][++i].validSince = uint48(_until);
		    }
		} else {
		    if (licenses[_lda][i].validSince >= _since) {
			for (uint j = i + 1; j < licenses[_lda].length; j++) licenses[_lda][j - 1] = licenses[_lda][j];
			licenses[_lda].length--;
			i--;
		    } else {
			licenses[_lda][i].validUntil = uint48(_since);
		    }
		}
	    }
	}
    }
}
