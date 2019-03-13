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
 * @title FAAbase
 * @dev The abstract base FAABS contract prototype. Handles common functions
 * @dev - Reference mappings
 * @dev - Nonprofit service fees
 *
 ***************************************************************************/

pragma solidity ^0.5.3;


contract FAAbase {

  /********************
   * @dev Address to Reference Mapping, within the Issuer domain
   * @dev issuer => address => reference
   ********************/
    mapping (address => mapping (address => string)) public addrRef;

  /********************
   * @dev Reference to Address Mapping, within the Issuer domain
   * @dev issuer => reference => address
   ********************/
    mapping (address => mapping (string => address)) refAddr;

  /********************
   * @dev FAABS nonprofit entity, authorized to collect the service fees
   ********************/
    address payable nonprofit;

  /********************
   * @dev Assign a reference to the address, within the Issuer domain.
   * @param _issuer address Issuer Address
   * @param _addr address The address to assign the reference to
   * @param _ref string The reference to be assigned. No action if an
   *                    empty string, or if already assigned to _addr.
   *                    Fail if the reference is already assigned to a
   *                    different address, or if a different reference
   *                    is already assigned to _addr.
   ********************/
    function _setRef(address _issuer, address _addr, string memory _ref) internal {
	if (bytes(_ref).length == 0) return;
	require (_addr != address(0));
	if (bytes(addrRef[_issuer][_addr]).length > 0) {
	    require (sha256(bytes(addrRef[_issuer][_addr])) == sha256(bytes(_ref)));
	} else {
	    require (refAddr[_issuer][_ref] == address(0));
	    refAddr[_issuer][_ref] = _addr;
	    addrRef[_issuer][_addr] = _ref;
	}
    }
    
  /********************
   * @dev Remove a previously assigned reference for the address.
   * @param _issuer address Issuer Address
   * @param _addr address The address to remove a reference from
   ********************/
    function _delRef(address _issuer, address _addr) internal {
	require (_addr != address(0));
	delete (refAddr[_issuer][addrRef[_issuer][_addr]]);
	delete (addrRef[_issuer][_addr]);
    }

  /********************
   * @dev Find an address by reference, within the Issuer's domain.
   * @dev A workaround for Solidity not being able to auto-generate
   * @dev a public getter for refAddr.
   * @param _issuer address Issuer Address
   * @param _ref string The reference string
   * @return string Matched address
   ********************/
    function addrByRef(address _issuer, string memory _ref) public view returns (address) {
        return refAddr[_issuer][_ref];
    }
    
  /********************
   * @dev The credit amount available for address to be withdrawn or used
   *      against the maintenance fee.
   *      In the default method, only the nonprofit is entitled to
   *      credits of the maintenance fees.
   *      Overridden in FAAdata to credit Owners' Transfer Record addresses.
   * @param _addr address The address to get credit amount for.
   * @return uint The credit amount.
   ********************/
    function getCredit(address _addr) public view returns (uint _credit) {
	if (_addr == nonprofit) _credit = address(this).balance;
    }

  /********************
   * @dev Claim the credit amount for the address. Claimed credit cannot be
   *      used again. In the default method, no action is taken.
   *      Overridden in FAAdata to credit Owners' Transfer Record addresses.
   * @param _addr address The address to claim the credits for.
   * @param _credit uint  The claimed credit amount.
   ********************/
    function _claimCredit(address _addr, uint _credit) internal {
    }
    
  /********************
   * @dev Require a service fee to the nonprofit, as a percentage of the
   * @dev prepaid gas cost for the transaction (gas limit * gas price)
   * @dev NOTE: Due to Solidity's restrictions, it's problematic to
   * @dev accurately assess the amount of gas supplied with a transaction
   * @dev from inside the contract. If this function is called in the
   * @dev beginning of a payable method, it makes a fair estimate with
   * @dev some safety margin.
   * @param _percent uint Minimum percentage of the gas cost required to
   *                      be paid with the transaction
   * @return uint The calculated prepaid gas cost, for convenience
   ********************/
    function _serviceFee(uint _percent) internal returns (uint _fee) {
	_fee = (gasleft() + 21000) * tx.gasprice;
	uint _credit = getCredit(msg.sender);
	uint _due = _fee * _percent / 100;
	require (msg.value + _credit >= _due);
	if (_credit > 0) _claimCredit(msg.sender, _credit > _due ? _due : _credit);
    }
    
  /********************
   * @dev Withdraw service fees collected by the contract to the nonprofit
   *      entity
   ********************/
    function withdraw(uint _amount) public {
	uint _credit = getCredit(msg.sender);
	require (_credit >= _amount);
	_claimCredit(msg.sender, _credit);
	msg.sender.transfer(_amount);
    }
}

