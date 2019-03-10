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
 * @title FAAdata
 * @dev FAABS end-to-end encrypted data
 * @dev - Devices
 * @dev - Device transfers
 * @dev - Inquiries
 *
 ***************************************************************************/

pragma solidity ^0.5.3;

contract FAAdata is FAAbase {

  /********************
   * @dev Transfer record mode.
   * @dev OWN        : An owner of the Device.
   * @dev BORROW     : A Borrower of the Device, trusted by the Owner. The
   *                   Borrower can claim temporary ownership of the Device
   *                   without excessively complicated audit trail.
   * @dev BACKUP     : A backup key holder, can help recovering the audit
   *                   trail if the Owner has lost the key or is not
   *                   accessible for any reason.
   * @dev AGENT      : An agent authorized by the Owner to transfer the Device
   *                   on the behalf of the Owner. Usually applies when the
   *                   Owner is a business entity or a government agency.
   ********************/
    enum Tmode {
	NULL,
	OWN,
	BORROW,
	BACKUP,
	AGENT
    }

  /********************
   * @dev Transfer record status.
   * @dev REQUESTED  : A request is created by the potential Receiver.
   *                   In most cases the request will be sent off blockchain
   *                   and get recorded once approved or denied by the Owner.
   * @dev APPROVED   : Approved by the Owner or Assignor. Once approved, the
   *                   Receiver can execute his rights.
   *                   For the Transfer Record mode OWN, the Receiver can
   *                   commit the ownership, or cancel the transfer.
   *                   For mode BORROW, the Borrowers and the Owner can
   *                   repeatedly commit the possession of the Device as it's
   *                   being borrowed and returned, until the Owner transfers
   *                   the ownership to the next owner, or the Borrower has
   *                   cancelled or is revoked.
   * @dev DENIED     : Denied by the Owner or Assignor, instead of approving.
   *                   When the request is sent off blockchain, the Owner or
   *                   Assignor can choose a silent denial, without leaving
   *                   a blockchain trail.
   * @dev CANCELED   : Canceled by the Receiver. Depending on the Transfer
   *                   Record mode:
   *            OWN    : The Receiver has canceled the request instead of
   *                     committing the ownership.
   *            BORROW : The Borrower has voluntarily declined to be able to
   *                     borrow the Device. The Borrower can decline at any
   *                     time, as long as he is not currently in possession
   *                     the Device.
   *            BACKUP : The Backup requestor has canceled the request before
   *                     the Owner has approved it.
   *            AGENT  : The Agent has cancelled the affiliation with the
   *                     Owner concerning the Device.
   * @dev REVOKED    : Revoked by the Owner after approval. Depending on the
   *                   Transfer Record mode:
   *            OWN    : The Owner has revoked the transfer after approving
   *                     but before the Receiver has committed the ownership
   *            BORROW : The Owner has denied the Borrower from further being
   *                     able to commit the possession of the device
   *            BACKUP : Not applicable
   *            AGENT  : The Owner has blocked the Agent from doing
   *                     the transfer after previously approving.
   ********************/
    enum Tstatus {
	NULL,
	REQUESTED,
	APPROVED,
	DENIED,
	CANCELED,
	REVOKED
    }

  /********************
   * @dev A Device Record
   * @param issuer address  The Issuer of the Device. For the US federal case,
   *                        the only valid Issuer is expected to be ATF.
   * @param current address The Transfer Record of the current Owner/Holder
   *                        of the Device. Points to a Transfer Record of
   *                        mode OWN or BORROW, and status APPROVED.
   * @param class address   The public device class, set by the Issuer.
   *                        Set to 0 if no device class info is intended to
   *                        be publicly listed.
   * @param eInfo bytes     End-to-end encrypted Device Info, encrypted by
   *                        the symmetric Access Key (see eAccess).
   *                        Device Info is a JSON string:
   *                          v = 1 (version number)
   *                          mfr
   *                          model
   *                          caliber
   *                        Any other specific fields can be used.
   ********************/
    struct Tdevice {
	address issuer;
	address current;
	address class;
	bytes eInfo;
    }

  /********************
   * @dev A Transfer Record
   * @param previous address The previous record.
   *                         For mode OWN, points to the previous Transfer
   *                         record, or to the Device record if it's the first
   *                         Transfer record. For other modes, points to the
   *                         Owner's Transfer record.
   * @param mode Tmode       Transfer Record Mode, see Tmode.
   * @param status Tstatus   Transfer Record Status, see Tstatus.
   * @param approvedAt uint48 The approval timestamp.
   * @param ePriv bytes      This field is intended to store the end-to-end
   *                         encrypted Private Transfer Key, encrypted by
   *                         ECDH(privLicenseKey, pubTransferKey) using the
   *                         Owner's Private License Key. Since this field is
   *                         decryptable only by the Owner, the Owner may
   *                         generally choose to store any kind of informtion
   *                         here, as other parties are not able to validate.
   * @param eInfo bytes      End-to-end encrypted Identity Info, encrypted by
   *                         the symmetric Access Key (see eAccess).
   *                         IdentityInfo = 0x01 || r || s || [ addrLK ]
   *                           0x01    = Version Number
   *                           (r,s)   = ECDSA(SHA256(idRec), SK)
   *                           idRec   = addrLK || addrTransfer || previous
   *                           LK      = The Owner's License Key (priv/pub/addr)
   *                           SK      = The Signer's License Key (priv/pub/addr)
   *                                     The Signer must be either same as the
   *                                     Owner, or have a valid agentLicense
   *                                     issued by the Owner.
   *                         The decrypted IdentityInfo allows to recover
   *                         complimentary candidates of pubSK, and verify
   *                         which one of them is consistent with the signature.
   *                         If optional addrLK is not provided in InentityInfo,
   *                         it means the Signer is the Owner (SK = LK), and
   *                         addrLK for idRec is derived from pubSK.
   *                         From the audit point of view:
   *                         - the signature in IdentityInfo must be valid,
   *                         - The Signer must be same as the Owner, or hold
   *                           'agentLicense' valid as of 'approvedAt',
   *                         - the Owner must hold a license that allows him
   *                           to own the Device, valid as of 'approvedAt'
   ********************/
    struct Ttransfer {
	address previous;
	Tmode mode;
	Tstatus status;
	uint48 approvedAt;
	bytes ePriv;
	bytes eInfo;
    }

  /********************
   * @dev An Inquiry Record
   * @param from address  The Inquirer's License Address. Recorded publicly on
   *                      the blockchain, unlike civil license addresses.
   * @param to address    The address of the Transfer Record or of the Assignor
   *                      the Inquiry is being sent to.
   * @param inquired address[] A list of Transfer Records and/or Device Records
   *                           the Inquirer would like to access.
   * @param eInfo bytes   Optionally, a list of additional addresses
   *                      supplied by the responding party.
   ********************/
    struct Tinquiry {
	address from;
	address to;
	address[] inquired;
	bytes eInfo;
    }
    
  /********************
   * @dev A Response Record
   *      This record is optionally posted in response to an Inquiry Record,
   *      when the responding party needs to share additional addresses
   *      and/or encrypted message with the Inquirer.
   * @param responded address[] An optional list of additional addresses
   *                            supplied by the responding party,
   *                            such as ATF responsing with an address of a
   *                            Device matching the criteria supplied in
   *                            the Inquiry's eInfo.
   * @param eInfo bytes         An optional end-to-end encrypted arbitrary
   *                            message to the Inquirer, encrypted with the
   *                            same Access Key as the matching Inquiry Record.
   *                            If the Inquiry did not have eInfo and Access
   *                            Key associated with it, the Responder creates
   *                            a new one and shares with the Inquirer via
   *                            eAccess record.
   ********************/
    struct Tresponse {
	address[] responded;
	bytes eInfo;
    }
    
  /********************
   * @dev The Device Records
   *      DeviceAddress => DeviceRecord
   ********************/
    mapping (address => Tdevice) public devices;
    
  /********************
   * @dev The Transfer Records
   *      TransferAddress => TransferRecord
   ********************/
    mapping (address => Ttransfer) public transfers;

  /********************
   * @dev The Transfer Assignors
   *      TransferAddress => AssignorAddress
   *      When an Assignor address is set for a particular Transfer address,
   *      it indicates that the ownership of the Device was assigned by a
   *      public authority, without the consent of the previous Owner.
   ********************/
    mapping (address => address) public assignors;

  /********************
   * @dev End-to-end encrypted Access Keys.
   *      A unique symmetric 256-bit Access Key is generated on the client
   *      side for each Device Record and for each Transfer Record, and is
   *      encrypted on the client side before being passed to blockchain.
   *
   * @dev RecordAddress => UserAddress => eAccessKey
   *      RecordAddress: The address of the record containing the encrypted
   *                     eInfo - Device Address, Transfer Address or Inquiry
   *                     Address.
   *      UserAddress  : The address that in intended to be able to decrypt
   *                     the eInfo on the record. Normally it's either a
   *                     Transfer Record Address to share the info along
   *                     the anonymous transfer chain, or a public Assignor
   *                     or Inquirer address.
   *      eAccessKey   : Encrypted 256-bit Access Key for the record:
   *                     algo = AES-256-CTR
   *                     key = SHA256(ECDH(UserKey, PeerKey))
   *                     ctr = RecordAddress[0..15]
   *      UserKey is a public/private key that matches UserAddress. A public
   *      key for each Transfer Address is recorded on the blockchain, except
   *      for abandoned transfers that were never committed. A public key for
   *      each Assignor or Inquirer is recorded on the blockchain, since
   *      assignments and inquiries are initiated from their respective public
   *      address.
   *      PeerKey is a public/private key of the address that shared the
   *      Access Key with the User, may be a Transfer Record address or an
   *      Assignor/Inquirer address. There is no link to the Peer Address
   *      within Solidity storage, this address is recorded on the Assign event
   *      logs which is accessible to the client side (see Assign event).
   *
   * @dev Each Access Key is used as en encryption key to eInfo field on the
   *      corresponding record. The format of eInfo is as following:
   *      0x01 || cipherText || GMAC
   *      0x01 = version number
   *      cipherText = the encrypted content
   *        algo = AES-256-GCM
   *        key = AccessKey
   *        iv = RecordAddress[0..11]
   *      GMAC = GCM GMAC value
   ********************/
    mapping (address => mapping(address => bytes32)) public eAccess;

  /********************
   * @dev The Inquiry Records
   *      InquiryAddress => InquiryRecord
   ********************/
    mapping (address => Tinquiry) public inquiries;
    
  /********************
   * @dev The Response Records
   *      InquiryAddress => ResponseRecord
   *      The key is same as for the matching Inquiry Record.
   ********************/
    mapping (address => Tresponse) public responses;
    
  /********************
   * @dev Assignor License.
   ********************/
    FAAlicense assignorLicense;
    
  /********************
   * @dev Authorities that issue valid Assignor Licenses for each Device Issuer.
   *      If no Authority is supplied, defaults to the Device Issuer address.
   *      A device issuer can call setAuthority() to specify a valid Authority.
   *      DeviceIssuerAddress => AuthorityAddress
   ********************/
    mapping (address => address) authorities;
    
  /********************
   * @dev Agent License. Not used inside the smart contract, provided as a
   *      reference for the client side app to validate licenses of Agents
   *      of business or government entities.
   ********************/
    FAAlicense agentLicemse;
    
  /********************
   * @dev Device event, emitted when a Device is created.
   *      Allows to trace all devices created by a particular Issuer.
   * @param _issuer address The Issuer of the Device
   * @param _device address The Device Record address
   ********************/
    event Device(address indexed _issuer, address _device);

  /********************
   * @dev Access event, emitted when an Access Key is made available to a User.
   * @param _record address   The address of the Device / Transfer / Inquiry
   *                          record the Access Key applies to
   * @param _user address     The User the Access Key is made available to
   * @param _peer address     The Peer, whose public key is to be used by the
   *                          User to decrypt the eAccess record.
   *                          The creator of the Access Key doesn't need to
   *                          explicitly share the key with themselves - as
   *                          long as they share it with at least one other
   *                          User, they can an eShare record they're listed as
   *                          a Peer on.
   ********************/
    event Access(address indexed _record, address indexed _user, address _peer);
    
  /********************
   * @dev Transfer event, emitted when a Device is transferred, either to a
   *      new Owner or to/from a Borrower. In particuar, Transfer event log is
   *      useful as audit audit trail for borrowing the Device.
   * @param _device address   The Device Record address.
   * @param _to address       The Receiver address.
   ********************/
    event Transfer(address indexed _device, address _to);
    
  /********************
   * @dev Assign event, emitted when a Transfer Record is assigned by a public
   *      authority.
   * @param _assignor address The Assignor's License address.
   * @param _record address   The Device Record being assigned.
   ********************/
    event Assign(address indexed _assignor, address _record);

  /********************
   * @dev Inquiry event, emitted when an Inquiry is posted.
   * @param _from address    The Inquirer's License Address.
   * @param _to address      The responder's address, either a Transfer Record
   *                         or a public authority's License Address
   * @param _inquiry address A unique Inquiry Record address
   ********************/
    event Inquiry(address indexed _from, address indexed _to, address _inquiry);
    
  /********************
   * @dev Response event, emitted when a response to an Inquiry is posted.
   * @param _inquiry address The matching Inquiry Record address.
   ********************/
    event Response(address indexed _inquiry);
    
  /********************
   * @dev Constructor
   * @param _nonprofit address  The nonprofit entity the feed are payable to
   * @param _assignorLicense address The license required for Assignor to hold.
   *                                 Must be issued by the Issuer of the Device
   *                                 being assigned, or by
   *                                 assignorIssuers[device.issuer] if set
   ********************/
    constructor(address payable _nonprofit, address _assignorLicense) public {
	nonprofit = _nonprofit;
	assignorLicense = FAAlicense(_assignorLicense);
    }
    
  /********************
   * @dev Make an Access Key available to a User.
   * @param _record address  The Device / Transfer / Inquiry Record address
   * @param _user address    The address to share the Access Key with.
   * @param _peer address    The address of the Peer who had encrypted eAccess
   * @param _eAccess bytes32 End-to-end encrypted Access Key, encrypted by the
   *                         shared secret of _user and _peer, see eAccess
   ********************/
    function _share(address _record, address _user, address _peer, bytes32 _eAccess) internal {
	if (eAccess[_record][_user] != bytes32(0)) {
	    require (eAccess[_record][_user] == _eAccess);
	    return;
	}
	require (_eAccess != bytes32(0));
	eAccess[_record][_user] = _eAccess;
	emit Access(_record, _user, _peer);
    }

  /********************
   * @dev Create a new Device Record. This operation charges 21 * gas fee,
   *      20 * gas fee to be forwarded to the Device Record address, the
   *      rest goes to the nonprofit.
   * @param _device address  The new Device Record address. Must be uinque
   *                         among Devices, Transfers and Inquiries.
   * @param _class address   Publicly listed device class. 0 if not applicable.
   * @param _eInfo bytes     End-to-end encrypted device info, see Tdevice.
   * @param _eAccess bytes32 End-to-end encrypted Access Key, encrypted by the
   *                         shared secret of _device and msg.sender.
   *                         Since the Device Address wasn't yet used as an
   *                         originator of transactions, the public key of the
   *                         Device is not recorded on the blockchain. The
   *                         Issuer must be either the one generating the
   *                         Device Record private key, or receive the public
   *                         key off blockchain. eAccess might not be
   *                         decryptable until the Device Address interacts
   *                         with the blockchain.
   * @param _serial string   An optional public serial number or unique
   *                         reference to be assigned to the Device.
   ********************/
    function createDevice(address payable _device, address _class, bytes memory _eInfo, bytes32 _eAccess, string memory _serial) public payable {
	uint _fee = _serviceFee(2100);
	require (devices[_device].current == address(0) && transfers[_device].previous == address(0) && inquiries[_device].from == address(0));
	devices[_device].issuer = msg.sender;
	devices[_device].current = _device;
	devices[_device].class = _class;
	devices[_device].eInfo = _eInfo;
	_share(_device, _device, msg.sender, _eAccess);
	_setRef(msg.sender, _device, _serial);
	_device.transfer(_fee * 20);
    }
    
  /********************
   * @dev Find a Device Record address from a Transfer Address, by following
   *      the chain of transfers.
   * @param _own address  The Transfer Record address.
   * @return address      The Device Record address, 0 if none found.
   ********************/
    function getDevice(address _own) public view returns (address _device) {
	address a;
	_device = _own;
	while ((a = transfers[_device].previous) != address(0)) _device = a;
    }
    
  /********************
   * @dev Get the Device Owner's address, current of former,
   *      from a Borrower / Agent / Backup address.
   * @param _own address  The Transfer Record address.
   * @return address      The Owner's Transfer Record address, 0 if none found.
   ********************/
    function getOwner(address _own) public view returns (address _owner) {
	_owner = _own;
	while (_owner != address(0) && transfers[_owner].mode != Tmode.OWN) _owner = transfers[_owner].previous;
    }
    
  /********************
   * @dev Find a current Owner of a Device, based on a Transfer Record address.
   * @param _own address  The Transfer Record address.
   * @return address      The current Owner's Transfer Record address, 0 if none found.
   ********************/
    function getCurrentOwner(address _own) public view returns (address _owner) {
	_owner = devices[getDevice(_own)].current;
	if (transfers[_owner].mode == Tmode.BORROW) {
	    require (transfers[_owner].status == Tstatus.APPROVED);
	    _owner = transfers[_owner].previous;
	}
	if (_owner != address(0)) require (transfers[_owner].mode == Tmode.OWN && transfers[_owner].status == Tstatus.APPROVED);
    }
    
  /********************
   * @dev Given a past Owner's Transfer Address, find the next Owner's address
   *      in the transfer chain for the Device.
   * @param _own address  The Transfer Record address.
   * @return address      The Next Owner's Transfer Record address, 0 if none found.
   ********************/
    function getNext(address _own) public view returns (address next) {
	_own = getOwner(_own);
	next = devices[getDevice(_own)].current;
	address a;
	while (next != address(0) && (a = transfers[next].previous) != _own) next = a;
    }
    
  /********************
   * @dev Given a past Owner's Transfer Address, find the next Owner's address
   *      in the transfer chain for the Device.
   * @param _own address  The Transfer Record address.
   * @return address      The Next Owner's Transfer Record address, 0 if none found.
   ********************/
    function getPrev(address _own) public view returns (address prev) {
	prev = transfers[getOwner(_own)].previous;
    }
    
  /********************
   * @dev Find the address the first eAccess record for the Transfer Record
   *      was shared with. It's either a public Assignor, or the previous
   *      Transfer Record address. Useful for retrieving the Transfer Record's
   *      own Access Key.
   * @param _own address  The Transfer Record address.
   * @return address      The Assignor / Previous address, 0 if none found.
   ********************/
    function getAssignor(address _own) public view returns (address _assignor) {
	_assignor = assignors[_own];
	if (_assignor == address(0)) _assignor = transfers[_own].previous;
    }
    
  /********************
   * @dev Find an Authority that issues valid Assignor Licenses for an issuer
   *      of a Device, based on a Transfer Record address.
   * @param _own address  The Transfer Record address.
   * @return address      The issuing Authority address, 0 if none found.
   ********************/
    function getAuthority(address _own) public view returns (address _authority) {
	address issuer = devices[getDevice(_own)].issuer;
	_authority = authorities[issuer];
	if (_authority == address(0)) _authority = issuer;
    }

  /********************
   * @dev Find the public serial number / reference of the Device by a Transfer
   *      Record address, if available.
   * @param _own address  The Transfer Record address.
   * @return string       The serial / reference, empty if none found.
   ********************/
    function getSerial(address _own) public view returns (string memory serial) {
	address device = getDevice(_own);
	return addrRef[devices[device].issuer][device];
    }
    
  /********************
   * @dev Create a new Transfer Record, or check if the existing one matches.
   * @param _curr address  The current (parent) Transfer Record address,
   *                       oe the Device Record address for the first transfer.
   * @param _own address   The new Transfer Record address.
   * @param _ePriv bytes   The value for ePriv (see Ttransfer)
   * @param _eInfo bytes   The value for eInfo (see Ttransfer)
   * @param _mode Tmode    The mode of the record (see Tmode)
   * @return bool          True if a new record has been created. False if the
   *                       record already existes, and matches the values.
   *                       Exception if the existing record doesn't match the
   *                       values, or the values are invalid.
   ********************/
    function _createTransfer(address _curr, address _own, bytes memory _ePriv, bytes memory _eInfo, Tmode _mode) internal returns (bool) {
	require (_eInfo.length > 0);
	require ((transfers[_curr].previous != address(0) || devices[_curr].issuer != address(0)) && devices[_own].issuer == address(0) && inquiries[_own].from == address(0));
	if (transfers[_own].previous != address(0)) {
	    require (transfers[_own].previous == _curr && transfers[_own].mode == _mode);
	    return false;
	}
	transfers[_own].previous = _curr;
	transfers[_own].mode = _mode;
	transfers[_own].status = Tstatus.REQUESTED;
	transfers[_own].ePriv = _ePriv;
	transfers[_own].eInfo = _eInfo;
	return true;
    }

  /********************
   * @dev Validate an Assignor for a Transfer Record. Must be a current Owner's
   *      Transfer Address, a current Owner's Agent, or a valid public Assignor.
   * @param _curr address     The current owner's Transfer Record address,
   *                          or the Device Transfer Address for the first
   *                          assignment (in the latter case, _assignor must
   *                          be an official assignor).
   * @param _assignor address The address which is expected to approve this
   *                          Transfer Record. It can be the current Owner's
   *                          Transfer Record address, an Agent affiliated
   *                          with the current Owner, or an authorized Assignor
   *                          with a valid public license.
   * @return Tmode            Tmode.OWN if _assignor is the Owner,
   *                          Tmode.AGENT if _assignor is the Owner's Agent,
   *                          Tmode.NULL is _assignor is a public Assignor.
   ********************/
    function _chkAssignor(address _curr, address _assignor) internal view returns (Tmode _mode) {
	if (_assignor != _curr) {
	    if (transfers[_assignor].previous == _curr && transfers[_assignor].mode == Tmode.AGENT) {
		require (transfers[_assignor].status == Tstatus.APPROVED);
		_mode = Tmode.AGENT;
	    } else {
		address authority = getAuthority(_curr);
		require (authority != address(0) && assignorLicense.validBy(_assignor, authority, now));
		_mode = Tmode.NULL;
	    }
	} else require ((_mode = transfers[_curr].mode) == Tmode.OWN);
    }

  /********************
   * @dev Check if the call is made by a Transfer Record of mode OWN, or by
   *      their valid agent.
   * @return address  The Transfer Record address of mode OWN,
   *                  exception if none matched.
   ********************/
    function _chkOwner() internal view returns (address _curr) {
	_curr = msg.sender;
	if (transfers[_curr].mode == Tmode.AGENT) {
	    require (transfers[_curr].status == Tstatus.APPROVED);
	    _curr = transfers[_curr].previous;
	}
	require (transfers[_curr].mode == Tmode.OWN && transfers[_curr].status == Tstatus.APPROVED);
    }
    
  /********************
   * @dev Request a new Transfer Record through the Blockchain, share
   *      end-to-end encrypted Access Key with the previous owner, agent or
   *      assignor. Invoked by init*() public calls.
   *      NOTE: Since the new Transfer Record address has been just created,
   *      it's generally not expected to have funds to pay the fees.
   *      More commonly, this request will be communicated off Blockchain
   *      to the '_assignor', who will use approve*() calls to create and
   *      immediately approve the new record, and fund the new Transfer
   *      Record's wallet with the amount for further fees.
   * @param _curr address  The current owner's Transfer Record address.
   * @param _ePriv bytes   The value for ePriv (see Ttransfer)
   * @param _eInfo bytes   The value for eInfo (see Ttransfer)
   * @param _mode Tmode    The mode of the record (see Tmode)
   * @param _assignor address The address which is expected to approve this
   *                          Transfer Record. It can be the current Owner's
   *                          Transfer Record address, an Agent affiliated
   *                          with the current Owner, or an authorized Assignor
   *                          with a valid public license.
   * @param _eAccess bytes32  End-to-end encrypted Access Key, shared with
   *                          _assignor
   * @param _eAccessCurr bytes32 End-to-end encrypted Access Key, shared with
   *                             the current Owner's Transfer Record key. Used
   *                             only when _assignor is an Owner's Agent.
   ********************/
    function _initTransfer(address _curr, bytes memory _ePriv, bytes memory _eInfo, Tmode _mode, address _assignor, bytes32 _eAccess, bytes32 _eAccessCurr) internal {
	if (_chkAssignor(_curr, _assignor) == Tmode.AGENT) {
	    _share(msg.sender, _curr, msg.sender, _eAccessCurr);
	}
	require (_createTransfer(_curr, msg.sender, _ePriv, _eInfo, _mode));
	_share(msg.sender, _assignor, msg.sender, _eAccess);
    }
    
  /********************
   * @dev Request a transfer to a new Owner through the Blockchain.
   *      See notes on _initTransfer()
   * @param _curr address  The current owner's Transfer Record address.
   * @param _ePriv bytes   The value for ePriv (see Ttransfer)
   * @param _eInfo bytes   The value for eInfo (see Ttransfer)
   * @param _assignor address The address which is expected to approve this
   *                          Transfer Record. It can be the current Owner's
   *                          Transfer Record address, an Agent affiliated
   *                          with the current Owner, or an authorized Assignor
   *                          with a valid public license.
   * @param _eAccess bytes32  End-to-end encrypted Access Key, shared with
   *                          _assignor
   * @param _eAccessCurr bytes32 End-to-end encrypted Access Key, shared with
   *                             the current Owner's Transfer Record key. Used
   *                             only when _assignor is an Owner's Agent.
   ********************/
    function initOwn(address _curr, bytes memory _ePriv, bytes memory _eInfo, address _assignor, bytes32 _eAccess, bytes32 _eAccessCurr) public payable {
	_serviceFee(100);
	require (transfers[_curr].mode == Tmode.OWN && devices[getDevice(_curr)].current == _curr);
	_initTransfer(_curr, _ePriv, _eInfo, Tmode.OWN, _assignor, _eAccess, _eAccessCurr);
    }
    
  /********************
   * @dev Request to become a Borrower of a Device.
   *      See notes on _initTransfer()
   * @param _own address   The current owner's Transfer Record address.
   * @param _ePriv bytes   The value for ePriv (see Ttransfer)
   * @param _eInfo bytes   The value for eInfo (see Ttransfer)
   * @param _eAccess bytes32  End-to-end encrypted Access Key, shared with _own
   ********************/
    function initBorrow(address _own, bytes memory _ePriv, bytes memory _eInfo, bytes32 _eAccess) public payable {
	_serviceFee(100);
	require (_own != address(0) && getCurrentOwner(_own) == _own);
	_initTransfer(_own, _ePriv, _eInfo, Tmode.BORROW, _own, _eAccess, bytes32(0));
    }

  /********************
   * @dev Request to become a Agent to the current Owner's Transfer Record.
   *      See notes on _initTransfer()
   * @param _own address   The current owner's Transfer Record address.
   * @param _ePriv bytes   The value for ePriv (see Ttransfer)
   * @param _eInfo bytes   The value for eInfo (see Ttransfer)
   * @param _eAccess bytes32  End-to-end encrypted Access Key, shared with _own
   ********************/
    function initAgent(address _own, bytes memory _ePriv, bytes memory _eInfo, bytes32 _eAccess) public payable {
	_serviceFee(100);
	address currowner = getCurrentOwner(_own);
	require (transfers[_own].mode == Tmode.OWN);
	require (currowner == _own || (currowner == getPrev(_own) && (transfers[_own].status == Tstatus.REQUESTED || transfers[_own].status == Tstatus.APPROVED)));
	_initTransfer(_own, _ePriv, _eInfo, Tmode.AGENT, _own, _eAccess, bytes32(0));
    }

  /********************
   * @dev Request to become a Backup data holder for a Transfer Record.
   *      See notes on _initTransfer()
   * @param _own address   The current owner's Transfer Record address.
   * @param _ePriv bytes   The value for ePriv (see Ttransfer)
   * @param _eInfo bytes   The value for eInfo (see Ttransfer)
   * @param _eAccess bytes32  End-to-end encrypted Access Key, shared with _own
   ********************/
    function initBackup(address _own, bytes memory _ePriv, bytes memory _eInfo, bytes32 _eAccess) public payable {
	_serviceFee(100);
	require (transfers[_own].mode == Tmode.OWN && transfers[_own].status == Tstatus.APPROVED);
	_initTransfer(_own, _ePriv, _eInfo, Tmode.BACKUP, _own, _eAccess, bytes32(0));
    }
    
  /********************
   * @dev Approve a Transfer Record, share end-to-end encrypted Access Key of
   *      the current Owner, and of the Agent if applicable.
   *      If the original Transfer Record request was sent off Blockchain,
   *      this function will create the Transfer Record using end-to-end
   *      encrypted data.
   * @param _curr address  The current Owner's Transfer Record address,
   *                       or the Device Record for the first transfer.
   * @param _own address   The address of the Transfer Record being approved.
   * @param _eAccess bytes32[5] End-to-end encrypted Access Keys. Any of the
   *                            members can be 0 when not applicable:
   *                     0: AK(msg.sender) => enc(_own, msg.sender)
   *                     1: AK(_curr) => enc(_own, msg.sender)
   *                     2: AK(_own) => enc(msg.sender, _own)
   *                     3: AK(_own) => enc(_curr, _own)
   *                     4: AK(DeviceAddr) => enc(_own, msg.sender)
   * @param _ePriv bytes   The value for ePriv of the Transfer Record for _own,
   *                       if it wasn't created yet.
   * @param _eInfo bytes   The value for e of the Transfer Record for _own,
   *                       if it wasn't created yet.
   * @param _mode Tmode    The mode of the Transfer Record for _own (see Tmode)
   *                       to be assigned if the record doesn't exist yet,
   *                       to be matched otherwise.
   ********************/
    function _approveTransfer(address _curr, address _own, bytes32[5] memory _eAccess, bytes memory _ePriv, bytes memory _eInfo, Tmode _mode) internal {
	require (transfers[_curr].status == Tstatus.APPROVED || devices[_curr].issuer != address(0));
	require (_own != address(0));
	Tmode amode = _chkAssignor(_curr, msg.sender);
	if (amode == Tmode.AGENT) {
	    if (eAccess[_own][_curr] == bytes32(0)) _share(_own, _curr, _own, _eAccess[3]);
	    _share(_curr, _own, msg.sender, _eAccess[1]);
	}
	if (_createTransfer(_curr, _own, _ePriv, _eInfo, _mode)) {
	    _share(_own, msg.sender, _own, _eAccess[2]);
	}
	if (amode == Tmode.NULL) {
	    assignors[_own] = msg.sender;
	    emit Assign(msg.sender, _own);
	} else {
	    _share(msg.sender, _own, msg.sender, _eAccess[0]);
	}
	_share(getDevice(_curr), _own, msg.sender, _eAccess[4]);
	transfers[_own].status = Tstatus.APPROVED;
	transfers[_own].approvedAt = uint48(now);
    }

  /********************
   * @dev Approve a new Owner's Transfer Record. After the approval, the new
   *      owner can commit the ownership of the Device.
   * @param _curr address  The current Owner's Transfer Record address.
   * @param _own address   The address of the new Owner's Transfer Record.
   * @param _eAccess bytes32[5] End-to-end encrypted Access Keys. Any of the
   *                            members can be 0 when not applicable:
   *                     0: AK(msg.sender) => enc(_own, msg.sender)
   *                     1: AK(_curr) => enc(_own, msg.sender)
   *                     2: AK(_own) => enc(msg.sender, _own)
   *                     3: AK(_own) => enc(_curr, _own)
   *                     4: AK(DeviceAddr) => enc(_own, msg.sender)
   *                       (in case if the approval is being done by an Agent,
   *                       and the new Transfer Record was communicated off
   *                       Blockchain, all 4 will be set)
   * @param _ePriv bytes   The value for ePriv of the Transfer Record for _own,
   *                       if it wasn't created yet.
   * @param _eInfo bytes   The value for e of the Transfer Record for _own,
   *                       if it wasn't created yet.
   ********************/
    function approveOwn(address _curr, address payable _own, bytes32[5] memory _eAccess, bytes memory _ePriv, bytes memory _eInfo) public payable {
	uint _fee = _serviceFee(500);
	require (_curr != address(0) && getCurrentOwner(_curr) == _curr);
	_approveTransfer(_curr, _own, _eAccess, _ePriv, _eInfo, Tmode.OWN);
	_own.transfer(_fee * 4);
    }

  /********************
   * @dev Approve a new Borrower's Transfer Record. After the approval, the new
   *      Borrower can commit the possession of the Device at any time, until
   *      canceled by the Borrower himself, revoked by the Owner, or the Device
   *      is transferred to another Owner.
   * @param _own address   The address of the new Borrower's Transfer Record.
   * @param _eAccess bytes32 End-to-end encrypted Owner's Access Keys, shared
   *                         with the Borrower.
   * @param _eAccessDev bytes32 End-to-end encrypted Device Access Keys, shared
   *                            with the Borrower.
   * @param _ePriv bytes   The value for ePriv of the Transfer Record for _own,
   *                       if it wasn't created yet.
   * @param _eInfo bytes   The value for e of the Transfer Record for _own,
   *                       if it wasn't created yet.
   * @param _eAccessOwn bytes32 End-to-end encrypted Borrower's Access Key,
   *                            shared with the Owner, if wasn't shared yet.
   ********************/
    function approveBorrow(address payable _own, bytes32 _eAccess, bytes32 _eAccessDev, bytes memory _ePriv, bytes memory _eInfo, bytes32 _eAccessOwn) public payable {
	uint _fee = _serviceFee(500);
	require (getCurrentOwner(msg.sender) == msg.sender);
	_approveTransfer(msg.sender, _own, [_eAccess, bytes32(0), _eAccessOwn, bytes32(0), _eAccessDev], _ePriv, _eInfo, Tmode.BORROW);
	_own.transfer(_fee * 4);
    }

  /********************
   * @dev Approve a new Agent's Transfer Record. After the approval, the new
   *      Agent can transfer the ownership of the Device on the behalf of the
   *      Owner, unless revoked by the Owner.
   * @param _own address   The address of the new Agent's Transfer Record.
   * @param _eAccess bytes32 End-to-end encrypted Owner's Access Keys, shared
   *                         with the Agent.
   * @param _eAccessDev bytes32 End-to-end encrypted Device Access Keys, shared
   *                            with the Agent.
   * @param _ePriv bytes   The value for ePriv of the Transfer Record for _own,
   *                       if it wasn't created yet.
   * @param _eInfo bytes   The value for e of the Transfer Record for _own,
   *                       if it wasn't created yet.
   * @param _eAccessOwn bytes32 End-to-end encrypted Agent's Access Key,
   *                            shared with the Owner, if wasn't shared yet.
   ********************/
    function approveAgent(address payable _own, bytes32 _eAccess, bytes32 _eAccessDev, bytes memory _ePriv, bytes memory _eInfo, bytes32 _eAccessOwn) public payable {
	uint _fee = _serviceFee(1500);
	require (getCurrentOwner(msg.sender) == msg.sender);
	_approveTransfer(_chkOwner(), _own, [_eAccess, bytes32(0), _eAccessOwn, bytes32(0), _eAccessDev], _ePriv, _eInfo, Tmode.AGENT);
	_own.transfer(_fee * 12);
    }

  /********************
   * @dev Approve a new Backup Transfer Record. After the approval, the new
   *      Backup data holder will have access to the Owner's Access Key.
   *      After approving the Backup Transfer Record, the client side software
   *      needs to make a Blockchain transaction, like sending some amount back
   *      to the Owner's Transfer Record, to ensure the public key is recorded
   *      on the Blockchain.
   * @param _own address   The address of the new Backup Transfer Record.
   * @param _eAccess bytes32 End-to-end encrypted Owner's Access Keys, shared
   *                         with the Backup holder.
   * @param _eAccessDev bytes32 End-to-end encrypted Device Access Keys, shared
   *                            with the Backup holder.
   * @param _ePriv bytes   The value for ePriv of the Transfer Record for _own,
   *                       if it wasn't created yet.
   * @param _eInfo bytes   The value for e of the Transfer Record for _own,
   *                       if it wasn't created yet.
   * @param _eAccessOwn bytes32 End-to-end encrypted Backup holder's Access Key,
   *                            shared with the Owner, if wasn't shared yet.
   ********************/
    function approveBackup(address payable _own, bytes32 _eAccess, bytes32 _eAccessDev, bytes memory _ePriv, bytes memory _eInfo, bytes32 _eAccessOwn) public payable {
	uint _fee = _serviceFee(300);
	_approveTransfer(_chkOwner(), _own, [_eAccess, bytes32(0), _eAccessOwn, bytes32(0), _eAccessDev], _ePriv, _eInfo, Tmode.BACKUP);
	_own.transfer(_fee * 2);
    }

  /********************
   * @dev Share an end-to-end encrypted Access Key with another party.
   * @param _record address  An address of a record the Access Key pertains to,
   *                         a Transfer / Device / Inquiry Record.
   * @param _user address    A User whom the Access Key is shared with. Can be
   *                         an address of any private key, normally a Transfer
   *                         Record address or a public authority address.
   * @param _eAccess bytes32 End-to-end encrypted Access Key for the record,
   *                         encrypted using the keys of the User and the
   *                         transaction sender, see eAccess.
   ********************/
    function share(address _record, address _user, bytes32 _eAccess) public payable {
	_serviceFee(100);
	require (_record == msg.sender || eAccess[_record][msg.sender] != bytes32(0));
	_share(_record, _user, msg.sender, _eAccess);
    }
    
  /********************
   * @dev Deny a Transfer request, for a Transfer Record posted on the
   *      Blockchain.
   * @param _own address The address of the Transfer Record to be denied.
   ********************/
    function deny(address _own) public payable {
	_serviceFee(100);
	address curr = _chkOwner();
	require (transfers[_own].status == Tstatus.REQUESTED);
	require (transfers[_own].previous == curr);
	transfers[_own].status = Tstatus.DENIED;
    }

  /********************
   * @dev Revoke the approval from the Transfer Record.
   * @param _own address The address of the Transfer Record to be revoked.
   ********************/
    function revoke(address _own) public payable {
	_serviceFee(100);
	address curr = _chkOwner();
	require (transfers[_own].status == Tstatus.APPROVED);
	require (transfers[_own].previous == curr);
	if (transfers[_own].mode == Tmode.OWN) {
	    require (getCurrentOwner(curr) == curr);
	} else if (transfers[_own].mode == Tmode.BORROW) {
	    require (devices[getDevice(curr)].current != _own);
	} else {
	    require (transfers[_own].mode == Tmode.AGENT);
	}
	transfers[_own].status = Tstatus.REVOKED;
    }
    
  /********************
   * @dev Commit the possession of the Device.
   *      The caller must be the Transfer Record that commits the possession.
   *      For mode OWN, commit() finalizes the transfer of the Device ownership,
   *      and it non-reversible.
   *      For mode BORROW, commit() can be called multiple times to switch the
   *      possession of the Device between the Borrower(s) and the Owner, as
   *      long as the Owner owns the device, and the Borrower's record is in
   *      APPROVED status.
   ********************/
    function commit() public payable {
	_serviceFee(100);
	require (transfers[msg.sender].status == Tstatus.APPROVED);
	address device = getDevice(msg.sender);
	require (devices[device].current != msg.sender);
	if (transfers[msg.sender].mode == Tmode.BORROW) {
	    require (getCurrentOwner(device) == transfers[msg.sender].previous);
	} else {
	    require (transfers[msg.sender].mode == Tmode.OWN);
	    require (transfers[msg.sender].previous == devices[device].current || getOwner(devices[device].current) == msg.sender);
	}
	devices[device].current = msg.sender;
	emit Transfer(device, msg.sender);
    }

  /********************
   * @dev Cancel a Transfer Record instead of committing, or voluntarily quit
   *      being an Agent or Borrower.
   ********************/
    function cancel() public payable {
	_serviceFee(100);
	if (transfers[msg.sender].status == Tstatus.APPROVED) {
	    if (transfers[msg.sender].mode == Tmode.OWN || transfers[msg.sender].mode == Tmode.BORROW) {
		require (devices[getDevice(msg.sender)].current != msg.sender);
	    } else {
		require (transfers[msg.sender].mode == Tmode.AGENT);
	    }
	} else {
	    require (transfers[msg.sender].status == Tstatus.REQUESTED);
	}
	transfers[msg.sender].status = Tstatus.CANCELED;
    }
    
  /********************
   * @dev Send an Inquiry to a holder of Access Keys.
   * @param _inquiry address  A unique address for the Inquiry Record. Should
   *                          not overlap with Transfer and Device records.
   * @param _to address       The recipient of the Inquiry, a Transfer Record
   *                          address or a public License address.
   * @param _inquired address[] A list of addresses the Inquirer would like to
   *                          get Access Keys for - Transfer or Device Records.
   * @param _eInfo bytes      An optional end-to-end encrypted message to the
   *                          recipient of the Inquiry.
   * @param _eAccess bytes32  An optional end-to-end encrypted Access Key to
   *                          _eInfo. Required if _eInfo is not empty.
   *                          (see eAccess).
   ********************/
    function inquire(address _inquiry, address payable _to, address[] memory _inquired, bytes memory _eInfo, bytes32 _eAccess) public payable {
	uint _fee = _serviceFee(5500);
	require (transfers[_inquiry].previous == address(0) && devices[_inquiry].issuer == address(0) && inquiries[_inquiry].from == address(0));
	for (uint i = 0; i < _inquired.length; i++) require (eAccess[_inquired[i]][_to] != bytes32(0));
	if (_eInfo.length > 0) {
	    _share(_inquiry, _to, msg.sender, _eAccess);
	}
	inquiries[_inquiry].from = msg.sender;
	inquiries[_inquiry].to = _to;
	inquiries[_inquiry].eInfo = _eInfo;
	inquiries[_inquiry].inquired = _inquired;
	emit Inquiry(msg.sender, _to, _inquiry);
	_to.transfer(_fee * 5);
    }
    
  /********************
   * @dev Respond to an Inquiry.
   * @param _inquiry address The Inquiry Record address.
   * @param _eKeys bytes32[] A list of end-to-end encrypted Access Keys
   *                         supplied in the response. The order of the elements
   *                         matches the inquired addresses, plus optional
   *                         extra elements, in the same order as addresses
   *                         in _extra.
   * @param _extra address[] A list of additional addresses supplied with the
   *                         response, in addition to the inquired ones.
   * @param _eInfo bytes     An optional end-to-end encrypted message to the
   *                         Inquirer.
   * @param _eAccess bytes32 An optional end-to-end encrypted Access Key to
   *                         _eInfo. Required if _eInfo is not empty AND if
   *                         _eAccess was not supplied by the Inquirer (see
   *                         eAccess).
   ********************/
    function respond(address _inquiry, bytes32[] memory _eKeys, address[] memory _extra, bytes memory _eInfo, bytes32 _eAccess) public {
	require (inquiries[_inquiry].to == msg.sender);
	require (inquiries[_inquiry].inquired.length + _extra.length == _eKeys.length);
	if (_eInfo.length > 0 && eAccess[_inquiry][msg.sender] == bytes32(0)) {
	    _share(_inquiry, inquiries[_inquiry].from, msg.sender, _eAccess);
	}
	uint i;
	for (i = 0; i < inquiries[_inquiry].inquired.length; i++) {
	    _share(inquiries[_inquiry].inquired[i], inquiries[_inquiry].from, msg.sender, _eKeys[i]);
	}
	for (uint j = 0; j < _extra.length; j++) {
	    _share(_extra[j], inquiries[_inquiry].from, msg.sender, _eKeys[i + j]);
	}
	responses[_inquiry].responded = _extra;
	responses[_inquiry].eInfo = _eInfo;
	emit Response(_inquiry);
    }
    
  /********************
   * @dev Get response addresses and end-to-end encrypted Access Keys.
   * @param _inquiry address The Inquiry Record address.
   * @param _idx uint        The index of responded item.
   * @return address, bytes32 Address and Access Key
   ********************/
    function getResponse(address _inquiry, uint _idx) public view returns (address _addr, bytes32 _eAccess) {
	require (_idx < inquiries[_inquiry].inquired.length + responses[_inquiry].responded.length);
	_addr = _idx >= inquiries[_inquiry].inquired.length ?
	    responses[_inquiry].responded[_idx - inquiries[_inquiry].inquired.length] :
	    inquiries[_inquiry].inquired[_idx];
	_eAccess = eAccess[_addr][inquiries[_inquiry].from];
    }
}
