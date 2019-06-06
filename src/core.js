import Eth from 'ethjs';
import Web3 from 'web3';
import axios from 'axios';
import bigInt from 'big-integer';
import abi from '../lib/abi.json';
import { recoverTypedSignature } from 'eth-sig-util';
import { hexToString, toHex, fromWei, isAddress, utf8ToHex } from 'web3-utils';
import {
	toBuffer,
	hashPersonalMessage,
	ecsign,
	bufferToHex,
	publicToAddress,
	addHexPrefix,
	fromSigned,
	bufferToInt,
	intToHex,
	toUnsigned,
	stripHexPrefix,
	fromRpcSig,
	ecrecover,
	toChecksumAddress
} from 'ethereumjs-util';


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Global Constants */

const CONTRACT = {
	address: {
		main: '0x8F6A7781F54335D10d02bDD9ce66ACE1647AbCA7',
		rinkeby: '0x731C54d14d853af7f6CB587c680Efc1db11a3757'
	},
	deployed: { // Block in which contract was deployed
		main: 7199557,
		rinkeby: 3754313
	}
};

const DEFAULTS = {
	updateOnNetworkChange: true,
	useOwnProvider: false,
	provider: {
		main: 'https://mainnet.infura.io/v3/1f0678a9617c4c7aa6896fd667aaa88c',
		rinkeby: 'https://rinkeby.infura.io/v3/1f0678a9617c4c7aa6896fd667aaa88c'
	}
};

const SUPPORTED_NETWORKS = ['main', 'rinkeby'/*, 'kovan', 'ropsten'*/];

const NETWORK_CODES = {
	'1': 'main',
	//'3': 'ropsten',
	//'42': 'kovan',
	'4': 'rinkeby'
};

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Environmental & Abstract Functions */

const _isBrowser = () => {
	return typeof window !== 'undefined';
};

const _ensureMetaMask = async (required) => {
	if (required && _isBrowser()) {
		await window.ethereum.enable();
	}
};

const _op = async (f, resolve, options) => { // Callbackify async ops
	const defaults = { ensureMetaMask: false };
	const _options = options ? {
		...defaults,
		...options
	} : defaults;
	if (resolve) {
		try {
			await _ensureMetaMask(_options.ensureMetaMask);
			const res = await f();
			resolve(null, res);
		} catch (err) {
			resolve(err);
		}
	} else {
		await _ensureMetaMask(_options.ensureMetaMask);
		return f();
	}
};

const _tx = async (provider, tx, event) => {
	let checkConfirmed; // Interval to manually check confirmation
	let check = 0; // Number of times confirmation checked
	let limit = 10; // Max number of times to check confirmation
	tx.on('transactionHash', (hash) => {
		checkConfirmed = setInterval(async () => {
			if (check > limit) {
				clearInterval(checkConfirmed);
				event({ name: 'slow' });
			} else {
				check += 1;
				try { // Silently catch network errors on interval
					const web3 = new Web3(provider);
					const receipt = await web3.eth.getTransactionReceipt(hash);
					if (receipt && receipt.blockNumber) { // Transaction mined
						clearInterval(checkConfirmed);
						event({
							name: receipt.status ? 'confirmed' : 'failed',
							data: receipt
						});
					}
				} catch (err) {
				}
			}
		}, 20000); // Assume 20 secs / block
		event({ name: 'hash', data: hash });
	}).on('error', () => {
		event({ name: 'error' });
	});
};


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Utils */

const utf8ToBytes20 = (utf8) => {
	const zeros = '0000000000000000000000000000000000000000';
	const hex = utf8ToHex(utf8);
	return hex + zeros.substring(0, 42 - hex.length);
};

const utf8ByteLength = (utf8) => {
	return utf8ToBytes20(utf8).length - 2;
}

const isAliasBytes20 = (alias) => {
	return utf8ByteLength(alias) <= 40;
}

const bytes32ToAddress = (bytes32) => {
	return toChecksumAddress('0x' + bytes32.substring(26));
};

const packTypedData = (data) => {
	return Object.keys(data).map(k => {
		const value = data[k];
		return {
			type: 'string',
			name: k,
			value: typeof value === 'string' ? value : JSON.stringify(value)
		};
	}).sort((a, b) => {
		const _a = utf8ToHex(a.name).substring(2);
		const _b = utf8ToHex(b.name).substring(2);
		return _a.localeCompare(_b);
	});
}

const signData = ({ data, privateKey }) => {
	const message = toBuffer(JSON.stringify(data));
	const msgHash = hashPersonalMessage(message);
	return bufferToHex((({ v, r, s }) => {
		const z = '0000000000000000000000000000000000000000000000000000000000000000';
		const p = (hex) => { return z.substring(0, 64 - hex.length) + hex; };
		const rSig = fromSigned(r);
		const sSig = fromSigned(s);
		const vSig = bufferToInt(v);
		const rStr = p(toUnsigned(rSig).toString('hex'));
		const sStr = p(toUnsigned(sSig).toString('hex'));
		const vStr = stripHexPrefix(intToHex(vSig));
		return addHexPrefix(rStr.concat(sStr, vStr)).toString('hex');
	})(ecsign(msgHash, toBuffer(privateKey))));
}

const getSigningAddress = ({ data, sig }) => {
	const message = toBuffer(JSON.stringify(data));
  const hash = hashPersonalMessage(message);
  const sigParams = fromRpcSig(toBuffer(sig));
  const publicKey = ecrecover(hash, sigParams.v, sigParams.r, sigParams.s);
  const signedBy = publicToAddress(publicKey);
  return bufferToHex(signedBy);
}

const getFiatConversionRates = async () => {
	const res = await axios.get('https://min-api.cryptocompare.com/data/price?fsym=ETH&tsyms=USD,DKK,JPY,PLN,AUD,EUR,KRW,RUB,BRL,GBP,MXN,SEK,CAD,HKD,MYR,SGD,CHF,HUF,NOK,THB,CLP,IDR,NZD,TRY,CNY,ILS,PHP,TWD,CZK,INR,PKR,ZAR');
	return res.data;
};

const getActiveNetwork = () => {
	let network = null;
	if (_isBrowser() && window.ethereum) {
		const { networkVersion } = window.ethereum;
		network = NETWORK_CODES[networkVersion];
	}
	return network;
};

const weiToFixedEth = (wei, precision) => {
	return parseFloat(fromWei(wei, 'ether')).toFixed(precision).toString();
};

const parseLogs = (logs) => {
	const parser = {
		BalIORecord: data => {
			const toAlias = hexToString(data[0]);
			const fromAlias = hexToString(data[1]);
			return {
				event: data[3] ? (toAlias ? 'deposit' : 'withdrawal') : 'transfer',
				data: toAlias ? {
					toAlias,
					fromAlias,
					amount: data[2]
				} : {
					alias: fromAlias,
					amount: data[2]
				}
			};
		},
		DirRecord: data => {
			const creation = data[1] === ZERO_ADDRESS;
			const alias = hexToString(data[0]);
			return {
				event: creation ? 'create_alias' : (data[3] ? 'change_address' : 'recover'),
				data: creation ? {
					alias,
					address: data[2]
				} : {
					alias,
					oldAddress: data[1],
					newAddress: data[2]  
				}
			};
		},
		SetData: data => {
			return null; // TODO not implemented
		}
	};
	return logs.map(item => {
		const { event, returnValues, blockNumber, transactionHash, transactionIndex, id } = item;
		return parser[event] ? {
			...parser[event](returnValues),
			timestamp: parseInt(returnValues.time),
			transactionIndex,
			transactionHash,
			blockNumber,
			id
		} : null;
	});
};

const encodeHypermessageURI = (data) => {

	const extra = [];
	const hyper = {
		_signed_: [],
		_params_: []
	};
	
	const encode = (k, v) => {
		return `${encodeURIComponent(k)}=${encodeURIComponent(v)}`;
	}

	for (let d of Object.keys(data)) {
		if (typeof hyper[d] !== 'undefined') {
			for (let key of Object.keys(data[d])) { // Prefix subkeys
				hyper[d].push(encode(d + key, data[d][key]));
			}
		} else {
			extra.push(encode(d, data[d]));
		}
	}

	return [ ...hyper._params_, ...hyper._signed_, ...extra ].join('&');
};

const decodeHypermessageURI = (uri) => {

	let s = uri;
	const extra = {};
	const hyper = {
		_signed_: {},
		_params_: {}
	};
	
	if (uri && uri.indexOf('#') !== -1) {
		s = uri.split('#')[1];
	} else if (uri && uri.indexOf('?') !== -1) {
		s = uri.split('?')[1];
	}

  const components = s.split('&');

  for (let c of components) {
  	let unsigned = true;
  	const kvp = c.split('=');
  	const key = decodeURIComponent(kvp[0]);
  	const val = decodeURIComponent(kvp[1]);
  	for (let prefix of Object.keys(hyper)) {
  		if (key.indexOf(prefix) !== -1) {
  			hyper[prefix][key.substring(prefix.length)] = val;
  			unsigned = false;
  		}
  	}
  	if (unsigned) {
  		extra[key] = val;
  	}
  }

	return { ...hyper, ...extra };
};

const HypermessageParser = (options) => {

	return async (req, res, next) => {

		try {

			const _options = {
				timeDeltaMax: 300,
				requireTimestamp: true,
				...[options || {}]
			};

			const core = req.app.get('core');
			const received = Math.floor(Date.now() / 1000);
			let data;

			if (req.body._params_) { // json encoded
				data = req.body;
			} else { // uri encoded
				data = decodeHypermessageURI(req.url);
			}

			if (!core) {
				throw { responseCode: 500, msg: 'Expected reference to \'core\' set on express app object' };
			}

			if (!data) {
				throw { responseCode: 400, msg: 'Failed to parse hypermessage' };
			}

			const verified = await core.verifyHypermessage(data);

			if (_options.requireTimestamp) {
				const t = parseInt(verified.signed['🕒']);
				if (!t || isNaN(t) || !isFinite(t)) {
					throw	{ responseCode: 400, msg: `Signed data must include \'🕒\' (time) in seconds since unix epoch (e.g. ${received})` };
				}

				if (Math.abs(received - t) > _options.timeDeltaMax) { // 5 mins window
					throw { responseCode: 400, msg: `Difference between \'🕒\' (time) in signed data and time measured by server exceeds timeDeltaMax (${options.timeDeltaMax} secs) -- please ensure client device clock is accurate.`};
				}
			}

			req.hypermessage = { ...verified, received };
			next();

		} catch (err) {
			res.status(err.responseCode || 500).send(err.msg);
		}
	};
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* API Instance */

class AliasEarth {

	constructor() { // Nothing to see here
	}

	async init(options, resolve) {
		return _op(async () => {
			this.options = options ? { ...DEFAULTS, ...options } : DEFAULTS;
			if (_isBrowser() && !this.options.useOwnProvider) { // Use injected window.ethereum
				if (window.ethereum) { // Provider detected
					this.options.provider = window.ethereum;
					if (!this.options.network) { // Network not specified
						this.options.network = getActiveNetwork();
					}
					if (this.options.updateOnNetworkChange) {
						this.options.provider.on('networkChanged', (code) => {
							this.options.network = NETWORK_CODES[code]
						});

					}
				} else { // No injected provider
					// TODO Prompt user to install MetaMask
				}
			} else { // Not in browser
				this.options.provider = getDefaultHttpProvider(this.options.network);
			}

			// if (!this.options.network) {
			// 	throw Error("Network not found. Please specify 'main', 'rinkeby', 'ropsten', or 'kovan'");
			// }

			if (!this.options.provider) {
				throw Error('Ethereum provider not found');
			}

			this.contract = await getContractInstance({
				...this.options,
				provider: this.options.provider
			});
		}, resolve);
	}

	config() {
		return this.options;
	}

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* Write Blockchain Data */

	async createAlias({ alias, linked, recovery }, event, resolve) {
		return _op(async () => {

			if (!alias) {
				throw Error('Must provide alias');
			}

			if (utf8ByteLength(alias) > 40) {
				throw Error('Alias byte length must be less than or equal to 40. Byte length can be calculated using static method AliasEarth.utf8ByteLength()');
			}

			if (!linked) {
				throw Error('Must provide managing address');
			}

			_tx(this.options.provider, this.contract.methods.createAccount(
				utf8ToBytes20(alias),
				recovery ? recovery : ZERO_ADDRESS
			).send({ from: linked }), event);
		}, resolve);
	}

	async setLinkedAddress({ alias, newLinked, from }, event, resolve) {
		return _op(async () => {

			let _from = from;
			if (!_from) {
				_from = await this.getActiveAddress();
			}

			if (!alias) {
				throw Error('Must provide alias');
			}

			if (!newLinked) {
				throw Error('Must provide \'newLinked\'');
			}

			if (!isAddress(newLinked)) {
				throw Error('\'newLinked\' is not a valid Ethereum address');
			}

			if (!_from) {
				throw Error('Failed to detect sender address, please specify \'from\'');
			}

			_tx(this.options.provider, this.contract.methods.changeLinkedAddress(
				utf8ToBytes20(alias),
				newLinked
			).send({ from: _from }), event);
		}, resolve);
	}

	async setRecoveryAddress({ alias, recovery, from }, event, resolve) {
		_op(async () => {

			let _from = from;
			if (!_from) {
				_from = await this.getActiveAddress();
			}

			if (!alias) {
				throw Error('Must provide alias');
			}

			if (!recovery) {
				throw Error('Must provide recovery');
			}

			if (!isAddress(recovery)) {
				throw Error('\'recovery\' is not a valid Ethereum address');
			}
 
			if (!_from) {
				throw Error('Failed to detect sender address, please specify \'from\'');
			}

			_tx(this.options.provider, this.contract.methods.setRecoveryAddress(
				utf8ToBytes20(alias),
				recovery
			).send({ from: _from }), event);
		}, resolve);
	}

	async recover({ alias, recovery }, event, resolve) {
		_op(async () => {

			if (!alias) {
				throw Error('Must provide alias');
			}

			if (!recovery) {
				throw Error('Must provide recovery');
			}

			if (!isAddress(recovery)) {
				throw Error('\'recovery\' is not a valid Ethereum address');
			}

			_tx(this.options.provider, this.contract.methods.recover(
				utf8ToBytes20(alias)
			).send({ from: recovery }), event);
		}, resolve);
	}

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* Read Blockchain Data */

	async aliasExists(alias, resolve) {
		return _op(async () => {

			if (!alias) {
				throw Error('Must provide alias');
			}

			const exists = await this.contract.methods.accountExists(
				utf8ToBytes20(alias)
			).call();

			return exists;
		}, resolve);
	}

	async isAddressAvailable(address, resolve) {
		return _op(async () => {
			const encountered = await this.contract.methods.encountered(address).call();
			return !encountered;
		}, resolve);
	}

	async getAliasFromAddress(address, resolve) {
		return _op(async () => {

			if (!address) {
				throw Error('Must specify address');
			}

			const hex = await this.contract.methods.directory(address).call();
			return hexToString(hex);
		});
	}

	async getAddresses(alias, resolve) {
		return _op(async () => {

			if (!alias) {
				throw Error('Must specify alias');
			}

			const addresses = await this.contract.methods.accounts(
				utf8ToBytes20(alias)
			).call();

			return {
				linked: addresses[0] === ZERO_ADDRESS ? '' : addresses[0],
				recovery: addresses[1] === ZERO_ADDRESS ? '' : addresses[1],
			};
		}, resolve);
	}

	async getBalances(identity, resolve) {
		return _op(async () => {

			const _identity = identity || await this.getActiveAddress();
			const balance = {};
			let alias = '';
			let address = '';
			
			if (isAddress(_identity)) { // Passed address
				address = _identity;
				const aliasHex = await this.contract.methods.directory(address).call();
				alias = hexToString(aliasHex);
			} else { // Passed alias
				alias = _identity;
				address = await this.contract.methods.getLinkedAddress(utf8ToBytes20(alias)).call();
			}

			if (alias) {
				balance.alias = await this.contract.methods.balances(utf8ToBytes20(alias)).call();
			}

			if (address) {
				const web3 = new Web3(this.options.provider);
				balance.address = await web3.eth.getBalance(address);
			}

			return { alias, address, balance };
		});
	}

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* Read Log Data */

	getLogs({ event, filter, fromBlock, toBlock }, resolve) {
		return _op(async () => {

			const { network } = this.options;
			const _fromBlock = !fromBlock || fromBlock < CONTRACT.deployed[network] ? CONTRACT.deployed[network] : fromBlock;
			const _toBlock = toBlock || 'latest';

			if (!(event === 'BalIORecord' || event === 'DirRecord' || event === 'SetData')) {
				throw Error('Must specify \'event\' as \'BalIORecord\', \'DirRecord\', or \'SetData\'');
			}

			const logs = await this.contract.getPastEvents(event, {
				fromBlock: _fromBlock,
    		toBlock: _toBlock,
    		filter
			});

			return parseLogs(logs);
		}, resolve);
	};

	getDeposits({ toAlias, fromAlias, fromBlock, toBlock }, resolve) {
		return _op(async () => {

			if (!(toAlias || fromAlias)) {
				throw Error('Please specify \'toAlias\' and/or \'fromAlias\'');
			}

			const filter = {};

			if (toAlias) {
				filter.to = utf8ToBytes20(toAlias);
			}

			if (fromAlias) {
				filter.from = utf8ToBytes20(fromAlias);
			}

			const data = await this.getLogs({
				event: 'BalIORecord',
				filter,
				fromBlock,
				toBlock
			});

			return data.filter(item => {
				return item.event === 'deposit';
			});
		}, resolve);
	}

	getBalanceActivity({ alias, selfOnly, fromBlock, toBlock }, resolve) {
		return _op(async () => {

			if (!alias) {
				throw Error('Please specify \'alias\'');
			}

			const hex = utf8ToBytes20(alias);
			const filter = { to: [utf8ToBytes20(''), hex] };
			if (selfOnly) {
				filter.from = hex;
			}

			const data = await this.getLogs({
				event: 'BalIORecord',
				fromBlock,
				toBlock,
				filter
			});

			return data;
		}, resolve);
	}

	getNewAliasLog(options, resolve) {
		return _op(async () => {
			const _options = options || {};
			const { fromBlock, toBlock } = _options;
			const data = await this.getLogs({
				event: 'DirRecord',
				fromBlock,
				toBlock
			});
			return data.filter(item => {
				return item.event === 'create_alias';
			});
		}, resolve);
	}

	getAliasEventLog({ alias, fromBlock, toBlock }, resolve) {
		return _op(async () => {

			if (!alias) {
				throw Error('Please specify \'alias\'');
			}

			const data = await this.getLogs({
				event: 'DirRecord',
				filter: { username: utf8ToBytes20(alias) },
				fromBlock,
				toBlock
			});

			return data;
		}, resolve);
	}

	getNormalizedAliasData(options, resolve) {
		return _op(async () => {
			const _options = options || {};
			const { fromBlock, toBlock } = _options;
			const logs = await this.getLogs({
				event: 'DirRecord',
				fromBlock,
				toBlock
			});

			const normalized = {};
			for (let item of logs) {
				const { event, data, blockNumber, transactionHash, timestamp } = item;
				const { alias, address, newAddress } = data;
				if (normalized[alias]) {
					normalized[alias].address = newAddress;
				} else {
					const initial = event === 'create_alias' ? {
						address,
						blockNumber,
						transactionHash,
						timestamp
					} : {};
					normalized[alias] = {
						address: newAddress,
						...initial
					};
				}
			}

			return normalized;
		}, resolve);
	}

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* Funds API */

	async sendEther({ toAddress, fromAddress, amount }, event, resolve) {
		return _op(async () => {
			let _fromAddress;

			if (fromAddress) { // Explicit sender address
				_fromAddress = fromAddress;
			} else { // Autodetect
				_fromAddress = await this.getActiveAddress();
			}

			if (!_fromAddress) {
				throw Error('\'fromAddress\' was not specified and could not be auto-detected from MetaMask');
			}

			if (!amount) {
				throw Error('Please specify the amount of wei that you want to deposit');
			}

			if (typeof amount !== 'string') {
				throw Error('Please specify \'amount\' as a string to avoid accuracy errors');
			}

			if (!bigInt(amount).gt('0')) {
				throw Error('\'amount\' must be a positive integer');
			}

			const web3 = new Web3(this.options.provider);
			_tx(this.options.provider, web3.eth.sendTransaction({
				to: toAddress,
				from: _fromAddress,
				value: amount
			}), event);
		});
	}

	async deposit({ toAlias, fromAddress, amount }, event, resolve) {
		return _op(async () => {
			let _fromAddress;
			let _fromAlias;
			let _toAlias;

			if (fromAddress) { // Explicit sender address
				_fromAddress = fromAddress;
			} else { // Autodetect
				_fromAddress = await this.getActiveAddress();
			}

			if (!_fromAddress) {
				throw Error('\'fromAddress\' was not specified and could not be auto-detected from MetaMask');
			}

			if (!amount) {
				throw Error('Please specify the amount of wei that you want to deposit');
			}

			if (typeof amount !== 'string') {
				throw Error('Please specify \'amount\' as a string to avoid accuracy errors');
			}

			if (!bigInt(amount).gt('0')) {
				throw Error('\'amount\' must be a positive integer');
			}

			_fromAlias = await this.contract.methods.directory(_fromAddress).call();
			_toAlias = utf8ToBytes20(toAlias);

			if (_fromAlias === _toAlias) { // Deposit to own alias
				_tx(this.options.provider, this.contract.methods.depositToSelf().send({
					from: _fromAddress,
					value: amount
				}), event);
			} else { // Deposit to another alias
				_tx(this.options.provider, this.contract.methods.depositToAccount(
					_toAlias
				).send({
					from: _fromAddress,
					value: amount
				}), event);
			}
		}, resolve);
	}

	async withdraw({ amount, toAddress }, event, resolve) {
		return _op(async () => {
			let _toAddress;

			if (toAddress) { // Explicit sender address
				_toAddress = toAddress;
			} else { // Autodetect
				_toAddress = await this.getActiveAddress();
			}

			if (!_toAddress) {
				throw Error('\'toAddress\' was not specified and could not be auto-detected from MetaMask');
			}

			if (!amount) {
				throw Error('Please specify the amount of wei that you want to withdraw');
			}

			if (typeof amount !== 'string') {
				throw Error('Please specify \'amount\' as a string to avoid accuracy errors');
			}

			if (!bigInt(amount).gt('0')) {
				throw Error('\'amount\' must be a positive integer');
			}

			_tx(this.options.provider, this.contract.methods.withdrawFunds(
				amount // amount in wei	
			).send({ from: _toAddress }), event);
		}, resolve);
	}

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* Hypermessage API */

	async verifyHypermessage(data, options, resolve) {
		return _op(async () => {

			let address;
			let alias;

			if (!data) {
				throw { responseCode: 400, msg: 'Hypermessage not found' };
			}

			const { _params_, _signed_ } = data;

 			if (!data || !data._params_ || !data._signed_) {
				throw { responseCode: 400, msg: 'Failed to parse hypermessage' };
 			}

			if (!_params_.sig) {
				throw { responseCode: 400, msg: 'Required \'sig\' parameter not provided' };
			}

			if (!_params_.alias) {
				throw { responseCode: 400, msg: 'Required \'alias\' parameter not provided' };
			}

			if (!_params_.network) {
				throw { responseCode: 400, msg: 'Required \'network\' parameter not provided' };
			}

			if (_params_.network !== this.options.network) {
				throw { responseCode: 403, msg: 'Provided \'network\' parameter does not match' };
			}

			if (_params_.sigtype === 'metamask_typed') {
				address = recoverTypedSignature({ data: packTypedData(_signed_), sig: _params_.sig });
			} else {
				throw { responseCode: 400, msg: 'Required _sigtype param not provided' }
			}

			try {	// Get alias name corresponding to address from blockchain
				const hex = await this.contract.methods.directory(address).call();
				alias = hexToString(hex);
			} catch (err) {
				throw { responseCode: 500, msg: 'Failed to verify data from blockchain. This is most likely a network error.' };
			}

			if (alias !== _params_.alias) { // Mismatch
				throw { responseCode: 403, msg: 'Failed to verify signature' };
			}
 
			return {
				author: { alias, address },
				params: _params_,
				signed: _signed_, // Signed data with params
				id: _params_.sig.substring(2, 26), // UUID generated from sig
			};

		}, resolve);
	};

	async createHypermessage(signed, options, resolve) {
		return _op(async () => {

			// TODO add support for sigtype 'native'

			const _options = {
				timestamp: true,
				encode: 'json',
				...options
			};

			const signer = await this.getActiveAddress();
			const alias = await this.getActiveAlias();

			if (!alias) {
				throw Error('Signing address is not linked to any alias');
			}

			const { timestamp, encode } = _options;
			const eth = new Eth(this.options.provider);
			const _signed_ = timestamp ? {
				...signed,
				'🕒': Math.floor(Date.now() / 1000)
			} : signed;

			const sig = await eth.signTypedData(packTypedData(_signed_), signer);

			const _params_ = {
				alias,
				sig,
				sigtype: 'metamask_typed',
				network: this.options.network
			};

			if (encode === 'json') {
				return { _signed_, _params_ };
			} else if (encode === 'uri') {
				return encodeHypermessageURI({ _signed_, _params_ });
			}

		}, resolve, { ensureMetaMask: true });
	}

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* Environmental Helpers */

	async getActiveAddress(resolve) {
		return _op(async () => {
			const web3 = new Web3(this.options.provider);
			const accounts = await web3.eth.getAccounts();
			return accounts[0];
		}, resolve, { ensureMetaMask: true });
	}

	async getActiveAlias(resolve) {
		return _op(async () => {
			const address = await this.getActiveAddress();
			const hex = await this.contract.methods.directory(address).call();
			return hexToString(hex);
		}, resolve, { ensureMetaMask: true });
	}
}

const getDefaultHttpProvider = (network) => {
	return new Web3.providers.HttpProvider(DEFAULTS.provider[network]);
};

const getContractInstance = async (options, resolve) => { // Return web3 contract instance
	return _op(async () => {
		const _options = options ? { ...DEFAULTS, ...options } : DEFAULTS;
		const network = _options.network;
		const provider = _options.useOwnProvider ? getDefaultHttpProvider(network) : _options.provider;

		if (!provider) {
			throw Error('Ethereum provider not found');
		}

		const web3 = new Web3(provider);
		const address = CONTRACT.address[network];
		const instance = await new web3.eth.Contract( // Load contract from address
			abi, // Interface
			address // Contract address
		);
		return instance; // Return the contract instance
	}, resolve);
}

const connect = async (options, resolve) => {
	return _op(async () => {
		const instance = new AliasEarth();
		await instance.init(options);
		return instance;
	}, resolve);
};

module.exports = {
	connect, // Get high level api
	getContractInstance, // Just the contract object
	HypermessageParser,
	constants: {
		CONTRACT,
		DEFAULTS,
		SUPPORTED_NETWORKS,
		NETWORK_CODES
	},
	utils: {
		utf8ToBytes20,
		utf8ByteLength,
		isAliasBytes20,
		bytes32ToAddress,
		packTypedData,
		signData,
		getSigningAddress,
		getFiatConversionRates,
		getActiveNetwork,
		weiToFixedEth,
		parseLogs,
		encodeHypermessageURI,
		decodeHypermessageURI
	}
};
