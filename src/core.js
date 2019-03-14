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
	ecrecover
} from 'ethereumjs-util';


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Global Constants */

const CONTRACT = {
	address: {
		main: '0x8F6A7781F54335D10d02bDD9ce66ACE1647AbCA7',
		rinkeby: '0x731C54d14d853af7f6CB587c680Efc1db11a3757'
	}
};

const DEFAULTS = {
	network: 'main',
	provider: {
		main: 'https://mainnet.infura.io/v3/1f0678a9617c4c7aa6896fd667aaa88c',
		rinkeby: 'https://rinkeby.infura.io/v3/1f0678a9617c4c7aa6896fd667aaa88c'
	}
};

const NETWORK_CODES = {
	'1': { key: 'main', label: 'Main Ethereum Network' },
	'3': { key: 'ropsten', label: 'Ropsten Test Network' },
	'42': { key: 'kovan', label: 'Kovan Test Network' },
	'4': { key: 'rinkeby', label: 'Rinkeby Test Network' }
};


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Environmental & Abstract Functions */

const _isBrowser = () => {
	return typeof window !== 'undefined';
};

const _ensureMetaMask = async () => {
	if (_isBrowser()) {
		await window.ethereum.enable();
	}
};

const _op = async (f, resolve) => { // Callbackify async ops
	if (resolve) {
		try {
			await _ensureMetaMask();
			const res = await f();
			resolve(null, res);
		} catch (err) {
			resolve(err);
		}
	} else {
		await _ensureMetaMask();
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
				event({ name: 'timeout' });
			} else {
				check += 1;
				try {
					const web3 = new Web3(provider);
					const receipt = await web3.eth.getTransactionReceipt(hash);
					if (receipt && receipt.blockNumber) { // Transaction mined
						console.log('-----receipt', receipt);
						clearInterval(checkConfirmed);
						event({
							name: receipt.status ? 'confirmed' : 'failed',
							data: receipt
						});
					}
				} catch (err) {
					console.log(err);
				}
			}
		}, 20000); // Assume 20 secs / block
		event({ name: 'hash', data: hash });
	}); // Transaction was sent
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

const isSameAddress = (a, b) => {
	return a.toUpperCase() === b.toUpperCase();
}

const packTypedData = (data) => {
	return Object.keys(data).map(k => {
		const value = data[k];
		return {
			type: 'string',
			name: k,
			value: typeof value === 'string' ? value : JSON.stringify(value)
		};
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

const getContractInstance = async ({ network, contract, provider }) => { // Return web3 contract instance

	const _provider = provider || DEFAULTS.provider[network];
	const web3 = new Web3(_provider);
	let instance;

	if (network === 'main' || network === 'rinkeby') { // Public network

		const address = CONTRACT.address[network];
		instance = await new web3.eth.Contract( // Load contract from address
			abi, // Interface
			address // Contract address
		);

	} else if (network === 'local') { // Testing / dev
		if (!contract) {
			throw Error(`For local deployments you must pass an existing contract instance as 'contract' in options`);
		}
		instance = contract; // Locally deployed contract passed in options
	} else {
		throw Error(`For the network option, please specify 'main', 'rinkeby', or 'local' (for dev)`);
	}

	return instance; // Return the contract instance
}

class AliasEarth {

	constructor() { // Nothing to see here
	}

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* Export Constants */

  static constants() {
    return {
      CONTRACT,
      DEFAULTS,
      NETWORK_CODES
    };
  }


	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* Export General Logic */

	static utf8ToBytes20(utf8) { return utf8ToBytes20(utf8); }

	static utf8ByteLength(utf8) { return utf8ByteLength(utf8); }

	static isAliasBytes20(alias) { return isAliasBytes20(alias); }

	static isSameAddress(a, b) { return isSameAddress(a, b); }

	static packTypedData(data) { return packTypedData(data); }

	static signData(params) { return signData(params); }

	static getSigningAddress(params) { return getSigningAddress(params); }

	static async getContractInstance(options) { return await getContractInstance(options); }

	static async _op(f, resolve) { return _op(f, resolve); }

	static async _tx(f, event) { return _tx(f, event); }


	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
	/* Async Instance API */

	async init(options, resolve) {
		return _op(async () => {

			this.options = options ? { ...DEFAULTS, ...options } : DEFAULTS;

			if (_isBrowser()) { // In browser
				if (window.ethereum) { // Provider detected

					this.options.provider = window.ethereum;
					if (!options.network) { // Network not specified
						const version = await window.ethereum.networkVersion;
						console.log('_network', NETWORK_CODES[version]);
						this.options.network = version ? NETWORK_CODES[version].key : DEFAULTS.network;
					}
					
				} else { // No injected provider
					// TODO Prompt user to install MetaMask
				}
			} else { // Not in browser
				this.options.provider = new Web3.providers.HttpProvider(DEFAULTS.provider[this.options.network]);
			}

			if (!this.options.network) {
				throw Error("Network not found. Please specify 'main', 'rinkeby', 'ropsten', or 'kovan'");
			}

			if (!this.options.provider) {
				throw Error('Ethereum provider not found');
			}

			this.contract = await getContractInstance({
				...this.options,
				provider: this.options.provider
			});

		}, resolve);
	}

	async deposit({ toAlias, fromAddress, amount }, resolve) {

		// TODO apply _op => _tx pattern

		let _fromAddress;
		let _from

		if (!amount) {
			throw Error('Please specify the amount of wei that you want to deposit');
		}

		if (typeof amount !== 'string') {
			throw Error('Please specify \'amount\' as a string to avoid accuracy errors');
		}

		if (!bigInt(amount).gt('0')) {
			throw Error('\'amount\' must be a positive integer');
		}

		if (!fromAddress) { // No sender specified
			_fromAddress = await this.getActiveAddress();
		}

		await this.contract.methods.depositToAccount(utf8ToBytes20(toAlias)).send({
			from: _fromAddress,
			value: amount
		});

	}

	async transfer() {
		// TODO
	}

	async withdraw() {
		// TODO 
	}

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

			await _tx(this.options.provider, this.contract.methods.createAccount(
				utf8ToBytes20(alias),
				recovery
			).send({ from: linked }), event);

		}, resolve);
	}

	async signDataWithMetaMask(data, resolve) {
		return _op(async () => {
			const eth = new Eth(this.options.provider);
			const signer = await this.getActiveAddress();
			const packed = packTypedData(data);
			const sig = await eth.signTypedData(packed, signer);
			return { data: packed, sig };
		}, resolve);
	}

	async signAuthParams({ app, exp }, resolve) {
		return _op(async () => {

			const alias = await this.getActiveAlias();
			let sig;

			if (!alias) {
				throw Error('The currently selected address is not associated with any alias');
			}

			if (!app) {
				throw Error('\'app\' (application name) must be provided');
			}

			if (!exp) {
				throw Error('\'exp\' (expiry in unix time) must be provided');
			}

			try {
				const signed = await this.signDataWithMetaMask({
					'🔑': alias,
					'🔐': app,
					'⏱️': exp
				});
				sig = signed.sig;
			} catch (err) {
				throw Error('User rejected signature');
			}

			return `_alias=${encodeURIComponent(alias)}&_app=${encodeURIComponent(app)}&_exp=${exp}&_sig=${sig}`;
		}, resolve);
	}

	async verifyAuthParams({ _alias, _app, _exp, _sig }, { app, maxSession, getCached }, resolve) {
		return _op(async () => {

			const _maxSession = maxSession || 2592000; // 30 days
			const _now = Math.floor(Date.now() / 1000);
			let address;
			let alias;

			if (!_alias) {
				throw Error({ responseCode: 400, msg: 'alias (alias mapped to signing address) must be provided in (eg \'alice\')' });
			}

			if (!_app) {
				throw Error({ responseCode: 400, msg: 'app (application name) must be provided (eg \'myapp\')' });
			}

			if (!_exp) {
				throw Error({ responseCode: 400, msg: 'exp (expiry time) not provided (eg \'1524241200\'' });
			}

			if (!_sig) {
				throw Error({ responseCode: 400, msg: 'Sig not provided' });
			}

			if (_now > _exp) { // Sig expired
				throw Error({ responseCode: 403, msg: 'Signature expired' });
			}

			if (_exp > _now + maxSession) {
				throw Error({ responseCode: 403, msg: `exp time too far in the future. Server\'s maxSession is ${maxSession} seconds` });
			}

			// Pack data how it would have been signed on the client
			const data = packTypedData({
				'🔑': _alias,
				'🔐': _app,
				'⏱️': _exp
			});

			try { // Compute signing address based on provided sig
				address = recoverTypedSignature({ data, sig: _sig });
			} catch (err) {
				throw Error({ responseCode: 403, msg: 'Failed to validate signature' });
			}

			if (getCached) {
				alias = await getCached(address);
			}

			if (!alias) { // Didn't get a value from cache
				try {	// Get alias name corresponding to address from blockchain
					const hex = await this.contract.methods.directory(address).call();
					alias = hexToString(hex);
				} catch (err) {
					throw Error({ responseCode: 500, msg: 'Failed to verify data from blockchain. This is most likely a network error.' });
				}
			}

			if (alias !== _alias) { // Alias doesn't match
				throw Error({ responseCode: 403, msg: 'Failed to validate signature' });
			}

			return { address, alias, app: _app, exp: _exp, sig: _sig };
		}, resolve);
	}

	async isAliasAvailable(alias, resolve) {
		return _op(async () => {

			if (!alias) {
				throw Error('Must provide alias');
			}

			const exists = await this.contract.methods.accountExists(
				utf8ToBytes20(alias)
			).call();

			return !exists;
		}, resolve);
	}

	async isAddressAvailable(address, resolve) {
		return _op(async () => {
			const encountered = await this.contract.methods.encountered(address).call();
			return !encountered;
		}, resolve);
	}

	async getActiveAddress(resolve) {
		return _op(async () => {
			const web3 = new Web3(this.options.provider);
			const accounts = await web3.eth.getAccounts();
			return accounts[0];
		}, resolve);
	}

	async getActiveAlias(resolve) {
		return _op(async () => {
			const address = await this.getActiveAddress();
			const hex = await this.contract.methods.directory(address).call();
			return hexToString(hex);
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
}

//export default AliasEarth;
module.exports = AliasEarth;
