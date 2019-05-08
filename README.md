## Welcome

This package is a wrapper around a vanilla web3 contract instance providing a high-level JavaScript API to interact with alias.earth on the Ethereum blockchain [on the mainnet](https://etherscan.io/address/0x8F6A7781F54335D10d02bDD9ce66ACE1647AbCA7) or [on the Rinkeby testnet](https://rinkeby.etherscan.io/address/0x731C54d14d853af7f6CB587c680Efc1db11a3757) from any MetaMask-enabled browser or Node backend. We're seeking developers to build applications that users can interact with using their alias.earth name and providing an alernative to centralized social media platforms. Please [join developer Discord](https://discord.gg/UDbqesA) to see what others are building and to get answers for any questions (or ideas / feature requests!) in this experimental pre-release.

## Contents

#### Quick Start
- [Usage with MetaMask](#quick-start-usage-with-metamask)
- [Usage without MetaMask](#quick-start-usage-without-metamask)

#### Reading Alias Data
- [aliasExists](#reading-alias-data-alias-exists)
- [isAddressAvailable](#reading-alias-data-is-address-available)
- [getAliasFromAddress](#reading-alias-data-get-alias-from-address)
- [getAddresses](#reading-alias-data-get-addresses)

#### Hypermessage Utils
- [Create Hypermessage](#hypermessage-utils-create)
- [Verify Hypermessage](#hypermessage-utils-verify)
- [Hypermessage Parser](#hypermessage-utils-parser)

## Quick Start

`npm i --save @alias-earth/core`

Assuming you're in a MetaMask enabled browser, all you need to do is import the module and call `connect()`. By default, alias.earth will use the injected provider at `window.ethereum` (if it exists) to connect to the Ethereum mainnet. **We're using the async/await syntax in these examples**, but you can also pass a function to `connect()` (or any asynchronous function in this API) as the second parameter which will be called in the standard Node-style `(err, result) => { ... }` callback pattern.

#### <a name="quick-start-usage-with-metamask">Usage With MetaMask</a>

```js
import earth from '@alias-earth/core';

// This example assumes we're in a browser and the
// user has installed MetaMask

let core;

// ...

try {

	if (!window.ethereum) {
		throw Error('Please install MetaMask');
	}

	core = await earth.connect();

} catch (err) {
	// Failed to connect
}

// now you call any API function using the 'core' object
```

It's worth noting that if you are using an injected provider, calling `connect()` will (if necessary) automatically handle calling `ethereum.enable()` under the hood, so you don't have to worry about that.

#### <a name="quick-start-usage-without-metamask">Usage Without MetaMask</a>

You only need MetaMask if your app's functionality involves users submitting transactions to the blockchain or signing data. If you're just using alias.earth to *read* data, you can let the core module handle that using its built-in Infura provider. Like this:

```js
import earth from '@alias-earth/core';

// We don't need MetaMask in this example, so it will
// work in any browser, or in a Node environment

let core;

try {

	core = await earth.connect({ useOwnProvider: true });

} catch (err) {
	// Failed to connect
}

// Now you can call API functions that only *read* data from
// the blockchain such as getAliasFromAddress({ address }) which
// (as you might expect) returns the alias linked to a given address.
```

## Reading Alias Data

#### <a name="reading-alias-data-alias-exists">aliasExists</a>

```js
const exists = await core.aliasExists('alice');
console.log(exists); // true
```

Returns `true` if the given `alias` has ever been created.

##### Parameters
- `alias`: required, alias for which to check existence

##### Returns `Boolean`

#### <a name="reading-alias-data-is-address-available">isAddressAvailable</a>

```js
const available = await core.isAddressAvailable('0x19646E56d36615A1A723650a2c65E4311D84bE70');
console.log(available); // false
```

Returns `true` if the given Etheruem `address` is or has ever been used as the managing address *or* the recovery address for any alias. This one-time-use policy for addresses is enforced at the contract level as a security measure.

##### Parameters
- `address`: required, address for which to check availability

##### Returns `Boolean`

#### <a name="reading-alias-data-get-alias-from-address">getAliasFromAddress</a>

```js
const alias = await core.getAliasFromAddress('0x19646E56d36615A1A723650a2c65E4311D84bE70');
console.log(alias); // 'alice'
```

Returns the `alias` (if any) currently linked to a given Etheruem `address`. If the address is currently unlinked, return an empty string.

##### Parameters
- `address`: required, address for which to find linked alias

##### Returns `String`

#### <a name="reading-alias-data-get-addresses">getAddresses</a>

```js
const { linked, recovery } = await core.getAddresses('alice');
console.log(linked); // '0x19646E56d36615A1A723650a2c65E4311D84bE70'
console.log(recovery); // '0x01061E883d375C36fE30776d1aba3627bfbd67BC'
```

Returns an object with both the `linked` and `recovery` addresses for a given `alias`. If either doesn't exist (in the case of the linked address the only way that could happen is if the alias itself didn't exist), return an empty string for that address.

##### Parameters
- `alias`: required, alias for which to find linked and recovery addresses

##### Returns `Object`
- `Object` *addresses*
  - `linked`: primary linked address
  - `recovery`: recovery address

## Hypermessage Utils

The core module provides functions for creating and verifying signed data linked to an identity on the blockchain in a standardized way. Consistency is important because the receiver of a hypermessage has to know how to structure the data in order to verify the signature.

##### Anatomy of a Hypermessage

```json
{
	"_signed_": {
		"foo": "bar",
		"fooo": "baaar",
		"🕒": "1557277420"
	},
	"_params_": {
		"alias": "alice",
		"sig": "0x960d6263585365fc35ab58516dd3b205f41f7b6269e4024accce92ef404cc91e5ad29c928ac73ab5865de390dc969be6cec4230f112109d7147c86e731a32e671c",
		"sig_type": "metamask_typed",
		"network": "main"
	}
}
```

A hypermessage has two parts: The `_signed_` object is the actual data that is signed by on the client using MetaMask. The `_params_` object is meta data which allows the receiver (such as an API server) to verify the signature (i.e. find the signing Ethereum address) and look up which alias that address is linked to on the blockchain. The '🕒' (unix timestamp, according to client) is added automatically so that it's possible for apps to enforce expiry times.

**IMPORTANT NOTE:** If you are using hypermessages for auth, you should always include something like `{ "app": "my_unique_app_name" }` in the signed data and explicitly check for that on your server. Otherwise it might be possible for an attacker who intercepts a hypermessage that the user has created in another context to sign in to your application.

#### <a name="hypermessage-utils-create">Create Hypermessage</a>

```js
// On sender's machine, assuming MetaMask is installed

let hypermessage;

try {

	// Simply pass an object containing the data to be signed
	hypermessage = await core.createHypermessage({ foo: bar });

} catch (err) {
	// User rejected sig request
}

console.log(hypermessage); // { _signed_: { ... }, _params_: { ... } }
```

Creating a hypermessage is dead simple. Pass an object that contains the data that the user needs to sign and MetaMask will pop up asking the user to confirm the signature, using whatever address it currently selected in MetaMask. Now the hypermessage can be sent to anyone.

##### Parameters
- `data`: required, object containing the data to be signed

##### Returns `Object`
- `Object` *hypermessage*
  - `_signed_`: *data that was signed*
  	- '🕒': timestamp is added automatically
  - `_params_`: *params to verify sig*
  	- `alias`: alias linked to signing address
  	- `sig`: cryptographic signature
  	- `sig_type`: format data was packed in for signing
  	- `network`: 'main' or 'rinkeby'

#### <a name="hypermessage-utils-verify">Verify Hypermessage</a>

```js
// On the receiver's machine

let verified;

try {
	verified = await core.verifyHypermessage(hypermessage);
} catch (err) {
	// Failed to verify
}

console.log(verified); // { id: '0x...', signed: { ... }, params: { ... }, author: { ... } }
```

The blockchain makes it possible for hypermessages (both integrity and authorship) to be trustlessly verified by anyone.

##### Parameters
- `hypermessage`: required, hypermessage to verify

##### Returns `Object`
- `Object` *hypermessage*
	- `id`: first 24 chars (excluding hex prefix) of signature, can be used as uuid
	- `signed` *data that was signed*
	- `params` *params by which sig was verified*
	  - `alias`: alias (claimed by sender)
	  - `sig`: cryptographic signature
	  - `sig_type`: format data was packed in for signing
	  - `network`: 'main' or 'rinkeby'
	-	`author` *verifed authorship info*
		- `alias`: alias that signed data (from blockchain)
		- `address`: address that signed data (computed)

#### <a name="hypermessage-utils-parser">Hypermessage Parser</a>

```js
// On express server

const express = require('express');
const parser = require('body-parser');
const earth = require('@alias-earth/core');

const app = express();
app.use(parser.json());

// The parser is looking for a json-encoded hypermessage
// in `req.body`, or url-encoded in `req.url`. Requests that
// do not contain a hypermessage or cannot be verified are
// rejected. Otherwise the parser sets the verified data
// on `req.hypermessage` before calling `next()`.
app.use(earth.HypermessageParser());

app.post('/message', (req, res) => {

	// The decoded and verified hypermessage
	// is available on `req.hypermessage`

	console.log(req.hypermessage); // { id: '0x...', signed: { ... }, params: { ... }, author: { ... }, received: 1557277420 }
});
```













