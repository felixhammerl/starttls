/**
 * Original: https://gist.github.com/TooTallNate/848444
 * Adapted: https://github.com/andris9/rai/blob/master/lib/starttls.js
 *
 * @overview
 * @author Matthew Caruana Galizia <m@m.cg>
 * @author Andris Reinman <andris.reinman@gmail.com>
 * @author Nathan Rajlich <nathan@tootallnate.net>
 * @copyright Copyright (c) 2012, Andris Reinman
 * @copyright Copyright (c) 2011, Nathan Rajlich
 * @license MIT
 * @preserve
 */

'use strict';

/*jshint node:true*/
/*global exports:true*/

var net = require('net');
var tls = require('tls');
var crypto = require('crypto');

module.exports = exports = function(options, onSecure) {
	var socket, securePair;

	if (options instanceof net.Socket) {
		socket = options;
		options = {
			socket: socket
		};
	} else if (options.socket) {
		socket = options.socket;
	} else {
		socket = options.socket = net.createConnection(options);
	}

	if (options.pair) {
		securePair = options.pair;
	} else {
		securePair = tls.createSecurePair(crypto.createCredentials(options), !!options.isServer, !!options.requestCert, !!options.rejectUnauthorized);
		options.pair = securePair;
	}

	// In Node < 0.9.0, socket.readable is undefined.
	if (socket.readable || undefined === socket.readable) {
		return startTls(options, onSecure);
	}

	// In Node > 0.9.0, if the socket is still unconnected then wait for connect.
	socket.once('connect', function() {
		startTls(options, onSecure);
	});

	return securePair;
};

exports.startTls = function(socket, options, onSecure) {
	if (typeof options === 'function' && typeof onSecure === 'undefined') {
		onSecure = options;
		options = {};
	}

	return startTls({
		socket: socket,
		pair: tls.createSecurePair(crypto.createCredentials(options), !!options.isServer, !!options.requestCert, !!options.rejectUnauthorized),
		isServer: !!options.isServer,
		requestCert: !!options.requestCert,
		rejectUnauthorized: !!options.rejectUnauthorized
	}, onSecure);
};

function startTls(options, onSecure) {
	var socket, host, securePair, clearText;

	socket = options.socket;
	host = options.host;
	securePair = options.pair;

	socket.ondata = null;
	socket.removeAllListeners('data');

	clearText = pipe(securePair, socket);

	securePair.once('secure', function() {
		var verifyError, identityError;

		// A cleartext stream has the boolean property 'authorized' to determine if it was verified by the CA. If 'authorized' is false, a property 'authorizationError' is set on the stream.
		if (options.requestCert && options.rejectUnauthorized) {
			verifyError = securePair.ssl.verifyError();
			clearText.authorized = !!verifyError;
			clearText.authorizationError = verifyError;
		} else {
			clearText.authorized = true;
		}

		if (!options.isServer && host && !tls.checkServerIdentity(host, clearText.getPeerCertificate())) {
			identityError = new Error('Server identity mismatch: invalid certificate for ' + host + '.');
		}

		// The callback parameter is optional.
		if (!onSecure) {
			return;
		}

		onSecure(verifyError || identityError, clearText);
	});

	clearText._controlReleased = true;

	return securePair;
}

function forwardEvents(events, emitterSource, emitterDestination) {
	var i, l, event, handler, forwardEvent;

	forwardEvent = function() {
		this.emit.apply(this, arguments);
	};

	for (i = 0, l = events.length; i < l; i++) {
		event = events[i];
		handler = forwardEvent.bind(emitterDestination, event);

		emitterSource.on(event, handler);
	}
}

function removeEvents(events, emitterSource) {
	var i, l;

	for (i = 0, l = events.length; i < l; i++) {
		emitterSource.removeAllListeners(events[i]);
	}
}

function pipe(securePair, socket) {
	securePair.encrypted.pipe(socket);
	socket.pipe(securePair.encrypted);

	securePair.fd = socket.fd;

	var clearText = securePair.cleartext;
	clearText.socket = socket;
	clearText.encrypted = securePair.encrypted;
	clearText.authorized = false;

	// Forward event emissions from the socket to the cleartext stream.
	var events = ['timeout', 'end', 'close', 'drain', 'error'];
	forwardEvents(events, socket, clearText);
	
	socket.on('error', onError);
	socket.on('close', onClose);
	securePair.on('error', onError);

	function onError(err) {
		if (clearText._controlReleased) {
			clearText.emit('error', err);
		}
	};

	function onClose() {
		socket.removeListener('error', onError);
		socket.removeListener('close', onClose);
		removeEvents(events, socket);
	};

	return clearText;
}