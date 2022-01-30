"use strict";

/********* Imports ********/

import {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  HMACWithSHA256,
  HMACWithSHA512,
  SHA256,
  SHA512,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  generateEG,
  computeDH,
  generateECDSA,
  signWithECDSA,
  verifyWithECDSA,
  randomHexString,
  hexStringSlice,
} from "./lib";

/********* Implementation ********/

export default class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    /**
     * data for each active connection
     */
    this.conns = {};
    this.certs = {}; // certificates of other users
    this.keyPair = {};
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   * @param {string} username username to generate certificate
   * @returns certificate
   */
  generateCertificate(username) {
    const keyPair = generateEG();
    this.keyPair = keyPair;
    const certificate = {
      username: username,
      pubKey: keyPair.pub,
    };
    return certificate;
  }

  /**
   * Receive and store another user's certificate.
   * @param {any} certificate certificate of another user
   * @param {string} signature
   */
  receiveCertificate(certificate, signature) {
    const remoteParty = certificate.username;
    const verify = verifyWithECDSA(
      this.caPublicKey,
      this.stringifyCert(certificate),
      signature
    );
    if (verify) this.certs[remoteParty] = certificate;
    else throw "Chữ ký của chứng thư không chính xác!";
  }

  /**
   * Generate the message to be sent to another user.
   * @param {string} name name of another user
   * @param {string} plaintext message to send
   * @returns header and cipher text
   */
  sendMessage(name, plaintext) {
    // Check the existence of connection data to receiving user
    if (this.conns[name] == null) this.initSend(name, this.certs[name].pubKey);
    const conn = this.conns[name];

    // If receiving, applies new DH ratchet to send msg
    if (!conn.sending) {
      conn.DHself = generateEG();
      const dh_out = computeDH(conn.DHself.sec, conn.DHremote);
      [conn.RK, conn.CKsend] = this.KDF_RK(conn.RK, dh_out);
      conn.sending = true;
    }

    // Compute new sending chain key and message key
    let MK;
    [conn.CKsend, MK] = this.KDF_CK(conn.CKsend);

    const [v, c] = this.encryptMKForGov(MK);

    const header = {
      pubKey: conn.DHself.pub,
      vGov: v,
      cGov: c,
    };

    const ciphertext = encryptWithGCM(MK, plaintext, JSON.stringify(header));
    return [header, ciphertext];
  }

  /**
   * Decrypt a message received from another user.
   *
   * @param {String} name name of another user
   * @param {[any, String]} array contain header and cipher text
   * @returns {string} plain text
   */
  receiveMessage(name, [header, ciphertext]) {
    // Check the existence of connection data to sending user
    if (this.conns[name] == null)
      this.initReceive(name, this.certs[name].pubKey);
    const conn = this.conns[name];

    // If get a new ratchet public key from sending user
    const remotePubKey = header.pubKey;
    if (remotePubKey != conn.DHremote)
      this.receiveNewPubKey(name, remotePubKey);

    // Compute new receiving key chain and message key
    let MK;
    [conn.CKreceive, MK] = this.KDF_CK(conn.CKreceive);
    return decryptWithGCM(MK, ciphertext, JSON.stringify(header));
  }

  /**
   * Encrypt message key to the government can decrypt
   * @param {string} MK messageKey
   * @returns {[string, string]} a public key for gov to compute DH and cipher messageKey
   */
  encryptMKForGov(MK) {
    const keyPair = generateEG();
    let key = computeDH(keyPair.sec, this.govPublicKey);
    key = hexStringSlice(key, 0, 128);
    const cipherMK = encryptWithGCM(key, MK);
    return [keyPair.pub, cipherMK];
  }

  /**
   * Init the connection with first message sent by current user
   * @param {string} name name of sending user
   * @param {string} remotePubKey public key of sending user
   */
  initSend(name, remotePubKey) {
    const SK = computeDH(this.keyPair.sec, remotePubKey);
    const newRatchetKeyPair = generateEG();
    const [newRK, newCKsend] = this.KDF_RK(
      SK,
      computeDH(newRatchetKeyPair.sec, remotePubKey)
    );
    this.conns[name] = {
      DHself: newRatchetKeyPair,
      DHremote: remotePubKey,
      RK: newRK,
      CKsend: newCKsend,
      CKreceive: null,
      sending: true,
    };
  }

  /**
   * Init connection with first message sent by other user
   * @param {string} name name of sending user
   * @param {string} remotePubKey public key of sending user
   */
  initReceive(name, remotePubKey) {
    const SK = computeDH(this.keyPair.sec, remotePubKey);
    this.conns[name] = {
      DHself: this.keyPair,
      DHremote: null,
      RK: SK,
      CKsend: null,
      CKreceive: null,
      sending: false,
    };
  }

  /**
   * Applies a DH ratchet step to derive new receiving and sending chain keys
   * @param {string} name name of other user
   * @param {string} pub new public key of them
   */
  receiveNewPubKey(name, pub) {
    const conn = this.conns[name];
    let dh_out = computeDH(conn.DHself.sec, pub);
    [conn.RK, conn.CKreceive] = this.KDF_RK(conn.RK, dh_out);
    conn.sending = false;
    conn.DHremote = pub;
  }

  /**
   * compute new root key and chain key
   * @param {string} key 256 bits key
   * @param {string} input 256 bits
   * @returns two 256 bits key
   */
  KDF_RK(rk, dh_out) {
    const keyPair = HKDF(dh_out, 512, rk, "rootKDF");
    const newRK = hexStringSlice(keyPair, 0, 256);
    const newCK = hexStringSlice(keyPair, 256, 512);
    return [newRK, newCK];
  }

  /**
   * compute new chainKey and messageKey
   * @param {string} ck 256 bits chain key
   * @returns 256 bits chain key and 128 bits message key
   */
  KDF_CK(ck) {
    const chainKey = HMACWithSHA256(ck, "chainKey");
    const messageKey = hexStringSlice(chainKey, 0, 128);
    return [chainKey, messageKey];
  }

  stringifyCert(cert) {
    if (typeof cert == "object") {
      return JSON.stringify(cert);
    } else if (typeof cert == "string") {
      return cert;
    } else {
      throw "Certificate is not a JSON or string";
    }
  }
}
