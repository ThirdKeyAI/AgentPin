/**
 * Key rotation helpers for AgentPin.
 */

import { generateKeyPair, generateKeyId } from './crypto.js';
import { pemToJwk } from './jwk.js';
import { addRevokedKey } from './revocation.js';

/**
 * Prepare a key rotation by generating a new keypair.
 * @param {string} oldKid - The key ID of the key being rotated out
 * @returns {{ newKeyPair: { privateKeyPem: string, publicKeyPem: string }, newKid: string, newJwk: object, oldKid: string }}
 */
export function prepareRotation(oldKid) {
    const newKeyPair = generateKeyPair();
    const newKid = generateKeyId(newKeyPair.publicKeyPem);
    const newJwk = pemToJwk(newKeyPair.publicKeyPem, newKid);
    return { newKeyPair, newKid, newJwk, oldKid };
}

/**
 * Apply a rotation plan by adding the new key to a discovery document.
 * @param {object} doc - Discovery document
 * @param {{ newJwk: object }} plan - Rotation plan from prepareRotation
 */
export function applyRotation(doc, plan) {
    doc.public_keys.push(plan.newJwk);
    doc.updated_at = new Date().toISOString();
}

/**
 * Complete a rotation by removing the old key and adding it to the revocation document.
 * @param {object} doc - Discovery document
 * @param {object} revocationDoc - Revocation document
 * @param {string} oldKid - The key ID being retired
 * @param {string} reason - Revocation reason
 */
export function completeRotation(doc, revocationDoc, oldKid, reason) {
    doc.public_keys = doc.public_keys.filter(k => k.kid !== oldKid);
    doc.updated_at = new Date().toISOString();
    addRevokedKey(revocationDoc, oldKid, reason);
}
