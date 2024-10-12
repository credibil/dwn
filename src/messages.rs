//! # Messages
//!
//! Decentralized Web Node messaging framework.

use serde::{Deserialize, Serialize};

/// All Decentralized Web Node messaging is transacted via Messages JSON objects.
/// Messages contain execution parameters, authorization material, authorization
/// signatures, and signing/encryption information.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// A 'stringified' (DAG CBOR encoded) [CID] of a `RecordId` object referencing
    /// the logical record associated with the message.
    ///
    /// [CID](https://docs.ipfs.tech/concepts/content-addressing/#identifier-formats)
    pub record_id: RecordId,

    /// The context id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    // /// A base64Url encoded string of the message’s data.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub data: Option<String>,
    /// The message descriptor.
    pub descriptor: Descriptor,

    /// Contains a JWS for messages requiring authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,

    /// Contains a JWS for messages requiring attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Jws>,
}

/// Contains the initial entry for its parent record.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordId {
    /// The 'stringified'  CID of the DAG CBOR encoded `Descriptor`
    /// object.
    pub descriptor_cid: String,
}

/// The message descriptor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    /// The associated DWN interface.
    pub interface: Interface,

    /// The interface method.
    pub method: Method,

    /// The interface protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,

    /// The path to the protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_path: Option<String>,

    /// Message recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

    /// The interface schema.
    pub schema: String,

    /// The message parent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// The 'stringified' Version 1 [CID] of the data, if the message has data
    /// associated with it.
    ///
    /// [CID](https://docs.ipfs.tech/concepts/content-addressing/#identifier-formats)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_cid: Option<String>,

    /// Size in bytes of the data, if the message has data associated with it.
    pub data_size: u64,

    /// Date the message was created.
    date_created: String,

    /// The timestamp of the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_timestamp: Option<String>,

    /// Whether the message is published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,

    /// The date the message was published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_published: Option<String>,

    /// The format of the data, if the message has data associated with it.
    ///
    /// The value corresponds with a registered IANA Media Type data format.
    /// For eaxample, `application/json`, `application/vc+jwt`, or
    /// `application/vc+ldp`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_format: Option<String>,
}

/// DWN interfaces.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum Interface {
    /// Records interface.
    #[default]
    Records,

    /// Protocols interface.
    Protocols,

    /// Messages interface.
    Messages,
}

/// Interface methods.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum Method {
    /// Read method.
    #[default]
    Read,

    /// Write method.
    Write,

    /// Query method.
    Query,

    /// Subscribe method.
    Configure,

    /// Subscribe method.
    Subscribe,

    /// Delete method.
    Delete,
}

/// Interface protocols.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum Protocol {
    /// IPFS protocol.
    #[default]
    Http,
}

/// Message authorization.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// The signature of the message signer.
    /// N.B.: Not the author of the message when signer is a delegate.
    pub signature: Jws,

    /// The delegated grant required when the message is signed by an
    /// author-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_delegated_grant: Option<DelegatedGrant>,

    /// An "overriding" signature for a DWN owner or owner-delegate to store a
    /// message authored by another entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<Jws>,

    /// The delegated grant required when the message is signed by an
    /// owner-delegate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_delegated_grant: Option<DelegatedGrant>,
}

/// JWS definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Jws {
    /// The encoded JWS payload. An empty string when JWS Unencoded Payload
    /// Option used.
    pub payload: String,

    /// JWS signatures.
    pub signatures: Vec<Signature>,
}

/// An entry of the `signatures` array in a general JWS.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Signature {
    /// The base64 url-encoded JWS protected header when the JWS protected
    /// header is non-empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,

    /// The base64 url-encoded JWS signature.
    pub signature: String,
}

/// Delegated grant.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedGrant {
    /// the grant's authorization.
    pub authorization: Box<Authorization>,

    /// A 'stringified' (DAG CBOR encoded) [CID] of a `RecordId` object referencing
    /// the logical record associated with the message.
    ///
    /// [CID](https://docs.ipfs.tech/concepts/content-addressing/#identifier-formats)
    pub record_id: String,

    /// Context id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    // NOTE: This is a direct expansion and copy of `DataEncodedRecordsWriteMessage` to avoid circular references.
    descriptor: Descriptor,

    encoded_data: String,
}

/// Encryption settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Encryption {
    /// Encryption algorithm.
    pub algorithm: EncryptionAlgorithm,

    /// The initialization vector.
    pub initialization_vector: String,

    /// The encrypted CEK.
    pub key_encryption: Vec<EncryptedKey>,
}

/// Supported ncryption algorithms.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum EncryptionAlgorithm {
    /// AES 256 CTR.
    #[serde(rename = "A256CTR")]
    #[default]
    Aes256Ctr,

    /// AES 256 GCM.
    #[serde(rename = "ECIES-ES256K")]
    EciesSecp256k1,
}

/// Encrypted key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedKey {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id) of
    /// the root public key used to encrypt the symmetric encryption key.
    pub root_key_d: String,

    /// The derived public key.
    pub derived_public_key: Option<PublicKeyJwk>,

    /// Encryption key derivation scheme.
    pub derivation_scheme: Option<KeyDerivationScheme>,

    /// The encryption algorithm.
    pub algorithm: EncryptionAlgorithm,

    /// The initialization vector.
    pub initialization_vector: String,

    /// The ephemeral public key.
    pub ephemeral_public_key: PublicKeyJwk,

    /// The MAC
    pub message_authentication_code: String,

    /// The encrypted key.
    pub encrypted_key: String,
}

/// Key derivation schemes.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum KeyDerivationScheme {
    /// Key derivation using the `dataFormat` value for Flat-space records.
    #[serde(rename = "dataFormats")]
    #[default]
    DataFormats,

    /// Key derivation using protocol context.
    #[serde(rename = "protocolContext")]
    ProtocolContext,

    /// Key derivation using the protocol path.
    #[serde(rename = "protocolPath")]
    ProtocolPath,

    /// Key derivation using the `schema` value for Flat-space records.
    #[serde(rename = "schemas")]
    Schemas,
}

/// JSON Web Key (JWK) definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJwk {
    /// The algorithm intended for use with the key.
    pub alg: Option<String>,

    /// The key ID.
    pub kid: Option<String>,

    /// The cryptographic key type, e.g. "OKP", "EC".
    pub kty: String,

    /// The cryptographic curve used with the key, e.g. 'Ed25519', 'ES256k'
    pub crv: String,

    /// Base64url encoded x point.
    pub x: String,

    /// Base64url encoded y point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

// /**
//  * Message returned in a query result.
//  * NOTE: the message structure is a modified version of the message received, the most notable differences are:
//  * 1. May include encoded data
//  */
// export type QueryResultEntry = GenericMessage & {
//   encodedData?: string;
// };

// export type MessagesReadMessage = GenericMessage & {
//   authorization: AuthorizationModel; // overriding `GenericMessage` with `authorization` being required
//   descriptor: MessagesReadDescriptor;
// };

// export type MessagesQueryMessage = GenericMessage & {
//   authorization: AuthorizationModel;
//   descriptor: MessagesQueryDescriptor;
// };

// export type ProtocolsConfigureMessage = GenericMessage & {
//   authorization: AuthorizationModel; // overriding `GenericMessage` with `authorization` being required
//   descriptor: ProtocolsConfigureDescriptor;
// };

// export type ProtocolsQueryMessage = GenericMessage & {
//   descriptor: ProtocolsQueryDescriptor;
// };

// /**
//  * Internal RecordsWrite message representation that can be in an incomplete state.
//  */
// export type InternalRecordsWriteMessage = GenericMessage & {
//   recordId?: string,
//   contextId?: string;
//   descriptor: RecordsWriteDescriptor;
//   attestation?: GeneralJws;
//   encryption?: EncryptionProperty;
// };

// export type RecordsQueryMessage = GenericMessage & {
//   descriptor: RecordsQueryDescriptor;
// }

// export type RecordsSubscribeMessage = GenericMessage & {
//   descriptor: RecordsSubscribeDescriptor;
// };

// export type RecordsDeleteMessage = GenericMessage & {
//   authorization: AuthorizationModel; // overriding `GenericMessage` with `authorization` being required
//   descriptor: RecordsDeleteDescriptor;
// };
