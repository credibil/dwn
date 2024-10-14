

/**
 * A class containing utility methods for working with DWN messages.
 */
impl Message {
   /// Gets the DID of the author of the given message.
  pub fn author(&self)-> Option<String> {
    // if (message.authorization === undefined) {
    //   return undefined;
    // }

    // let author;
    // if (message.authorization.authorDelegatedGrant !== undefined) {
    //   author = Message.getSigner(message.authorization.authorDelegatedGrant);
    // } else {
    //   author = Message.getSigner(message);
    // }
    // return author;

    todo!()
  }

   /// Validates the given message against the corresponding JSON schema.
  pub fn validate_json_schema(rawMessage: Message) -> Result<()> {
    // const dwnInterface = rawMessage.descriptor.interface;
    // const dwnMethod = rawMessage.descriptor.method;
    // const schemaLookupKey = dwnInterface + dwnMethod;

    // // throws an error if message is invalid
    // validateJsonSchema(schemaLookupKey, rawMessage);

    todo!()
  }

  /**
   * Gets the DID of the signer of the given message, returns `undefined` if message is not signed.
   */
  pub fn signer(&self)-> Option<String> {
    // if (message.authorization == undefined) {
    //   return undefined;
    // }
    // const signer = Jws.getSignerDid(message.authorization.signature.signatures[0]);
    // return signer;

    todo!()
  }


   /// Gets the CID of the given message.
  pub async fn  cid(&self)-> Result<String> {
    // NOTE: we wrap the `computeCid()` here in case that
    // the message will contain properties that should not be part of the CID computation
    // and we need to strip them out (like `encodedData` that we historically had for a long time),
    // but we can remove this method entirely if the code becomes stable and it is apparent that the wrapper is not needed

    // // ^--- seems like we might need to keep this around for now.
    // const rawMessage = { ...message } as any;
    // if (rawMessage.encodedData) {
    //   delete rawMessage.encodedData;
    // }

    // const cid = await Cid.computeCid(rawMessage as GenericMessage);
    // return cid;

    todo!()
  }

   /// Compares message CID in lexicographical order according to the spec.
   /// returns 1 if `a` is larger than `b`; -1 if `a` is smaller/older than
   /// `b`; 0 otherwise (same message)
  pub  async fn compare_cid(a: GenericMessage, b: GenericMessage)->Resulte<u64> {
    // // the < and > operators compare strings in lexicographical order
    // const cidA = await Message.getCid(a);
    // const cidB = await Message.getCid(b);
    // return lexicographicalCompare(cidA, cidB);

    todo!()
  }


/// Creates the `authorization` property to be included in a DWN message.
/// @param signer Message signer.
/// @returns {AuthorizationModel} used as an `authorization` property.
  pub async fn create_authorization(
    descriptor: Descriptor,
    signer: Signer,
    delegatedGrant: Option<DataEncodedRecordsWriteMessage>,
    permissionGrantId: Option<String>,
    protocolRole: Option<String>,
  )-> Result<AuthorizationModel> {
    // const { descriptor, signer, delegatedGrant, permissionGrantId, protocolRole } = input;

    // let delegatedGrantId;
    // if (delegatedGrant !== undefined) {
    //   delegatedGrantId = await Message.getCid(delegatedGrant);
    // }

    // const signature = await Message.createSignature(descriptor, signer, { delegatedGrantId, permissionGrantId, protocolRole });
    // const authorization: AuthorizationModel = {
    //   signature
    // };
    // if (delegatedGrant !== undefined) {
    //   authorization.authorDelegatedGrant = delegatedGrant;
    // }
    // return authorization;

    todo!()
  }

  /**
   * Creates a generic signature from the given DWN message descriptor by including `descriptorCid` as the required property in the signature payload.
   * NOTE: there is an opportunity to consolidate RecordsWrite.createSignerSignature() wth this method
   */
  pub  async createSignature(
    descriptor: Descriptor,
    signer: Signer,
    additionalPayloadProperties?: { delegatedGrantId?: string, permissionGrantId?: string, protocolRole?: string }
  ): Promise<GeneralJws> {
    const descriptorCid = await Cid.computeCid(descriptor);

    const signaturePayload: GenericSignaturePayload = { descriptorCid, ...additionalPayloadProperties };
    removeUndefinedProperties(signaturePayload);

    const signaturePayloadBytes = Encoder.objectToBytes(signaturePayload);

    const builder = await GeneralJwsBuilder.create(signaturePayloadBytes, [signer]);
    const signature = builder.getJws();

    return signature;
  }

  /**
   * @returns newest message in the array. `undefined` if given array is empty.
   */
  pub  async getNewestMessage(messages: GenericMessage[]): Promise<GenericMessage | undefined> {
    let currentNewestMessage: GenericMessage | undefined = undefined;
    for (const message of messages) {
      if (currentNewestMessage === undefined || await Message.isNewer(message, currentNewestMessage)) {
        currentNewestMessage = message;
      }
    }

    return currentNewestMessage;
  }

  /**
   * @returns oldest message in the array. `undefined` if given array is empty.
   */
  pub  async getOldestMessage(messages: GenericMessage[]): Promise<GenericMessage | undefined> {
    let currentOldestMessage: GenericMessage | undefined = undefined;
    for (const message of messages) {
      if (currentOldestMessage === undefined || await Message.isOlder(message, currentOldestMessage)) {
        currentOldestMessage = message;
      }
    }

    return currentOldestMessage;
  }

  /**
   * Checks if first message is newer than second message.
   * @returns `true` if `a` is newer than `b`; `false` otherwise
   */
  pub  async isNewer(a: GenericMessage, b: GenericMessage): Promise<boolean> {
    const aIsNewer = (await Message.compareMessageTimestamp(a, b) > 0);
    return aIsNewer;
  }

  /**
   * Checks if first message is older than second message.
   * @returns `true` if `a` is older than `b`; `false` otherwise
   */
  pub  async isOlder(a: GenericMessage, b: GenericMessage): Promise<boolean> {
    const aIsOlder = (await Message.compareMessageTimestamp(a, b) < 0);
    return aIsOlder;
  }

  /**
   * See if the given message is signed by an author-delegate.
   */
  pub  isSignedByAuthorDelegate(message: GenericMessage): boolean {
    return message.authorization?.authorDelegatedGrant !== undefined;
  }

  /**
   * See if the given message is signed by an owner-delegate.
   */
  pub  isSignedByOwnerDelegate(message: GenericMessage): boolean {
    return message.authorization?.ownerDelegatedGrant !== undefined;
  }

  /**
   * Compares the `messageTimestamp` of the given messages with a fallback to message CID according to the spec.
   * @returns 1 if `a` is larger/newer than `b`; -1 if `a` is smaller/older than `b`; 0 otherwise (same age)
   */
  pub  async compareMessageTimestamp(a: GenericMessage, b: GenericMessage): Promise<number> {
    if (a.descriptor.messageTimestamp > b.descriptor.messageTimestamp) {
      return 1;
    } else if (a.descriptor.messageTimestamp < b.descriptor.messageTimestamp) {
      return -1;
    }

    // else `messageTimestamp` is the same between a and b
    // compare the `dataCid` instead, the < and > operators compare strings in lexicographical order
    return Message.compareCid(a, b);
  }

  /**
   * Validates the structural integrity of the message signature given:
   * 1. The message signature must contain exactly 1 signature
   * 2. Passes JSON schema validation
   * 3. The `descriptorCid` property matches the CID of the message descriptor
   * NOTE: signature is NOT verified.
   * @param payloadJsonSchemaKey The key to look up the JSON schema referenced in `compile-validators.js` and perform payload schema validation on.
   * @returns the parsed JSON payload object if validation succeeds.
   */
  pub  async validateSignatureStructure(
    messageSignature: GeneralJws,
    messageDescriptor: Descriptor,
    payloadJsonSchemaKey: string = 'GenericSignaturePayload',
  ): Promise<GenericSignaturePayload> {

    if (messageSignature.signatures.length !== 1) {
      throw new DwnError(DwnErrorCode.AuthenticationMoreThanOneSignatureNotSupported, 'expected no more than 1 signature for authorization purpose');
    }

    // validate payload integrity
    const payloadJson = Jws.decodePlainObjectPayload(messageSignature);

    validateJsonSchema(payloadJsonSchemaKey, payloadJson);

    // `descriptorCid` validation - ensure that the provided descriptorCid matches the CID of the actual message
    const { descriptorCid } = payloadJson;
    const expectedDescriptorCid = await Cid.computeCid(messageDescriptor);
    if (descriptorCid !== expectedDescriptorCid) {
      throw new DwnError(
        DwnErrorCode.AuthenticateDescriptorCidMismatch,
        `provided descriptorCid ${descriptorCid} does not match expected CID ${expectedDescriptorCid}`
      );
    }

    return payloadJson;
  }
}