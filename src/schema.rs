use anyhow::Result;

use crate::service::Message;

/// Validates the given payload using JSON schema keyed by the given schema name.
/// Throws if the given payload fails validation.
pub fn validate_schema(_schema: &str, _payload: &Message) -> Result<()> {
    // TODO: implement this

    // // const validateFn = validator.getSchema(schemaName);
    // const validateFn = (precompiledValidators as any)[schemaName];

    // if(!validateFn) {
    //     throw new DwnError(DwnErrorCode.SchemaValidatorSchemaNotFound, `schema for ${schemaName} not found.`);
    // }

    // validateFn(payload);

    // if(!validateFn.errors) {
    //     return;
    // }

    // // AJV is configured by default to stop validating after the 1st error is encountered which means
    // // there will only ever be one error;
    // const [errorObj] = validateFn.errors;
    // let { instancePath, message, keyword } = errorObj;

    // if (!instancePath) {
    //     instancePath = schemaName;
    // }

    // // handle a few frequently occurred errors to give more meaningful error for debugging

    // if (keyword === 'additionalProperties') {
    //     const keyword = errorObj.params.additionalProperty;
    //     throw new DwnError(DwnErrorCode.SchemaValidatorAdditionalPropertyNotAllowed, `${message}: ${instancePath}: ${keyword}`);
    // }

    // if (keyword === 'unevaluatedProperties') {
    //     const keyword = errorObj.params.unevaluatedProperty;
    //     throw new DwnError(DwnErrorCode.SchemaValidatorUnevaluatedPropertyNotAllowed, `${message}: ${instancePath}: ${keyword}`);
    // }

    // throw new DwnError(DwnErrorCode.SchemaValidatorFailure, `${instancePath}: ${message}`);

    Ok(())
}
