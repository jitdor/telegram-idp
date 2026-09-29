/**
 * An RFC 6749 style error. `error` is one of the registered OAuth error codes;
 * the HTTP layer renders it as `{ error, error_description }` (or as redirect
 * query parameters on the authorization endpoint).
 */
export class OAuthError extends Error {
  /**
   * @param {string} error OAuth error code, e.g. `invalid_grant`
   * @param {string} [description]
   * @param {number} [status] HTTP status
   */
  constructor(error, description, status = 400) {
    super(description || error);
    this.name = 'OAuthError';
    this.error = error;
    this.description = description;
    this.status = status;
  }

  toJSON() {
    return this.description
      ? { error: this.error, error_description: this.description }
      : { error: this.error };
  }
}

/**
 * An authorization-endpoint error that must NOT be redirected to the client,
 * because the client or redirect_uri could not be verified (RFC 6749 §4.1.2.1).
 */
export class UnsafeRedirectError extends OAuthError {
  constructor(error, description) {
    super(error, description, 400);
    this.name = 'UnsafeRedirectError';
  }
}

export const invalidClient = (description = 'Client authentication failed') =>
  new OAuthError('invalid_client', description, 401);
export const invalidGrant = (description) => new OAuthError('invalid_grant', description);
export const invalidRequest = (description) => new OAuthError('invalid_request', description);
export const invalidToken = (description = 'The access token is invalid') =>
  new OAuthError('invalid_token', description, 401);
