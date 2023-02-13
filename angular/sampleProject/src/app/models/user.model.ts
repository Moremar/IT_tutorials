export class User {

/**
 * User object used for authentication
 * The token and its expiration dates are private to prevente modification.
 * The token has a getter that only returns it if it is still valid.
 */

  constructor(
    public email: string,
    public userId: string,
    private _token: string,
    private _tokenExpirationDate: Date
  ) {}

  // token getter
  get token() : string {
    if (!this._token || !this._tokenExpirationDate || new Date() > this._tokenExpirationDate) {
      return null;
    }
    return this._token;
  }

}
