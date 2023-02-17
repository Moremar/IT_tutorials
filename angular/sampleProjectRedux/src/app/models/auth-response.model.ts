export class AuthResponse {

  constructor(
    public idToken: string,
    public email: string,
    public refreshToken: string,
    public expiresIn: string,
    public localId: string,
    public registered? : string
  ) {}

}
