export class Credentials {

  constructor(
    public email: string,
    public password: string,
    public returnSecureToken: boolean = true
  ) {}

}
