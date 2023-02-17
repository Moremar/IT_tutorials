/**
 * This file is used with the production configuration, for example when running "ng build".
 *
 * To start a project, the backend firebase DB URL and API key must be set in the below properties.

* Note that the content of this file is not secret and should not contain API secret keys or credentials.
 * It can be read by any user checking the JS code of the frontend.
 */

export const environment = {
  firebase: {
    // URL of the Firebase database, found in the Firebase project dashboard under Realtime Database
    // db_url: '<FIREBASE_REALTIME_DATABASE_URL>',
    db_url: 'https://recipe-sample-project-default-rtdb.asia-southeast1.firebasedatabase.app',
    // Web API key of the Firebase project, found in in the Firebase project dashboard : Project Overview > Settings
    // api_key: '<FIREBASE_PROJECT_WEB_API_KEY>',
    api_key: 'AIzaSyAFZwvU68ejs8jhBqpe1p4-vgBMDo5ABz8',
    // URLs of signup and login endpoints
    signup_url: 'https://identitytoolkit.googleapis.com/v1/accounts:signUp',
    login_url: 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword'
  }
};
