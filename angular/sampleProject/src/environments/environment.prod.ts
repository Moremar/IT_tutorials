
/**
 * In a real project, these environment files should be in the .gitignore file.
 * Note that the content of this file is not secret and should not contain API secret keys or credentials.
 * It can be read by any user checking the JS code of the frontend.
 */

export const environment = {
  production: true,
  firebase: {
    // URL of the Firebase database, found in the Firebase project dashboard under Realtime Database
    db_url: '<FIREBASE_REALTIME_DATABASE_URL>',
    // Web API key of the Firebase project, found in in the Firebase project dashboard : Project Overview > Settings
    api_key: '<FIREBASE_PROJECT_WEB_API_KEY>',
    // URLs of signup and login endpoints
    signup_url: 'https://identitytoolkit.googleapis.com/v1/accounts:signUp',
    login_url: 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword'
  }
};
