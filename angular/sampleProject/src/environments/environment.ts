// This file can be replaced during build by using the `fileReplacements` array.
// `ng build --prod` replaces `environment.ts` with `environment.prod.ts`.
// The list of file replacements can be found in `angular.json`.

export const environment = {
  production: false,
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

/*
 * For easier debugging in development mode, you can import the following file
 * to ignore zone related error stack frames such as `zone.run`, `zoneDelegate.invokeTask`.
 *
 * This import should be commented out in production mode because it will have a negative impact
 * on performance if an error is thrown.
 */
// import 'zone.js/dist/zone-error';  // Included with Angular CLI.
