
/**
 * In a real project, these environment files should be in the .gitignore file.
 * Note that the content of this file is not secret and should not contain API secret keys or credentials.
 * It can be read by any user checking the JS code of the frontend.
 */

export const environment = {
  production: true,
  firebase: {
    // replace this URL with the realtime database URL of the associated Firebase backend project
    url: 'https://recipe-sample-project-default-rtdb.asia-southeast1.firebasedatabase.app'
  }
};
