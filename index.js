const fs = require('fs');
const express = require('express');
const bcrypt = require('bcrypt-nodejs');

const salt = bcrypt.genSaltSync(10);
const router = express.Router();

/**
 * Returns a router to use as middleware. It defines the routes 
 * '/login', '/register'
 *   via GET and POST methods, 
 * '/logout' 
 *   via the GET method only. And 
 * '/content' 
 *   via the GET method and this is the route that will be protected. 
 *   Users must be logged in before accessing this route, otherwise a 401 
 *   message will be sent with an unauthorized view.
 *
 * @param {Object} options This is the configuration needed for the authentication.
 * The properties are the following:
 * passwordFile: location of the file to store the users credentials.
 * pathToProtect: the files that will be accessible only when users are logged in.
 * registerView: view containing the form to register. It will be served at '/register'
 * via the HTTP GET method.
 * successRegisterView: view with the message to render when the user registers successfully.
 * errorRegisterView: view to render when there is an error in the registration.
 * loginView: view containing the form to log in. It will be served at '/login'
 * via the HTTP GET method.
 * successLoginView: view with the message to render when the user logs in successfully.
 * errorLoginView: view to render when there is an error in the login.
 * logoutView: view to render when they log out.
 * unauthorizedView: view to render when a user tries to access '/content' without being logged in
 */
function authentication(options) {
  const {
    passwordFile,
    pathToProtect,
    registerView,
    successRegisterView,
    errorRegisterView,
    loginView,
    successLoginView,
    errorLoginView,
    logoutView,
    unauthorizedView,
  } = options;

  // Create password file if it doesn't exist
  if (!fs.existsSync(passwordFile)) {
    fs.writeFileSync(passwordFile, '{}');
  }

  // Authentication middleware, if the user doesn't have a session we sent a 401 message
  const auth = (req, res, next) => {
    if (req.session && req.session.username && req.session.password) {
      return next();
    }

    return res.status(401).render(unauthorizedView);
  };

  // Set two middlewares
  router.use('/content', auth, express.static(pathToProtect));

  //
  // Now we set the routes so the users can register and log in and the
  // auth function allows them to see the content
  //

  // Route to send "login" page
  router.get('/login', (req, res) => {
    if (!req.session.username) {
      res.render(loginView);
    } else if (req.session.username) {
      res.render(successLoginView, {username:req.session.username});
    }
  });

  // Route to validate user log in
  router.post('/login', (req, res) => {
    const configFile = fs.readFileSync(passwordFile);
    const config = JSON.parse(configFile);

    const p = config[req.body.username];
    if (p) {
      if (
        req.session &&
        req.body &&
        req.body.password &&
        bcrypt.compareSync(req.body.password, p)
      ) {
        req.session.username = req.body.username;
        req.session.password = req.body.password;
        req.session.admin = true;
        return res.render(successLoginView, {username:req.session.username});
      }
      return res.render(errorLoginView);
    }
    return res.render(errorLoginView);
  });

  // Route to send registration page
  router.get('/register', (req, res) => {
    if (!req.session.username) {
      res.render(registerView);
    } else {
      res.render(successLoginView, {username:req.session.username});
    }
  });

  // Route to validate user registration
  router.post('/register', (req, res) => {
    const configFile = fs.readFileSync(passwordFile);
    const config = JSON.parse(configFile);
    const p = config[req.body.username];

    if (!p) {
      config[req.body.username] = bcrypt.hashSync(req.body.password, salt);
    } else {
      return res.render(errorRegisterView, req.body.username);
    }

    const configJSON = JSON.stringify(config);
    fs.writeFileSync(passwordFile, configJSON);
    return res.render(successRegisterView, {username:req.body.username});
  });

  // Route to logout
  router.get('/logout', (req, res) => {
    let user = req.session.username;
    req.session.destroy();
    res.render(logoutView, { user});
  });

  return router;
}

module.exports = authentication;
