'use strict';

const admin = require('./utils/realm');
const NodeApp = require('./fixtures/node-console/restify').NodeApp;
const TestVector = require('./utils/helper').TestVector;

const test = require('blue-tape');
const axios = require('axios');
const getToken = require('./utils/token');

const realmName = 'mixed-mode-realm';
const realmManager = admin.createRealm(realmName);
const app = new NodeApp();

const auth = {
  username: 'test-admin',
  password: 'password'
};

test('setup', t => {
  return realmManager.then(() => {
    return admin.createClient(app.confidential(), realmName)
      .then((installation) => {
        return app.build(installation);
      });
  });
});

test('Should test protected route.', t => {
  t.plan(1);
  const opt = {
    url: `${app.address}/service/admin`
  };
  return t.shouldFail(axios(opt), 'Access denied', 'Response should be access denied for no credentials');
});

test('Should test protected route with admin credentials.', t => {
  t.plan(1);
  return getToken({ realmName }).then((token) => {
    const opt = {
      url: `${app.address}/service/admin`,
      headers: { Authorization: `Bearer ${token}` }
    };
    return axios(opt)
      .then(response => {
        t.equal(response.data.message, 'admin');
      })
      .catch(error => {
        t.fail(error.response.data);
      });
  });
});

test('Should test protected route with invalid access token.', t => {
  t.plan(1);
  return getToken({ realmName }).then((token) => {
    const opt = {
      url: `${app.address}/service/admin`,
      headers: {
        Authorization: 'Bearer ' + token.replace(/(.+?\..+?\.).*/, '$1.Invalid')
      }
    };
    return t.shouldFail(axios(opt), 'Access denied', 'Response should be access denied for invalid access token');
  });
});

test('Should handle direct access grants.', t => {
  t.plan(3);
  return axios.post(`${app.address}/service/grant`, auth)
    .then(response => {
      t.ok(response.data.id_token, 'Response should contain an id_token');
      t.ok(response.data.access_token, 'Response should contain an access_token');
      t.ok(response.data.refresh_token, 'Response should contain an refresh_token');
    })
    .catch(error => {
      t.fail(error.response.data);
    });
});

test('Should test admin logout endpoint with incomplete payload', t => {
  t.plan(2);

  var app = new NodeApp();
  var client = admin.createClient(app.confidential('adminapp'), realmName);

  return client.then((installation) => {
    app.build(installation);

    let opt = {
      method: 'post',
      url: `${app.address}/k_logout`,
      data: TestVector.logoutIncompletePayload
    };
    return axios(opt).catch(err => {
      t.equal(err.response.status, 401);
      /* eslint no-useless-escape: "error" */
      t.equal(err.response.data, 'Cannot read property \'kid\' of undefined');
      app.destroy();
    });
  }).then(() => {
    app.destroy();
  });
});

test('Should test admin logout endpoint with payload signed by a different key pair', t => {
  t.plan(2);

  var app = new NodeApp();
  var client = admin.createClient(app.confidential('adminapp2'), realmName);

  return client.then((installation) => {
    app.build(installation);

    let opt = {
      method: 'post',
      url: `${app.address}/k_logout`,
      data: TestVector.logoutWrongKeyPairPayload
    };
    return axios(opt).catch(err => {
      t.equal(err.response.status, 401);
      t.equal(err.response.data, 'admin request failed: invalid token (signature)');
      app.destroy();
    });
  }).then(() => {
    app.destroy();
  });
});

test('Should test admin logout endpoint with valid payload', t => {
  t.plan(1);

  var app = new NodeApp();
  var client = admin.createClient(app.confidential('adminapp3'), realmName);

  return client.then((installation) => {
    app.build(installation);
    let opt = {
      method: 'post',
      url: `${app.address}/k_logout`,
      data: TestVector.logoutValidPayload
    };
    return axios(opt).then(response => {
      t.equal(response.status, 200);
    }).catch(err => {
      t.fail(err.response.data);
    });
  }).then(() => {
    app.destroy();
  });
});

test('Should test admin push_not_before endpoint with incomplete payload', t => {
  t.plan(2);

  var app = new NodeApp();
  var client = admin.createClient(app.confidential('adminapp5'), realmName);

  return client.then((installation) => {
    app.build(installation);

    let opt = {
      method: 'post',
      url: `${app.address}/k_push_not_before`,
      data: TestVector.notBeforeIncompletePayload
    };
    return axios(opt).catch(err => {
      t.equal(err.response.status, 401);
      /* eslint no-useless-escape: "error" */
      t.equal(err.response.data, 'Cannot read property \'kid\' of undefined');
      app.destroy();
    });
  }).then(() => {
    app.destroy();
  });
});

test('Should test admin push_not_before endpoint with payload signed by a different key pair', t => {
  t.plan(2);

  var app = new NodeApp();
  var client = admin.createClient(app.confidential('adminapp6'), realmName);

  return client.then((installation) => {
    app.build(installation);

    let opt = {
      method: 'post',
      url: `${app.address}/k_push_not_before`,
      data: TestVector.notBeforeWrongKeyPairPayload
    };
    return axios(opt).catch(err => {
      t.equal(err.response.status, 401);
      t.equal(err.response.data, 'admin request failed: invalid token (signature)');
      app.destroy();
    });
  }).then(() => {
    app.destroy();
  });
});

test('Should verify during authentication if the token contains the client name as audience.', t => {
  t.plan(3);
  const someapp = new NodeApp();
  var client = admin.createClient(someapp.confidential('audience-app'), realmName);

  return client.then((installation) => {
    installation.verifyTokenAudience = true;
    someapp.build(installation);

    return axios.post(`${someapp.address}/service/grant`, auth)
      .then(response => {
        t.ok(response.data.id_token, 'Response should contain an id_token');
        t.ok(response.data.access_token, 'Response should contain an access_token');
        t.ok(response.data.refresh_token, 'Response should contain an refresh_token');
      })
      .catch(error => {
        t.fail(error.response.data);
      });
  }).then(() => {
    someapp.destroy();
  });
});

test('Should test admin push_not_before endpoint with valid payload', t => {
  t.plan(1);

  var app = new NodeApp();
  var client = admin.createClient(app.confidential('adminapp7'), realmName);

  return client.then((installation) => {
    app.build(installation);
    let opt = {
      method: 'post',
      url: `${app.address}/k_push_not_before`,
      data: TestVector.notBeforeValidPayload
    };
    return axios(opt).then(response => {
      t.equal(response.status, 200);
    }).catch(err => {
      t.fail(err.response.data);
    });
  }).then(() => {
    app.destroy();
  });
});

test('teardown', t => {
  return realmManager.then((realm) => {
    app.destroy();
    admin.destroy(realmName);
  });
});
