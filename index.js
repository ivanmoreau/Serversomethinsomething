const express = require('express')
const app = express()
const { promisify } = require('util')
const crypto = require('crypto')
const AuthClient = require('fxa-js-client')
const defaults = require('./defaults')
const tokenServer = require('./token-server')
const Sync = require('firefox-sync')

/**
 * See <https://www.codejam.info/2021/08/scripting-firefox-sync-lockwise-figuring-the-protocol.html>.
 *
 * @param {Buffer} syncKey
 * @returns {Promise<import('../types').KeyBundle>}
 * From valeriangalliat/node-firefox-sync @ GitHub
 */
 async function deriveKeys (syncKey) {
    const salt = ''
    const info = 'identity.mozilla.com/picl/v1/oldsync'
    const bundle = Buffer.from(await promisify(crypto.hkdf)('sha256', syncKey, salt, info, 64))
  
    return {
      encryptionKey: bundle.slice(0, 32).toString('base64'),
      hmacKey: bundle.slice(32, 64).toString('base64')
    }
  }

// From valeriangalliat/node-firefox-sync @ GitHub
async function password (creds) {
  const { clientId, scope, authServerUrl } = { ...defaults }
  const authClient = new AuthClient(authServerUrl)

  const keyFetchToken = creds.keyFetchToken;
  const unwrapBKey = creds.unwrapBKey;
  const sessionToken = creds.sessionToken;

  const accountKeys = await authClient.accountKeys(keyFetchToken, unwrapBKey)
  const oauthToken = await authClient.createOAuthToken(sessionToken, clientId, {
    scope
  })

  const syncKey = Buffer.from(accountKeys.kB, 'hex')
  const keyBundle = await deriveKeys(syncKey)
  const scopedKeyData = await authClient.getOAuthScopedKeyData(sessionToken, clientId, scope)
  const clientState = crypto.createHash('sha256').update(syncKey).digest().slice(0, 16).toString('base64url')
  const syncKeyBundle = { ...keyBundle, kid: `${scopedKeyData[scope].keyRotationTimestamp}-${clientState}` }
  const asad = tokenServer.refresh({ oauthToken, syncKeyBundle });
  console.log(asad);
  return asad
}

app.use(
  express.urlencoded({
    extended: true
  })
)

app.use(express.json())

const hostname = '127.0.0.1';
const port = 3000;


  app.post('/login2', async (req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');

    const ads = await password(req.body);
    res.end(JSON.stringify(ads));
})


app.post('/getCollection', async (req, res) => {
    const params = {}
    params.full = true

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');

    var sync = Sync()
    sync.creds = req.body.creds.creds
    console.log(req.body.collection)
    console.log(sync.creds)
    const items = await sync.getCollection(req.body.collection,
        { full: true })
      console.log(JSON.stringify(items))
    res.end(JSON.stringify(items));
})

app.post('/upItemsCollection', async (req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');

    var sync = Sync()
    console.log(req.body.payload)
    sync.creds = req.body.creds.creds
    const items = await sync.putCollectionItems(req.body.collection,
        req.body.payload)

    res.end(JSON.stringify(items));
})


app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})


/**
 * 
 * 
 * {
  "forms": 1637471275.85,
  "history": 1638291852.27,
  "tabs": 1638291852.08,
  "crypto": 1636937525.04,
  "bookmarks": 1637471275.68,
  "meta": 1636937528.49,
  "passwords": 1636937526.71,
  "prefs": 1636937526.26,
  "clients": 1638272974.74
}





payload: {
      id: 'unfiled',
      type: 'folder',
      parentid: 'places',
      hasDupe: true,
      parentName: '',
      dateAdded: 1636790922173,
      title: 'unfiled',
      children: []
    }





 */