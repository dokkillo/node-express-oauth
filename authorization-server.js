const fs = require("fs")
const url = require("url")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/authorize', function (req, res) {
	var clientId = req.query.client_id;
	var client = clients[clientId];
	if(!client)
	{
		res.status(401).end();
	}
	else
	{	
		if (typeof req.query.scope !== "string" || 	!containsAll(client.scopes, req.query.scope.split(" "))	) 	
		{
			res.status(401).end();			
		}
		else
		{	
			const requestId = randomString()
			requests[requestId] = req.query
			res.render("login",  {
				client,
				scope: req.query.scope,
				requestId,
			});
			
		}
	}

	
  });

  app.post('/approve', function (req, res) {
	const { userName, password, requestId } = req.body
	if (!userName || users[userName] !== password) {
		res.status(401).end();		
	}
	const clientReq = requests[requestId]
	delete requests[requestId]
	if (!clientReq) {
		res.status(401).end();
	}
	const code = randomString()
	authorizationCodes[code] = { clientReq, userName }
	const redirectUri = url.parse(clientReq.redirect_uri)
	redirectUri.query = {
		code,
		state: clientReq.state,
	}
	res.redirect(url.format(redirectUri))

	res.status(200).end();

  });


  app.post('/token', function (req, res) {

	let authCredentials = req.headers.authorization
	if (!authCredentials) {
		res.status(401).end();
		}

	const code = req.body.code
	if (!code || !authorizationCodes[code]) {
			res.status(401).end();
	}
	const { clientReq, userName } = authorizationCodes[code]
	delete authorizationCodes[code]

	const token = jwt.sign(
		{
			userName,
			scope: clientReq.scope,
		},
		config.privateKey,
		{
			algorithm: "RS256",
			expiresIn: 300,
			issuer: "http://localhost:" + config.port,
		}
	)

	res.json({
		access_token: token,
		token_type: "Bearer",
		scope: clientReq.scope,
	})

	res.status(200).end();

  });

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
