#!/usr/bin/end node
"use strict";

var fs = require('fs');
var Discord = require('discord.js');
var Request = require('request');
var Crypto = require("crypto");
var request = Request.defaults({
    headers: {
        'User-Agent': 'gdq-role-bot v' + require('./package.json').version,
		'accept': '*/*'
    },
	jar: true
});

var cfg = require('./config.js');


var express = require("express");
var app = express();
var bodyParser = require('body-parser');
app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
var server = require('http').Server(app);
server.listen(8002);

var responseTemplate = fs.readFileSync("index.html", "utf-8");

var oauth2 = require('simple-oauth2')({
	clientID: cfg.client_id,
	clientSecret: cfg.client_secret,
	site: 'https://discordapp.com/api',
	tokenPath: '/oauth2/token',
	authorizationPath: '/oauth2/authorize'
});

var authorization_uri = oauth2.authCode.authorizeURL({
	redirect_uri: cfg.domain+'/login',
	scope: 'identify email'
});

console.log(authorization_uri);

var rolemap = {
	null: ["attendees"],
	"": ["attendees"],
	"attendee": ["attendees"],
	"volunteer": ["attendees","volunteers"],
	"runnervolunteer": ["attendees","runners","volunteers"],
	"runner": ["attendees","runners"],
	"press": ["attendees"],
	"enforcement": ["attendees","volunteers"],
	"partner": ["attendees","partners"],
	"staff": ["attendees","gdqstaff"]
}

var cookieJar = request.jar();

console.log("Filling cookie jar");
for(var i=0;i<cfg.cookies.length;++i) {
	cookieJar.setCookie(request.cookie(cfg.cookies[i]), cfg.site);
}
console.log("Cookie jar full");

function getExtraRole(email) {
	var extraJSON = fs.readFileSync("extra.json", "utf-8");
	var extraRoles = JSON.parse(extraJSON);
	return extraRoles[email];
}
function getEmailRedirect(email) {
	var emailJSON = fs.readFileSync("emails.json", "utf-8");
	var emails = JSON.parse(emailJSON);
	return emails[email] || email;
}

function getToken(callback) {
	console.log("Getting gdq access token");
	request.get({
		url: badgesite,
		jar: cookieJar
	}, function(error, response, body) {
		if (error || response.statusCode != 200) {
			callback("An error occured when getting the gdq token: "+error+". Status code: "+response.statusCode);
		} else {
			if(body[0] == "<") {
				callback("An error occured when getting the gdq token: Invalid cookies");
			} else {
				try {
					var tokenResponse = JSON.parse(body);
					if(tokenResponse._token) {
						callback(null, tokenResponse._token);
					} else {
						callback("No gdq token returned.");
					}
				} catch(err) {
					callback("An error occured when getting the gdq token: "+err);
				}
			}
		}
	});
}

function getRole(email, callback, retries, retryreason) {
	if(retries === undefined) retries = 1;
	if(retries < 0) return callback(retryreason);
	console.log("Getting gdq role for "+email);
	getToken(function(error, token){
		if(error) {
			callback(error);
		} else {
			console.log("Got gdq token "+token);
			// now we have the token, we can try to get the role.
			
			request.post({
				url: badgesite,
				form: {
					"email": email,
					"_token": token,
				},
				jar: cookieJar
			}, function(error, response, body) {
				if (error || response.statusCode != 200) {
					var errormessage = "An error occured when getting the gdq role for "+email+": "+error+". Status code: "+response.statusCode;
					// retry once for 302s
					console.log(errormessage);
					if(response.statusCode === 302 && retries > 0) {
						console.log("Retrying...")
						getRole(email, callback, retries - 1, errormessage);
					}
					else callback(errormessage);
				} else {
					var roleResponse = JSON.parse(body);
					console.log("Got role response for "+email+": "+roleResponse.type);
					callback(null, rolemap[roleResponse.type]);
				}
			});
		}
	});
}

function encrypt(data){
	var cipher = Crypto.createCipher('aes-256-cbc',cfg.secret)
	var crypted = cipher.update(data,'utf8','base64')
	crypted += cipher.final('base64');
	return crypted.replace(/\+/g,"_").replace(/\//g,"-").replace(/=/g,"~");
}
function decrypt(text){
	text = text.replace(/_/g,"+").replace(/-/g,"/").replace(/~/g,"=");
	var decipher = Crypto.createDecipher('aes-256-cbc',cfg.secret)
	var dec = decipher.update(text,'base64','utf8')
	dec += decipher.final('utf8');
	return dec;
}
async function applyRole(discordinfo, email, cb) {
	if(!email) {
		cb("Error", "An error occurred: No email specified");
		return;
	}
	getRole(email, async function(error, roles) {
		// we got the user and the roles this user receives. Lets add them.
		if(error) {
			cb("Error", error);
		} else {
			roles = (roles || []).slice();
			var extraRole = getExtraRole(email);
			if(extraRole !== undefined) {
				roles.push(extraRole);
			}
			console.log("Roles to add for "+email+": "+roles.join(", "));
			if(roles.length > 0) {
				var roleObjects = roles.map((x)=>theGuild.roles.find("name",x));
				var user = await client.fetchUser(discordinfo.id);
				var member = await theGuild.fetchMember(discordinfo.id);
				member.addRoles(roleObjects).then(function(){
					if(roles.length == 1) {
						cb("Success", "Role "+roles[0]+" added to your account "+discordinfo.username+". Enjoy your stay!<p>You may now close this page</p>");
					} else {
						cb("Success", "Roles "+roles.join(" and ")+" added to your account "+discordinfo.username+". Enjoy your stay!<p>You may now close this page</p>");
					}
				}, function(error){
					console.error(error);
					cb("Error", "An error occurred: "+error);
				});
			} else {
				var verificationCode = encrypt(JSON.stringify(discordinfo));
				cb("Error", 'We couldnt find a GDQ registration for your email ('+email.replace("<", "&lt;")+'). Please change and verify your Discord email to the one you used to register.</p><p>If you <b>cannot</b> do this for some reason, please DM ShadowWraith on the GDQ Discord. ');
			}
		}
	});
}

function getMe(token,cb) {
	oauth2.api("get", "/users/@me", { access_token: token.token.access_token }, function(error, result){
		if (error) {
			console.log('User info error: ', error.message);
			cb({"error":error.message});
		} else {
			console.log(result);
			if(result.verified) {
				var email = getEmailRedirect(result.email);
				applyRole(result, email, cb);
			} else {
				cb("Error", "Your email is not verified. Please verify your email in your settings and make sure your browser is logged on to the correct account before trying again.");
			}
		}
	});
}

app.get('/gdq-attendee/', function (req, res) {
	var fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
	console.log("Getting "+fullUrl);
	res.redirect(authorization_uri);
});


function makeResp(res, result, data) {
		if(result == "Error") data += "<p>If the problem persists, please contact ShadowWraith in the GDQ Discord server.</p>";
		var page = responseTemplate.replace("{{result}}", result).replace("{{message}}", data);
		res.set('Content-Type', 'text/html').end(page);
}

app.get('/gdq-attendee/login', function(req, res, next) {
	var fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
	console.log("Getting "+fullUrl);
	var code = req.query.code;
	console.log("Got code "+code);
	oauth2.authCode.getToken({
		code: code,
		redirect_uri: cfg.domain+'/login'
	}, saveToken);
	function saveToken(error, result){
		if (error) {
			console.log('Access Token Error: ', error.message);
			res.redirect(cfg.domain);
		} else {
			console.log("Returned Discord access token");
			var token = oauth2.accessToken.create(result);
			getMe(token, function(result, data){
				makeResp(res,result,data);
			});
		}
	}
});

// manage roles permission is required
const invitelink = 'https://discordapp.com/oauth2/authorize?client_id='
    + cfg.client_id + '&scope=bot&permissions='+0x10000000;
const authlink = 'https://discordapp.com/oauth2/authorize?client_id='
    + cfg.client_id + '&scope=email';
console.log("Bot invite link: "+invitelink);

var client = new Discord.Client({
    autoReconnect: true
});
var theGuild;
client.on('ready', function () {
    console.log("Ready");
    client.user.setStatus('online');
	theGuild = client.guilds.find("id",cfg.guild);
});

client.on('message', function (message) {
    let words = message.cleanContent.match(/(?:[^\s"]+|"[^"]*")+/g);
    if (words && words[0].startsWith(cfg.prefix)) {
        let cmd = words[0].substring(cfg.prefix.length);
        if (commands[cmd]) {
            words.shift();
            commands[cmd](message, words);
        }
    }
});

client.on('warn', function (warn) {
    console.error('WARN', warn);
});

client.on('error', function (error) {
    console.error('ERROR', error);
});

client.login(cfg.token).catch(function (error) {
    if (error) {
        console.error("Couldn't login: ", error);
        process.exit(15);
    }
});

function reflect(promise){
    return promise.then(function(v){ return {v:v, status: "resolved" }},
                        function(e){ return {e:e, status: "rejected" }});
}

function waitAll(promises, resolved, rejected) {
	var res = [];
	var rej = [];
	promises.forEach();
	Promise.all(promises.map( function(p){
			return promise.then(
				function(v){
					res.push(v)
					return 1
				},
				function(e){
					rej.push(e)
					return 0
				}
			);
		})
	).then((v)=>{return {"resolved": res, "rejected": rej} });
}

function memberName(mem) {
	return mem.nickname || mem.user.username;
}

var commands = {
	gdq_purge: function(message, words) {
		var guildMember = theGuild.members.find("id",message.author.id);
		if(guildMember.hasPermissions(["MANAGE_MESSAGES"])) {
			var member = theGuild.members.find(mem=>{
				return (mem.nickname === words[0] || mem.user.username === words[0]); 
			});
			console.log("Member to purge: "+(member.nickname || member.user.username));
			theGuild.channels.forEach(function(channel, name){
				if(channel.type == "text") {
					channel.fetchMessages({limit: 100}).then(function(msgs) {
						var messages = msgs.filter(msg=>{return msg.author.id == member.id});
						if(messages.size>0) {
							console.log("Deleting "+messages.size+" messages in channel "+channel);
							channel.bulkDelete(messages).catch(function(error) {
								if(error) {
									console.error(error);
								}
							});
						} else {
							console.log("Deleting no messages in channel "+channel.name);
						}
					}, function(err) {
						console.error(err);
						message.reply("Couldnt load messages in "+channel.name);
					});
				}
			});
			message.reply("User "+memberName(member)+" was purged");
		} else {
			message.reply("Access denied.");
		}
	},
	gdq_clear_role: function(message, words) {
		var guildMember = theGuild.members.find("id",message.author.id);
		if(guildMember.hasPermissions(["ADMINISTRATOR","MANAGE_ROLES_OR_PERMISSIONS"])) {
			var role = theGuild.roles.find("name",words[0]);
			var promises = [];
			if(role) {
				var memCnt = role.members.size;
				Promise.all(role.members.map((member)=>{
					return reflect(member.removeRole(role));
				})).then(function(results) {
					message.reply("Removed role "+role.name+" for "+memCnt+" members");
				}, function(error) {
					message.reply("Couldn't remove role: "+error);
				});
			} else {
				message.reply("Role "+words[0]+" does not exist");
			}
		} else {
			message.reply("Access denied.");
		}
	}
};

function sendReply(message, reply) {
    client.reply(message, reply, { tts: false }, function (error) {
        if (error) {
            console.error('WERROR', error);
        }
    });
}

process.on('SIGINT', function () {
    console.log("Logging out");
    client.destroy().then(function () { process.exit(); });
});
