import hmacsha1 from 'hmacsha1';
import * as sha256 from "fast-sha256";

(function(app){
	class OAuth2Access {
		constructor(token, token_type, expires_in = -1, refresh_token = null, scope = null, extras){
			this.token = token;
			this.token_type = token_type;
			this.expires = (expires_in) ? ((new Date()).getTime() + parseInt(expires_in)) : -1;
			this.refresh_token = refresh_token;
			this.scope = scope;
			this.extras = extras;
			this.__listners = {};
			if(expires_in > -1)
				setTimeout(function(){
					var ev = new Event('expired');
					ev.srcElement = this;
					this.dispatchEvent(ev);
				}.bind(this), parseInt(expires_in) * 1000);
		}
		addEventListener(type, code){
			if(!this.__listners[type])
				this.__listners[type] = [];
			this.__listners[type].push(code);
		}
		removeEventListener(type, code){
			if(this.__listners[type]){
				var indx = this.__listners[type].indexOf(code);
				if(indx != -1)
					array.splice(indx, 1);
			}
		}
		dispatchEvent(e){
			for(var func of this.__listners[e.name])
				func.call(this, e);
		}
		toPlainObject(){
			//TODO:
		}
	}
	class OAuth2Module extends BobbleHead.Module{
		constructor(){
			super('oauth2');
			this.services = {};
			this.tokens = {
				content: {},
				save: function(s){
					//TODO:
				},
				setAccess: function(s, a){
					this.content[s] = a;
					if(this.persist[s]==true)
						this.save(s);
				},
				getAccess: function(s){
					return this.content[s];
				}
			};
			//TODO: load from localDatabase tokens
			this.persist = {};
			var nav = window.navigator;
			var screen = window.screen;
			this.guid = nav.mimeTypes.length;
			this.guid += nav.userAgent.replace(/\D+/g, '');
			this.guid += nav.plugins.length;
			this.guid += screen.height || '';
			this.guid += screen.width || '';
			this.guid += screen.pixelDepth || '';
			this.allParamsRegex = /([^&#=]+)(?:=([^&#]*)|&|#|$)/gm;
		}
		addService(data){
			if(!data.service_name) return 'service_name missing';
			if(!data.client_id) return 'client_id missing';
			if(!data.auth_url) return 'auth_url missing';
			if(!data.response_type) return 'response_type missing';
			if(!data.client_secret && data.response_type == 'code') return 'client_secret missing';
			if(data.response_type != 'token' && !data.token_url) return 'token_url missing';
			if(!data.redirect_uri) return 'redirect_uri missing';
			
			var serv_name = data.service_name;
			this.services[serv_name] = data;
			if(this.services[serv_name]['persist'])
				if(this.services[serv_name]['persist'] === false)
					delete this.services[serv_name]['persist'];
				else if(this.services[serv_name]['persist'] === true){
					this.persist[serv_name] = true;
					delete this.services[serv_name]['persist'];
				}
			return true;
		}
		logout(data){
			if(!data.get('service_name'))
				return 'service_name missing';
			else{
				var serv_name = data.get('service_name');
				this.tokens.setAccess(serv_name, null);
			}
			return true;
		}
		parseTokenFromResponse(serv_name, scope, response){
			var access_token;
			var token_type;
			var expires_in;
			var refresh_token;
			var parsedObj = response.content;
			if(typeof response.content == 'string'){
				parsedObj = this.getAllParam(response.content);
			}
			access_token = parsedObj.access_token;
			token_type = parsedObj.token_type;
			expires_in = parsedObj.expires_in;
			refresh_token = parsedObj.refresh_token;
			var _scope = parsedObj.scope || scope;
			var extras = null;
			for(var key in parsedObj){
				if(key != 'access_token' &&
						key != 'token_type' &&
						key != 'expires_in' &&
						key != 'refresh_token' &&
						key != 'scope'){
					if(extras == null)
						extras = {};
					extras[key] = response.content[key];
				}
			}
			var accessObj = new OAuth2Access(access_token, token_type, expires_in, refresh_token, _scope, extras);
			if(refresh_token &&
				refresh_token!= '' &&
				(token_type.toLowerCase() == 'bearer' ||
				token_type.toLowerCase() == 'mac')
			)
				accessObj.addEventListener('expired',this.refreshToken.bind(this, serv_name, scope));
			this.tokens.setAccess(serv_name, accessObj);
			return accessObj;
		}
		refreshToken(servName, scope, e){
			var access = e.srcElement;
			var d = new FormData();
			d.set('grant_type', 'refresh_token');
			d.set('refresh_token',access.refresh_token);
			if(scope)
				d.set('scope',access.scope);
			var header = null;
			if(access.token_type.toLowerCase() == 'bearer')
				header = {
					'Authorization': 'Bearer '+access.access_token
				};
			else if(access.token_type.toLowerCase() == 'mac' &&
				access.extras.mac_key &&
				access.extras.mac_algorithm &&
				(access.extras.mac_algorithm == "hmac-sha-1" ||
				access.extras.mac_algorithm == "hmac-sha-256")){
				var ts = (new Date()).getTime();
				var nonce = '';
				var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
				for (var i = 0; i < 8; i++)
					nonce += possible.charAt(Math.floor(Math.random() * 62));
				var l = document.createElement("a");
				l.href = this.services[servName].token_url;
				var domain = {
					host: l.hostname,
					port: l.port
				};
				var normReqString = ts +
					nonce +
					'POST' +
					this.services[servName].token_url +
					domain.host +
					domain.port;
				header = {
					'Authorization': 'MAC id="'+access.extras.mac_key+'",\
										ts="'+ts+'",\
										nonce="'+nonce+'",\
										mac="'+
											(access.extras.mac_algorithm == "hmac-sha-1") ?
												hmacsha1(access.extras.mac_key, normReqString) :
												(access.extras.mac_algorithm == "hmac-sha-256") ?
													sha256.hmac(access.extras.mac_key, normReqString) :
													''
										+'"'
				};
			}
			defaultConnector.request(
				new BobbleHead.ConnectorRequest('post', this.services[servName].token_url, d, header, this.services[serv_name].token_response_type)
			).then(this.parseTokenFromResponse.bind(this,servName, scope));
		}
		getParam(url, param){
			var index = url.indexOf(param+'=');
			var value = null;
			if(index != -1 &&
				( index>0 || (
					url[index-1] == '?' ||
					url[index-1] == '#' ||
					url[index-1] == '&'
				))){
				var end_index = url.indexOf('&', index +param.length +1);
				if(end_index == -1)
					end_index = url.indexOf('#', index +param.length +1);
				if(end_index == -1)
					end_index = undefined;
				value = decodeURIComponent(url.substring(index+param.length +1, end_index));
			}
			return value;
		}
		getAllParam(url){
			var param_start_int = url.indexOf('?');
			var param_start_das = url.indexOf('#');
			var param_start_and = url.indexOf('&');
			var toCompare = [];
			if(param_start_int != -1)
				toCompare.push(param_start_int);
			if(param_start_das != -1)
				toCompare.push(param_start_das);
			if(param_start_and != -1)
				toCompare.push(param_start_and);
			var param_start = 0;
			for(var comp of toCompare)
				if(comp < param_start)
					param_start = comp;
			while(url[param_start] == '?' ||
				url[param_start] == '#' ||
				url[param_start] == '&')
				param_start++;
			url = url.substring(param_start +1);
			var hold;
			var result = {};
			while ((hold = this.allParamsRegex.exec(url)) !== null) {
				result[hold[1]] = hold[2] || true;
			}
			return result;
		}
		init(configuration){
			super.init(configuration);
			console.log(111);
			
			var services = configuration.getProperty('services');
			if(services){
				for(var serv_name in services){
					var serv = services[serv_name];
					serv.service_name = serv_name;
					this.addService(serv);
				}
			}
			
			this.controller('addService', function(data, success, error){
				var _data = {};
				for(var v of data.entries())
					_data[v[0]] = v[1];
				var res = this.addService(_data);
				if(res === true)
					success();
				else
					error(res);
			}.bind(this));
			
			this.controller('getAccess', function(data, success, error){
				if(!data.get('service_name'))
					error('service_name missing');
				else if(!this.services[data.get('service_name')])
					error(data.get('service_name') + ' service not found');
				else
					success(this.tokens.getAccess(data.get('service_name')) || null);
			}.bind(this));
			
			this.controller('setAccess', function(data, success, error){
				if(!data.get('service_name'))
					error('service_name missing');
				else if(!this.services[data.get('service_name')])
					error(data.get('service_name') + ' service not found');
				else{
					this.tokens.setAccess(data.get('service_name'), new OAuth2Access(
						data.get('token'),
						data.get('token_type'),
						parseInt(data.get('expires')) - (new Date()).getTime(),
						data.get('refresh_token'),
						data.get('scope')
					));
					success();
				}
			}.bind(this));
			
			this.controller('logout', function(data, success, error){
				var res = this.logout(data);
				if(res === true)
					success();
				else
					error(res);
			}.bind(this));
			
			this.controller('login', function(data, success, error){
				if(!data.get('service_name'))
					error('service_name missing');
				else if(!this.services[data.get('service_name')])
					error(data.get('service_name') + ' service not found');
				else{
					var serv_name = data.get('service_name');
					var scope = data.get('scope');
					var params = [];
					for(var param_name in this.services[serv_name])
						if(param_name!='auth_url' &&
							param_name!='client_secret' &&
							param_name!='token_url' &&
							param_name!='service_name' &&
							param_name!='token_response_type')
							params.push(param_name+'='+this.services[serv_name][param_name]);
					var state = '{code:'+
						(new Date()).getTime().toString(16)+
						',guid:'+this.guid+
						'}';
					params.push('state='+state);
					if(scope)
						params.push('scope='+scope);
					var login_url = this.services[serv_name].auth_url + '?' + params.join('&');
					var loginWindow = window.open(login_url, '_blank', 'location=yes,clearsessioncache=yes');
					var catch_func = function(self){
						try{
							var url = loginWindow.location.href;
							//loginWindow.addEventListener('load', function(int_func, e){
								//var url = e.srcElement.URL;
								if(url){
									if(this.services[serv_name].response_type == "code"){
										url = url.split("#")[0];   
										var code = this.getParam(url,'code');
										var _error = this.getParam(url,'error');
										if (code || _error){
											loginWindow.close();
											this.logout(data);
											if(code){
												var d = new FormData();
												d.set('code',code);
												d.set('client_id',this.services[serv_name].client_id);
												d.set('client_secret',this.services[serv_name].client_secret);
												d.set('redirect_uri',this.services[serv_name].redirect_uri);
												if(scope)
													d.set('scope',scope);
												d.set('grant_type','authorization_code');
												defaultConnector.request(
													new BobbleHead.ConnectorRequest('post', this.services[serv_name].token_url, d, null, this.services[serv_name].token_response_type)
												).then(function(response){
													var accessObj = this.parseTokenFromResponse(serv_name, scope, response);
													success(accessObj);
												}.bind(this)).catch(function(response){
													this.logout(data);
													error(response);
												}.bind(this));
											}else if(_error){
												this.logout(data);
												error(_error);
											}
										}
									}else if(this.services[serv_name].response_type == 'token'){
										var access_token = this.getParam(url,'access_token');
										var expires_in = this.getParam(url,'expires_in');
										var _error = this.getParam(url,'error');
										var _scope = this.getParam(url,'scope') || scope;
										var _state = this.getParam(url,'state');
										if(_state == state &&(access_token || _error)){
											loginWindow.close();
											this.logout(data);
											if(access_token){
												var accessObj = new OAuth2Access(access_token, 'token', expires_in, _scope);
												this.tokens.setAccess(serv_name, accessObj);
												success(accessObj);
											}else if(_error)
												error(_error);			
										}else{
											loginWindow.close();
											this.logout(data);
											error('CSRF protection triggered');
										}
									}
								}
							//}.bind(this, self), false);
						}catch(e){
							if(e.name == 'SecurityError')
								setTimeout(self.bind(this,self), 1000);
							else
								error(e.message);
						}
					};
					setTimeout(catch_func.bind(this,catch_func), 1000);
					loginWindow.addEventListener('close', function(){
						console.log(4444);
					});
				}
			});
		}
	};
	var module = new OAuth2Module();
	app.registerModule(module);
	app.addToGlobalContext('OAuth2Access',OAuth2Access);
})(BobbleHead.app);