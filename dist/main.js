!function(e){var t={};function s(r){if(t[r])return t[r].exports;var i=t[r]={i:r,l:!1,exports:{}};return e[r].call(i.exports,i,i.exports,s),i.l=!0,i.exports}s.m=e,s.c=t,s.d=function(e,t,r){s.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},s.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},s.t=function(e,t){if(1&t&&(e=s(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var r=Object.create(null);if(s.r(r),Object.defineProperty(r,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var i in e)s.d(r,i,function(t){return e[t]}.bind(null,i));return r},s.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return s.d(t,"a",t),t},s.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},s.p="",s(s.s=2)}([function(e,t){e.exports=function(e,t,s,r){function i(e,t,s,r){return e<20?t&s|~t&r:e<40?t^s^r:e<60?t&s|t&r|s&r:t^s^r}function n(e){return e<20?1518500249:e<40?1859775393:e<60?-1894007588:-899497514}function o(e,t){var s=(65535&e)+(65535&t);return(e>>16)+(t>>16)+(s>>16)<<16|65535&s}function a(e,t){return e<<t|e>>>32-t}function h(e,t){e[t>>5]|=128<<24-t%32,e[15+(t+64>>9<<4)]=t;for(var s=[80],r=1732584193,h=-271733879,c=-1732584194,u=271733878,f=-1009589776,l=0;l<e.length;l+=16){for(var v=r,p=h,g=c,d=u,_=f,m=0;m<80;m++){s[m]=m<16?e[l+m]:a(s[m-3]^s[m-8]^s[m-14]^s[m-16],1);var b=o(o(a(r,5),i(m,h,c,u)),o(o(f,s[m]),n(m)));f=u,u=c,c=a(h,30),h=r,r=b}r=o(r,v),h=o(h,p),c=o(c,g),u=o(u,d),f=o(f,_)}return[r,h,c,u,f]}function c(e){for(var t=[],s=(1<<r)-1,i=0;i<e.length*r;i+=r)t[i>>5]|=(e.charCodeAt(i/8)&s)<<32-r-i%32;return t}return s||(s="="),r||(r=8),function(e,t){return function(e){for(var t="",r=0;r<4*e.length;r+=3)for(var i=(e[r>>2]>>8*(3-r%4)&255)<<16|(e[r+1>>2]>>8*(3-(r+1)%4)&255)<<8|e[r+2>>2]>>8*(3-(r+2)%4)&255,n=0;n<4;n++)8*r+6*n>32*e.length?t+=s:t+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(i>>6*(3-n)&63);return t}(function(e,t){var s=c(e);s.length>16&&(s=h(s,e.length*r));for(var i=[16],n=[16],o=0;o<16;o++)i[o]=909522486^s[o],n[o]=1549556828^s[o];var a=h(i.concat(c(t)),512+t.length*r);return h(n.concat(a),672)}(e,t))}(e,t)}},function(e,t,s){var r;!function(t,i){var n={};!function(e){"use strict";e.__esModule=!0,e.digestLength=32,e.blockSize=64;var t=new Uint32Array([1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298]);function s(e,s,r,i,n){for(var o,a,h,c,u,f,l,v,p,g,d,_,m;n>=64;){for(o=s[0],a=s[1],h=s[2],c=s[3],u=s[4],f=s[5],l=s[6],v=s[7],g=0;g<16;g++)d=i+4*g,e[g]=(255&r[d])<<24|(255&r[d+1])<<16|(255&r[d+2])<<8|255&r[d+3];for(g=16;g<64;g++)p=e[g-2],_=(p>>>17|p<<15)^(p>>>19|p<<13)^p>>>10,p=e[g-15],m=(p>>>7|p<<25)^(p>>>18|p<<14)^p>>>3,e[g]=(_+e[g-7]|0)+(m+e[g-16]|0);for(g=0;g<64;g++)_=(((u>>>6|u<<26)^(u>>>11|u<<21)^(u>>>25|u<<7))+(u&f^~u&l)|0)+(v+(t[g]+e[g]|0)|0)|0,m=((o>>>2|o<<30)^(o>>>13|o<<19)^(o>>>22|o<<10))+(o&a^o&h^a&h)|0,v=l,l=f,f=u,u=c+_|0,c=h,h=a,a=o,o=_+m|0;s[0]+=o,s[1]+=a,s[2]+=h,s[3]+=c,s[4]+=u,s[5]+=f,s[6]+=l,s[7]+=v,i+=64,n-=64}return i}var r=function(){function t(){this.digestLength=e.digestLength,this.blockSize=e.blockSize,this.state=new Int32Array(8),this.temp=new Int32Array(64),this.buffer=new Uint8Array(128),this.bufferLength=0,this.bytesHashed=0,this.finished=!1,this.reset()}return t.prototype.reset=function(){return this.state[0]=1779033703,this.state[1]=3144134277,this.state[2]=1013904242,this.state[3]=2773480762,this.state[4]=1359893119,this.state[5]=2600822924,this.state[6]=528734635,this.state[7]=1541459225,this.bufferLength=0,this.bytesHashed=0,this.finished=!1,this},t.prototype.clean=function(){for(var e=0;e<this.buffer.length;e++)this.buffer[e]=0;for(var e=0;e<this.temp.length;e++)this.temp[e]=0;this.reset()},t.prototype.update=function(e,t){if(void 0===t&&(t=e.length),this.finished)throw new Error("SHA256: can't update because hash was finished.");var r=0;if(this.bytesHashed+=t,this.bufferLength>0){for(;this.bufferLength<64&&t>0;)this.buffer[this.bufferLength++]=e[r++],t--;64===this.bufferLength&&(s(this.temp,this.state,this.buffer,0,64),this.bufferLength=0)}for(t>=64&&(r=s(this.temp,this.state,e,r,t),t%=64);t>0;)this.buffer[this.bufferLength++]=e[r++],t--;return this},t.prototype.finish=function(e){if(!this.finished){var t=this.bytesHashed,r=this.bufferLength,i=t/536870912|0,n=t<<3,o=t%64<56?64:128;this.buffer[r]=128;for(var a=r+1;a<o-8;a++)this.buffer[a]=0;this.buffer[o-8]=i>>>24&255,this.buffer[o-7]=i>>>16&255,this.buffer[o-6]=i>>>8&255,this.buffer[o-5]=i>>>0&255,this.buffer[o-4]=n>>>24&255,this.buffer[o-3]=n>>>16&255,this.buffer[o-2]=n>>>8&255,this.buffer[o-1]=n>>>0&255,s(this.temp,this.state,this.buffer,0,o),this.finished=!0}for(var a=0;a<8;a++)e[4*a+0]=this.state[a]>>>24&255,e[4*a+1]=this.state[a]>>>16&255,e[4*a+2]=this.state[a]>>>8&255,e[4*a+3]=this.state[a]>>>0&255;return this},t.prototype.digest=function(){var e=new Uint8Array(this.digestLength);return this.finish(e),e},t.prototype._saveState=function(e){for(var t=0;t<this.state.length;t++)e[t]=this.state[t]},t.prototype._restoreState=function(e,t){for(var s=0;s<this.state.length;s++)this.state[s]=e[s];this.bytesHashed=t,this.finished=!1,this.bufferLength=0},t}();e.Hash=r;var i=function(){function e(e){this.inner=new r,this.outer=new r,this.blockSize=this.inner.blockSize,this.digestLength=this.inner.digestLength;var t=new Uint8Array(this.blockSize);if(e.length>this.blockSize)(new r).update(e).finish(t).clean();else for(var s=0;s<e.length;s++)t[s]=e[s];for(var s=0;s<t.length;s++)t[s]^=54;this.inner.update(t);for(var s=0;s<t.length;s++)t[s]^=106;this.outer.update(t),this.istate=new Uint32Array(8),this.ostate=new Uint32Array(8),this.inner._saveState(this.istate),this.outer._saveState(this.ostate);for(var s=0;s<t.length;s++)t[s]=0}return e.prototype.reset=function(){return this.inner._restoreState(this.istate,this.inner.blockSize),this.outer._restoreState(this.ostate,this.outer.blockSize),this},e.prototype.clean=function(){for(var e=0;e<this.istate.length;e++)this.ostate[e]=this.istate[e]=0;this.inner.clean(),this.outer.clean()},e.prototype.update=function(e){return this.inner.update(e),this},e.prototype.finish=function(e){return this.outer.finished?this.outer.finish(e):(this.inner.finish(e),this.outer.update(e,this.digestLength).finish(e)),this},e.prototype.digest=function(){var e=new Uint8Array(this.digestLength);return this.finish(e),e},e}();function n(e){var t=(new r).update(e),s=t.digest();return t.clean(),s}e.HMAC=i,e.hash=n,e.default=n,e.hmac=function(e,t){var s=new i(e).update(t),r=s.digest();return s.clean(),r},e.pbkdf2=function(e,t,s,r){for(var n=new i(e),o=n.digestLength,a=new Uint8Array(4),h=new Uint8Array(o),c=new Uint8Array(o),u=new Uint8Array(r),f=0;f*o<r;f++){var l=f+1;a[0]=l>>>24&255,a[1]=l>>>16&255,a[2]=l>>>8&255,a[3]=l>>>0&255,n.reset(),n.update(t),n.update(a),n.finish(c);for(var v=0;v<o;v++)h[v]=c[v];for(var v=2;v<=s;v++){n.reset(),n.update(c).finish(c);for(var p=0;p<o;p++)h[p]^=c[p]}for(var v=0;v<o&&f*o+v<r;v++)u[f*o+v]=h[v]}for(var f=0;f<o;f++)h[f]=c[f]=0;for(var f=0;f<4;f++)a[f]=0;return n.clean(),u}}(n);var o=n.default;for(var a in n)o[a]=n[a];"object"==typeof e&&"object"==typeof e.exports?e.exports=o:void 0===(r=function(){return o}.call(n,s,n,e))||(e.exports=r)}()},function(e,t,s){"use strict";s.r(t);var r=s(0),i=s.n(r);s(1);!function(e){class t{constructor(e,t,s=-1,r=null,i=null,n){this.token=e,this.token_type=t,this.expires=s?(new Date).getTime()+parseInt(s):-1,this.refresh_token=r,this.scope=i,this.extras=n,this.__listners={},s>-1&&setTimeout(function(){var e=new Event("expired");e.srcElement=this,this.dispatchEvent(e)}.bind(this),1e3*parseInt(s))}addEventListener(e,t){this.__listners[e]||(this.__listners[e]=[]),this.__listners[e].push(t)}removeEventListener(e,t){if(this.__listners[e]){var s=this.__listners[e].indexOf(t);-1!=s&&array.splice(s,1)}}dispatchEvent(e){for(var t of this.__listners[e.name])t.call(this,e)}toPlainObject(){}}var s=new class extends BobbleHead.Module{constructor(){super("oauth2"),this.services={},this.tokens={content:{},save:function(e){},setAccess:function(e,t){this.content[e]=t,1==this.persist[e]&&this.save(e)},getAccess:function(e){return this.content[e]}},this.persist={};var e=window.navigator,t=window.screen;this.guid=e.mimeTypes.length,this.guid+=e.userAgent.replace(/\D+/g,""),this.guid+=e.plugins.length,this.guid+=t.height||"",this.guid+=t.width||"",this.guid+=t.pixelDepth||"",this.allParamsRegex=/([^&#=]+)(?:=([^&#]*)|&|#|$)/gm}addService(e){if(!e.service_name)return"service_name missing";if(!e.client_id)return"client_id missing";if(!e.auth_url)return"auth_url missing";if(!e.response_type)return"response_type missing";if(!e.client_secret&&"code"==e.response_type)return"client_secret missing";if("token"!=e.response_type&&!e.token_url)return"token_url missing";if(!e.redirect_uri)return"redirect_uri missing";var t=e.service_name;return this.services[t]=e,this.services[t].persist&&(!1===this.services[t].persist?delete this.services[t].persist:!0===this.services[t].persist&&(this.persist[t]=!0,delete this.services[t].persist)),!0}logout(e){if(!e.get("service_name"))return"service_name missing";var t=e.get("service_name");return this.tokens.setAccess(t,null),!0}parseTokenFromResponse(e,s,r){var i,n,o,a,h=r.content;"string"==typeof r.content&&(h=this.getAllParam(r.content)),i=h.access_token,n=h.token_type,o=h.expires_in,a=h.refresh_token;var c=h.scope||s,u=null;for(var f in h)"access_token"!=f&&"token_type"!=f&&"expires_in"!=f&&"refresh_token"!=f&&"scope"!=f&&(null==u&&(u={}),u[f]=r.content[f]);var l=new t(i,n,o,a,c,u);return!a||""==a||"bearer"!=n.toLowerCase()&&"mac"!=n.toLowerCase()||l.addEventListener("expired",this.refreshToken.bind(this,e,s)),this.tokens.setAccess(e,l),l}refreshToken(e,t,s){var r=s.srcElement,n=new FormData;n.set("grant_type","refresh_token"),n.set("refresh_token",r.refresh_token),t&&n.set("scope",r.scope);var o=null;if("bearer"==r.token_type.toLowerCase())o={Authorization:"Bearer "+r.access_token};else if("mac"==r.token_type.toLowerCase()&&r.extras.mac_key&&r.extras.mac_algorithm&&("hmac-sha-1"==r.extras.mac_algorithm||"hmac-sha-256"==r.extras.mac_algorithm)){for(var a=(new Date).getTime(),h="",c=0;c<8;c++)h+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(Math.floor(62*Math.random()));var u=document.createElement("a");u.href=this.services[e].token_url;var f={host:u.hostname,port:u.port},l=a+h+"POST"+this.services[e].token_url+f.host+f.port;o={Authorization:i()(r.extras.mac_key,l)}}defaultConnector.request(new BobbleHead.ConnectorRequest("post",this.services[e].token_url,n,o,this.services[serv_name].token_response_type)).then(this.parseTokenFromResponse.bind(this,e,t))}getParam(e,t){var s=e.indexOf(t+"="),r=null;if(-1!=s&&(s>0||"?"==e[s-1]||"#"==e[s-1]||"&"==e[s-1])){var i=e.indexOf("&",s+t.length+1);-1==i&&(i=e.indexOf("#",s+t.length+1)),-1==i&&(i=void 0),r=decodeURIComponent(e.substring(s+t.length+1,i))}return r}getAllParam(e){var t=e.indexOf("?"),s=e.indexOf("#"),r=e.indexOf("&"),i=[];-1!=t&&i.push(t),-1!=s&&i.push(s),-1!=r&&i.push(r);var n,o=0;for(var a of i)a<o&&(o=a);for(;"?"==e[o]||"#"==e[o]||"&"==e[o];)o++;e=e.substring(o+1);for(var h={};null!==(n=this.allParamsRegex.exec(e));)h[n[1]]=n[2]||!0;return h}init(e){super.init(e),console.log(111);var s=e.getProperty("services");if(s)for(var r in s){var i=s[r];i.service_name=r,this.addService(i)}this.controller("addService",function(e,t,s){var r={};for(var i of e.entries())r[i[0]]=i[1];var n=this.addService(r);!0===n?t():s(n)}.bind(this)),this.controller("getAccess",function(e,t,s){e.get("service_name")?this.services[e.get("service_name")]?t(this.tokens.getAccess(e.get("service_name"))||null):s(e.get("service_name")+" service not found"):s("service_name missing")}.bind(this)),this.controller("setAccess",function(e,s,r){e.get("service_name")?this.services[e.get("service_name")]?(this.tokens.setAccess(e.get("service_name"),new t(e.get("token"),e.get("token_type"),parseInt(e.get("expires"))-(new Date).getTime(),e.get("refresh_token"),e.get("scope"))),s()):r(e.get("service_name")+" service not found"):r("service_name missing")}.bind(this)),this.controller("logout",function(e,t,s){var r=this.logout(e);!0===r?t():s(r)}.bind(this)),this.controller("login",function(e,s,r){if(e.get("service_name"))if(this.services[e.get("service_name")]){var i=e.get("service_name"),n=e.get("scope"),o=[];for(var a in this.services[i])"auth_url"!=a&&"client_secret"!=a&&"token_url"!=a&&"service_name"!=a&&"token_response_type"!=a&&o.push(a+"="+this.services[i][a]);var h="{code:"+(new Date).getTime().toString(16)+",guid:"+this.guid+"}";o.push("state="+h),n&&o.push("scope="+n);var c=this.services[i].auth_url+"?"+o.join("&"),u=window.open(c,"_blank","location=yes,clearsessioncache=yes"),f=function(o){try{var a=u.location.href;if(a)if("code"==this.services[i].response_type){a=a.split("#")[0];var c=this.getParam(a,"code"),f=this.getParam(a,"error");if(c||f)if(u.close(),this.logout(e),c){var l=new FormData;l.set("code",c),l.set("client_id",this.services[i].client_id),l.set("client_secret",this.services[i].client_secret),l.set("redirect_uri",this.services[i].redirect_uri),n&&l.set("scope",n),l.set("grant_type","authorization_code"),defaultConnector.request(new BobbleHead.ConnectorRequest("post",this.services[i].token_url,l,null,this.services[i].token_response_type)).then(function(e){var t=this.parseTokenFromResponse(i,n,e);s(t)}.bind(this)).catch(function(t){this.logout(e),r(t)}.bind(this))}else f&&(this.logout(e),r(f))}else if("token"==this.services[i].response_type){var v=this.getParam(a,"access_token"),p=this.getParam(a,"expires_in"),g=(f=this.getParam(a,"error"),this.getParam(a,"scope")||n);if(this.getParam(a,"state")==h&&(v||f))if(u.close(),this.logout(e),v){var d=new t(v,"token",p,g);this.tokens.setAccess(i,d),s(d)}else f&&r(f);else u.close(),this.logout(e),r("CSRF protection triggered")}}catch(e){"SecurityError"==e.name?setTimeout(o.bind(this,o),1e3):r(e.message)}};setTimeout(f.bind(this,f),1e3),u.addEventListener("close",function(){console.log(4444)})}else r(e.get("service_name")+" service not found");else r("service_name missing")})}};e.registerModule(s),e.addToGlobalContext("OAuth2Access",t)}(BobbleHead.app)}]);