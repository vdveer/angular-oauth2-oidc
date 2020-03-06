import { __awaiter, __decorate, __extends, __generator, __metadata, __param, __read, __values } from "tslib";
import { Injectable, NgZone, Optional, OnDestroy } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Subject, of, race, from } from 'rxjs';
import { filter, delay, first, tap, map, switchMap, debounceTime } from 'rxjs/operators';
import { ValidationHandler, ValidationParams } from './token-validation/validation-handler';
import { UrlHelperService } from './url-helper.service';
import { OAuthInfoEvent, OAuthErrorEvent, OAuthSuccessEvent } from './events';
import { OAuthLogger, OAuthStorage, LoginOptions, ParsedIdToken, OidcDiscoveryDoc, TokenResponse, UserInfo } from './types';
import { b64DecodeUnicode, base64UrlEncode } from './base64-helper';
import { AuthConfig } from './auth.config';
import { WebHttpUrlEncodingCodec } from './encoder';
import { HashHandler } from './token-validation/hash-handler';
/**
 * Service for logging in and logging out with
 * OIDC and OAuth2. Supports implicit flow and
 * password flow.
 */
var OAuthService = /** @class */ (function (_super) {
    __extends(OAuthService, _super);
    function OAuthService(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto) {
        var _this = _super.call(this) || this;
        _this.ngZone = ngZone;
        _this.http = http;
        _this.config = config;
        _this.urlHelper = urlHelper;
        _this.logger = logger;
        _this.crypto = crypto;
        /**
         * @internal
         * Deprecated:  use property events instead
         */
        _this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        _this.state = '';
        _this.eventsSubject = new Subject();
        _this.discoveryDocumentLoadedSubject = new Subject();
        _this.grantTypesSupported = [];
        _this.inImplicitFlow = false;
        _this.debug('angular-oauth2-oidc v8-beta');
        _this.discoveryDocumentLoaded$ = _this.discoveryDocumentLoadedSubject.asObservable();
        _this.events = _this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            _this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            _this.configure(config);
        }
        try {
            if (storage) {
                _this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                _this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).'
                + 'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        _this.setupRefreshTimer();
        return _this;
    }
    /**
     * Use this method to configure the service
     * @param config the configuration
     */
    OAuthService.prototype.configure = function (config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign({}, new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    };
    OAuthService.prototype.configChanged = function () {
        this.setupRefreshTimer();
    };
    OAuthService.prototype.restartSessionChecksIfStillLoggedIn = function () {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    };
    OAuthService.prototype.restartRefreshTimerIfStillLoggedIn = function () {
        this.setupExpirationTimers();
    };
    OAuthService.prototype.setupSessionCheck = function () {
        var _this = this;
        this.events.pipe(filter(function (e) { return e.type === 'token_received'; })).subscribe(function (e) {
            _this.initSessionCheck();
        });
    };
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param params Additional parameter to pass
     * @param listenTo Setup automatic refresh of a specific token type
     */
    OAuthService.prototype.setupAutomaticSilentRefresh = function (params, listenTo, noPrompt) {
        var _this = this;
        if (params === void 0) { params = {}; }
        if (noPrompt === void 0) { noPrompt = true; }
        var shouldRunSilentRefresh = true;
        this.events.pipe(tap(function (e) {
            if (e.type === 'token_received') {
                shouldRunSilentRefresh = true;
            }
            else if (e.type === 'logout') {
                shouldRunSilentRefresh = false;
            }
        }), filter(function (e) { return e.type === 'token_expires'; }), debounceTime(1000)).subscribe(function (e) {
            var event = e;
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) && shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                _this.refreshInternal(params, noPrompt).catch(function (_) {
                    _this.debug('Automatic silent refresh did not work');
                });
            }
        });
        this.restartRefreshTimerIfStillLoggedIn();
    };
    OAuthService.prototype.refreshInternal = function (params, noPrompt) {
        if (!this.silentRefreshRedirectUri && this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    };
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    OAuthService.prototype.loadDiscoveryDocumentAndTryLogin = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        return this.loadDiscoveryDocument().then(function (doc) {
            return _this.tryLogin(options);
        });
    };
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initLoginFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    OAuthService.prototype.loadDiscoveryDocumentAndLogin = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        if (!options) {
            options = { state: '' };
        }
        return this.loadDiscoveryDocumentAndTryLogin(options).then(function (_) {
            if (!_this.hasValidIdToken() || !_this.hasValidAccessToken()) {
                if (_this.responseType === 'code') {
                    _this.initCodeFlow();
                }
                else {
                    _this.initImplicitFlow();
                }
                return false;
            }
            else {
                return true;
            }
        });
    };
    OAuthService.prototype.debug = function () {
        var args = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            args[_i] = arguments[_i];
        }
        if (this.showDebugInformation) {
            this.logger.debug.apply(this.logger, args);
        }
    };
    OAuthService.prototype.validateUrlFromDiscoveryDocument = function (url) {
        var errors = [];
        var httpsCheck = this.validateUrlForHttps(url);
        var issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    };
    OAuthService.prototype.validateUrlForHttps = function (url) {
        if (!url) {
            return true;
        }
        var lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    };
    OAuthService.prototype.assertUrlNotNullAndCorrectProtocol = function (url, description) {
        if (!url) {
            throw new Error("'" + description + "' should not be null");
        }
        if (!this.validateUrlForHttps(url)) {
            throw new Error("'" + description + "' must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
    };
    OAuthService.prototype.validateUrlAgainstIssuer = function (url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    };
    OAuthService.prototype.setupRefreshTimer = function () {
        var _this = this;
        if (typeof window === 'undefined') {
            this.debug('timer not supported on this plattform');
            return;
        }
        if (this.hasValidIdToken() || this.hasValidAccessToken()) {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        }
        if (this.tokenReceivedSubscription)
            this.tokenReceivedSubscription.unsubscribe();
        this.tokenReceivedSubscription = this.events.pipe(filter(function (e) { return e.type === 'token_received'; })).subscribe(function (_) {
            _this.clearAccessTokenTimer();
            _this.clearIdTokenTimer();
            _this.setupExpirationTimers();
        });
    };
    OAuthService.prototype.setupExpirationTimers = function () {
        if (this.hasValidAccessToken()) {
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken()) {
            this.setupIdTokenTimer();
        }
    };
    OAuthService.prototype.setupAccessTokenTimer = function () {
        var _this = this;
        var expiration = this.getAccessTokenExpiration();
        var storedAt = this.getAccessTokenStoredAt();
        var timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(function () {
            _this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe(function (e) {
                _this.ngZone.run(function () {
                    _this.eventsSubject.next(e);
                });
            });
        });
    };
    OAuthService.prototype.setupIdTokenTimer = function () {
        var _this = this;
        var expiration = this.getIdTokenExpiration();
        var storedAt = this.getIdTokenStoredAt();
        var timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(function () {
            _this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe(function (e) {
                _this.ngZone.run(function () {
                    _this.eventsSubject.next(e);
                });
            });
        });
    };
    OAuthService.prototype.clearAccessTokenTimer = function () {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    };
    OAuthService.prototype.clearIdTokenTimer = function () {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    };
    OAuthService.prototype.calcTimeout = function (storedAt, expiration) {
        var now = Date.now();
        var delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    };
    /**
     * DEPRECATED. Use a provider for OAuthStorage instead:
     *
     * { provide: OAuthStorage, useFactory: oAuthStorageFactory }
     * export function oAuthStorageFactory(): OAuthStorage { return localStorage; }
     * Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @ignore
     *
     * @param storage
     */
    OAuthService.prototype.setStorage = function (storage) {
        this._storage = storage;
        this.configChanged();
    };
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param fullUrl
     */
    OAuthService.prototype.loadDiscoveryDocument = function (fullUrl) {
        var _this = this;
        if (fullUrl === void 0) { fullUrl = null; }
        return new Promise(function (resolve, reject) {
            if (!fullUrl) {
                fullUrl = _this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!_this.validateUrlForHttps(fullUrl)) {
                reject('issuer  must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
                return;
            }
            _this.http.get(fullUrl).subscribe(function (doc) {
                if (!_this.validateDiscoveryDocument(doc)) {
                    _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                _this.loginUrl = doc.authorization_endpoint;
                _this.logoutUrl = doc.end_session_endpoint || _this.logoutUrl;
                _this.grantTypesSupported = doc.grant_types_supported;
                _this.issuer = doc.issuer;
                _this.tokenEndpoint = doc.token_endpoint;
                _this.userinfoEndpoint = doc.userinfo_endpoint || _this.userinfoEndpoint;
                _this.jwksUri = doc.jwks_uri;
                _this.sessionCheckIFrameUrl = doc.check_session_iframe || _this.sessionCheckIFrameUrl;
                _this.discoveryDocumentLoaded = true;
                _this.discoveryDocumentLoadedSubject.next(doc);
                if (_this.sessionChecksEnabled) {
                    _this.restartSessionChecksIfStillLoggedIn();
                }
                _this.loadJwks()
                    .then(function (jwks) {
                    var result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    var event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    _this.eventsSubject.next(event);
                    resolve(event);
                    return;
                })
                    .catch(function (err) {
                    _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                });
            }, function (err) {
                _this.logger.error('error loading discovery document', err);
                _this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            });
        });
    };
    OAuthService.prototype.loadJwks = function () {
        var _this = this;
        return new Promise(function (resolve, reject) {
            if (_this.jwksUri) {
                _this.http.get(_this.jwksUri).subscribe(function (jwks) {
                    _this.jwks = jwks;
                    _this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }, function (err) {
                    _this.logger.error('error loading jwks', err);
                    _this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                });
            }
            else {
                resolve(null);
            }
        });
    };
    OAuthService.prototype.validateDiscoveryDocument = function (doc) {
        var errors;
        if (!this.skipIssuerCheck && doc.issuer !== this.issuer) {
            this.logger.error('invalid issuer in discovery document', 'expected: ' + this.issuer, 'current: ' + doc.issuer);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.authorization_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating authorization_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.end_session_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating end_session_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.token_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating token_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.userinfo_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating userinfo_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.jwks_uri);
        if (errors.length > 0) {
            this.logger.error('error validating jwks_uri in discovery document', errors);
            return false;
        }
        if (this.sessionChecksEnabled && !doc.check_session_iframe) {
            this.logger.warn('sessionChecksEnabled is activated but discovery document' +
                ' does not contain a check_session_iframe field');
        }
        return true;
    };
    /**
     * Uses password flow to exchange userName and password for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    OAuthService.prototype.fetchTokenUsingPasswordFlowAndLoadUserProfile = function (userName, password, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then(function () { return _this.loadUserProfile(); });
    };
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     */
    OAuthService.prototype.loadUserProfile = function () {
        var _this = this;
        if (!this.hasValidAccessToken()) {
            throw new Error('Can not load User Profile without access_token');
        }
        if (!this.validateUrlForHttps(this.userinfoEndpoint)) {
            throw new Error('userinfoEndpoint must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
        }
        return new Promise(function (resolve, reject) {
            var headers = new HttpHeaders().set('Authorization', 'Bearer ' + _this.getAccessToken());
            _this.http.get(_this.userinfoEndpoint, { headers: headers }).subscribe(function (info) {
                _this.debug('userinfo received', info);
                var existingClaims = _this.getIdentityClaims() || {};
                if (!_this.skipSubjectCheck) {
                    if (_this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        var err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                _this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                _this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }, function (err) {
                _this.logger.error('error loading user info', err);
                _this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            });
        });
    };
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    OAuthService.prototype.fetchTokenUsingPasswordFlow = function (userName, password, headers) {
        var _this = this;
        if (headers === void 0) { headers = new HttpHeaders(); }
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise(function (resolve, reject) {
            var e_1, _a;
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * @stable
             */
            var params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', _this.scope)
                .set('username', userName)
                .set('password', password);
            if (_this.useHttpBasicAuth) {
                var header = btoa(_this.clientId + ":" + _this.dummyClientSecret);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!_this.useHttpBasicAuth) {
                params = params.set('client_id', _this.clientId);
            }
            if (!_this.useHttpBasicAuth && _this.dummyClientSecret) {
                params = params.set('client_secret', _this.dummyClientSecret);
            }
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_1_1) { e_1 = { error: e_1_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_1) throw e_1.error; }
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .subscribe(function (tokenResponse) {
                _this.debug('tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, _this.extractRecognizedCustomParameters(tokenResponse));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }, function (err) {
                _this.logger.error('Error performing password flow', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            });
        });
    };
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     */
    OAuthService.prototype.refreshToken = function () {
        var _this = this;
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise(function (resolve, reject) {
            var e_2, _a;
            var params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('scope', _this.scope)
                .set('refresh_token', _this._storage.getItem('refresh_token'));
            var headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            if (_this.useHttpBasicAuth) {
                var header = btoa(_this.clientId + ":" + _this.dummyClientSecret);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!_this.useHttpBasicAuth) {
                params = params.set('client_id', _this.clientId);
            }
            if (!_this.useHttpBasicAuth && _this.dummyClientSecret) {
                params = params.set('client_secret', _this.dummyClientSecret);
            }
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_2_1) { e_2 = { error: e_2_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_2) throw e_2.error; }
                }
            }
            _this.http
                .post(_this.tokenEndpoint, params, { headers: headers })
                .pipe(switchMap(function (tokenResponse) {
                if (tokenResponse.id_token) {
                    return from(_this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true))
                        .pipe(tap(function (result) { return _this.storeIdToken(result); }), map(function (_) { return tokenResponse; }));
                }
                else {
                    return of(tokenResponse);
                }
            }))
                .subscribe(function (tokenResponse) {
                _this.debug('refresh tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, _this.extractRecognizedCustomParameters(tokenResponse));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }, function (err) {
                _this.logger.error('Error refreshing token', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    };
    OAuthService.prototype.removeSilentRefreshEventListener = function () {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    };
    OAuthService.prototype.setupSilentRefreshEventListener = function () {
        var _this = this;
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = function (e) {
            var message = _this.processMessageEventMessage(e);
            _this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                customRedirectUri: _this.silentRefreshRedirectUri || _this.redirectUri
            }).catch(function (err) { return _this.debug('tryLogin during silent refresh failed', err); });
        };
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    };
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     */
    OAuthService.prototype.silentRefresh = function (params, noPrompt) {
        var _this = this;
        if (params === void 0) { params = {}; }
        if (noPrompt === void 0) { noPrompt = true; }
        var claims = this.getIdentityClaims() || {};
        if (this.useIdTokenHintForSilentRefresh && this.hasValidIdToken()) {
            params['id_token_hint'] = this.getIdToken();
        }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl  must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
        }
        if (typeof document === 'undefined') {
            throw new Error('silent refresh is not supported on this platform');
        }
        var existingIframe = document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        var iframe = document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        var redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then(function (url) {
            iframe.setAttribute('src', url);
            if (!_this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            document.body.appendChild(iframe);
        });
        var errors = this.events.pipe(filter(function (e) { return e instanceof OAuthErrorEvent; }), first());
        var success = this.events.pipe(filter(function (e) { return e.type === 'token_received'; }), first());
        var timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(map(function (e) {
            if (e instanceof OAuthErrorEvent) {
                if (e.type === 'silent_refresh_timeout') {
                    _this.eventsSubject.next(e);
                }
                else {
                    e = new OAuthErrorEvent('silent_refresh_error', e);
                    _this.eventsSubject.next(e);
                }
                throw e;
            }
            else if (e.type === 'token_received') {
                e = new OAuthSuccessEvent('silently_refreshed');
                _this.eventsSubject.next(e);
            }
            return e;
        }))
            .toPromise();
    };
    /**
     * This method exists for backwards compatibility.
     * {@link OAuthService#initLoginFlowInPopup} handles both code
     * and implicit flows.
     */
    OAuthService.prototype.initImplicitFlowInPopup = function (options) {
        return this.initLoginFlowInPopup(options);
    };
    OAuthService.prototype.initLoginFlowInPopup = function (options) {
        var _this = this;
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then(function (url) {
            return new Promise(function (resolve, reject) {
                /**
                 * Error handling section
                 */
                var checkForPopupClosedInterval = 500;
                var windowRef = window.open(url, '_blank', _this.calculatePopupFeatures(options));
                var checkForPopupClosedTimer;
                var checkForPopupClosed = function () {
                    if (!windowRef || windowRef.closed) {
                        cleanup();
                        reject(new OAuthErrorEvent('popup_closed', {}));
                    }
                };
                if (!windowRef) {
                    reject(new OAuthErrorEvent('popup_blocked', {}));
                }
                else {
                    checkForPopupClosedTimer = window.setInterval(checkForPopupClosed, checkForPopupClosedInterval);
                }
                var cleanup = function () {
                    window.clearInterval(checkForPopupClosedTimer);
                    window.removeEventListener('message', listener);
                    if (windowRef !== null) {
                        windowRef.close();
                    }
                    windowRef = null;
                };
                var listener = function (e) {
                    var message = _this.processMessageEventMessage(e);
                    if (message && message !== null) {
                        _this.tryLogin({
                            customHashFragment: message,
                            preventClearHashAfterLogin: true,
                            customRedirectUri: _this.silentRefreshRedirectUri,
                        }).then(function () {
                            cleanup();
                            resolve();
                        }, function (err) {
                            cleanup();
                            reject(err);
                        });
                    }
                    else {
                        console.log('false event firing');
                    }
                };
                window.addEventListener('message', listener);
            });
        });
    };
    OAuthService.prototype.calculatePopupFeatures = function (options) {
        // Specify an static height and width and calculate centered position
        var height = options.height || 470;
        var width = options.width || 500;
        var left = window.screenLeft + ((window.outerWidth - width) / 2);
        var top = window.screenTop + ((window.outerHeight - height) / 2);
        return "location=no,toolbar=no,width=" + width + ",height=" + height + ",top=" + top + ",left=" + left;
    };
    OAuthService.prototype.processMessageEventMessage = function (e) {
        var expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        var prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    };
    OAuthService.prototype.canPerformSessionCheck = function () {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        var sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof document === 'undefined') {
            return false;
        }
        return true;
    };
    OAuthService.prototype.setupSessionCheckEventListener = function () {
        var _this = this;
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = function (e) {
            var origin = e.origin.toLowerCase();
            var issuer = _this.issuer.toLowerCase();
            _this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                _this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer);
                return;
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    _this.handleSessionUnchanged();
                    break;
                case 'changed':
                    _this.ngZone.run(function () {
                        _this.handleSessionChange();
                    });
                    break;
                case 'error':
                    _this.ngZone.run(function () {
                        _this.handleSessionError();
                    });
                    break;
            }
            _this.debug('got info from session check inframe', e);
        };
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular(function () {
            window.addEventListener('message', _this.sessionCheckEventListener);
        });
    };
    OAuthService.prototype.handleSessionUnchanged = function () {
        this.debug('session check', 'session unchanged');
    };
    OAuthService.prototype.handleSessionChange = function () {
        var _this = this;
        /* events: session_changed, relogin, stopTimer, logged_out*/
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch(function (_) {
                return _this.debug('silent refresh failed after session changed');
            });
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    };
    OAuthService.prototype.waitForSilentRefreshAfterSessionChange = function () {
        var _this = this;
        this.events
            .pipe(filter(function (e) {
            return e.type === 'silently_refreshed' ||
                e.type === 'silent_refresh_timeout' ||
                e.type === 'silent_refresh_error';
        }), first())
            .subscribe(function (e) {
            if (e.type !== 'silently_refreshed') {
                _this.debug('silent refresh did not work after session changed');
                _this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                _this.logOut(true);
            }
        });
    };
    OAuthService.prototype.handleSessionError = function () {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    };
    OAuthService.prototype.removeSessionCheckEventListener = function () {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    };
    OAuthService.prototype.initSessionCheck = function () {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        var existingIframe = document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        var iframe = document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        var url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    };
    OAuthService.prototype.startSessionCheckTimer = function () {
        var _this = this;
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular(function () {
            _this.sessionCheckTimer = setInterval(_this.checkSession.bind(_this), _this.sessionCheckIntervall);
        });
    };
    OAuthService.prototype.stopSessionCheckTimer = function () {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    };
    OAuthService.prototype.checkSession = function () {
        var iframe = document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        var sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        var message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    };
    OAuthService.prototype.createLoginUrl = function (state, loginHint, customRedirectUri, noPrompt, params) {
        if (state === void 0) { state = ''; }
        if (loginHint === void 0) { loginHint = ''; }
        if (customRedirectUri === void 0) { customRedirectUri = ''; }
        if (noPrompt === void 0) { noPrompt = false; }
        if (params === void 0) { params = {}; }
        return __awaiter(this, void 0, void 0, function () {
            var that, redirectUri, nonce, seperationChar, scope, url, _a, challenge, verifier, _b, _c, key, _d, _e, key;
            var e_3, _f, e_4, _g;
            return __generator(this, function (_h) {
                switch (_h.label) {
                    case 0:
                        that = this;
                        if (customRedirectUri) {
                            redirectUri = customRedirectUri;
                        }
                        else {
                            redirectUri = this.redirectUri;
                        }
                        return [4 /*yield*/, this.createAndSaveNonce()];
                    case 1:
                        nonce = _h.sent();
                        if (state) {
                            state = nonce + this.config.nonceStateSeparator + state;
                        }
                        else {
                            state = nonce;
                        }
                        if (!this.requestAccessToken && !this.oidc) {
                            throw new Error('Either requestAccessToken or oidc or both must be true');
                        }
                        if (this.config.responseType) {
                            this.responseType = this.config.responseType;
                        }
                        else {
                            if (this.oidc && this.requestAccessToken) {
                                this.responseType = 'id_token token';
                            }
                            else if (this.oidc && !this.requestAccessToken) {
                                this.responseType = 'id_token';
                            }
                            else {
                                this.responseType = 'token';
                            }
                        }
                        seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
                        scope = that.scope;
                        if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                            scope = 'openid ' + scope;
                        }
                        url = that.loginUrl +
                            seperationChar +
                            'response_type=' +
                            encodeURIComponent(that.responseType) +
                            '&client_id=' +
                            encodeURIComponent(that.clientId) +
                            '&state=' +
                            encodeURIComponent(state) +
                            '&redirect_uri=' +
                            encodeURIComponent(redirectUri) +
                            '&scope=' +
                            encodeURIComponent(scope);
                        if (!(this.responseType === 'code' && !this.disablePKCE)) return [3 /*break*/, 3];
                        return [4 /*yield*/, this.createChallangeVerifierPairForPKCE()];
                    case 2:
                        _a = __read.apply(void 0, [_h.sent(), 2]), challenge = _a[0], verifier = _a[1];
                        this._storage.setItem('PKCI_verifier', verifier);
                        url += '&code_challenge=' + challenge;
                        url += '&code_challenge_method=S256';
                        _h.label = 3;
                    case 3:
                        if (loginHint) {
                            url += '&login_hint=' + encodeURIComponent(loginHint);
                        }
                        if (that.resource) {
                            url += '&resource=' + encodeURIComponent(that.resource);
                        }
                        if (that.oidc) {
                            url += '&nonce=' + encodeURIComponent(nonce);
                        }
                        if (noPrompt) {
                            url += '&prompt=none';
                        }
                        try {
                            for (_b = __values(Object.keys(params)), _c = _b.next(); !_c.done; _c = _b.next()) {
                                key = _c.value;
                                url +=
                                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
                            }
                        }
                        catch (e_3_1) { e_3 = { error: e_3_1 }; }
                        finally {
                            try {
                                if (_c && !_c.done && (_f = _b.return)) _f.call(_b);
                            }
                            finally { if (e_3) throw e_3.error; }
                        }
                        if (this.customQueryParams) {
                            try {
                                for (_d = __values(Object.getOwnPropertyNames(this.customQueryParams)), _e = _d.next(); !_e.done; _e = _d.next()) {
                                    key = _e.value;
                                    url +=
                                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                                }
                            }
                            catch (e_4_1) { e_4 = { error: e_4_1 }; }
                            finally {
                                try {
                                    if (_e && !_e.done && (_g = _d.return)) _g.call(_d);
                                }
                                finally { if (e_4) throw e_4.error; }
                            }
                        }
                        return [2 /*return*/, url];
                }
            });
        });
    };
    OAuthService.prototype.initImplicitFlowInternal = function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = ''; }
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl  must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
        }
        var addParams = {};
        var loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch(function (error) {
            console.error('Error in initImplicitFlow', error);
            _this.inImplicitFlow = false;
        });
    };
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     */
    OAuthService.prototype.initImplicitFlow = function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = ''; }
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(function (e) { return e.type === 'discovery_document_loaded'; }))
                .subscribe(function (_) { return _this.initImplicitFlowInternal(additionalState, params); });
        }
    };
    /**
     * Reset current implicit flow
     *
     * @description This method allows resetting the current implict flow in order to be initialized again.
     */
    OAuthService.prototype.resetImplicitFlow = function () {
        this.inImplicitFlow = false;
    };
    OAuthService.prototype.callOnTokenReceivedIfExists = function (options) {
        var that = this;
        if (options.onTokenReceived) {
            var tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    };
    OAuthService.prototype.storeAccessTokenResponse = function (accessToken, refreshToken, expiresIn, grantedScopes, customParameters) {
        var _this = this;
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            var expiresInMilliSeconds = expiresIn * 1000;
            var now = new Date();
            var expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
        if (customParameters) {
            Object.keys(customParameters).forEach(function (key) {
                _this._storage.setItem(key, customParameters[key]);
            });
        }
    };
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param options Optional options.
     */
    OAuthService.prototype.tryLogin = function (options) {
        if (options === void 0) { options = null; }
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow(options).then(function (_) { return true; });
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    };
    OAuthService.prototype.parseQueryString = function (queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    };
    OAuthService.prototype.tryLoginCodeFlow = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        options = options || {};
        var querySource = options.customHashFragment ?
            options.customHashFragment.substring(1) :
            window.location.search;
        var parts = this.getCodePartsFromUrl(window.location.search);
        var code = parts['code'];
        var state = parts['state'];
        if (!options.preventClearHashAfterLogin) {
            var href = location.href
                .replace(/[&\?]code=[^&\$]*/, '')
                .replace(/[&\?]scope=[^&\$]*/, '')
                .replace(/[&\?]state=[^&\$]*/, '')
                .replace(/[&\?]session_state=[^&\$]*/, '');
            history.replaceState(null, window.name, href);
        }
        var _a = __read(this.parseState(state), 2), nonceInState = _a[0], userState = _a[1];
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            var err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        if (!nonceInState) {
            return Promise.resolve();
        }
        var success = this.validateNonce(nonceInState);
        if (!success) {
            var event_1 = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event_1);
            return Promise.reject(event_1);
        }
        if (code) {
            return new Promise(function (resolve, reject) {
                _this.getTokenFromCode(code, options).then(function (result) {
                    resolve();
                }).catch(function (err) {
                    reject(err);
                });
            });
        }
        else {
            return Promise.resolve();
        }
    };
    /**
    * Retrieve the returned auth code from the redirect uri that has been called.
    * If required also check hash, as we could use hash location strategy.
    */
    OAuthService.prototype.getCodePartsFromUrl = function (queryString) {
        if (!queryString || queryString.length === 0) {
            return this.urlHelper.getHashFragmentParams();
        }
        // normalize query string
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    };
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     */
    OAuthService.prototype.getTokenFromCode = function (code, options) {
        var params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', options.customRedirectUri || this.redirectUri);
        if (!this.disablePKCE) {
            var pkciVerifier = this._storage.getItem('PKCI_verifier');
            if (!pkciVerifier) {
                console.warn('No PKCI verifier found in oauth storage!');
            }
            else {
                params = params.set('code_verifier', pkciVerifier);
            }
        }
        return this.fetchAndProcessToken(params);
    };
    OAuthService.prototype.fetchAndProcessToken = function (params) {
        var _this = this;
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        var headers = new HttpHeaders()
            .set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            var header = btoa(this.clientId + ":" + this.dummyClientSecret);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        return new Promise(function (resolve, reject) {
            var e_5, _a;
            if (_this.customQueryParams) {
                try {
                    for (var _b = __values(Object.getOwnPropertyNames(_this.customQueryParams)), _c = _b.next(); !_c.done; _c = _b.next()) {
                        var key = _c.value;
                        params = params.set(key, _this.customQueryParams[key]);
                    }
                }
                catch (e_5_1) { e_5 = { error: e_5_1 }; }
                finally {
                    try {
                        if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                    }
                    finally { if (e_5) throw e_5.error; }
                }
            }
            _this.http.post(_this.tokenEndpoint, params, { headers: headers }).subscribe(function (tokenResponse) {
                _this.debug('refresh tokenResponse', tokenResponse);
                _this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, _this.extractRecognizedCustomParameters(tokenResponse));
                if (_this.oidc && tokenResponse.id_token) {
                    _this.processIdToken(tokenResponse.id_token, tokenResponse.access_token).
                        then(function (result) {
                        _this.storeIdToken(result);
                        _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    })
                        .catch(function (reason) {
                        _this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    });
                }
                else {
                    _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    _this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }, function (err) {
                console.error('Error getting token', err);
                _this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    };
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param options Optional options.
     */
    OAuthService.prototype.tryLoginImplicitFlow = function (options) {
        var _this = this;
        if (options === void 0) { options = null; }
        options = options || {};
        var parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        var state = parts['state'];
        var _a = __read(this.parseState(state), 2), nonceInState = _a[0], userState = _a[1];
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            var err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        var accessToken = parts['access_token'];
        var idToken = parts['id_token'];
        var sessionState = parts['session_state'];
        var grantedScopes = parts['scope'];
        if (!this.requestAccessToken && !this.oidc) {
            return Promise.reject('Either requestAccessToken or oidc (or both) must be true.');
        }
        if (this.requestAccessToken && !accessToken) {
            return Promise.resolve(false);
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck && !state) {
            return Promise.resolve(false);
        }
        if (this.oidc && !idToken) {
            return Promise.resolve(false);
        }
        if (this.sessionChecksEnabled && !sessionState) {
            this.logger.warn('session checks (Session Status Change Notification) ' +
                'were activated in the configuration but the id_token ' +
                'does not contain a session_state claim');
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck) {
            var success = this.validateNonce(nonceInState);
            if (!success) {
                var event_2 = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event_2);
                return Promise.reject(event_2);
            }
        }
        if (this.requestAccessToken) {
            this.storeAccessTokenResponse(accessToken, null, parts['expires_in'] || this.fallbackAccessTokenExpirationTimeInSec, grantedScopes);
        }
        if (!this.oidc) {
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.callOnTokenReceivedIfExists(options);
            return Promise.resolve(true);
        }
        return this.processIdToken(idToken, accessToken)
            .then(function (result) {
            if (options.validationHandler) {
                return options
                    .validationHandler({
                    accessToken: accessToken,
                    idClaims: result.idTokenClaims,
                    idToken: result.idToken,
                    state: state
                })
                    .then(function (_) { return result; });
            }
            return result;
        })
            .then(function (result) {
            _this.storeIdToken(result);
            _this.storeSessionState(sessionState);
            if (_this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            _this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            _this.callOnTokenReceivedIfExists(options);
            _this.inImplicitFlow = false;
            return true;
        })
            .catch(function (reason) {
            _this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            _this.logger.error('Error validating tokens');
            _this.logger.error(reason);
            return Promise.reject(reason);
        });
    };
    OAuthService.prototype.parseState = function (state) {
        var nonce = state;
        var userState = '';
        if (state) {
            var idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    };
    OAuthService.prototype.validateNonce = function (nonceInState) {
        var savedNonce = this._storage.getItem('nonce');
        if (savedNonce !== nonceInState) {
            var err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    };
    OAuthService.prototype.storeIdToken = function (idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    };
    OAuthService.prototype.storeSessionState = function (sessionState) {
        this._storage.setItem('session_state', sessionState);
    };
    OAuthService.prototype.getSessionState = function () {
        return this._storage.getItem('session_state');
    };
    OAuthService.prototype.handleLoginError = function (options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
            location.hash = '';
        }
    };
    /**
     * @ignore
     */
    OAuthService.prototype.processIdToken = function (idToken, accessToken, skipNonceCheck) {
        var _this = this;
        if (skipNonceCheck === void 0) { skipNonceCheck = false; }
        var tokenParts = idToken.split('.');
        var headerBase64 = this.padBase64(tokenParts[0]);
        var headerJson = b64DecodeUnicode(headerBase64);
        var header = JSON.parse(headerJson);
        var claimsBase64 = this.padBase64(tokenParts[1]);
        var claimsJson = b64DecodeUnicode(claimsBase64);
        var claims = JSON.parse(claimsJson);
        var savedNonce = this._storage.getItem('nonce');
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every(function (v) { return v !== _this.clientId; })) {
                var err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                var err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            var err = 'No sub claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /* For now, we only check whether the sub against
         * silentRefreshSubject when sessionChecksEnabled is on
         * We will reconsider in a later version to do this
         * in every other case too.
         */
        if (this.sessionChecksEnabled &&
            this.silentRefreshSubject &&
            this.silentRefreshSubject !== claims['sub']) {
            var err = 'After refreshing, we got an id_token for another user (sub). ' +
                ("Expected sub: " + this.silentRefreshSubject + ", received sub: " + claims['sub']);
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            var err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            var err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!skipNonceCheck && claims.nonce !== savedNonce) {
            var err = 'Wrong nonce: ' + claims.nonce;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        // at_hash is not applicable to authorization code flow
        // addressing https://github.com/manfredsteyer/angular-oauth2-oidc/issues/661
        // i.e. Based on spec the at_hash check is only true for implicit code flow on Ping Federate
        // https://www.pingidentity.com/developer/en/resources/openid-connect-developers-guide.html
        if (this.hasOwnProperty('responseType') && this.responseType === 'code') {
            this.disableAtHashCheck = true;
        }
        if (!this.disableAtHashCheck &&
            this.requestAccessToken &&
            !claims['at_hash']) {
            var err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        var now = Date.now();
        var issuedAtMSec = claims.iat * 1000;
        var expiresAtMSec = claims.exp * 1000;
        var clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            var err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        var validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: function () { return _this.loadJwks(); }
        };
        if (this.disableAtHashCheck) {
            return this.checkSignature(validationParams).then(function (_) {
                var result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                return result;
            });
        }
        return this.checkAtHash(validationParams)
            .then(function (atHashValid) {
            if (!_this.disableAtHashCheck &&
                _this.requestAccessToken &&
                !atHashValid) {
                var err = 'Wrong at_hash';
                _this.logger.warn(err);
                return Promise.reject(err);
            }
            return _this.checkSignature(validationParams).then(function (_) {
                var atHashCheckEnabled = !_this.disableAtHashCheck;
                var result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                if (atHashCheckEnabled) {
                    return _this.checkAtHash(validationParams).then(function (atHashValid) {
                        if (_this.requestAccessToken && !atHashValid) {
                            var err = 'Wrong at_hash';
                            _this.logger.warn(err);
                            return Promise.reject(err);
                        }
                        else {
                            return result;
                        }
                    });
                }
                else {
                    return result;
                }
            });
        });
    };
    /**
     * Returns the received claims about the user.
     */
    OAuthService.prototype.getIdentityClaims = function () {
        var claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    };
    /**
     * Returns the granted scopes from the server.
     */
    OAuthService.prototype.getGrantedScopes = function () {
        var scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    };
    /**
     * Returns the current id_token.
     */
    OAuthService.prototype.getIdToken = function () {
        return this._storage
            ? this._storage.getItem('id_token')
            : null;
    };
    OAuthService.prototype.padBase64 = function (base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    };
    /**
     * Returns the current access_token.
     */
    OAuthService.prototype.getAccessToken = function () {
        return this._storage
            ? this._storage.getItem('access_token')
            : null;
    };
    OAuthService.prototype.getRefreshToken = function () {
        return this._storage
            ? this._storage.getItem('refresh_token')
            : null;
    };
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     */
    OAuthService.prototype.getAccessTokenExpiration = function () {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    };
    OAuthService.prototype.getAccessTokenStoredAt = function () {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    };
    OAuthService.prototype.getIdTokenStoredAt = function () {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    };
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     */
    OAuthService.prototype.getIdTokenExpiration = function () {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    };
    /**
     * Checkes, whether there is a valid access_token.
     */
    OAuthService.prototype.hasValidAccessToken = function () {
        if (this.getAccessToken()) {
            var expiresAt = this._storage.getItem('expires_at');
            var now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    };
    /**
     * Checks whether there is a valid id_token.
     */
    OAuthService.prototype.hasValidIdToken = function () {
        if (this.getIdToken()) {
            var expiresAt = this._storage.getItem('id_token_expires_at');
            var now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    };
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     */
    OAuthService.prototype.authorizationHeader = function () {
        return 'Bearer ' + this.getAccessToken();
    };
    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it.
     * @param noRedirectToLogoutUrl
     */
    OAuthService.prototype.logOut = function (noRedirectToLogoutUrl) {
        if (noRedirectToLogoutUrl === void 0) { noRedirectToLogoutUrl = false; }
        var id_token = this.getIdToken();
        this._storage.removeItem('access_token');
        this._storage.removeItem('id_token');
        this._storage.removeItem('refresh_token');
        this._storage.removeItem('nonce');
        this._storage.removeItem('expires_at');
        this._storage.removeItem('id_token_claims_obj');
        this._storage.removeItem('id_token_expires_at');
        this._storage.removeItem('id_token_stored_at');
        this._storage.removeItem('access_token_stored_at');
        this._storage.removeItem('granted_scopes');
        this._storage.removeItem('session_state');
        this.silentRefreshSubject = null;
        this.eventsSubject.next(new OAuthInfoEvent('logout'));
        if (!this.logoutUrl) {
            return;
        }
        if (noRedirectToLogoutUrl) {
            return;
        }
        if (!id_token && !this.postLogoutRedirectUri) {
            return;
        }
        var logoutUrl;
        if (!this.validateUrlForHttps(this.logoutUrl)) {
            throw new Error('logoutUrl  must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
        }
        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl
                .replace(/\{\{id_token\}\}/, id_token)
                .replace(/\{\{client_id\}\}/, this.clientId);
        }
        else {
            var params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            var postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
            if (postLogoutUrl) {
                params = params.set('post_logout_redirect_uri', postLogoutUrl);
            }
            logoutUrl =
                this.logoutUrl +
                    (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                    params.toString();
        }
        this.config.openUri(logoutUrl);
    };
    /**
     * @ignore
     */
    OAuthService.prototype.createAndSaveNonce = function () {
        var that = this;
        return this.createNonce().then(function (nonce) {
            that._storage.setItem('nonce', nonce);
            return nonce;
        });
    };
    /**
     * @ignore
     */
    OAuthService.prototype.ngOnDestroy = function () {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
        this.removeSilentRefreshEventListener();
        var silentRefreshFrame = document.getElementById(this.silentRefreshIFrameName);
        if (silentRefreshFrame) {
            silentRefreshFrame.remove();
        }
        this.stopSessionCheckTimer();
        this.removeSessionCheckEventListener();
        var sessionCheckFrame = document.getElementById(this.sessionCheckIFrameName);
        if (sessionCheckFrame) {
            sessionCheckFrame.remove();
        }
    };
    OAuthService.prototype.createNonce = function () {
        var _this = this;
        return new Promise(function (resolve) {
            if (_this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
             * This alphabet is from:
             * https://tools.ietf.org/html/rfc7636#section-4.1
             *
             * [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
             */
            var unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            var size = 45;
            var id = '';
            var crypto = typeof self === 'undefined' ? null : (self.crypto || self['msCrypto']);
            if (crypto) {
                var bytes = new Uint8Array(size);
                crypto.getRandomValues(bytes);
                bytes = bytes.map(function (x) { return unreserved.charCodeAt(x % unreserved.length); });
                id = String.fromCharCode.apply(null, bytes);
            }
            else {
                while (0 < size--) {
                    id += unreserved[Math.random() * unreserved.length | 0];
                }
            }
            resolve(base64UrlEncode(id));
        });
    };
    OAuthService.prototype.checkAtHash = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                if (!this.tokenValidationHandler) {
                    this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                    return [2 /*return*/, true];
                }
                return [2 /*return*/, this.tokenValidationHandler.validateAtHash(params)];
            });
        });
    };
    OAuthService.prototype.checkSignature = function (params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    };
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     */
    OAuthService.prototype.initLoginFlow = function (additionalState, params) {
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    };
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     */
    OAuthService.prototype.initCodeFlow = function (additionalState, params) {
        var _this = this;
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events.pipe(filter(function (e) { return e.type === 'discovery_document_loaded'; }))
                .subscribe(function (_) { return _this.initCodeFlowInternal(additionalState, params); });
        }
    };
    OAuthService.prototype.initCodeFlowInternal = function (additionalState, params) {
        if (additionalState === void 0) { additionalState = ''; }
        if (params === void 0) { params = {}; }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl  must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
        }
        this.createLoginUrl(additionalState, '', null, false, params)
            .then(this.config.openUri)
            .catch(function (error) {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        });
    };
    OAuthService.prototype.createChallangeVerifierPairForPKCE = function () {
        return __awaiter(this, void 0, void 0, function () {
            var verifier, challengeRaw, challange;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!this.crypto) {
                            throw new Error('PKCI support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
                        }
                        return [4 /*yield*/, this.createNonce()];
                    case 1:
                        verifier = _a.sent();
                        return [4 /*yield*/, this.crypto.calcHash(verifier, 'sha-256')];
                    case 2:
                        challengeRaw = _a.sent();
                        challange = base64UrlEncode(challengeRaw);
                        return [2 /*return*/, [challange, verifier]];
                }
            });
        });
    };
    OAuthService.prototype.extractRecognizedCustomParameters = function (tokenResponse) {
        if (!this.config.customTokenParameters) {
            return {};
        }
        var foundParameters = {};
        this.config.customTokenParameters.forEach(function (recognizedParameter) {
            if (tokenResponse[recognizedParameter]) {
                foundParameters[recognizedParameter] = tokenResponse[recognizedParameter];
            }
        });
        return foundParameters;
    };
    OAuthService.ctorParameters = function () { return [
        { type: NgZone },
        { type: HttpClient },
        { type: OAuthStorage, decorators: [{ type: Optional }] },
        { type: ValidationHandler, decorators: [{ type: Optional }] },
        { type: AuthConfig, decorators: [{ type: Optional }] },
        { type: UrlHelperService },
        { type: OAuthLogger },
        { type: HashHandler, decorators: [{ type: Optional }] }
    ]; };
    OAuthService = __decorate([
        Injectable(),
        __param(2, Optional()),
        __param(3, Optional()),
        __param(4, Optional()),
        __param(7, Optional()),
        __metadata("design:paramtypes", [NgZone,
            HttpClient,
            OAuthStorage,
            ValidationHandler,
            AuthConfig,
            UrlHelperService,
            OAuthLogger,
            HashHandler])
    ], OAuthService);
    return OAuthService;
}(AuthConfig));
export { OAuthService };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQ3hFLE9BQU8sRUFBRSxVQUFVLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQzNFLE9BQU8sRUFBYyxPQUFPLEVBQWdCLEVBQUUsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBQ3pFLE9BQU8sRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxZQUFZLEVBQUUsTUFBTSxnQkFBZ0IsQ0FBQztBQUV6RixPQUFPLEVBQ0gsaUJBQWlCLEVBQ2pCLGdCQUFnQixFQUNuQixNQUFNLHVDQUF1QyxDQUFDO0FBQy9DLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQ3hELE9BQU8sRUFFSCxjQUFjLEVBQ2QsZUFBZSxFQUNmLGlCQUFpQixFQUNwQixNQUFNLFVBQVUsQ0FBQztBQUNsQixPQUFPLEVBQ0gsV0FBVyxFQUNYLFlBQVksRUFDWixZQUFZLEVBQ1osYUFBYSxFQUNiLGdCQUFnQixFQUNoQixhQUFhLEVBQ2IsUUFBUSxFQUNYLE1BQU0sU0FBUyxDQUFDO0FBQ2pCLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxlQUFlLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUNwRSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQzNDLE9BQU8sRUFBRSx1QkFBdUIsRUFBRSxNQUFNLFdBQVcsQ0FBQztBQUNwRCxPQUFPLEVBQUUsV0FBVyxFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFF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QUFVLHVCQUF2QyxRQUFRO2dCQUNZLGdCQUFnQjtnQkFDbkIsV0FBVztnQkFDQyxXQUFXLHVCQUF4QyxRQUFROztJQXhESixZQUFZO1FBRHhCLFVBQVUsRUFBRTtRQW9ESixXQUFBLFFBQVEsRUFBRSxDQUFBO1FBQ1YsV0FBQSxRQUFRLEVBQUUsQ0FBQTtRQUNWLFdBQUEsUUFBUSxFQUFFLENBQUE7UUFHVixXQUFBLFFBQVEsRUFBRSxDQUFBO3lDQVBPLE1BQU07WUFDUixVQUFVO1lBQ0wsWUFBWTtZQUNHLGlCQUFpQjtZQUN2QixVQUFVO1lBQ25CLGdCQUFnQjtZQUNuQixXQUFXO1lBQ0MsV0FBVztPQXhEcEMsWUFBWSxDQXl2RXhCO0lBQUQsbUJBQUM7Q0FBQSxBQXp2RUQsQ0FBa0MsVUFBVSxHQXl2RTNDO1NBenZFWSxZQUFZIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmdab25lLCBPcHRpb25hbCwgT25EZXN0cm95IH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBIdHRwQ2xpZW50LCBIdHRwSGVhZGVycywgSHR0cFBhcmFtcyB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcbmltcG9ydCB7IE9ic2VydmFibGUsIFN1YmplY3QsIFN1YnNjcmlwdGlvbiwgb2YsIHJhY2UsIGZyb20gfSBmcm9tICdyeGpzJztcbmltcG9ydCB7IGZpbHRlciwgZGVsYXksIGZpcnN0LCB0YXAsIG1hcCwgc3dpdGNoTWFwLCBkZWJvdW5jZVRpbWUgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5cbmltcG9ydCB7XG4gICAgVmFsaWRhdGlvbkhhbmRsZXIsXG4gICAgVmFsaWRhdGlvblBhcmFtc1xufSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyJztcbmltcG9ydCB7IFVybEhlbHBlclNlcnZpY2UgfSBmcm9tICcuL3VybC1oZWxwZXIuc2VydmljZSc7XG5pbXBvcnQge1xuICAgIE9BdXRoRXZlbnQsXG4gICAgT0F1dGhJbmZvRXZlbnQsXG4gICAgT0F1dGhFcnJvckV2ZW50LFxuICAgIE9BdXRoU3VjY2Vzc0V2ZW50XG59IGZyb20gJy4vZXZlbnRzJztcbmltcG9ydCB7XG4gICAgT0F1dGhMb2dnZXIsXG4gICAgT0F1dGhTdG9yYWdlLFxuICAgIExvZ2luT3B0aW9ucyxcbiAgICBQYXJzZWRJZFRva2VuLFxuICAgIE9pZGNEaXNjb3ZlcnlEb2MsXG4gICAgVG9rZW5SZXNwb25zZSxcbiAgICBVc2VySW5mb1xufSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IGI2NERlY29kZVVuaWNvZGUsIGJhc2U2NFVybEVuY29kZSB9IGZyb20gJy4vYmFzZTY0LWhlbHBlcic7XG5pbXBvcnQgeyBBdXRoQ29uZmlnIH0gZnJvbSAnLi9hdXRoLmNvbmZpZyc7XG5pbXBvcnQgeyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYyB9IGZyb20gJy4vZW5jb2Rlcic7XG5pbXBvcnQgeyBIYXNoSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9oYXNoLWhhbmRsZXInO1xuXG4vKipcbiAqIFNlcnZpY2UgZm9yIGxvZ2dpbmcgaW4gYW5kIGxvZ2dpbmcgb3V0IHdpdGhcbiAqIE9JREMgYW5kIE9BdXRoMi4gU3VwcG9ydHMgaW1wbGljaXQgZmxvdyBhbmRcbiAqIHBhc3N3b3JkIGZsb3cuXG4gKi9cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBPQXV0aFNlcnZpY2UgZXh0ZW5kcyBBdXRoQ29uZmlnIGltcGxlbWVudHMgT25EZXN0cm95IHtcbiAgICAvLyBFeHRlbmRpbmcgQXV0aENvbmZpZyBpc3QganVzdCBmb3IgTEVHQUNZIHJlYXNvbnNcbiAgICAvLyB0byBub3QgYnJlYWsgZXhpc3RpbmcgY29kZS5cblxuICAgIC8qKlxuICAgICAqIFRoZSBWYWxpZGF0aW9uSGFuZGxlciB1c2VkIHRvIHZhbGlkYXRlIHJlY2VpdmVkXG4gICAgICogaWRfdG9rZW5zLlxuICAgICAqL1xuICAgIHB1YmxpYyB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcjtcblxuICAgIC8qKlxuICAgICAqIEBpbnRlcm5hbFxuICAgICAqIERlcHJlY2F0ZWQ6ICB1c2UgcHJvcGVydHkgZXZlbnRzIGluc3RlYWRcbiAgICAgKi9cbiAgICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQgPSBmYWxzZTtcblxuICAgIC8qKlxuICAgICAqIEBpbnRlcm5hbFxuICAgICAqIERlcHJlY2F0ZWQ6ICB1c2UgcHJvcGVydHkgZXZlbnRzIGluc3RlYWRcbiAgICAgKi9cbiAgICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQkOiBPYnNlcnZhYmxlPE9pZGNEaXNjb3ZlcnlEb2M+O1xuXG4gICAgLyoqXG4gICAgICogSW5mb3JtcyBhYm91dCBldmVudHMsIGxpa2UgdG9rZW5fcmVjZWl2ZWQgb3IgdG9rZW5fZXhwaXJlcy5cbiAgICAgKiBTZWUgdGhlIHN0cmluZyBlbnVtIEV2ZW50VHlwZSBmb3IgYSBmdWxsIGxpc3Qgb2YgZXZlbnQgdHlwZXMuXG4gICAgICovXG4gICAgcHVibGljIGV2ZW50czogT2JzZXJ2YWJsZTxPQXV0aEV2ZW50PjtcblxuICAgIC8qKlxuICAgICAqIFRoZSByZWNlaXZlZCAocGFzc2VkIGFyb3VuZCkgc3RhdGUsIHdoZW4gbG9nZ2luZ1xuICAgICAqIGluIHdpdGggaW1wbGljaXQgZmxvdy5cbiAgICAgKi9cbiAgICBwdWJsaWMgc3RhdGU/PSAnJztcblxuICAgIHByb3RlY3RlZCBldmVudHNTdWJqZWN0OiBTdWJqZWN0PE9BdXRoRXZlbnQ+ID0gbmV3IFN1YmplY3Q8T0F1dGhFdmVudD4oKTtcbiAgICBwcm90ZWN0ZWQgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0OiBTdWJqZWN0PE9pZGNEaXNjb3ZlcnlEb2M+ID0gbmV3IFN1YmplY3Q8T2lkY0Rpc2NvdmVyeURvYz4oKTtcbiAgICBwcm90ZWN0ZWQgc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lcjogRXZlbnRMaXN0ZW5lcjtcbiAgICBwcm90ZWN0ZWQgZ3JhbnRUeXBlc1N1cHBvcnRlZDogQXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgIHByb3RlY3RlZCBfc3RvcmFnZTogT0F1dGhTdG9yYWdlO1xuICAgIHByb3RlY3RlZCBhY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcbiAgICBwcm90ZWN0ZWQgaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcbiAgICBwcm90ZWN0ZWQgdG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbjogU3Vic2NyaXB0aW9uO1xuICAgIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyOiBFdmVudExpc3RlbmVyO1xuICAgIHByb3RlY3RlZCBqd2tzVXJpOiBzdHJpbmc7XG4gICAgcHJvdGVjdGVkIHNlc3Npb25DaGVja1RpbWVyOiBhbnk7XG4gICAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hTdWJqZWN0OiBzdHJpbmc7XG4gICAgcHJvdGVjdGVkIGluSW1wbGljaXRGbG93ID0gZmFsc2U7XG5cbiAgICBjb25zdHJ1Y3RvcihcbiAgICAgICAgcHJvdGVjdGVkIG5nWm9uZTogTmdab25lLFxuICAgICAgICBwcm90ZWN0ZWQgaHR0cDogSHR0cENsaWVudCxcbiAgICAgICAgQE9wdGlvbmFsKCkgc3RvcmFnZTogT0F1dGhTdG9yYWdlLFxuICAgICAgICBAT3B0aW9uYWwoKSB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcixcbiAgICAgICAgQE9wdGlvbmFsKCkgcHJvdGVjdGVkIGNvbmZpZzogQXV0aENvbmZpZyxcbiAgICAgICAgcHJvdGVjdGVkIHVybEhlbHBlcjogVXJsSGVscGVyU2VydmljZSxcbiAgICAgICAgcHJvdGVjdGVkIGxvZ2dlcjogT0F1dGhMb2dnZXIsXG4gICAgICAgIEBPcHRpb25hbCgpIHByb3RlY3RlZCBjcnlwdG86IEhhc2hIYW5kbGVyLFxuICAgICkge1xuICAgICAgICBzdXBlcigpO1xuXG4gICAgICAgIHRoaXMuZGVidWcoJ2FuZ3VsYXItb2F1dGgyLW9pZGMgdjgtYmV0YScpO1xuXG4gICAgICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQkID0gdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3QuYXNPYnNlcnZhYmxlKCk7XG4gICAgICAgIHRoaXMuZXZlbnRzID0gdGhpcy5ldmVudHNTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xuXG4gICAgICAgIGlmICh0b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XG4gICAgICAgICAgICB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIgPSB0b2tlblZhbGlkYXRpb25IYW5kbGVyO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGNvbmZpZykge1xuICAgICAgICAgICAgdGhpcy5jb25maWd1cmUoY29uZmlnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBpZiAoc3RvcmFnZSkge1xuICAgICAgICAgICAgICAgIHRoaXMuc2V0U3RvcmFnZShzdG9yYWdlKTtcbiAgICAgICAgICAgIH0gZWxzZSBpZiAodHlwZW9mIHNlc3Npb25TdG9yYWdlICE9PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgICAgIHRoaXMuc2V0U3RvcmFnZShzZXNzaW9uU3RvcmFnZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0gY2F0Y2ggKGUpIHtcblxuICAgICAgICAgICAgY29uc29sZS5lcnJvcihcbiAgICAgICAgICAgICAgICAnTm8gT0F1dGhTdG9yYWdlIHByb3ZpZGVkIGFuZCBjYW5ub3QgYWNjZXNzIGRlZmF1bHQgKHNlc3Npb25TdG9yYWdlKS4nXG4gICAgICAgICAgICAgICAgKyAnQ29uc2lkZXIgcHJvdmlkaW5nIGEgY3VzdG9tIE9BdXRoU3RvcmFnZSBpbXBsZW1lbnRhdGlvbiBpbiB5b3VyIG1vZHVsZS4nLFxuICAgICAgICAgICAgICAgIGVcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXNlIHRoaXMgbWV0aG9kIHRvIGNvbmZpZ3VyZSB0aGUgc2VydmljZVxuICAgICAqIEBwYXJhbSBjb25maWcgdGhlIGNvbmZpZ3VyYXRpb25cbiAgICAgKi9cbiAgICBwdWJsaWMgY29uZmlndXJlKGNvbmZpZzogQXV0aENvbmZpZyk6IHZvaWQge1xuICAgICAgICAvLyBGb3IgdGhlIHNha2Ugb2YgZG93bndhcmQgY29tcGF0aWJpbGl0eSB3aXRoXG4gICAgICAgIC8vIG9yaWdpbmFsIGNvbmZpZ3VyYXRpb24gQVBJXG4gICAgICAgIE9iamVjdC5hc3NpZ24odGhpcywgbmV3IEF1dGhDb25maWcoKSwgY29uZmlnKTtcblxuICAgICAgICB0aGlzLmNvbmZpZyA9IE9iamVjdC5hc3NpZ24oe30gYXMgQXV0aENvbmZpZywgbmV3IEF1dGhDb25maWcoKSwgY29uZmlnKTtcblxuICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgICAgICAgdGhpcy5zZXR1cFNlc3Npb25DaGVjaygpO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNvbmZpZ0NoYW5nZWQoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuc2V0dXBSZWZyZXNoVGltZXIoKTtcbiAgICB9XG5cbiAgICBwdWJsaWMgcmVzdGFydFNlc3Npb25DaGVja3NJZlN0aWxsTG9nZ2VkSW4oKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICAgICAgICB0aGlzLmluaXRTZXNzaW9uQ2hlY2soKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCByZXN0YXJ0UmVmcmVzaFRpbWVySWZTdGlsbExvZ2dlZEluKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVjaygpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5ldmVudHMucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpKS5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgICB0aGlzLmluaXRTZXNzaW9uQ2hlY2soKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogV2lsbCBzZXR1cCB1cCBzaWxlbnQgcmVmcmVzaGluZyBmb3Igd2hlbiB0aGUgdG9rZW4gaXNcbiAgICAgKiBhYm91dCB0byBleHBpcmUuIFdoZW4gdGhlIHVzZXIgaXMgbG9nZ2VkIG91dCB2aWEgdGhpcy5sb2dPdXQgbWV0aG9kLCB0aGVcbiAgICAgKiBzaWxlbnQgcmVmcmVzaGluZyB3aWxsIHBhdXNlIGFuZCBub3QgcmVmcmVzaCB0aGUgdG9rZW5zIHVudGlsIHRoZSB1c2VyIGlzXG4gICAgICogbG9nZ2VkIGJhY2sgaW4gdmlhIHJlY2VpdmluZyBhIG5ldyB0b2tlbi5cbiAgICAgKiBAcGFyYW0gcGFyYW1zIEFkZGl0aW9uYWwgcGFyYW1ldGVyIHRvIHBhc3NcbiAgICAgKiBAcGFyYW0gbGlzdGVuVG8gU2V0dXAgYXV0b21hdGljIHJlZnJlc2ggb2YgYSBzcGVjaWZpYyB0b2tlbiB0eXBlXG4gICAgICovXG4gICAgcHVibGljIHNldHVwQXV0b21hdGljU2lsZW50UmVmcmVzaChwYXJhbXM6IG9iamVjdCA9IHt9LCBsaXN0ZW5Ubz86ICdhY2Nlc3NfdG9rZW4nIHwgJ2lkX3Rva2VuJyB8ICdhbnknLCBub1Byb21wdCA9IHRydWUpOiB2b2lkIHtcbiAgICAgICAgbGV0IHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xuICAgICAgICB0aGlzLmV2ZW50cy5waXBlKFxuICAgICAgICAgICAgdGFwKChlKSA9PiB7XG4gICAgICAgICAgICAgICAgaWYgKGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykge1xuICAgICAgICAgICAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKGUudHlwZSA9PT0gJ2xvZ291dCcpIHtcbiAgICAgICAgICAgICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pLFxuICAgICAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fZXhwaXJlcycpLFxuICAgICAgICAgICAgZGVib3VuY2VUaW1lKDEwMDApLFxuICAgICAgICApLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gZSBhcyBPQXV0aEluZm9FdmVudDtcbiAgICAgICAgICAgIGlmICgobGlzdGVuVG8gPT0gbnVsbCB8fCBsaXN0ZW5UbyA9PT0gJ2FueScgfHwgZXZlbnQuaW5mbyA9PT0gbGlzdGVuVG8pICYmIHNob3VsZFJ1blNpbGVudFJlZnJlc2gpIHtcbiAgICAgICAgICAgICAgICAvLyB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgICAgICAgdGhpcy5yZWZyZXNoSW50ZXJuYWwocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ0F1dG9tYXRpYyBzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsnKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG5cbiAgICAgICAgdGhpcy5yZXN0YXJ0UmVmcmVzaFRpbWVySWZTdGlsbExvZ2dlZEluKCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHJlZnJlc2hJbnRlcm5hbChwYXJhbXMsIG5vUHJvbXB0KTogUHJvbWlzZTxUb2tlblJlc3BvbnNlIHwgT0F1dGhFdmVudD4ge1xuXG4gICAgICAgIGlmICghdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFRva2VuKCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5zaWxlbnRSZWZyZXNoKHBhcmFtcywgbm9Qcm9tcHQpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ29udmVuaWVuY2UgbWV0aG9kIHRoYXQgZmlyc3QgY2FsbHMgYGxvYWREaXNjb3ZlcnlEb2N1bWVudCguLi4pYCBhbmRcbiAgICAgKiBkaXJlY3RseSBjaGFpbnMgdXNpbmcgdGhlIGB0aGVuKC4uLilgIHBhcnQgb2YgdGhlIHByb21pc2UgdG8gY2FsbFxuICAgICAqIHRoZSBgdHJ5TG9naW4oLi4uKWAgbWV0aG9kLlxuICAgICAqXG4gICAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICByZXR1cm4gdGhpcy5sb2FkRGlzY292ZXJ5RG9jdW1lbnQoKS50aGVuKGRvYyA9PiB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy50cnlMb2dpbihvcHRpb25zKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ29udmVuaWVuY2UgbWV0aG9kIHRoYXQgZmlyc3QgY2FsbHMgYGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKC4uLilgXG4gICAgICogYW5kIGlmIHRoZW4gY2hhaW5zIHRvIGBpbml0TG9naW5GbG93KClgLCBidXQgb25seSBpZiB0aGVyZSBpcyBubyB2YWxpZFxuICAgICAqIElkVG9rZW4gb3Igbm8gdmFsaWQgQWNjZXNzVG9rZW4uXG4gICAgICpcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyBMb2dpbk9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIHRvIGB0cnlMb2dpbiguLi4pYFxuICAgICAqL1xuICAgIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRMb2dpbihvcHRpb25zOiBMb2dpbk9wdGlvbnMgJiB7IHN0YXRlPzogc3RyaW5nIH0gPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgICAgIGlmICghb3B0aW9ucykge1xuICAgICAgICAgICAgb3B0aW9ucyA9IHsgc3RhdGU6ICcnIH07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4ob3B0aW9ucykudGhlbihfID0+IHtcbiAgICAgICAgICAgIGlmICghdGhpcy5oYXNWYWxpZElkVG9rZW4oKSB8fCAhdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgICAgICAgICAgICBpZiAodGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmluaXRDb2RlRmxvdygpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuaW5pdEltcGxpY2l0RmxvdygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgZGVidWcoLi4uYXJncyk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5zaG93RGVidWdJbmZvcm1hdGlvbikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZGVidWcuYXBwbHkodGhpcy5sb2dnZXIsIGFyZ3MpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KHVybDogc3RyaW5nKTogc3RyaW5nW10ge1xuICAgICAgICBjb25zdCBlcnJvcnM6IHN0cmluZ1tdID0gW107XG4gICAgICAgIGNvbnN0IGh0dHBzQ2hlY2sgPSB0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModXJsKTtcbiAgICAgICAgY29uc3QgaXNzdWVyQ2hlY2sgPSB0aGlzLnZhbGlkYXRlVXJsQWdhaW5zdElzc3Vlcih1cmwpO1xuXG4gICAgICAgIGlmICghaHR0cHNDaGVjaykge1xuICAgICAgICAgICAgZXJyb3JzLnB1c2goXG4gICAgICAgICAgICAgICAgJ2h0dHBzIGZvciBhbGwgdXJscyByZXF1aXJlZC4gQWxzbyBmb3IgdXJscyByZWNlaXZlZCBieSBkaXNjb3ZlcnkuJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghaXNzdWVyQ2hlY2spIHtcbiAgICAgICAgICAgIGVycm9ycy5wdXNoKFxuICAgICAgICAgICAgICAgICdFdmVyeSB1cmwgaW4gZGlzY292ZXJ5IGRvY3VtZW50IGhhcyB0byBzdGFydCB3aXRoIHRoZSBpc3N1ZXIgdXJsLicgK1xuICAgICAgICAgICAgICAgICdBbHNvIHNlZSBwcm9wZXJ0eSBzdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24uJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBlcnJvcnM7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsRm9ySHR0cHModXJsOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKCF1cmwpIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgbGNVcmwgPSB1cmwudG9Mb3dlckNhc2UoKTtcblxuICAgICAgICBpZiAodGhpcy5yZXF1aXJlSHR0cHMgPT09IGZhbHNlKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChcbiAgICAgICAgICAgIChsY1VybC5tYXRjaCgvXmh0dHA6XFwvXFwvbG9jYWxob3N0KCR8WzpcXC9dKS8pIHx8XG4gICAgICAgICAgICAgICAgbGNVcmwubWF0Y2goL15odHRwOlxcL1xcL2xvY2FsaG9zdCgkfFs6XFwvXSkvKSkgJiZcbiAgICAgICAgICAgIHRoaXMucmVxdWlyZUh0dHBzID09PSAncmVtb3RlT25seSdcbiAgICAgICAgKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBsY1VybC5zdGFydHNXaXRoKCdodHRwczovLycpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBhc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKHVybDogc3RyaW5nIHwgdW5kZWZpbmVkLCBkZXNjcmlwdGlvbjogc3RyaW5nKSB7XG4gICAgICAgIGlmICghdXJsKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYCcke2Rlc2NyaXB0aW9ufScgc2hvdWxkIG5vdCBiZSBudWxsYCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModXJsKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGAnJHtkZXNjcmlwdGlvbn0nIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLmApO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsQWdhaW5zdElzc3Vlcih1cmw6IHN0cmluZykge1xuICAgICAgICBpZiAoIXRoaXMuc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXVybCkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHVybC50b0xvd2VyQ2FzZSgpLnN0YXJ0c1dpdGgodGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwUmVmcmVzaFRpbWVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodHlwZW9mIHdpbmRvdyA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3RpbWVyIG5vdCBzdXBwb3J0ZWQgb24gdGhpcyBwbGF0dGZvcm0nKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpIHx8IHRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24pXG4gICAgICAgICAgICB0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcblxuICAgICAgICB0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24gPSB0aGlzLmV2ZW50cy5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpLnN1YnNjcmliZShfID0+IHtcbiAgICAgICAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gICAgICAgICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgICAgICAgIHRoaXMuc2V0dXBBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICAgIH1cblxuXG4gICAgICAgIGlmICh0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICAgICAgICB0aGlzLnNldHVwSWRUb2tlblRpbWVyKCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBBY2Nlc3NUb2tlblRpbWVyKCk6IHZvaWQge1xuXG4gICAgICAgIGNvbnN0IGV4cGlyYXRpb24gPSB0aGlzLmdldEFjY2Vzc1Rva2VuRXhwaXJhdGlvbigpO1xuICAgICAgICBjb25zdCBzdG9yZWRBdCA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5TdG9yZWRBdCgpO1xuICAgICAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XG5cbiAgICAgICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24gPSBvZihcbiAgICAgICAgICAgICAgICBuZXcgT0F1dGhJbmZvRXZlbnQoJ3Rva2VuX2V4cGlyZXMnLCAnYWNjZXNzX3Rva2VuJylcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICAucGlwZShkZWxheSh0aW1lb3V0KSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBJZFRva2VuVGltZXIoKTogdm9pZCB7XG5cbiAgICAgICAgY29uc3QgZXhwaXJhdGlvbiA9IHRoaXMuZ2V0SWRUb2tlbkV4cGlyYXRpb24oKTtcbiAgICAgICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldElkVG9rZW5TdG9yZWRBdCgpO1xuICAgICAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XG5cbiAgICAgICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxuICAgICAgICAgICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdpZF90b2tlbicpXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNsZWFyQWNjZXNzVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uKSB7XG4gICAgICAgICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNsZWFySWRUb2tlblRpbWVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xuICAgICAgICAgICAgdGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhbGNUaW1lb3V0KHN0b3JlZEF0OiBudW1iZXIsIGV4cGlyYXRpb246IG51bWJlcik6IG51bWJlciB7XG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIGNvbnN0IGRlbHRhID0gKGV4cGlyYXRpb24gLSBzdG9yZWRBdCkgKiB0aGlzLnRpbWVvdXRGYWN0b3IgLSAobm93IC0gc3RvcmVkQXQpO1xuICAgICAgICByZXR1cm4gTWF0aC5tYXgoMCwgZGVsdGEpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERFUFJFQ0FURUQuIFVzZSBhIHByb3ZpZGVyIGZvciBPQXV0aFN0b3JhZ2UgaW5zdGVhZDpcbiAgICAgKlxuICAgICAqIHsgcHJvdmlkZTogT0F1dGhTdG9yYWdlLCB1c2VGYWN0b3J5OiBvQXV0aFN0b3JhZ2VGYWN0b3J5IH1cbiAgICAgKiBleHBvcnQgZnVuY3Rpb24gb0F1dGhTdG9yYWdlRmFjdG9yeSgpOiBPQXV0aFN0b3JhZ2UgeyByZXR1cm4gbG9jYWxTdG9yYWdlOyB9XG4gICAgICogU2V0cyBhIGN1c3RvbSBzdG9yYWdlIHVzZWQgdG8gc3RvcmUgdGhlIHJlY2VpdmVkXG4gICAgICogdG9rZW5zIG9uIGNsaWVudCBzaWRlLiBCeSBkZWZhdWx0LCB0aGUgYnJvd3NlcidzXG4gICAgICogc2Vzc2lvblN0b3JhZ2UgaXMgdXNlZC5cbiAgICAgKiBAaWdub3JlXG4gICAgICpcbiAgICAgKiBAcGFyYW0gc3RvcmFnZVxuICAgICAqL1xuICAgIHB1YmxpYyBzZXRTdG9yYWdlKHN0b3JhZ2U6IE9BdXRoU3RvcmFnZSk6IHZvaWQge1xuICAgICAgICB0aGlzLl9zdG9yYWdlID0gc3RvcmFnZTtcbiAgICAgICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTG9hZHMgdGhlIGRpc2NvdmVyeSBkb2N1bWVudCB0byBjb25maWd1cmUgbW9zdFxuICAgICAqIHByb3BlcnRpZXMgb2YgdGhpcyBzZXJ2aWNlLiBUaGUgdXJsIG9mIHRoZSBkaXNjb3ZlcnlcbiAgICAgKiBkb2N1bWVudCBpcyBpbmZlcmVkIGZyb20gdGhlIGlzc3VlcidzIHVybCBhY2NvcmRpbmdcbiAgICAgKiB0byB0aGUgT3BlbklkIENvbm5lY3Qgc3BlYy4gVG8gdXNlIGFub3RoZXIgdXJsIHlvdVxuICAgICAqIGNhbiBwYXNzIGl0IHRvIHRvIG9wdGlvbmFsIHBhcmFtZXRlciBmdWxsVXJsLlxuICAgICAqXG4gICAgICogQHBhcmFtIGZ1bGxVcmxcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50KGZ1bGxVcmw6IHN0cmluZyA9IG51bGwpOiBQcm9taXNlPE9BdXRoU3VjY2Vzc0V2ZW50PiB7XG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICBpZiAoIWZ1bGxVcmwpIHtcbiAgICAgICAgICAgICAgICBmdWxsVXJsID0gdGhpcy5pc3N1ZXIgfHwgJyc7XG4gICAgICAgICAgICAgICAgaWYgKCFmdWxsVXJsLmVuZHNXaXRoKCcvJykpIHtcbiAgICAgICAgICAgICAgICAgICAgZnVsbFVybCArPSAnLyc7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGZ1bGxVcmwgKz0gJy53ZWxsLWtub3duL29wZW5pZC1jb25maWd1cmF0aW9uJztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHMoZnVsbFVybCkpIHtcbiAgICAgICAgICAgICAgICByZWplY3QoJ2lzc3VlciAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSBcXCdyZXF1aXJlSHR0cHNcXCcgbXVzdCBiZSBzZXQgdG8gXFwnZmFsc2VcXCcgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS4nKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHRoaXMuaHR0cC5nZXQ8T2lkY0Rpc2NvdmVyeURvYz4oZnVsbFVybCkuc3Vic2NyaWJlKFxuICAgICAgICAgICAgICAgIGRvYyA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy52YWxpZGF0ZURpc2NvdmVyeURvY3VtZW50KGRvYykpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJywgbnVsbClcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2luVXJsID0gZG9jLmF1dGhvcml6YXRpb25fZW5kcG9pbnQ7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nb3V0VXJsID0gZG9jLmVuZF9zZXNzaW9uX2VuZHBvaW50IHx8IHRoaXMubG9nb3V0VXJsO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmdyYW50VHlwZXNTdXBwb3J0ZWQgPSBkb2MuZ3JhbnRfdHlwZXNfc3VwcG9ydGVkO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmlzc3VlciA9IGRvYy5pc3N1ZXI7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMudG9rZW5FbmRwb2ludCA9IGRvYy50b2tlbl9lbmRwb2ludDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy51c2VyaW5mb0VuZHBvaW50ID0gZG9jLnVzZXJpbmZvX2VuZHBvaW50IHx8IHRoaXMudXNlcmluZm9FbmRwb2ludDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5qd2tzVXJpID0gZG9jLmp3a3NfdXJpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybCA9IGRvYy5jaGVja19zZXNzaW9uX2lmcmFtZSB8fCB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybDtcblxuICAgICAgICAgICAgICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3QubmV4dChkb2MpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnJlc3RhcnRTZXNzaW9uQ2hlY2tzSWZTdGlsbExvZ2dlZEluKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvYWRKd2tzKClcbiAgICAgICAgICAgICAgICAgICAgICAgIC50aGVuKGp3a3MgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHJlc3VsdDogb2JqZWN0ID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkaXNjb3ZlcnlEb2N1bWVudDogZG9jLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBqd2tzOiBqd2tzXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUoZXZlbnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2F0Y2goZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGRpc2NvdmVyeSBkb2N1bWVudCcsIGVycik7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBsb2FkSndrcygpOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2U8b2JqZWN0PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICBpZiAodGhpcy5qd2tzVXJpKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5odHRwLmdldCh0aGlzLmp3a3NVcmkpLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICAgICAgandrcyA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmp3a3MgPSBqd2tzO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJylcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKGp3a3MpO1xuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgandrcycsIGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdqd2tzX2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXNvbHZlKG51bGwpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgdmFsaWRhdGVEaXNjb3ZlcnlEb2N1bWVudChkb2M6IE9pZGNEaXNjb3ZlcnlEb2MpOiBib29sZWFuIHtcbiAgICAgICAgbGV0IGVycm9yczogc3RyaW5nW107XG5cbiAgICAgICAgaWYgKCF0aGlzLnNraXBJc3N1ZXJDaGVjayAmJiBkb2MuaXNzdWVyICE9PSB0aGlzLmlzc3Vlcikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2ludmFsaWQgaXNzdWVyIGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgICAgICAgICAgJ2V4cGVjdGVkOiAnICsgdGhpcy5pc3N1ZXIsXG4gICAgICAgICAgICAgICAgJ2N1cnJlbnQ6ICcgKyBkb2MuaXNzdWVyXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MuYXV0aG9yaXphdGlvbl9lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgYXV0aG9yaXphdGlvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgIGVycm9yc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmVuZF9zZXNzaW9uX2VuZHBvaW50KTtcbiAgICAgICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyBlbmRfc2Vzc2lvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgIGVycm9yc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnRva2VuX2VuZHBvaW50KTtcbiAgICAgICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyB0b2tlbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgIGVycm9yc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnVzZXJpbmZvX2VuZHBvaW50KTtcbiAgICAgICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyB1c2VyaW5mb19lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgIGVycm9yc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmp3a3NfdXJpKTtcbiAgICAgICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgdmFsaWRhdGluZyBqd2tzX3VyaSBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLCBlcnJvcnMpO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQgJiYgIWRvYy5jaGVja19zZXNzaW9uX2lmcmFtZSkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCBkaXNjb3ZlcnkgZG9jdW1lbnQnICtcbiAgICAgICAgICAgICAgICAnIGRvZXMgbm90IGNvbnRhaW4gYSBjaGVja19zZXNzaW9uX2lmcmFtZSBmaWVsZCdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVc2VzIHBhc3N3b3JkIGZsb3cgdG8gZXhjaGFuZ2UgdXNlck5hbWUgYW5kIHBhc3N3b3JkIGZvciBhblxuICAgICAqIGFjY2Vzc190b2tlbi4gQWZ0ZXIgcmVjZWl2aW5nIHRoZSBhY2Nlc3NfdG9rZW4sIHRoaXMgbWV0aG9kXG4gICAgICogdXNlcyBpdCB0byBxdWVyeSB0aGUgdXNlcmluZm8gZW5kcG9pbnQgaW4gb3JkZXIgdG8gZ2V0IGluZm9ybWF0aW9uXG4gICAgICogYWJvdXQgdGhlIHVzZXIgaW4gcXVlc3Rpb24uXG4gICAgICpcbiAgICAgKiBXaGVuIHVzaW5nIHRoaXMsIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cbiAgICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb25cbiAgICAgKiBmYWlsLlxuICAgICAqXG4gICAgICogQHBhcmFtIHVzZXJOYW1lXG4gICAgICogQHBhcmFtIHBhc3N3b3JkXG4gICAgICogQHBhcmFtIGhlYWRlcnMgT3B0aW9uYWwgYWRkaXRpb25hbCBodHRwLWhlYWRlcnMuXG4gICAgICovXG4gICAgcHVibGljIGZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvd0FuZExvYWRVc2VyUHJvZmlsZShcbiAgICAgICAgdXNlck5hbWU6IHN0cmluZyxcbiAgICAgICAgcGFzc3dvcmQ6IHN0cmluZyxcbiAgICAgICAgaGVhZGVyczogSHR0cEhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxuICAgICk6IFByb21pc2U8VXNlckluZm8+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93KHVzZXJOYW1lLCBwYXNzd29yZCwgaGVhZGVycykudGhlbihcbiAgICAgICAgICAgICgpID0+IHRoaXMubG9hZFVzZXJQcm9maWxlKClcbiAgICAgICAgKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMb2FkcyB0aGUgdXNlciBwcm9maWxlIGJ5IGFjY2Vzc2luZyB0aGUgdXNlciBpbmZvIGVuZHBvaW50IGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QuXG4gICAgICpcbiAgICAgKiBXaGVuIHVzaW5nIHRoaXMgd2l0aCBPQXV0aDIgcGFzc3dvcmQgZmxvdywgbWFrZSBzdXJlIHRoYXQgdGhlIHByb3BlcnR5IG9pZGMgaXMgc2V0IHRvIGZhbHNlLlxuICAgICAqIE90aGVyd2lzZSBzdHJpY3RlciB2YWxpZGF0aW9ucyB0YWtlIHBsYWNlIHRoYXQgbWFrZSB0aGlzIG9wZXJhdGlvbiBmYWlsLlxuICAgICAqL1xuICAgIHB1YmxpYyBsb2FkVXNlclByb2ZpbGUoKTogUHJvbWlzZTxVc2VySW5mbz4ge1xuICAgICAgICBpZiAoIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NhbiBub3QgbG9hZCBVc2VyIFByb2ZpbGUgd2l0aG91dCBhY2Nlc3NfdG9rZW4nKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLnVzZXJpbmZvRW5kcG9pbnQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ3VzZXJpbmZvRW5kcG9pbnQgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSBcXCdyZXF1aXJlSHR0cHNcXCcgbXVzdCBiZSBzZXQgdG8gXFwnZmFsc2VcXCcgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS4nKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICBjb25zdCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxuICAgICAgICAgICAgICAgICdBdXRob3JpemF0aW9uJyxcbiAgICAgICAgICAgICAgICAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKClcbiAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgIHRoaXMuaHR0cC5nZXQ8VXNlckluZm8+KHRoaXMudXNlcmluZm9FbmRwb2ludCwgeyBoZWFkZXJzIH0pLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICBpbmZvID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZygndXNlcmluZm8gcmVjZWl2ZWQnLCBpbmZvKTtcblxuICAgICAgICAgICAgICAgICAgICBjb25zdCBleGlzdGluZ0NsYWltcyA9IHRoaXMuZ2V0SWRlbnRpdHlDbGFpbXMoKSB8fCB7fTtcblxuICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuc2tpcFN1YmplY3RDaGVjaykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMub2lkYyAmJlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICghZXhpc3RpbmdDbGFpbXNbJ3N1YiddIHx8IGluZm8uc3ViICE9PSBleGlzdGluZ0NsYWltc1snc3ViJ10pXG4gICAgICAgICAgICAgICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBlcnIgPVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnaWYgcHJvcGVydHkgb2lkYyBpcyB0cnVlLCB0aGUgcmVjZWl2ZWQgdXNlci1pZCAoc3ViKSBoYXMgdG8gYmUgdGhlIHVzZXItaWQgJyArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdvZiB0aGUgdXNlciB0aGF0IGhhcyBsb2dnZWQgaW4gd2l0aCBvaWRjLlxcbicgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnaWYgeW91IGFyZSBub3QgdXNpbmcgb2lkYyBidXQganVzdCBvYXV0aDIgcGFzc3dvcmQgZmxvdyBzZXQgb2lkYyB0byBmYWxzZSc7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpbmZvID0gT2JqZWN0LmFzc2lnbih7fSwgZXhpc3RpbmdDbGFpbXMsIGluZm8pO1xuXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIEpTT04uc3RyaW5naWZ5KGluZm8pKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd1c2VyX3Byb2ZpbGVfbG9hZGVkJykpO1xuICAgICAgICAgICAgICAgICAgICByZXNvbHZlKGluZm8pO1xuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgdXNlciBpbmZvJywgZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd1c2VyX3Byb2ZpbGVfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW4gYWNjZXNzX3Rva2VuLlxuICAgICAqIEBwYXJhbSB1c2VyTmFtZVxuICAgICAqIEBwYXJhbSBwYXNzd29yZFxuICAgICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxuICAgICAqL1xuICAgIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3coXG4gICAgICAgIHVzZXJOYW1lOiBzdHJpbmcsXG4gICAgICAgIHBhc3N3b3JkOiBzdHJpbmcsXG4gICAgICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcblxuICAgICk6IFByb21pc2U8VG9rZW5SZXNwb25zZT4ge1xuICAgICAgICB0aGlzLmFzc2VydFVybE5vdE51bGxBbmRDb3JyZWN0UHJvdG9jb2wodGhpcy50b2tlbkVuZHBvaW50LCAndG9rZW5FbmRwb2ludCcpO1xuXG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAqIEEgYEh0dHBQYXJhbWV0ZXJDb2RlY2AgdGhhdCB1c2VzIGBlbmNvZGVVUklDb21wb25lbnRgIGFuZCBgZGVjb2RlVVJJQ29tcG9uZW50YCB0b1xuICAgICAgICAgICAgICogc2VyaWFsaXplIGFuZCBwYXJzZSBVUkwgcGFyYW1ldGVyIGtleXMgYW5kIHZhbHVlcy5cbiAgICAgICAgICAgICAqXG4gICAgICAgICAgICAgKiBAc3RhYmxlXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcyh7IGVuY29kZXI6IG5ldyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYygpIH0pXG4gICAgICAgICAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdwYXNzd29yZCcpXG4gICAgICAgICAgICAgICAgLnNldCgnc2NvcGUnLCB0aGlzLnNjb3BlKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3VzZXJuYW1lJywgdXNlck5hbWUpXG4gICAgICAgICAgICAgICAgLnNldCgncGFzc3dvcmQnLCBwYXNzd29yZCk7XG5cbiAgICAgICAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcbiAgICAgICAgICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXG4gICAgICAgICAgICAgICAgICAgICdBdXRob3JpemF0aW9uJyxcbiAgICAgICAgICAgICAgICAgICAgJ0Jhc2ljICcgKyBoZWFkZXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KFxuICAgICAgICAgICAgICAgICdDb250ZW50LVR5cGUnLFxuICAgICAgICAgICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmh0dHBcbiAgICAgICAgICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5leHRyYWN0UmVjb2duaXplZEN1c3RvbVBhcmFtZXRlcnModG9rZW5SZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHBlcmZvcm1pbmcgcGFzc3dvcmQgZmxvdycsIGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIGVycikpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWZyZXNoZXMgdGhlIHRva2VuIHVzaW5nIGEgcmVmcmVzaF90b2tlbi5cbiAgICAgKiBUaGlzIGRvZXMgbm90IHdvcmsgZm9yIGltcGxpY2l0IGZsb3csIGIvY1xuICAgICAqIHRoZXJlIGlzIG5vIHJlZnJlc2hfdG9rZW4gaW4gdGhpcyBmbG93LlxuICAgICAqIEEgc29sdXRpb24gZm9yIHRoaXMgaXMgcHJvdmlkZWQgYnkgdGhlXG4gICAgICogbWV0aG9kIHNpbGVudFJlZnJlc2guXG4gICAgICovXG4gICAgcHVibGljIHJlZnJlc2hUb2tlbigpOiBQcm9taXNlPFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgdGhpcy5hc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKHRoaXMudG9rZW5FbmRwb2ludCwgJ3Rva2VuRW5kcG9pbnQnKTtcblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKClcbiAgICAgICAgICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3JlZnJlc2hfdG9rZW4nKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3Njb3BlJywgdGhpcy5zY29wZSlcbiAgICAgICAgICAgICAgICAuc2V0KCdyZWZyZXNoX3Rva2VuJywgdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdyZWZyZXNoX3Rva2VuJykpO1xuXG4gICAgICAgICAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcbiAgICAgICAgICAgICAgICAnQ29udGVudC1UeXBlJyxcbiAgICAgICAgICAgICAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xuICAgICAgICAgICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgICAgICAgICAgICAgJ0F1dGhvcml6YXRpb24nLFxuICAgICAgICAgICAgICAgICAgICAnQmFzaWMgJyArIGhlYWRlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmh0dHBcbiAgICAgICAgICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXG4gICAgICAgICAgICAgICAgLnBpcGUoc3dpdGNoTWFwKHRva2VuUmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAodG9rZW5SZXNwb25zZS5pZF90b2tlbikge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZyb20odGhpcy5wcm9jZXNzSWRUb2tlbih0b2tlblJlc3BvbnNlLmlkX3Rva2VuLCB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbiwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLnBpcGUoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRhcChyZXN1bHQgPT4gdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KSksXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1hcChfID0+IHRva2VuUmVzcG9uc2UpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBvZih0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pKVxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZygncmVmcmVzaCB0b2tlblJlc3BvbnNlJywgdG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5leHRyYWN0UmVjb2duaXplZEN1c3RvbVBhcmFtZXRlcnModG9rZW5SZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcmVmcmVzaGluZyB0b2tlbicsIGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyKSB7XG4gICAgICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcihcbiAgICAgICAgICAgICAgICAnbWVzc2FnZScsXG4gICAgICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyID0gbnVsbDtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XG5cbiAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMucHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZSk7XG5cbiAgICAgICAgICAgIHRoaXMudHJ5TG9naW4oe1xuICAgICAgICAgICAgICAgIGN1c3RvbUhhc2hGcmFnbWVudDogbWVzc2FnZSxcbiAgICAgICAgICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcbiAgICAgICAgICAgICAgICBjdXN0b21SZWRpcmVjdFVyaTogdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaVxuICAgICAgICAgICAgfSkuY2F0Y2goZXJyID0+IHRoaXMuZGVidWcoJ3RyeUxvZ2luIGR1cmluZyBzaWxlbnQgcmVmcmVzaCBmYWlsZWQnLCBlcnIpKTtcbiAgICAgICAgfTtcblxuICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcihcbiAgICAgICAgICAgICdtZXNzYWdlJyxcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lclxuICAgICAgICApO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFBlcmZvcm1zIGEgc2lsZW50IHJlZnJlc2ggZm9yIGltcGxpY2l0IGZsb3cuXG4gICAgICogVXNlIHRoaXMgbWV0aG9kIHRvIGdldCBuZXcgdG9rZW5zIHdoZW4vYmVmb3JlXG4gICAgICogdGhlIGV4aXN0aW5nIHRva2VucyBleHBpcmUuXG4gICAgICovXG4gICAgcHVibGljIHNpbGVudFJlZnJlc2gocGFyYW1zOiBvYmplY3QgPSB7fSwgbm9Qcm9tcHQgPSB0cnVlKTogUHJvbWlzZTxPQXV0aEV2ZW50PiB7XG4gICAgICAgIGNvbnN0IGNsYWltczogb2JqZWN0ID0gdGhpcy5nZXRJZGVudGl0eUNsYWltcygpIHx8IHt9O1xuXG4gICAgICAgIGlmICh0aGlzLnVzZUlkVG9rZW5IaW50Rm9yU2lsZW50UmVmcmVzaCAmJiB0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICAgICAgICBwYXJhbXNbJ2lkX3Rva2VuX2hpbnQnXSA9IHRoaXMuZ2V0SWRUb2tlbigpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignbG9naW5VcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgXFwncmVxdWlyZUh0dHBzXFwnIG11c3QgYmUgc2V0IHRvIFxcJ2ZhbHNlXFwnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuJyk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdzaWxlbnQgcmVmcmVzaCBpcyBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdGZvcm0nKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lXG4gICAgICAgICk7XG5cbiAgICAgICAgaWYgKGV4aXN0aW5nSWZyYW1lKSB7XG4gICAgICAgICAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgPSBjbGFpbXNbJ3N1YiddO1xuXG4gICAgICAgIGNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpO1xuICAgICAgICBpZnJhbWUuaWQgPSB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lO1xuXG4gICAgICAgIHRoaXMuc2V0dXBTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIGNvbnN0IHJlZGlyZWN0VXJpID0gdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgICAgdGhpcy5jcmVhdGVMb2dpblVybChudWxsLCBudWxsLCByZWRpcmVjdFVyaSwgbm9Qcm9tcHQsIHBhcmFtcykudGhlbih1cmwgPT4ge1xuICAgICAgICAgICAgaWZyYW1lLnNldEF0dHJpYnV0ZSgnc3JjJywgdXJsKTtcblxuICAgICAgICAgICAgaWYgKCF0aGlzLnNpbGVudFJlZnJlc2hTaG93SUZyYW1lKSB7XG4gICAgICAgICAgICAgICAgaWZyYW1lLnN0eWxlWydkaXNwbGF5J10gPSAnbm9uZSc7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGlmcmFtZSk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGNvbnN0IGVycm9ycyA9IHRoaXMuZXZlbnRzLnBpcGUoXG4gICAgICAgICAgICBmaWx0ZXIoZSA9PiBlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSxcbiAgICAgICAgICAgIGZpcnN0KClcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMuZXZlbnRzLnBpcGUoXG4gICAgICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpLFxuICAgICAgICAgICAgZmlyc3QoKVxuICAgICAgICApO1xuICAgICAgICBjb25zdCB0aW1lb3V0ID0gb2YoXG4gICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdzaWxlbnRfcmVmcmVzaF90aW1lb3V0JywgbnVsbClcbiAgICAgICAgKS5waXBlKGRlbGF5KHRoaXMuc2lsZW50UmVmcmVzaFRpbWVvdXQpKTtcblxuICAgICAgICByZXR1cm4gcmFjZShbZXJyb3JzLCBzdWNjZXNzLCB0aW1lb3V0XSlcbiAgICAgICAgICAgIC5waXBlKFxuICAgICAgICAgICAgICAgIG1hcChlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBPQXV0aEVycm9yRXZlbnQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0Jykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfZXJyb3InLCBlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIHRocm93IGU7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBlID0gbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCdzaWxlbnRseV9yZWZyZXNoZWQnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBlO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAudG9Qcm9taXNlKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVGhpcyBtZXRob2QgZXhpc3RzIGZvciBiYWNrd2FyZHMgY29tcGF0aWJpbGl0eS5cbiAgICAgKiB7QGxpbmsgT0F1dGhTZXJ2aWNlI2luaXRMb2dpbkZsb3dJblBvcHVwfSBoYW5kbGVzIGJvdGggY29kZVxuICAgICAqIGFuZCBpbXBsaWNpdCBmbG93cy5cbiAgICAgKi9cbiAgICBwdWJsaWMgaW5pdEltcGxpY2l0Rmxvd0luUG9wdXAob3B0aW9ucz86IHsgaGVpZ2h0PzogbnVtYmVyLCB3aWR0aD86IG51bWJlciB9KSB7XG4gICAgICAgIHJldHVybiB0aGlzLmluaXRMb2dpbkZsb3dJblBvcHVwKG9wdGlvbnMpO1xuICAgIH1cblxuICAgIHB1YmxpYyBpbml0TG9naW5GbG93SW5Qb3B1cChvcHRpb25zPzogeyBoZWlnaHQ/OiBudW1iZXIsIHdpZHRoPzogbnVtYmVyIH0pIHtcbiAgICAgICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG4gICAgICAgIHJldHVybiB0aGlzLmNyZWF0ZUxvZ2luVXJsKG51bGwsIG51bGwsIHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpLCBmYWxzZSwge1xuICAgICAgICAgICAgZGlzcGxheTogJ3BvcHVwJ1xuICAgICAgICB9KS50aGVuKHVybCA9PiB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICAgICAqIEVycm9yIGhhbmRsaW5nIHNlY3Rpb25cbiAgICAgICAgICAgICAgICAgKi9cbiAgICAgICAgICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWwgPSA1MDA7XG4gICAgICAgICAgICAgICAgbGV0IHdpbmRvd1JlZiA9IHdpbmRvdy5vcGVuKHVybCwgJ19ibGFuaycsIHRoaXMuY2FsY3VsYXRlUG9wdXBGZWF0dXJlcyhvcHRpb25zKSk7XG4gICAgICAgICAgICAgICAgbGV0IGNoZWNrRm9yUG9wdXBDbG9zZWRUaW1lcjogYW55O1xuICAgICAgICAgICAgICAgIGNvbnN0IGNoZWNrRm9yUG9wdXBDbG9zZWQgPSAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghd2luZG93UmVmIHx8IHdpbmRvd1JlZi5jbG9zZWQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChuZXcgT0F1dGhFcnJvckV2ZW50KCdwb3B1cF9jbG9zZWQnLCB7fSkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICBpZiAoIXdpbmRvd1JlZikge1xuICAgICAgICAgICAgICAgICAgICByZWplY3QobmV3IE9BdXRoRXJyb3JFdmVudCgncG9wdXBfYmxvY2tlZCcsIHt9KSk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyID0gd2luZG93LnNldEludGVydmFsKGNoZWNrRm9yUG9wdXBDbG9zZWQsIGNoZWNrRm9yUG9wdXBDbG9zZWRJbnRlcnZhbCk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgY29uc3QgY2xlYW51cCA9ICgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgd2luZG93LmNsZWFySW50ZXJ2YWwoY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyKTtcbiAgICAgICAgICAgICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBsaXN0ZW5lcik7XG4gICAgICAgICAgICAgICAgICAgIGlmICh3aW5kb3dSZWYgIT09IG51bGwpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHdpbmRvd1JlZi5jbG9zZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIHdpbmRvd1JlZiA9IG51bGw7XG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIGNvbnN0IGxpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5wcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlKTtcblxuICAgICAgICAgICAgICAgICAgICBpZiAobWVzc2FnZSAmJiBtZXNzYWdlICE9PSBudWxsKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnRyeUxvZ2luKHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdXN0b21IYXNoRnJhZ21lbnQ6IG1lc3NhZ2UsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJldmVudENsZWFySGFzaEFmdGVyTG9naW46IHRydWUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY3VzdG9tUmVkaXJlY3RVcmk6IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgICAgICAgICAgICAgfSkudGhlbigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xlYW51cCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0sIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xlYW51cCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnZmFsc2UgZXZlbnQgZmlyaW5nJyk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIGxpc3RlbmVyKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2FsY3VsYXRlUG9wdXBGZWF0dXJlcyhvcHRpb25zOiB7IGhlaWdodD86IG51bWJlciwgd2lkdGg/OiBudW1iZXIgfSk6IHN0cmluZyB7XG4gICAgICAgIC8vIFNwZWNpZnkgYW4gc3RhdGljIGhlaWdodCBhbmQgd2lkdGggYW5kIGNhbGN1bGF0ZSBjZW50ZXJlZCBwb3NpdGlvblxuXG4gICAgICAgIGNvbnN0IGhlaWdodCA9IG9wdGlvbnMuaGVpZ2h0IHx8IDQ3MDtcbiAgICAgICAgY29uc3Qgd2lkdGggPSBvcHRpb25zLndpZHRoIHx8IDUwMDtcbiAgICAgICAgY29uc3QgbGVmdCA9IHdpbmRvdy5zY3JlZW5MZWZ0ICsgKCh3aW5kb3cub3V0ZXJXaWR0aCAtIHdpZHRoKSAvIDIpO1xuICAgICAgICBjb25zdCB0b3AgPSB3aW5kb3cuc2NyZWVuVG9wICsgKCh3aW5kb3cub3V0ZXJIZWlnaHQgLSBoZWlnaHQpIC8gMik7XG4gICAgICAgIHJldHVybiBgbG9jYXRpb249bm8sdG9vbGJhcj1ubyx3aWR0aD0ke3dpZHRofSxoZWlnaHQ9JHtoZWlnaHR9LHRvcD0ke3RvcH0sbGVmdD0ke2xlZnR9YDtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZTogTWVzc2FnZUV2ZW50KTogc3RyaW5nIHtcbiAgICAgICAgbGV0IGV4cGVjdGVkUHJlZml4ID0gJyMnO1xuXG4gICAgICAgIGlmICh0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4KSB7XG4gICAgICAgICAgICBleHBlY3RlZFByZWZpeCArPSB0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4O1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFlIHx8ICFlLmRhdGEgfHwgdHlwZW9mIGUuZGF0YSAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHByZWZpeGVkTWVzc2FnZTogc3RyaW5nID0gZS5kYXRhO1xuXG4gICAgICAgIGlmICghcHJlZml4ZWRNZXNzYWdlLnN0YXJ0c1dpdGgoZXhwZWN0ZWRQcmVmaXgpKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gJyMnICsgcHJlZml4ZWRNZXNzYWdlLnN1YnN0cihleHBlY3RlZFByZWZpeC5sZW5ndGgpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCk6IGJvb2xlYW4ge1xuICAgICAgICBpZiAoIXRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgdGhlcmUgaXMgbm8gc2Vzc2lvbkNoZWNrSUZyYW1lVXJsJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xuICAgICAgICBpZiAoIXNlc3Npb25TdGF0ZSkge1xuICAgICAgICAgICAgY29uc29sZS53YXJuKFxuICAgICAgICAgICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25fc3RhdGUnXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0eXBlb2YgZG9jdW1lbnQgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcblxuICAgICAgICB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICAgICAgICBjb25zdCBvcmlnaW4gPSBlLm9yaWdpbi50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgY29uc3QgaXNzdWVyID0gdGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKTtcblxuICAgICAgICAgICAgdGhpcy5kZWJ1Zygnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicpO1xuXG4gICAgICAgICAgICBpZiAoIWlzc3Vlci5zdGFydHNXaXRoKG9yaWdpbikpIHtcbiAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKFxuICAgICAgICAgICAgICAgICAgICAnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicsXG4gICAgICAgICAgICAgICAgICAgICd3cm9uZyBvcmlnaW4nLFxuICAgICAgICAgICAgICAgICAgICBvcmlnaW4sXG4gICAgICAgICAgICAgICAgICAgICdleHBlY3RlZCcsXG4gICAgICAgICAgICAgICAgICAgIGlzc3VlclxuICAgICAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIG9ubHkgcnVuIGluIEFuZ3VsYXIgem9uZSBpZiBpdCBpcyAnY2hhbmdlZCcgb3IgJ2Vycm9yJ1xuICAgICAgICAgICAgc3dpdGNoIChlLmRhdGEpIHtcbiAgICAgICAgICAgICAgICBjYXNlICd1bmNoYW5nZWQnOlxuICAgICAgICAgICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25VbmNoYW5nZWQoKTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnY2hhbmdlZCc6XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25DaGFuZ2UoKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ2Vycm9yJzpcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvbkVycm9yKCk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdGhpcy5kZWJ1ZygnZ290IGluZm8gZnJvbSBzZXNzaW9uIGNoZWNrIGluZnJhbWUnLCBlKTtcbiAgICAgICAgfTtcblxuICAgICAgICAvLyBwcmV2ZW50IEFuZ3VsYXIgZnJvbSByZWZyZXNoaW5nIHRoZSB2aWV3IG9uIGV2ZXJ5IG1lc3NhZ2UgKHJ1bnMgaW4gaW50ZXJ2YWxzKVxuICAgICAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcik7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uVW5jaGFuZ2VkKCk6IHZvaWQge1xuICAgICAgICB0aGlzLmRlYnVnKCdzZXNzaW9uIGNoZWNrJywgJ3Nlc3Npb24gdW5jaGFuZ2VkJyk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25DaGFuZ2UoKTogdm9pZCB7XG4gICAgICAgIC8qIGV2ZW50czogc2Vzc2lvbl9jaGFuZ2VkLCByZWxvZ2luLCBzdG9wVGltZXIsIGxvZ2dlZF9vdXQqL1xuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fY2hhbmdlZCcpKTtcbiAgICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICAgICAgaWYgKHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpKSB7XG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2goKS5jYXRjaChfID0+XG4gICAgICAgICAgICAgICAgdGhpcy5kZWJ1Zygnc2lsZW50IHJlZnJlc2ggZmFpbGVkIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgdGhpcy53YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XG4gICAgICAgICAgICB0aGlzLmxvZ091dCh0cnVlKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCB3YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5ldmVudHNcbiAgICAgICAgICAgIC5waXBlKFxuICAgICAgICAgICAgICAgIGZpbHRlcihcbiAgICAgICAgICAgICAgICAgICAgKGU6IE9BdXRoRXZlbnQpID0+XG4gICAgICAgICAgICAgICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRseV9yZWZyZXNoZWQnIHx8XG4gICAgICAgICAgICAgICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0JyB8fFxuICAgICAgICAgICAgICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfZXJyb3InXG4gICAgICAgICAgICAgICAgKSxcbiAgICAgICAgICAgICAgICBmaXJzdCgpXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgICAgICAgIGlmIChlLnR5cGUgIT09ICdzaWxlbnRseV9yZWZyZXNoZWQnKSB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3NpbGVudCByZWZyZXNoIGRpZCBub3Qgd29yayBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uRXJyb3IoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9lcnJvcicpKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcmVtb3ZlU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcikge1xuICAgICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpO1xuICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyID0gbnVsbDtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBpbml0U2Vzc2lvbkNoZWNrKCk6IHZvaWQge1xuICAgICAgICBpZiAoIXRoaXMuY2FuUGVyZm9ybVNlc3Npb25DaGVjaygpKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBleGlzdGluZ0lmcmFtZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZSk7XG4gICAgICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xuICAgICAgICAgICAgZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChleGlzdGluZ0lmcmFtZSk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcbiAgICAgICAgaWZyYW1lLmlkID0gdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lO1xuXG4gICAgICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XG5cbiAgICAgICAgY29uc3QgdXJsID0gdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmw7XG4gICAgICAgIGlmcmFtZS5zZXRBdHRyaWJ1dGUoJ3NyYycsIHVybCk7XG4gICAgICAgIGlmcmFtZS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnO1xuICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGlmcmFtZSk7XG5cbiAgICAgICAgdGhpcy5zdGFydFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIgPSBzZXRJbnRlcnZhbChcbiAgICAgICAgICAgICAgICB0aGlzLmNoZWNrU2Vzc2lvbi5iaW5kKHRoaXMpLFxuICAgICAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSW50ZXJ2YWxsXG4gICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tUaW1lcikge1xuICAgICAgICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLnNlc3Npb25DaGVja1RpbWVyKTtcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIgPSBudWxsO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNoZWNrU2Vzc2lvbigpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgaWZyYW1lOiBhbnkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWUpO1xuXG4gICAgICAgIGlmICghaWZyYW1lKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAgICAgICAgICdjaGVja1Nlc3Npb24gZGlkIG5vdCBmaW5kIGlmcmFtZScsXG4gICAgICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gdGhpcy5nZXRTZXNzaW9uU3RhdGUoKTtcblxuICAgICAgICBpZiAoIXNlc3Npb25TdGF0ZSkge1xuICAgICAgICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLmNsaWVudElkICsgJyAnICsgc2Vzc2lvblN0YXRlO1xuICAgICAgICBpZnJhbWUuY29udGVudFdpbmRvdy5wb3N0TWVzc2FnZShtZXNzYWdlLCB0aGlzLmlzc3Vlcik7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGFzeW5jIGNyZWF0ZUxvZ2luVXJsKFxuICAgICAgICBzdGF0ZSA9ICcnLFxuICAgICAgICBsb2dpbkhpbnQgPSAnJyxcbiAgICAgICAgY3VzdG9tUmVkaXJlY3RVcmkgPSAnJyxcbiAgICAgICAgbm9Qcm9tcHQgPSBmYWxzZSxcbiAgICAgICAgcGFyYW1zOiBvYmplY3QgPSB7fVxuICAgICk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xuXG4gICAgICAgIGxldCByZWRpcmVjdFVyaTogc3RyaW5nO1xuXG4gICAgICAgIGlmIChjdXN0b21SZWRpcmVjdFVyaSkge1xuICAgICAgICAgICAgcmVkaXJlY3RVcmkgPSBjdXN0b21SZWRpcmVjdFVyaTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJlZGlyZWN0VXJpID0gdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IG5vbmNlID0gYXdhaXQgdGhpcy5jcmVhdGVBbmRTYXZlTm9uY2UoKTtcblxuICAgICAgICBpZiAoc3RhdGUpIHtcbiAgICAgICAgICAgIHN0YXRlID0gbm9uY2UgKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yICsgc3RhdGU7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBzdGF0ZSA9IG5vbmNlO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ0VpdGhlciByZXF1ZXN0QWNjZXNzVG9rZW4gb3Igb2lkYyBvciBib3RoIG11c3QgYmUgdHJ1ZSdcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5jb25maWcucmVzcG9uc2VUeXBlKSB7XG4gICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9IHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmICh0aGlzLm9pZGMgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbiB0b2tlbic7XG4gICAgICAgICAgICB9IGVsc2UgaWYgKHRoaXMub2lkYyAmJiAhdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbic7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ3Rva2VuJztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHNlcGVyYXRpb25DaGFyID0gdGhhdC5sb2dpblVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JztcblxuICAgICAgICBsZXQgc2NvcGUgPSB0aGF0LnNjb3BlO1xuXG4gICAgICAgIGlmICh0aGlzLm9pZGMgJiYgIXNjb3BlLm1hdGNoKC8oXnxcXHMpb3BlbmlkKCR8XFxzKS8pKSB7XG4gICAgICAgICAgICBzY29wZSA9ICdvcGVuaWQgJyArIHNjb3BlO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IHVybCA9XG4gICAgICAgICAgICB0aGF0LmxvZ2luVXJsICtcbiAgICAgICAgICAgIHNlcGVyYXRpb25DaGFyICtcbiAgICAgICAgICAgICdyZXNwb25zZV90eXBlPScgK1xuICAgICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzcG9uc2VUeXBlKSArXG4gICAgICAgICAgICAnJmNsaWVudF9pZD0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LmNsaWVudElkKSArXG4gICAgICAgICAgICAnJnN0YXRlPScgK1xuICAgICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKSArXG4gICAgICAgICAgICAnJnJlZGlyZWN0X3VyaT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgK1xuICAgICAgICAgICAgJyZzY29wZT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzY29wZSk7XG5cbiAgICAgICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScgJiYgIXRoaXMuZGlzYWJsZVBLQ0UpIHtcbiAgICAgICAgICAgIGNvbnN0IFtjaGFsbGVuZ2UsIHZlcmlmaWVyXSA9IGF3YWl0IHRoaXMuY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpO1xuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJywgdmVyaWZpZXIpO1xuICAgICAgICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2U9JyArIGNoYWxsZW5nZTtcbiAgICAgICAgICAgIHVybCArPSAnJmNvZGVfY2hhbGxlbmdlX21ldGhvZD1TMjU2JztcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChsb2dpbkhpbnQpIHtcbiAgICAgICAgICAgIHVybCArPSAnJmxvZ2luX2hpbnQ9JyArIGVuY29kZVVSSUNvbXBvbmVudChsb2dpbkhpbnQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoYXQucmVzb3VyY2UpIHtcbiAgICAgICAgICAgIHVybCArPSAnJnJlc291cmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQodGhhdC5yZXNvdXJjZSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhhdC5vaWRjKSB7XG4gICAgICAgICAgICB1cmwgKz0gJyZub25jZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KG5vbmNlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChub1Byb21wdCkge1xuICAgICAgICAgICAgdXJsICs9ICcmcHJvbXB0PW5vbmUnO1xuICAgICAgICB9XG5cbiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmtleXMocGFyYW1zKSkge1xuICAgICAgICAgICAgdXJsICs9XG4gICAgICAgICAgICAgICAgJyYnICsgZW5jb2RlVVJJQ29tcG9uZW50KGtleSkgKyAnPScgKyBlbmNvZGVVUklDb21wb25lbnQocGFyYW1zW2tleV0pO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgICAgICAgdXJsICs9XG4gICAgICAgICAgICAgICAgICAgICcmJyArIGtleSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHVybDtcblxuICAgIH1cblxuICAgIGluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtczogc3RyaW5nIHwgb2JqZWN0ID0gJydcbiAgICApOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuaW5JbXBsaWNpdEZsb3cpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSB0cnVlO1xuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ2xvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IFxcJ3JlcXVpcmVIdHRwc1xcJyBtdXN0IGJlIHNldCB0byBcXCdmYWxzZVxcJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBsZXQgYWRkUGFyYW1zOiBvYmplY3QgPSB7fTtcbiAgICAgICAgbGV0IGxvZ2luSGludDogc3RyaW5nID0gbnVsbDtcblxuICAgICAgICBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIGxvZ2luSGludCA9IHBhcmFtcztcbiAgICAgICAgfSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zID09PSAnb2JqZWN0Jykge1xuICAgICAgICAgICAgYWRkUGFyYW1zID0gcGFyYW1zO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5jcmVhdGVMb2dpblVybChhZGRpdGlvbmFsU3RhdGUsIGxvZ2luSGludCwgbnVsbCwgZmFsc2UsIGFkZFBhcmFtcylcbiAgICAgICAgICAgIC50aGVuKHRoaXMuY29uZmlnLm9wZW5VcmkpXG4gICAgICAgICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGluIGluaXRJbXBsaWNpdEZsb3cnLCBlcnJvcik7XG4gICAgICAgICAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuICAgICAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU3RhcnRzIHRoZSBpbXBsaWNpdCBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xuICAgICAqIHRoZSBhdXRoIHNlcnZlcnMnIGxvZ2luIHVybC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBhZGRpdGlvbmFsU3RhdGUgT3B0aW9uYWwgc3RhdGUgdGhhdCBpcyBwYXNzZWQgYXJvdW5kLlxuICAgICAqICBZb3UnbGwgZmluZCB0aGlzIHN0YXRlIGluIHRoZSBwcm9wZXJ0eSBgc3RhdGVgIGFmdGVyIGB0cnlMb2dpbmAgbG9nZ2VkIGluIHRoZSB1c2VyLlxuICAgICAqIEBwYXJhbSBwYXJhbXMgSGFzaCB3aXRoIGFkZGl0aW9uYWwgcGFyYW1ldGVyLiBJZiBpdCBpcyBhIHN0cmluZywgaXQgaXMgdXNlZCBmb3IgdGhlXG4gICAgICogICAgICAgICAgICAgICBwYXJhbWV0ZXIgbG9naW5IaW50IChmb3IgdGhlIHNha2Ugb2YgY29tcGF0aWJpbGl0eSB3aXRoIGZvcm1lciB2ZXJzaW9ucylcbiAgICAgKi9cbiAgICBwdWJsaWMgaW5pdEltcGxpY2l0RmxvdyhcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtczogc3RyaW5nIHwgb2JqZWN0ID0gJydcbiAgICApOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XG4gICAgICAgICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1xuICAgICAgICAgICAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKF8gPT4gdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlc2V0IGN1cnJlbnQgaW1wbGljaXQgZmxvd1xuICAgICAqXG4gICAgICogQGRlc2NyaXB0aW9uIFRoaXMgbWV0aG9kIGFsbG93cyByZXNldHRpbmcgdGhlIGN1cnJlbnQgaW1wbGljdCBmbG93IGluIG9yZGVyIHRvIGJlIGluaXRpYWxpemVkIGFnYWluLlxuICAgICAqL1xuICAgIHB1YmxpYyByZXNldEltcGxpY2l0RmxvdygpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9uczogTG9naW5PcHRpb25zKTogdm9pZCB7XG4gICAgICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xuICAgICAgICBpZiAob3B0aW9ucy5vblRva2VuUmVjZWl2ZWQpIHtcbiAgICAgICAgICAgIGNvbnN0IHRva2VuUGFyYW1zID0ge1xuICAgICAgICAgICAgICAgIGlkQ2xhaW1zOiB0aGF0LmdldElkZW50aXR5Q2xhaW1zKCksXG4gICAgICAgICAgICAgICAgaWRUb2tlbjogdGhhdC5nZXRJZFRva2VuKCksXG4gICAgICAgICAgICAgICAgYWNjZXNzVG9rZW46IHRoYXQuZ2V0QWNjZXNzVG9rZW4oKSxcbiAgICAgICAgICAgICAgICBzdGF0ZTogdGhhdC5zdGF0ZVxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIG9wdGlvbnMub25Ub2tlblJlY2VpdmVkKHRva2VuUGFyYW1zKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBzdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgIGFjY2Vzc1Rva2VuOiBzdHJpbmcsXG4gICAgICAgIHJlZnJlc2hUb2tlbjogc3RyaW5nLFxuICAgICAgICBleHBpcmVzSW46IG51bWJlcixcbiAgICAgICAgZ3JhbnRlZFNjb3BlczogU3RyaW5nLFxuICAgICAgICBjdXN0b21QYXJhbWV0ZXJzPzogYW55XG4gICAgKTogdm9pZCB7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnYWNjZXNzX3Rva2VuJywgYWNjZXNzVG9rZW4pO1xuICAgICAgICBpZiAoZ3JhbnRlZFNjb3Blcykge1xuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdncmFudGVkX3Njb3BlcycsIEpTT04uc3RyaW5naWZ5KGdyYW50ZWRTY29wZXMuc3BsaXQoJysnKSkpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcsICcnICsgRGF0ZS5ub3coKSk7XG4gICAgICAgIGlmIChleHBpcmVzSW4pIHtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXNJbk1pbGxpU2Vjb25kcyA9IGV4cGlyZXNJbiAqIDEwMDA7XG4gICAgICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgY29uc3QgZXhwaXJlc0F0ID0gbm93LmdldFRpbWUoKSArIGV4cGlyZXNJbk1pbGxpU2Vjb25kcztcbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnZXhwaXJlc19hdCcsICcnICsgZXhwaXJlc0F0KTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChyZWZyZXNoVG9rZW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgncmVmcmVzaF90b2tlbicsIHJlZnJlc2hUb2tlbik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGN1c3RvbVBhcmFtZXRlcnMpIHtcbiAgICAgICAgICAgIE9iamVjdC5rZXlzKGN1c3RvbVBhcmFtZXRlcnMpLmZvckVhY2goa2V5ID0+IHtcbiAgICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKGtleSwgY3VzdG9tUGFyYW1ldGVyc1trZXldKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVsZWdhdGVzIHRvIHRyeUxvZ2luSW1wbGljaXRGbG93IGZvciB0aGUgc2FrZSBvZiBjb21wZXRhYmlsaXR5XG4gICAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cbiAgICAgKi9cbiAgICBwdWJsaWMgdHJ5TG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICBpZiAodGhpcy5jb25maWcucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luQ29kZUZsb3cob3B0aW9ucykudGhlbihfID0+IHRydWUpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICB9XG5cblxuXG4gICAgcHJpdmF0ZSBwYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nOiBzdHJpbmcpOiBvYmplY3Qge1xuICAgICAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICAgICAgcmV0dXJuIHt9O1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHF1ZXJ5U3RyaW5nLmNoYXJBdCgwKSA9PT0gJz8nKSB7XG4gICAgICAgICAgICBxdWVyeVN0cmluZyA9IHF1ZXJ5U3RyaW5nLnN1YnN0cigxKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5wYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nKTtcblxuXG4gICAgfVxuXG4gICAgcHVibGljIHRyeUxvZ2luQ29kZUZsb3cob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8dm9pZD4ge1xuICAgICAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcblxuICAgICAgICBjb25zdCBxdWVyeVNvdXJjZSA9IG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50ID9cbiAgICAgICAgICAgIG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50LnN1YnN0cmluZygxKSA6XG4gICAgICAgICAgICB3aW5kb3cubG9jYXRpb24uc2VhcmNoO1xuXG4gICAgICAgIGNvbnN0IHBhcnRzID0gdGhpcy5nZXRDb2RlUGFydHNGcm9tVXJsKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpO1xuXG4gICAgICAgIGNvbnN0IGNvZGUgPSBwYXJ0c1snY29kZSddO1xuICAgICAgICBjb25zdCBzdGF0ZSA9IHBhcnRzWydzdGF0ZSddO1xuXG4gICAgICAgIGlmICghb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgICAgICAgY29uc3QgaHJlZiA9IGxvY2F0aW9uLmhyZWZcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvWyZcXD9dY29kZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9bJlxcP11zY29wZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9bJlxcP11zdGF0ZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9bJlxcP11zZXNzaW9uX3N0YXRlPVteJlxcJF0qLywgJycpO1xuXG4gICAgICAgICAgICBoaXN0b3J5LnJlcGxhY2VTdGF0ZShudWxsLCB3aW5kb3cubmFtZSwgaHJlZik7XG4gICAgICAgIH1cblxuICAgICAgICBsZXQgW25vbmNlSW5TdGF0ZSwgdXNlclN0YXRlXSA9IHRoaXMucGFyc2VTdGF0ZShzdGF0ZSk7XG4gICAgICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XG5cbiAgICAgICAgaWYgKHBhcnRzWydlcnJvciddKSB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdlcnJvciB0cnlpbmcgdG8gbG9naW4nKTtcbiAgICAgICAgICAgIHRoaXMuaGFuZGxlTG9naW5FcnJvcih7fSwgcGFydHMpO1xuICAgICAgICAgICAgY29uc3QgZXJyID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnY29kZV9lcnJvcicsIHt9LCBwYXJ0cyk7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIW5vbmNlSW5TdGF0ZSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMudmFsaWRhdGVOb25jZShub25jZUluU3RhdGUpO1xuICAgICAgICBpZiAoIXN1Y2Nlc3MpIHtcbiAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnaW52YWxpZF9ub25jZV9pbl9zdGF0ZScsIG51bGwpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChjb2RlKSB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgICAgIHRoaXMuZ2V0VG9rZW5Gcm9tQ29kZShjb2RlLCBvcHRpb25zKS50aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgICAgICAgICB9KS5jYXRjaChlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgKiBSZXRyaWV2ZSB0aGUgcmV0dXJuZWQgYXV0aCBjb2RlIGZyb20gdGhlIHJlZGlyZWN0IHVyaSB0aGF0IGhhcyBiZWVuIGNhbGxlZC5cbiAgICAqIElmIHJlcXVpcmVkIGFsc28gY2hlY2sgaGFzaCwgYXMgd2UgY291bGQgdXNlIGhhc2ggbG9jYXRpb24gc3RyYXRlZ3kuXG4gICAgKi9cbiAgICBwcml2YXRlIGdldENvZGVQYXJ0c0Zyb21VcmwocXVlcnlTdHJpbmc6IHN0cmluZyk6IG9iamVjdCB7XG4gICAgICAgIGlmICghcXVlcnlTdHJpbmcgfHwgcXVlcnlTdHJpbmcubGVuZ3RoID09PSAwKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy51cmxIZWxwZXIuZ2V0SGFzaEZyYWdtZW50UGFyYW1zKCk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBub3JtYWxpemUgcXVlcnkgc3RyaW5nXG4gICAgICAgIGlmIChxdWVyeVN0cmluZy5jaGFyQXQoMCkgPT09ICc/Jykge1xuICAgICAgICAgICAgcXVlcnlTdHJpbmcgPSBxdWVyeVN0cmluZy5zdWJzdHIoMSk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy51cmxIZWxwZXIucGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR2V0IHRva2VuIHVzaW5nIGFuIGludGVybWVkaWF0ZSBjb2RlLiBXb3JrcyBmb3IgdGhlIEF1dGhvcml6YXRpb24gQ29kZSBmbG93LlxuICAgICAqL1xuICAgIHByaXZhdGUgZ2V0VG9rZW5Gcm9tQ29kZShjb2RlOiBzdHJpbmcsIG9wdGlvbnM6IExvZ2luT3B0aW9ucyk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXG4gICAgICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ2F1dGhvcml6YXRpb25fY29kZScpXG4gICAgICAgICAgICAuc2V0KCdjb2RlJywgY29kZSlcbiAgICAgICAgICAgIC5zZXQoJ3JlZGlyZWN0X3VyaScsIG9wdGlvbnMuY3VzdG9tUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaSk7XG5cbiAgICAgICAgaWYgKCF0aGlzLmRpc2FibGVQS0NFKSB7XG4gICAgICAgICAgICBjb25zdCBwa2NpVmVyaWZpZXIgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ1BLQ0lfdmVyaWZpZXInKTtcblxuICAgICAgICAgICAgaWYgKCFwa2NpVmVyaWZpZXIpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLndhcm4oJ05vIFBLQ0kgdmVyaWZpZXIgZm91bmQgaW4gb2F1dGggc3RvcmFnZSEnKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY29kZV92ZXJpZmllcicsIHBrY2lWZXJpZmllcik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy5mZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXMpO1xuICAgIH1cblxuICAgIHByaXZhdGUgZmV0Y2hBbmRQcm9jZXNzVG9rZW4ocGFyYW1zOiBIdHRwUGFyYW1zKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlPiB7XG5cbiAgICAgICAgdGhpcy5hc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKHRoaXMudG9rZW5FbmRwb2ludCwgJ3Rva2VuRW5kcG9pbnQnKTtcbiAgICAgICAgbGV0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxuICAgICAgICAgICAgLnNldCgnQ29udGVudC1UeXBlJywgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCcpO1xuXG4gICAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xuICAgICAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KFxuICAgICAgICAgICAgICAgICdBdXRob3JpemF0aW9uJyxcbiAgICAgICAgICAgICAgICAnQmFzaWMgJyArIGhlYWRlcik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuXG4gICAgICAgICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHRoaXMuaHR0cC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSkuc3Vic2NyaWJlKFxuICAgICAgICAgICAgICAgICh0b2tlblJlc3BvbnNlKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3JlZnJlc2ggdG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luLFxuICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5zY29wZSxcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5vaWRjICYmIHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMucHJvY2Vzc0lkVG9rZW4odG9rZW5SZXNwb25zZS5pZF90b2tlbiwgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4pLlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLmNhdGNoKHJlYXNvbiA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InLCByZWFzb24pKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgdmFsaWRhdGluZyB0b2tlbnMnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihyZWFzb24pO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChyZWFzb24pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJykpO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAoZXJyKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGdldHRpbmcgdG9rZW4nLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKSk7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGFyZSB0b2tlbnMgaW4gdGhlIGhhc2ggZnJhZ21lbnRcbiAgICAgKiBhcyBhIHJlc3VsdCBvZiB0aGUgaW1wbGljaXQgZmxvdy4gVGhlc2UgdG9rZW5zIGFyZVxuICAgICAqIHBhcnNlZCwgdmFsaWRhdGVkIGFuZCB1c2VkIHRvIHNpZ24gdGhlIHVzZXIgaW4gdG8gdGhlXG4gICAgICogY3VycmVudCBjbGllbnQuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyBPcHRpb25hbCBvcHRpb25zLlxuICAgICAqL1xuICAgIHB1YmxpYyB0cnlMb2dpbkltcGxpY2l0RmxvdyhvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuXG4gICAgICAgIGxldCBwYXJ0czogb2JqZWN0O1xuXG4gICAgICAgIGlmIChvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCkge1xuICAgICAgICAgICAgcGFydHMgPSB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMob3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnQpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcGFydHMgPSB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuZGVidWcoJ3BhcnNlZCB1cmwnLCBwYXJ0cyk7XG5cbiAgICAgICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgICAgICBsZXQgW25vbmNlSW5TdGF0ZSwgdXNlclN0YXRlXSA9IHRoaXMucGFyc2VTdGF0ZShzdGF0ZSk7XG4gICAgICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XG5cbiAgICAgICAgaWYgKHBhcnRzWydlcnJvciddKSB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdlcnJvciB0cnlpbmcgdG8gbG9naW4nKTtcbiAgICAgICAgICAgIHRoaXMuaGFuZGxlTG9naW5FcnJvcihvcHRpb25zLCBwYXJ0cyk7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIHt9LCBwYXJ0cyk7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBhY2Nlc3NUb2tlbiA9IHBhcnRzWydhY2Nlc3NfdG9rZW4nXTtcbiAgICAgICAgY29uc3QgaWRUb2tlbiA9IHBhcnRzWydpZF90b2tlbiddO1xuICAgICAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSBwYXJ0c1snc2Vzc2lvbl9zdGF0ZSddO1xuICAgICAgICBjb25zdCBncmFudGVkU2NvcGVzID0gcGFydHNbJ3Njb3BlJ107XG5cbiAgICAgICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICAgICAgICAgICAgJ0VpdGhlciByZXF1ZXN0QWNjZXNzVG9rZW4gb3Igb2lkYyAob3IgYm90aCkgbXVzdCBiZSB0cnVlLidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIWFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIW9wdGlvbnMuZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2sgJiYgIXN0YXRlKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5vaWRjICYmICFpZFRva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFzZXNzaW9uU3RhdGUpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb24gY2hlY2tzIChTZXNzaW9uIFN0YXR1cyBDaGFuZ2UgTm90aWZpY2F0aW9uKSAnICtcbiAgICAgICAgICAgICAgICAnd2VyZSBhY3RpdmF0ZWQgaW4gdGhlIGNvbmZpZ3VyYXRpb24gYnV0IHRoZSBpZF90b2tlbiAnICtcbiAgICAgICAgICAgICAgICAnZG9lcyBub3QgY29udGFpbiBhIHNlc3Npb25fc3RhdGUgY2xhaW0nXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFvcHRpb25zLmRpc2FibGVPQXV0aDJTdGF0ZUNoZWNrKSB7XG4gICAgICAgICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XG5cbiAgICAgICAgICAgIGlmICghc3VjY2Vzcykge1xuICAgICAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnaW52YWxpZF9ub25jZV9pbl9zdGF0ZScsIG51bGwpO1xuICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICAgICAgICAgICAgICBhY2Nlc3NUb2tlbixcbiAgICAgICAgICAgICAgICBudWxsLFxuICAgICAgICAgICAgICAgIHBhcnRzWydleHBpcmVzX2luJ10gfHwgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcbiAgICAgICAgICAgICAgICBncmFudGVkU2NvcGVzXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLm9pZGMpIHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICAgICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodHJ1ZSk7XG5cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3NJZFRva2VuKGlkVG9rZW4sIGFjY2Vzc1Rva2VuKVxuICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICBpZiAob3B0aW9ucy52YWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gb3B0aW9uc1xuICAgICAgICAgICAgICAgICAgICAgICAgLnZhbGlkYXRpb25IYW5kbGVyKHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhY2Nlc3NUb2tlbjogYWNjZXNzVG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWRDbGFpbXM6IHJlc3VsdC5pZFRva2VuQ2xhaW1zLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkVG9rZW46IHJlc3VsdC5pZFRva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXRlOiBzdGF0ZVxuICAgICAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgICAgIC50aGVuKF8gPT4gcmVzdWx0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XG4gICAgICAgICAgICAgICAgdGhpcy5zdG9yZVNlc3Npb25TdGF0ZShzZXNzaW9uU3RhdGUpO1xuICAgICAgICAgICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4gJiYgIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgICAgICAgICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgIHRoaXMuY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnMpO1xuICAgICAgICAgICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAuY2F0Y2gocmVhc29uID0+IHtcbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fdmFsaWRhdGlvbl9lcnJvcicsIHJlYXNvbilcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKHJlYXNvbik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlYXNvbik7XG4gICAgICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcml2YXRlIHBhcnNlU3RhdGUoc3RhdGU6IHN0cmluZyk6IFtzdHJpbmcsIHN0cmluZ10ge1xuICAgICAgICBsZXQgbm9uY2UgPSBzdGF0ZTtcbiAgICAgICAgbGV0IHVzZXJTdGF0ZSA9ICcnO1xuXG4gICAgICAgIGlmIChzdGF0ZSkge1xuICAgICAgICAgICAgY29uc3QgaWR4ID0gc3RhdGUuaW5kZXhPZih0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yKTtcbiAgICAgICAgICAgIGlmIChpZHggPiAtMSkge1xuICAgICAgICAgICAgICAgIG5vbmNlID0gc3RhdGUuc3Vic3RyKDAsIGlkeCk7XG4gICAgICAgICAgICAgICAgdXNlclN0YXRlID0gc3RhdGUuc3Vic3RyKGlkeCArIHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IubGVuZ3RoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gW25vbmNlLCB1c2VyU3RhdGVdO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZU5vbmNlKFxuICAgICAgICBub25jZUluU3RhdGU6IHN0cmluZ1xuICAgICk6IGJvb2xlYW4ge1xuICAgICAgICBjb25zdCBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xuICAgICAgICBpZiAoc2F2ZWROb25jZSAhPT0gbm9uY2VJblN0YXRlKSB7XG5cbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdWYWxpZGF0aW5nIGFjY2Vzc190b2tlbiBmYWlsZWQsIHdyb25nIHN0YXRlL25vbmNlLic7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKGVyciwgc2F2ZWROb25jZSwgbm9uY2VJblN0YXRlKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcmVJZFRva2VuKGlkVG9rZW46IFBhcnNlZElkVG9rZW4pOiB2b2lkIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbicsIGlkVG9rZW4uaWRUb2tlbik7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIGlkVG9rZW4uaWRUb2tlbkNsYWltc0pzb24pO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnLCAnJyArIGlkVG9rZW4uaWRUb2tlbkV4cGlyZXNBdCk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0JywgJycgKyBEYXRlLm5vdygpKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlOiBzdHJpbmcpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdzZXNzaW9uX3N0YXRlJywgc2Vzc2lvblN0YXRlKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgZ2V0U2Vzc2lvblN0YXRlKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3Nlc3Npb25fc3RhdGUnKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaGFuZGxlTG9naW5FcnJvcihvcHRpb25zOiBMb2dpbk9wdGlvbnMsIHBhcnRzOiBvYmplY3QpOiB2b2lkIHtcbiAgICAgICAgaWYgKG9wdGlvbnMub25Mb2dpbkVycm9yKSB7XG4gICAgICAgICAgICBvcHRpb25zLm9uTG9naW5FcnJvcihwYXJ0cyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQGlnbm9yZVxuICAgICAqL1xuICAgIHB1YmxpYyBwcm9jZXNzSWRUb2tlbihcbiAgICAgICAgaWRUb2tlbjogc3RyaW5nLFxuICAgICAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxuICAgICAgICBza2lwTm9uY2VDaGVjayA9IGZhbHNlXG4gICAgKTogUHJvbWlzZTxQYXJzZWRJZFRva2VuPiB7XG4gICAgICAgIGNvbnN0IHRva2VuUGFydHMgPSBpZFRva2VuLnNwbGl0KCcuJyk7XG4gICAgICAgIGNvbnN0IGhlYWRlckJhc2U2NCA9IHRoaXMucGFkQmFzZTY0KHRva2VuUGFydHNbMF0pO1xuICAgICAgICBjb25zdCBoZWFkZXJKc29uID0gYjY0RGVjb2RlVW5pY29kZShoZWFkZXJCYXNlNjQpO1xuICAgICAgICBjb25zdCBoZWFkZXIgPSBKU09OLnBhcnNlKGhlYWRlckpzb24pO1xuICAgICAgICBjb25zdCBjbGFpbXNCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzFdKTtcbiAgICAgICAgY29uc3QgY2xhaW1zSnNvbiA9IGI2NERlY29kZVVuaWNvZGUoY2xhaW1zQmFzZTY0KTtcbiAgICAgICAgY29uc3QgY2xhaW1zID0gSlNPTi5wYXJzZShjbGFpbXNKc29uKTtcbiAgICAgICAgY29uc3Qgc2F2ZWROb25jZSA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcblxuICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShjbGFpbXMuYXVkKSkge1xuICAgICAgICAgICAgaWYgKGNsYWltcy5hdWQuZXZlcnkodiA9PiB2ICE9PSB0aGlzLmNsaWVudElkKSkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQuam9pbignLCcpO1xuICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmIChjbGFpbXMuYXVkICE9PSB0aGlzLmNsaWVudElkKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZDtcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWNsYWltcy5zdWIpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdObyBzdWIgY2xhaW0gaW4gaWRfdG9rZW4nO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICAvKiBGb3Igbm93LCB3ZSBvbmx5IGNoZWNrIHdoZXRoZXIgdGhlIHN1YiBhZ2FpbnN0XG4gICAgICAgICAqIHNpbGVudFJlZnJlc2hTdWJqZWN0IHdoZW4gc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgb25cbiAgICAgICAgICogV2Ugd2lsbCByZWNvbnNpZGVyIGluIGEgbGF0ZXIgdmVyc2lvbiB0byBkbyB0aGlzXG4gICAgICAgICAqIGluIGV2ZXJ5IG90aGVyIGNhc2UgdG9vLlxuICAgICAgICAgKi9cbiAgICAgICAgaWYgKFxuICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJlxuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAmJlxuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAhPT0gY2xhaW1zWydzdWInXVxuICAgICAgICApIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9XG4gICAgICAgICAgICAgICAgJ0FmdGVyIHJlZnJlc2hpbmcsIHdlIGdvdCBhbiBpZF90b2tlbiBmb3IgYW5vdGhlciB1c2VyIChzdWIpLiAnICtcbiAgICAgICAgICAgICAgICBgRXhwZWN0ZWQgc3ViOiAke3RoaXMuc2lsZW50UmVmcmVzaFN1YmplY3R9LCByZWNlaXZlZCBzdWI6ICR7XG4gICAgICAgICAgICAgICAgY2xhaW1zWydzdWInXVxuICAgICAgICAgICAgICAgIH1gO1xuXG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghY2xhaW1zLmlhdCkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ05vIGlhdCBjbGFpbSBpbiBpZF90b2tlbic7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgY2xhaW1zLmlzcyAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBpc3N1ZXI6ICcgKyBjbGFpbXMuaXNzO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXNraXBOb25jZUNoZWNrICYmIGNsYWltcy5ub25jZSAhPT0gc2F2ZWROb25jZSkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIG5vbmNlOiAnICsgY2xhaW1zLm5vbmNlO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cbiAgICAgICAgLy8gYXRfaGFzaCBpcyBub3QgYXBwbGljYWJsZSB0byBhdXRob3JpemF0aW9uIGNvZGUgZmxvd1xuICAgICAgICAvLyBhZGRyZXNzaW5nIGh0dHBzOi8vZ2l0aHViLmNvbS9tYW5mcmVkc3RleWVyL2FuZ3VsYXItb2F1dGgyLW9pZGMvaXNzdWVzLzY2MVxuICAgICAgICAvLyBpLmUuIEJhc2VkIG9uIHNwZWMgdGhlIGF0X2hhc2ggY2hlY2sgaXMgb25seSB0cnVlIGZvciBpbXBsaWNpdCBjb2RlIGZsb3cgb24gUGluZyBGZWRlcmF0ZVxuICAgICAgICAvLyBodHRwczovL3d3dy5waW5naWRlbnRpdHkuY29tL2RldmVsb3Blci9lbi9yZXNvdXJjZXMvb3BlbmlkLWNvbm5lY3QtZGV2ZWxvcGVycy1ndWlkZS5odG1sXG4gICAgICAgIGlmICh0aGlzLmhhc093blByb3BlcnR5KCdyZXNwb25zZVR5cGUnKSAmJiB0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICAgICAgICB0aGlzLmRpc2FibGVBdEhhc2hDaGVjayA9IHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKFxuICAgICAgICAgICAgIXRoaXMuZGlzYWJsZUF0SGFzaENoZWNrICYmXG4gICAgICAgICAgICB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJlxuICAgICAgICAgICAgIWNsYWltc1snYXRfaGFzaCddXG4gICAgICAgICkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ0FuIGF0X2hhc2ggaXMgbmVlZGVkISc7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIGNvbnN0IGlzc3VlZEF0TVNlYyA9IGNsYWltcy5pYXQgKiAxMDAwO1xuICAgICAgICBjb25zdCBleHBpcmVzQXRNU2VjID0gY2xhaW1zLmV4cCAqIDEwMDA7XG4gICAgICAgIGNvbnN0IGNsb2NrU2tld0luTVNlYyA9ICh0aGlzLmNsb2NrU2tld0luU2VjIHx8IDYwMCkgKiAxMDAwO1xuXG4gICAgICAgIGlmIChcbiAgICAgICAgICAgIGlzc3VlZEF0TVNlYyAtIGNsb2NrU2tld0luTVNlYyA+PSBub3cgfHxcbiAgICAgICAgICAgIGV4cGlyZXNBdE1TZWMgKyBjbG9ja1NrZXdJbk1TZWMgPD0gbm93XG4gICAgICAgICkge1xuICAgICAgICAgICAgY29uc3QgZXJyID0gJ1Rva2VuIGhhcyBleHBpcmVkJztcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyKTtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3Ioe1xuICAgICAgICAgICAgICAgIG5vdzogbm93LFxuICAgICAgICAgICAgICAgIGlzc3VlZEF0TVNlYzogaXNzdWVkQXRNU2VjLFxuICAgICAgICAgICAgICAgIGV4cGlyZXNBdE1TZWM6IGV4cGlyZXNBdE1TZWNcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zID0ge1xuICAgICAgICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxuICAgICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgICAgICAgIGp3a3M6IHRoaXMuandrcyxcbiAgICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcbiAgICAgICAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcbiAgICAgICAgICAgIGxvYWRLZXlzOiAoKSA9PiB0aGlzLmxvYWRKd2tzKClcbiAgICAgICAgfTtcblxuICAgICAgICBpZiAodGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2spIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmNoZWNrU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oXyA9PiB7XG4gICAgICAgICAgICAgICAgY29uc3QgcmVzdWx0OiBQYXJzZWRJZFRva2VuID0ge1xuICAgICAgICAgICAgICAgICAgICBpZFRva2VuOiBpZFRva2VuLFxuICAgICAgICAgICAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXG4gICAgICAgICAgICAgICAgICAgIGlkVG9rZW5DbGFpbXNKc29uOiBjbGFpbXNKc29uLFxuICAgICAgICAgICAgICAgICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXG4gICAgICAgICAgICAgICAgICAgIGlkVG9rZW5IZWFkZXJKc29uOiBoZWFkZXJKc29uLFxuICAgICAgICAgICAgICAgICAgICBpZFRva2VuRXhwaXJlc0F0OiBleHBpcmVzQXRNU2VjXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy5jaGVja0F0SGFzaCh2YWxpZGF0aW9uUGFyYW1zKVxuICAgICAgICAgICAgLnRoZW4oYXRIYXNoVmFsaWQgPT4ge1xuICAgICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICAgICAgIXRoaXMuZGlzYWJsZUF0SGFzaENoZWNrICYmXG4gICAgICAgICAgICAgICAgICAgIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmXG4gICAgICAgICAgICAgICAgICAgICFhdEhhc2hWYWxpZFxuICAgICAgICAgICAgICAgICkge1xuICAgICAgICAgICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXRfaGFzaCc7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMuY2hlY2tTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtcykudGhlbihfID0+IHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgYXRIYXNoQ2hlY2tFbmFibGVkID0gIXRoaXMuZGlzYWJsZUF0SGFzaENoZWNrO1xuICAgICAgICAgICAgICAgICAgICBjb25zdCByZXN1bHQ6IFBhcnNlZElkVG9rZW4gPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZFRva2VuOiBpZFRva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgaWRUb2tlbkNsYWltczogY2xhaW1zLFxuICAgICAgICAgICAgICAgICAgICAgICAgaWRUb2tlbkNsYWltc0pzb246IGNsYWltc0pzb24sXG4gICAgICAgICAgICAgICAgICAgICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXG4gICAgICAgICAgICAgICAgICAgICAgICBpZFRva2VuSGVhZGVySnNvbjogaGVhZGVySnNvbixcbiAgICAgICAgICAgICAgICAgICAgICAgIGlkVG9rZW5FeHBpcmVzQXQ6IGV4cGlyZXNBdE1TZWNcbiAgICAgICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGF0SGFzaENoZWNrRW5hYmxlZCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMuY2hlY2tBdEhhc2godmFsaWRhdGlvblBhcmFtcykudGhlbihhdEhhc2hWYWxpZCA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFhdEhhc2hWYWxpZCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXRfaGFzaCc7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIHJlY2VpdmVkIGNsYWltcyBhYm91dCB0aGUgdXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0SWRlbnRpdHlDbGFpbXMoKTogb2JqZWN0IHtcbiAgICAgICAgY29uc3QgY2xhaW1zID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgICAgIGlmICghY2xhaW1zKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gSlNPTi5wYXJzZShjbGFpbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGdyYW50ZWQgc2NvcGVzIGZyb20gdGhlIHNlcnZlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0R3JhbnRlZFNjb3BlcygpOiBvYmplY3Qge1xuICAgICAgICBjb25zdCBzY29wZXMgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2dyYW50ZWRfc2NvcGVzJyk7XG4gICAgICAgIGlmICghc2NvcGVzKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gSlNPTi5wYXJzZShzY29wZXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGN1cnJlbnQgaWRfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGdldElkVG9rZW4oKTogc3RyaW5nIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2VcbiAgICAgICAgICAgID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbicpXG4gICAgICAgICAgICA6IG51bGw7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHBhZEJhc2U2NChiYXNlNjRkYXRhKTogc3RyaW5nIHtcbiAgICAgICAgd2hpbGUgKGJhc2U2NGRhdGEubGVuZ3RoICUgNCAhPT0gMCkge1xuICAgICAgICAgICAgYmFzZTY0ZGF0YSArPSAnPSc7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGJhc2U2NGRhdGE7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgY3VycmVudCBhY2Nlc3NfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGdldEFjY2Vzc1Rva2VuKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlXG4gICAgICAgICAgICA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnYWNjZXNzX3Rva2VuJylcbiAgICAgICAgICAgIDogbnVsbDtcbiAgICB9XG5cbiAgICBwdWJsaWMgZ2V0UmVmcmVzaFRva2VuKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlXG4gICAgICAgICAgICA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgncmVmcmVzaF90b2tlbicpXG4gICAgICAgICAgICA6IG51bGw7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgZXhwaXJhdGlvbiBkYXRlIG9mIHRoZSBhY2Nlc3NfdG9rZW5cbiAgICAgKiBhcyBtaWxsaXNlY29uZHMgc2luY2UgMTk3MC5cbiAgICAgKi9cbiAgICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XG4gICAgICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0JykpIHtcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSwgMTApO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBnZXRBY2Nlc3NUb2tlblN0b3JlZEF0KCk6IG51bWJlciB7XG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKSwgMTApO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBnZXRJZFRva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcbiAgICAgICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBleHBpcmF0aW9uIGRhdGUgb2YgdGhlIGlkX3Rva2VuXG4gICAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXG4gICAgICovXG4gICAgcHVibGljIGdldElkVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XG4gICAgICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JykpIHtcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpLCAxMCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2hlY2tlcywgd2hldGhlciB0aGVyZSBpcyBhIHZhbGlkIGFjY2Vzc190b2tlbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgaGFzVmFsaWRBY2Nlc3NUb2tlbigpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKHRoaXMuZ2V0QWNjZXNzVG9rZW4oKSkge1xuICAgICAgICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0Jyk7XG4gICAgICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgaWRfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGhhc1ZhbGlkSWRUb2tlbigpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKHRoaXMuZ2V0SWRUb2tlbigpKSB7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcbiAgICAgICAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICBpZiAoZXhwaXJlc0F0ICYmIHBhcnNlSW50KGV4cGlyZXNBdCwgMTApIDwgbm93LmdldFRpbWUoKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgYXV0aC1oZWFkZXIgdGhhdCBjYW4gYmUgdXNlZFxuICAgICAqIHRvIHRyYW5zbWl0IHRoZSBhY2Nlc3NfdG9rZW4gdG8gYSBzZXJ2aWNlXG4gICAgICovXG4gICAgcHVibGljIGF1dGhvcml6YXRpb25IZWFkZXIoKTogc3RyaW5nIHtcbiAgICAgICAgcmV0dXJuICdCZWFyZXIgJyArIHRoaXMuZ2V0QWNjZXNzVG9rZW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmVzIGFsbCB0b2tlbnMgYW5kIGxvZ3MgdGhlIHVzZXIgb3V0LlxuICAgICAqIElmIGEgbG9nb3V0IHVybCBpcyBjb25maWd1cmVkLCB0aGUgdXNlciBpc1xuICAgICAqIHJlZGlyZWN0ZWQgdG8gaXQuXG4gICAgICogQHBhcmFtIG5vUmVkaXJlY3RUb0xvZ291dFVybFxuICAgICAqL1xuICAgIHB1YmxpYyBsb2dPdXQobm9SZWRpcmVjdFRvTG9nb3V0VXJsID0gZmFsc2UpOiB2b2lkIHtcbiAgICAgICAgY29uc3QgaWRfdG9rZW4gPSB0aGlzLmdldElkVG9rZW4oKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW4nKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbicpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3JlZnJlc2hfdG9rZW4nKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdub25jZScpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2V4cGlyZXNfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdncmFudGVkX3Njb3BlcycpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3Nlc3Npb25fc3RhdGUnKTtcblxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gbnVsbDtcblxuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ2xvZ291dCcpKTtcblxuICAgICAgICBpZiAoIXRoaXMubG9nb3V0VXJsKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgaWYgKG5vUmVkaXJlY3RUb0xvZ291dFVybCkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFpZF90b2tlbiAmJiAhdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCBsb2dvdXRVcmw6IHN0cmluZztcblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ291dFVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAnbG9nb3V0VXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IFxcJ3JlcXVpcmVIdHRwc1xcJyBtdXN0IGJlIHNldCB0byBcXCdmYWxzZVxcJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBGb3IgYmFja3dhcmQgY29tcGF0aWJpbGl0eVxuICAgICAgICBpZiAodGhpcy5sb2dvdXRVcmwuaW5kZXhPZigne3snKSA+IC0xKSB7XG4gICAgICAgICAgICBsb2dvdXRVcmwgPSB0aGlzLmxvZ291dFVybFxuICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9cXHtcXHtpZF90b2tlblxcfVxcfS8sIGlkX3Rva2VuKVxuICAgICAgICAgICAgICAgIC5yZXBsYWNlKC9cXHtcXHtjbGllbnRfaWRcXH1cXH0vLCB0aGlzLmNsaWVudElkKTtcbiAgICAgICAgfSBlbHNlIHtcblxuICAgICAgICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKCk7XG5cbiAgICAgICAgICAgIGlmIChpZF90b2tlbikge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2lkX3Rva2VuX2hpbnQnLCBpZF90b2tlbik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGNvbnN0IHBvc3RMb2dvdXRVcmwgPSB0aGlzLnBvc3RMb2dvdXRSZWRpcmVjdFVyaSB8fCB0aGlzLnJlZGlyZWN0VXJpO1xuICAgICAgICAgICAgaWYgKHBvc3RMb2dvdXRVcmwpIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdwb3N0X2xvZ291dF9yZWRpcmVjdF91cmknLCBwb3N0TG9nb3V0VXJsKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgbG9nb3V0VXJsID1cbiAgICAgICAgICAgICAgICB0aGlzLmxvZ291dFVybCArXG4gICAgICAgICAgICAgICAgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJz8nKSA+IC0xID8gJyYnIDogJz8nKSArXG4gICAgICAgICAgICAgICAgcGFyYW1zLnRvU3RyaW5nKCk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5jb25maWcub3BlblVyaShsb2dvdXRVcmwpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEBpZ25vcmVcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlQW5kU2F2ZU5vbmNlKCk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xuICAgICAgICByZXR1cm4gdGhpcy5jcmVhdGVOb25jZSgpLnRoZW4oZnVuY3Rpb24gKG5vbmNlOiBhbnkpIHtcbiAgICAgICAgICAgIHRoYXQuX3N0b3JhZ2Uuc2V0SXRlbSgnbm9uY2UnLCBub25jZSk7XG4gICAgICAgICAgICByZXR1cm4gbm9uY2U7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEBpZ25vcmVcbiAgICAgKi9cbiAgICBwdWJsaWMgbmdPbkRlc3Ryb3koKTogdm9pZCB7XG4gICAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcblxuICAgICAgICB0aGlzLnJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XG4gICAgICAgIGNvbnN0IHNpbGVudFJlZnJlc2hGcmFtZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWUpO1xuICAgICAgICBpZiAoc2lsZW50UmVmcmVzaEZyYW1lKSB7XG4gICAgICAgICAgICBzaWxlbnRSZWZyZXNoRnJhbWUucmVtb3ZlKCk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgICAgICB0aGlzLnJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcbiAgICAgICAgY29uc3Qgc2Vzc2lvbkNoZWNrRnJhbWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWUpO1xuICAgICAgICBpZiAoc2Vzc2lvbkNoZWNrRnJhbWUpIHtcbiAgICAgICAgICAgIHNlc3Npb25DaGVja0ZyYW1lLnJlbW92ZSgpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNyZWF0ZU5vbmNlKCk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4ge1xuICAgICAgICAgICAgaWYgKHRoaXMucm5nVXJsKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICAgICAnY3JlYXRlTm9uY2Ugd2l0aCBybmctd2ViLWFwaSBoYXMgbm90IGJlZW4gaW1wbGVtZW50ZWQgc28gZmFyJ1xuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8qXG4gICAgICAgICAgICAgKiBUaGlzIGFscGhhYmV0IGlzIGZyb206XG4gICAgICAgICAgICAgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzYzNiNzZWN0aW9uLTQuMVxuICAgICAgICAgICAgICpcbiAgICAgICAgICAgICAqIFtBLVpdIC8gW2Etel0gLyBbMC05XSAvIFwiLVwiIC8gXCIuXCIgLyBcIl9cIiAvIFwiflwiXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIGNvbnN0IHVucmVzZXJ2ZWQgPSAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODktLl9+JztcbiAgICAgICAgICAgIGxldCBzaXplID0gNDU7XG4gICAgICAgICAgICBsZXQgaWQgPSAnJztcblxuICAgICAgICAgICAgY29uc3QgY3J5cHRvID0gdHlwZW9mIHNlbGYgPT09ICd1bmRlZmluZWQnID8gbnVsbCA6IChzZWxmLmNyeXB0byB8fCBzZWxmWydtc0NyeXB0byddKTtcbiAgICAgICAgICAgIGlmIChjcnlwdG8pIHtcbiAgICAgICAgICAgICAgICBsZXQgYnl0ZXMgPSBuZXcgVWludDhBcnJheShzaXplKTtcbiAgICAgICAgICAgICAgICBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKGJ5dGVzKTtcbiAgICAgICAgICAgICAgICBieXRlcyA9IGJ5dGVzLm1hcCh4ID0+IHVucmVzZXJ2ZWQuY2hhckNvZGVBdCh4ICUgdW5yZXNlcnZlZC5sZW5ndGgpKTtcbiAgICAgICAgICAgICAgICBpZCA9IFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgYnl0ZXMpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICB3aGlsZSAoMCA8IHNpemUtLSkge1xuICAgICAgICAgICAgICAgICAgICBpZCArPSB1bnJlc2VydmVkW01hdGgucmFuZG9tKCkgKiB1bnJlc2VydmVkLmxlbmd0aCB8IDBdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmVzb2x2ZShiYXNlNjRVcmxFbmNvZGUoaWQpKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGFzeW5jIGNoZWNrQXRIYXNoKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgYXRfaGFzaC4nXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZUF0SGFzaChwYXJhbXMpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjaGVja1NpZ25hdHVyZShwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT4ge1xuICAgICAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgc2lnbmF0dXJlLidcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKG51bGwpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIudmFsaWRhdGVTaWduYXR1cmUocGFyYW1zKTtcbiAgICB9XG5cblxuICAgIC8qKlxuICAgICAqIFN0YXJ0IHRoZSBpbXBsaWNpdCBmbG93IG9yIHRoZSBjb2RlIGZsb3csXG4gICAgICogZGVwZW5kaW5nIG9uIHlvdXIgY29uZmlndXJhdGlvbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgaW5pdExvZ2luRmxvdyhcbiAgICAgICAgYWRkaXRpb25hbFN0YXRlID0gJycsXG4gICAgICAgIHBhcmFtcyA9IHt9XG4gICAgKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5pbml0Q29kZUZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuaW5pdEltcGxpY2l0RmxvdyhhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTdGFydHMgdGhlIGF1dGhvcml6YXRpb24gY29kZSBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xuICAgICAqIHRoZSBhdXRoIHNlcnZlcnMgbG9naW4gdXJsLlxuICAgICAqL1xuICAgIHB1YmxpYyBpbml0Q29kZUZsb3coXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXMgPSB7fVxuICAgICk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5sb2dpblVybCAhPT0gJycpIHtcbiAgICAgICAgICAgIHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5ldmVudHMucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByaXZhdGUgaW5pdENvZGVGbG93SW50ZXJuYWwoXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXMgPSB7fVxuICAgICk6IHZvaWQge1xuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ2xvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IFxcJ3JlcXVpcmVIdHRwc1xcJyBtdXN0IGJlIHNldCB0byBcXCdmYWxzZVxcJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLicpO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5jcmVhdGVMb2dpblVybChhZGRpdGlvbmFsU3RhdGUsICcnLCBudWxsLCBmYWxzZSwgcGFyYW1zKVxuICAgICAgICAgICAgLnRoZW4odGhpcy5jb25maWcub3BlblVyaSlcbiAgICAgICAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgaW4gaW5pdEF1dGhvcml6YXRpb25Db2RlRmxvdycpO1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICAgICAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGFzeW5jIGNyZWF0ZUNoYWxsYW5nZVZlcmlmaWVyUGFpckZvclBLQ0UoKTogUHJvbWlzZTxbc3RyaW5nLCBzdHJpbmddPiB7XG5cbiAgICAgICAgaWYgKCF0aGlzLmNyeXB0bykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdQS0NJIHN1cHBvcnQgZm9yIGNvZGUgZmxvdyBuZWVkcyBhIENyeXB0b0hhbmRlci4gRGlkIHlvdSBpbXBvcnQgdGhlIE9BdXRoTW9kdWxlIHVzaW5nIGZvclJvb3QoKSA/Jyk7XG4gICAgICAgIH1cblxuXG4gICAgICAgIGNvbnN0IHZlcmlmaWVyID0gYXdhaXQgdGhpcy5jcmVhdGVOb25jZSgpO1xuICAgICAgICBjb25zdCBjaGFsbGVuZ2VSYXcgPSBhd2FpdCB0aGlzLmNyeXB0by5jYWxjSGFzaCh2ZXJpZmllciwgJ3NoYS0yNTYnKTtcbiAgICAgICAgY29uc3QgY2hhbGxhbmdlID0gYmFzZTY0VXJsRW5jb2RlKGNoYWxsZW5nZVJhdyk7XG5cbiAgICAgICAgcmV0dXJuIFtjaGFsbGFuZ2UsIHZlcmlmaWVyXTtcbiAgICB9XG5cbiAgICBwcml2YXRlIGV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyh0b2tlblJlc3BvbnNlOiBUb2tlblJlc3BvbnNlKTogYW55IHtcbiAgICAgIGlmICghdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgcmV0dXJuIHt9O1xuICAgICAgfVxuICAgICAgbGV0IGZvdW5kUGFyYW1ldGVyczogYW55ID0ge307XG4gICAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMuZm9yRWFjaChyZWNvZ25pemVkUGFyYW1ldGVyID0+IHtcbiAgICAgICAgICBpZiAodG9rZW5SZXNwb25zZVtyZWNvZ25pemVkUGFyYW1ldGVyXSkge1xuICAgICAgICAgICAgZm91bmRQYXJhbWV0ZXJzW3JlY29nbml6ZWRQYXJhbWV0ZXJdID0gdG9rZW5SZXNwb25zZVtyZWNvZ25pemVkUGFyYW1ldGVyXTtcbiAgICAgICAgICB9XG4gICAgICB9KTtcbiAgICAgIHJldHVybiBmb3VuZFBhcmFtZXRlcnM7XG4gICAgfVxufVxuIl19