import { __awaiter, __decorate, __metadata, __param } from "tslib";
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
let OAuthService = class OAuthService extends AuthConfig {
    constructor(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto) {
        super();
        this.ngZone = ngZone;
        this.http = http;
        this.config = config;
        this.urlHelper = urlHelper;
        this.logger = logger;
        this.crypto = crypto;
        /**
         * @internal
         * Deprecated:  use property events instead
         */
        this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        this.state = '';
        this.eventsSubject = new Subject();
        this.discoveryDocumentLoadedSubject = new Subject();
        this.grantTypesSupported = [];
        this.inImplicitFlow = false;
        this.debug('angular-oauth2-oidc v8-beta');
        this.discoveryDocumentLoaded$ = this.discoveryDocumentLoadedSubject.asObservable();
        this.events = this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            this.configure(config);
        }
        try {
            if (storage) {
                this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).'
                + 'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        this.setupRefreshTimer();
    }
    /**
     * Use this method to configure the service
     * @param config the configuration
     */
    configure(config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign({}, new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    }
    configChanged() {
        this.setupRefreshTimer();
    }
    restartSessionChecksIfStillLoggedIn() {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    }
    restartRefreshTimerIfStillLoggedIn() {
        this.setupExpirationTimers();
    }
    setupSessionCheck() {
        this.events.pipe(filter(e => e.type === 'token_received')).subscribe(e => {
            this.initSessionCheck();
        });
    }
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param params Additional parameter to pass
     * @param listenTo Setup automatic refresh of a specific token type
     */
    setupAutomaticSilentRefresh(params = {}, listenTo, noPrompt = true) {
        let shouldRunSilentRefresh = true;
        this.events.pipe(tap((e) => {
            if (e.type === 'token_received') {
                shouldRunSilentRefresh = true;
            }
            else if (e.type === 'logout') {
                shouldRunSilentRefresh = false;
            }
        }), filter(e => e.type === 'token_expires'), debounceTime(1000)).subscribe(e => {
            const event = e;
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) && shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                this.refreshInternal(params, noPrompt).catch(_ => {
                    this.debug('Automatic silent refresh did not work');
                });
            }
        });
        this.restartRefreshTimerIfStillLoggedIn();
    }
    refreshInternal(params, noPrompt) {
        if (!this.silentRefreshRedirectUri && this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    loadDiscoveryDocumentAndTryLogin(options = null) {
        return this.loadDiscoveryDocument().then(doc => {
            return this.tryLogin(options);
        });
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initLoginFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    loadDiscoveryDocumentAndLogin(options = null) {
        if (!options) {
            options = { state: '' };
        }
        return this.loadDiscoveryDocumentAndTryLogin(options).then(_ => {
            if (!this.hasValidIdToken() || !this.hasValidAccessToken()) {
                if (this.responseType === 'code') {
                    this.initCodeFlow();
                }
                else {
                    this.initImplicitFlow();
                }
                return false;
            }
            else {
                return true;
            }
        });
    }
    debug(...args) {
        if (this.showDebugInformation) {
            this.logger.debug.apply(this.logger, args);
        }
    }
    validateUrlFromDiscoveryDocument(url) {
        const errors = [];
        const httpsCheck = this.validateUrlForHttps(url);
        const issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    }
    validateUrlForHttps(url) {
        if (!url) {
            return true;
        }
        const lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    }
    assertUrlNotNullAndCorrectProtocol(url, description) {
        if (!url) {
            throw new Error(`'${description}' should not be null`);
        }
        if (!this.validateUrlForHttps(url)) {
            throw new Error(`'${description}' must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).`);
        }
    }
    validateUrlAgainstIssuer(url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    }
    setupRefreshTimer() {
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
        this.tokenReceivedSubscription = this.events.pipe(filter(e => e.type === 'token_received')).subscribe(_ => {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        });
    }
    setupExpirationTimers() {
        if (this.hasValidAccessToken()) {
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken()) {
            this.setupIdTokenTimer();
        }
    }
    setupAccessTokenTimer() {
        const expiration = this.getAccessTokenExpiration();
        const storedAt = this.getAccessTokenStoredAt();
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(() => {
            this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe(e => {
                this.ngZone.run(() => {
                    this.eventsSubject.next(e);
                });
            });
        });
    }
    setupIdTokenTimer() {
        const expiration = this.getIdTokenExpiration();
        const storedAt = this.getIdTokenStoredAt();
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(() => {
            this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe(e => {
                this.ngZone.run(() => {
                    this.eventsSubject.next(e);
                });
            });
        });
    }
    clearAccessTokenTimer() {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    }
    clearIdTokenTimer() {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    }
    calcTimeout(storedAt, expiration) {
        const now = Date.now();
        const delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    }
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
    setStorage(storage) {
        this._storage = storage;
        this.configChanged();
    }
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param fullUrl
     */
    loadDiscoveryDocument(fullUrl = null) {
        return new Promise((resolve, reject) => {
            if (!fullUrl) {
                fullUrl = this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!this.validateUrlForHttps(fullUrl)) {
                reject('issuer  must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
                return;
            }
            this.http.get(fullUrl).subscribe(doc => {
                if (!this.validateDiscoveryDocument(doc)) {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                this.loginUrl = doc.authorization_endpoint;
                this.logoutUrl = doc.end_session_endpoint || this.logoutUrl;
                this.grantTypesSupported = doc.grant_types_supported;
                this.issuer = doc.issuer;
                this.tokenEndpoint = doc.token_endpoint;
                this.userinfoEndpoint = doc.userinfo_endpoint || this.userinfoEndpoint;
                this.jwksUri = doc.jwks_uri;
                this.sessionCheckIFrameUrl = doc.check_session_iframe || this.sessionCheckIFrameUrl;
                this.discoveryDocumentLoaded = true;
                this.discoveryDocumentLoadedSubject.next(doc);
                if (this.sessionChecksEnabled) {
                    this.restartSessionChecksIfStillLoggedIn();
                }
                this.loadJwks()
                    .then(jwks => {
                    const result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    const event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    this.eventsSubject.next(event);
                    resolve(event);
                    return;
                })
                    .catch(err => {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                });
            }, err => {
                this.logger.error('error loading discovery document', err);
                this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            });
        });
    }
    loadJwks() {
        return new Promise((resolve, reject) => {
            if (this.jwksUri) {
                this.http.get(this.jwksUri).subscribe(jwks => {
                    this.jwks = jwks;
                    this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }, err => {
                    this.logger.error('error loading jwks', err);
                    this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                });
            }
            else {
                resolve(null);
            }
        });
    }
    validateDiscoveryDocument(doc) {
        let errors;
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
    }
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
    fetchTokenUsingPasswordFlowAndLoadUserProfile(userName, password, headers = new HttpHeaders()) {
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then(() => this.loadUserProfile());
    }
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     */
    loadUserProfile() {
        if (!this.hasValidAccessToken()) {
            throw new Error('Can not load User Profile without access_token');
        }
        if (!this.validateUrlForHttps(this.userinfoEndpoint)) {
            throw new Error('userinfoEndpoint must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
        }
        return new Promise((resolve, reject) => {
            const headers = new HttpHeaders().set('Authorization', 'Bearer ' + this.getAccessToken());
            this.http.get(this.userinfoEndpoint, { headers }).subscribe(info => {
                this.debug('userinfo received', info);
                const existingClaims = this.getIdentityClaims() || {};
                if (!this.skipSubjectCheck) {
                    if (this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        const err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }, err => {
                this.logger.error('error loading user info', err);
                this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            });
        });
    }
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    fetchTokenUsingPasswordFlow(userName, password, headers = new HttpHeaders()) {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise((resolve, reject) => {
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * @stable
             */
            let params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', this.scope)
                .set('username', userName)
                .set('password', password);
            if (this.useHttpBasicAuth) {
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe(tokenResponse => {
                this.debug('tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }, err => {
                this.logger.error('Error performing password flow', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            });
        });
    }
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     */
    refreshToken() {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise((resolve, reject) => {
            let params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('scope', this.scope)
                .set('refresh_token', this._storage.getItem('refresh_token'));
            let headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            if (this.useHttpBasicAuth) {
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .pipe(switchMap(tokenResponse => {
                if (tokenResponse.id_token) {
                    return from(this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true))
                        .pipe(tap(result => this.storeIdToken(result)), map(_ => tokenResponse));
                }
                else {
                    return of(tokenResponse);
                }
            }))
                .subscribe(tokenResponse => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }, err => {
                this.logger.error('Error refreshing token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    }
    removeSilentRefreshEventListener() {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    }
    setupSilentRefreshEventListener() {
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = (e) => {
            const message = this.processMessageEventMessage(e);
            this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                customRedirectUri: this.silentRefreshRedirectUri || this.redirectUri
            }).catch(err => this.debug('tryLogin during silent refresh failed', err));
        };
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    }
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     */
    silentRefresh(params = {}, noPrompt = true) {
        const claims = this.getIdentityClaims() || {};
        if (this.useIdTokenHintForSilentRefresh && this.hasValidIdToken()) {
            params['id_token_hint'] = this.getIdToken();
        }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl  must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
        }
        if (typeof document === 'undefined') {
            throw new Error('silent refresh is not supported on this platform');
        }
        const existingIframe = document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        const iframe = document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        const redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then(url => {
            iframe.setAttribute('src', url);
            if (!this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            document.body.appendChild(iframe);
        });
        const errors = this.events.pipe(filter(e => e instanceof OAuthErrorEvent), first());
        const success = this.events.pipe(filter(e => e.type === 'token_received'), first());
        const timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(map(e => {
            if (e instanceof OAuthErrorEvent) {
                if (e.type === 'silent_refresh_timeout') {
                    this.eventsSubject.next(e);
                }
                else {
                    e = new OAuthErrorEvent('silent_refresh_error', e);
                    this.eventsSubject.next(e);
                }
                throw e;
            }
            else if (e.type === 'token_received') {
                e = new OAuthSuccessEvent('silently_refreshed');
                this.eventsSubject.next(e);
            }
            return e;
        }))
            .toPromise();
    }
    /**
     * This method exists for backwards compatibility.
     * {@link OAuthService#initLoginFlowInPopup} handles both code
     * and implicit flows.
     */
    initImplicitFlowInPopup(options) {
        return this.initLoginFlowInPopup(options);
    }
    initLoginFlowInPopup(options) {
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then(url => {
            return new Promise((resolve, reject) => {
                /**
                 * Error handling section
                 */
                const checkForPopupClosedInterval = 500;
                let windowRef = window.open(url, '_blank', this.calculatePopupFeatures(options));
                let checkForPopupClosedTimer;
                const checkForPopupClosed = () => {
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
                const cleanup = () => {
                    window.clearInterval(checkForPopupClosedTimer);
                    window.removeEventListener('message', listener);
                    if (windowRef !== null) {
                        windowRef.close();
                    }
                    windowRef = null;
                };
                const listener = (e) => {
                    const message = this.processMessageEventMessage(e);
                    if (message && message !== null) {
                        this.tryLogin({
                            customHashFragment: message,
                            preventClearHashAfterLogin: true,
                            customRedirectUri: this.silentRefreshRedirectUri,
                        }).then(() => {
                            cleanup();
                            resolve();
                        }, err => {
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
    }
    calculatePopupFeatures(options) {
        // Specify an static height and width and calculate centered position
        const height = options.height || 470;
        const width = options.width || 500;
        const left = window.screenLeft + ((window.outerWidth - width) / 2);
        const top = window.screenTop + ((window.outerHeight - height) / 2);
        return `location=no,toolbar=no,width=${width},height=${height},top=${top},left=${left}`;
    }
    processMessageEventMessage(e) {
        let expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        const prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    }
    canPerformSessionCheck() {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        const sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof document === 'undefined') {
            return false;
        }
        return true;
    }
    setupSessionCheckEventListener() {
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = (e) => {
            const origin = e.origin.toLowerCase();
            const issuer = this.issuer.toLowerCase();
            this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer);
                return;
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    this.handleSessionUnchanged();
                    break;
                case 'changed':
                    this.ngZone.run(() => {
                        this.handleSessionChange();
                    });
                    break;
                case 'error':
                    this.ngZone.run(() => {
                        this.handleSessionError();
                    });
                    break;
            }
            this.debug('got info from session check inframe', e);
        };
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular(() => {
            window.addEventListener('message', this.sessionCheckEventListener);
        });
    }
    handleSessionUnchanged() {
        this.debug('session check', 'session unchanged');
    }
    handleSessionChange() {
        /* events: session_changed, relogin, stopTimer, logged_out*/
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch(_ => this.debug('silent refresh failed after session changed'));
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    }
    waitForSilentRefreshAfterSessionChange() {
        this.events
            .pipe(filter((e) => e.type === 'silently_refreshed' ||
            e.type === 'silent_refresh_timeout' ||
            e.type === 'silent_refresh_error'), first())
            .subscribe(e => {
            if (e.type !== 'silently_refreshed') {
                this.debug('silent refresh did not work after session changed');
                this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                this.logOut(true);
            }
        });
    }
    handleSessionError() {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    }
    removeSessionCheckEventListener() {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    }
    initSessionCheck() {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        const existingIframe = document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        const iframe = document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        const url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    }
    startSessionCheckTimer() {
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular(() => {
            this.sessionCheckTimer = setInterval(this.checkSession.bind(this), this.sessionCheckIntervall);
        });
    }
    stopSessionCheckTimer() {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    }
    checkSession() {
        const iframe = document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        const sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        const message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    }
    createLoginUrl(state = '', loginHint = '', customRedirectUri = '', noPrompt = false, params = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const that = this;
            let redirectUri;
            if (customRedirectUri) {
                redirectUri = customRedirectUri;
            }
            else {
                redirectUri = this.redirectUri;
            }
            const nonce = yield this.createAndSaveNonce();
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
            const seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
            let scope = that.scope;
            if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                scope = 'openid ' + scope;
            }
            let url = that.loginUrl +
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
            if (this.responseType === 'code' && !this.disablePKCE) {
                const [challenge, verifier] = yield this.createChallangeVerifierPairForPKCE();
                this._storage.setItem('PKCI_verifier', verifier);
                url += '&code_challenge=' + challenge;
                url += '&code_challenge_method=S256';
            }
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
            for (const key of Object.keys(params)) {
                url +=
                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    url +=
                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                }
            }
            return url;
        });
    }
    initImplicitFlowInternal(additionalState = '', params = '') {
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl  must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
        }
        let addParams = {};
        let loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch(error => {
            console.error('Error in initImplicitFlow', error);
            this.inImplicitFlow = false;
        });
    }
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     */
    initImplicitFlow(additionalState = '', params = '') {
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(e => e.type === 'discovery_document_loaded'))
                .subscribe(_ => this.initImplicitFlowInternal(additionalState, params));
        }
    }
    /**
     * Reset current implicit flow
     *
     * @description This method allows resetting the current implict flow in order to be initialized again.
     */
    resetImplicitFlow() {
        this.inImplicitFlow = false;
    }
    callOnTokenReceivedIfExists(options) {
        const that = this;
        if (options.onTokenReceived) {
            const tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    }
    storeAccessTokenResponse(accessToken, refreshToken, expiresIn, grantedScopes, customParameters) {
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            const expiresInMilliSeconds = expiresIn * 1000;
            const now = new Date();
            const expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
        if (customParameters) {
            Object.keys(customParameters).forEach(key => {
                this._storage.setItem(key, customParameters[key]);
            });
        }
    }
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param options Optional options.
     */
    tryLogin(options = null) {
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow(options).then(_ => true);
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    }
    parseQueryString(queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    tryLoginCodeFlow(options = null) {
        options = options || {};
        const querySource = options.customHashFragment ?
            options.customHashFragment.substring(1) :
            window.location.search;
        const parts = this.getCodePartsFromUrl(window.location.search);
        const code = parts['code'];
        const state = parts['state'];
        if (!options.preventClearHashAfterLogin) {
            const href = location.href
                .replace(/[&\?]code=[^&\$]*/, '')
                .replace(/[&\?]scope=[^&\$]*/, '')
                .replace(/[&\?]state=[^&\$]*/, '')
                .replace(/[&\?]session_state=[^&\$]*/, '');
            history.replaceState(null, window.name, href);
        }
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            const err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        if (!nonceInState) {
            return Promise.resolve();
        }
        const success = this.validateNonce(nonceInState);
        if (!success) {
            const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event);
            return Promise.reject(event);
        }
        if (code) {
            return new Promise((resolve, reject) => {
                this.getTokenFromCode(code, options).then(result => {
                    resolve();
                }).catch(err => {
                    reject(err);
                });
            });
        }
        else {
            return Promise.resolve();
        }
    }
    /**
    * Retrieve the returned auth code from the redirect uri that has been called.
    * If required also check hash, as we could use hash location strategy.
    */
    getCodePartsFromUrl(queryString) {
        if (!queryString || queryString.length === 0) {
            return this.urlHelper.getHashFragmentParams();
        }
        // normalize query string
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     */
    getTokenFromCode(code, options) {
        let params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', options.customRedirectUri || this.redirectUri);
        if (!this.disablePKCE) {
            const pkciVerifier = this._storage.getItem('PKCI_verifier');
            if (!pkciVerifier) {
                console.warn('No PKCI verifier found in oauth storage!');
            }
            else {
                params = params.set('code_verifier', pkciVerifier);
            }
        }
        return this.fetchAndProcessToken(params);
    }
    fetchAndProcessToken(params) {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        let headers = new HttpHeaders()
            .set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        return new Promise((resolve, reject) => {
            if (this.customQueryParams) {
                for (let key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http.post(this.tokenEndpoint, params, { headers }).subscribe((tokenResponse) => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                if (this.oidc && tokenResponse.id_token) {
                    this.processIdToken(tokenResponse.id_token, tokenResponse.access_token).
                        then(result => {
                        this.storeIdToken(result);
                        this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    })
                        .catch(reason => {
                        this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    });
                }
                else {
                    this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }, (err) => {
                console.error('Error getting token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    }
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param options Optional options.
     */
    tryLoginImplicitFlow(options = null) {
        options = options || {};
        let parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        const state = parts['state'];
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            const err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        const accessToken = parts['access_token'];
        const idToken = parts['id_token'];
        const sessionState = parts['session_state'];
        const grantedScopes = parts['scope'];
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
            const success = this.validateNonce(nonceInState);
            if (!success) {
                const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event);
                return Promise.reject(event);
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
            .then(result => {
            if (options.validationHandler) {
                return options
                    .validationHandler({
                    accessToken: accessToken,
                    idClaims: result.idTokenClaims,
                    idToken: result.idToken,
                    state: state
                })
                    .then(_ => result);
            }
            return result;
        })
            .then(result => {
            this.storeIdToken(result);
            this.storeSessionState(sessionState);
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            this.callOnTokenReceivedIfExists(options);
            this.inImplicitFlow = false;
            return true;
        })
            .catch(reason => {
            this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            this.logger.error('Error validating tokens');
            this.logger.error(reason);
            return Promise.reject(reason);
        });
    }
    parseState(state) {
        let nonce = state;
        let userState = '';
        if (state) {
            const idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    }
    validateNonce(nonceInState) {
        const savedNonce = this._storage.getItem('nonce');
        if (savedNonce !== nonceInState) {
            const err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    }
    storeIdToken(idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    }
    storeSessionState(sessionState) {
        this._storage.setItem('session_state', sessionState);
    }
    getSessionState() {
        return this._storage.getItem('session_state');
    }
    handleLoginError(options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
            location.hash = '';
        }
    }
    /**
     * @ignore
     */
    processIdToken(idToken, accessToken, skipNonceCheck = false) {
        const tokenParts = idToken.split('.');
        const headerBase64 = this.padBase64(tokenParts[0]);
        const headerJson = b64DecodeUnicode(headerBase64);
        const header = JSON.parse(headerJson);
        const claimsBase64 = this.padBase64(tokenParts[1]);
        const claimsJson = b64DecodeUnicode(claimsBase64);
        const claims = JSON.parse(claimsJson);
        const savedNonce = this._storage.getItem('nonce');
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every(v => v !== this.clientId)) {
                const err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                const err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            const err = 'No sub claim in id_token';
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
            const err = 'After refreshing, we got an id_token for another user (sub). ' +
                `Expected sub: ${this.silentRefreshSubject}, received sub: ${claims['sub']}`;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            const err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            const err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!skipNonceCheck && claims.nonce !== savedNonce) {
            const err = 'Wrong nonce: ' + claims.nonce;
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
            const err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        const now = Date.now();
        const issuedAtMSec = claims.iat * 1000;
        const expiresAtMSec = claims.exp * 1000;
        const clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            const err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        const validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: () => this.loadJwks()
        };
        if (this.disableAtHashCheck) {
            return this.checkSignature(validationParams).then(_ => {
                const result = {
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
            .then(atHashValid => {
            if (!this.disableAtHashCheck &&
                this.requestAccessToken &&
                !atHashValid) {
                const err = 'Wrong at_hash';
                this.logger.warn(err);
                return Promise.reject(err);
            }
            return this.checkSignature(validationParams).then(_ => {
                const atHashCheckEnabled = !this.disableAtHashCheck;
                const result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                if (atHashCheckEnabled) {
                    return this.checkAtHash(validationParams).then(atHashValid => {
                        if (this.requestAccessToken && !atHashValid) {
                            const err = 'Wrong at_hash';
                            this.logger.warn(err);
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
    }
    /**
     * Returns the received claims about the user.
     */
    getIdentityClaims() {
        const claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    }
    /**
     * Returns the granted scopes from the server.
     */
    getGrantedScopes() {
        const scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    }
    /**
     * Returns the current id_token.
     */
    getIdToken() {
        return this._storage
            ? this._storage.getItem('id_token')
            : null;
    }
    padBase64(base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    }
    /**
     * Returns the current access_token.
     */
    getAccessToken() {
        return this._storage
            ? this._storage.getItem('access_token')
            : null;
    }
    getRefreshToken() {
        return this._storage
            ? this._storage.getItem('refresh_token')
            : null;
    }
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     */
    getAccessTokenExpiration() {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    }
    getAccessTokenStoredAt() {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    }
    getIdTokenStoredAt() {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    }
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     */
    getIdTokenExpiration() {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    }
    /**
     * Checkes, whether there is a valid access_token.
     */
    hasValidAccessToken() {
        if (this.getAccessToken()) {
            const expiresAt = this._storage.getItem('expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Checks whether there is a valid id_token.
     */
    hasValidIdToken() {
        if (this.getIdToken()) {
            const expiresAt = this._storage.getItem('id_token_expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     */
    authorizationHeader() {
        return 'Bearer ' + this.getAccessToken();
    }
    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it.
     * @param noRedirectToLogoutUrl
     */
    logOut(noRedirectToLogoutUrl = false) {
        const id_token = this.getIdToken();
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
        let logoutUrl;
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
            let params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            const postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
            if (postLogoutUrl) {
                params = params.set('post_logout_redirect_uri', postLogoutUrl);
            }
            logoutUrl =
                this.logoutUrl +
                    (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                    params.toString();
        }
        this.config.openUri(logoutUrl);
    }
    /**
     * @ignore
     */
    createAndSaveNonce() {
        const that = this;
        return this.createNonce().then(function (nonce) {
            that._storage.setItem('nonce', nonce);
            return nonce;
        });
    }
    /**
     * @ignore
     */
    ngOnDestroy() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
        this.removeSilentRefreshEventListener();
        const silentRefreshFrame = document.getElementById(this.silentRefreshIFrameName);
        if (silentRefreshFrame) {
            silentRefreshFrame.remove();
        }
        this.stopSessionCheckTimer();
        this.removeSessionCheckEventListener();
        const sessionCheckFrame = document.getElementById(this.sessionCheckIFrameName);
        if (sessionCheckFrame) {
            sessionCheckFrame.remove();
        }
    }
    createNonce() {
        return new Promise((resolve) => {
            if (this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
             * This alphabet is from:
             * https://tools.ietf.org/html/rfc7636#section-4.1
             *
             * [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
             */
            const unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            let size = 45;
            let id = '';
            const crypto = typeof self === 'undefined' ? null : (self.crypto || self['msCrypto']);
            if (crypto) {
                let bytes = new Uint8Array(size);
                crypto.getRandomValues(bytes);
                bytes = bytes.map(x => unreserved.charCodeAt(x % unreserved.length));
                id = String.fromCharCode.apply(null, bytes);
            }
            else {
                while (0 < size--) {
                    id += unreserved[Math.random() * unreserved.length | 0];
                }
            }
            resolve(base64UrlEncode(id));
        });
    }
    checkAtHash(params) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.tokenValidationHandler) {
                this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                return true;
            }
            return this.tokenValidationHandler.validateAtHash(params);
        });
    }
    checkSignature(params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    }
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     */
    initLoginFlow(additionalState = '', params = {}) {
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    }
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     */
    initCodeFlow(additionalState = '', params = {}) {
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events.pipe(filter(e => e.type === 'discovery_document_loaded'))
                .subscribe(_ => this.initCodeFlowInternal(additionalState, params));
        }
    }
    initCodeFlowInternal(additionalState = '', params = {}) {
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl  must use HTTPS (with TLS), or config value for property \'requireHttps\' must be set to \'false\' and allow HTTP (without TLS).');
        }
        this.createLoginUrl(additionalState, '', null, false, params)
            .then(this.config.openUri)
            .catch(error => {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        });
    }
    createChallangeVerifierPairForPKCE() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.crypto) {
                throw new Error('PKCI support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
            }
            const verifier = yield this.createNonce();
            const challengeRaw = yield this.crypto.calcHash(verifier, 'sha-256');
            const challange = base64UrlEncode(challengeRaw);
            return [challange, verifier];
        });
    }
    extractRecognizedCustomParameters(tokenResponse) {
        if (!this.config.customTokenParameters) {
            return {};
        }
        let foundParameters = {};
        this.config.customTokenParameters.forEach(recognizedParameter => {
            if (tokenResponse[recognizedParameter]) {
                foundParameters[recognizedParameter] = tokenResponse[recognizedParameter];
            }
        });
        return foundParameters;
    }
};
OAuthService.ctorParameters = () => [
    { type: NgZone },
    { type: HttpClient },
    { type: OAuthStorage, decorators: [{ type: Optional }] },
    { type: ValidationHandler, decorators: [{ type: Optional }] },
    { type: AuthConfig, decorators: [{ type: Optional }] },
    { type: UrlHelperService },
    { type: OAuthLogger },
    { type: HashHandler, decorators: [{ type: Optional }] }
];
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
export { OAuthService };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQ3hFLE9BQU8sRUFBRSxVQUFVLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQzNFLE9BQU8sRUFBYyxPQUFPLEVBQWdCLEVBQUUsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE1BQU0sTUFBTSxDQUFDO0FBQ3pFLE9BQU8sRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxZQUFZLEVBQUUsTUFBTSxnQkFBZ0IsQ0FBQztBQUV6RixPQUFPLEVBQ0gsaUJBQWlCLEVBQ2pCLGdCQUFnQixFQUNuQixNQUFNLHVDQUF1QyxDQUFDO0FBQy9DLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQ3hELE9BQU8sRUFFSCxjQUFjLEVBQ2QsZUFBZSxFQUNmLGlCQUFpQixFQUNwQixNQUFNLFVBQVUsQ0FBQztBQUNsQixPQUFPLEVBQ0gsV0FBVyxFQUNYLFlBQVksRUFDWixZQUFZLEVBQ1osYUFBYSxFQUNiLGdCQUFnQixFQUNoQixhQUFhLEVBQ2IsUUFBUSxFQUNYLE1BQU0sU0FBUyxDQUFDO0FBQ2pCLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxlQUFlLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUNwRSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQzNDLE9BQU8sRUFBRSx1QkFBdUIsRUFBRSxNQUFNLFdBQVcsQ0FBQztBQUNwRCxPQUFPLEVBQUUsV0FBVyxFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFF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WUFBWSxDQUFDLENBQUM7WUFFaEQsT0FBTyxDQUFDLFNBQVMsRUFBRSxRQUFRLENBQUMsQ0FBQztRQUNqQyxDQUFDO0tBQUE7SUFFTyxpQ0FBaUMsQ0FBQyxhQUE0QjtRQUNwRSxJQUFJLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxxQkFBcUIsRUFBRTtZQUNwQyxPQUFPLEVBQUUsQ0FBQztTQUNiO1FBQ0QsSUFBSSxlQUFlLEdBQVEsRUFBRSxDQUFDO1FBQzlCLElBQUksQ0FBQyxNQUFNLENBQUMscUJBQXFCLENBQUMsT0FBTyxDQUFDLG1CQUFtQixDQUFDLEVBQUU7WUFDNUQsSUFBSSxhQUFhLENBQUMsbUJBQW1CLENBQUMsRUFBRTtnQkFDdEMsZUFBZSxDQUFDLG1CQUFtQixDQUFDLEdBQUcsYUFBYSxDQUFDLG1CQUFtQixDQUFDLENBQUM7YUFDM0U7UUFDTCxDQUFDLENBQUMsQ0FBQztRQUNILE9BQU8sZUFBZSxDQUFDO0lBQ3pCLENBQUM7Q0FDSixDQUFBOztZQXhzRXlCLE1BQU07WUFDUixVQUFVO1lBQ0wsWUFBWSx1QkFBaEMsUUFBUTtZQUMyQixpQkFBaUIsdUJBQXBELFFBQVE7WUFDcUIsVUFBVSx1QkFBdkMsUUFBUTtZQUNZLGdCQUFnQjtZQUNuQixXQUFXO1lBQ0MsV0FBVyx1QkFBeEMsUUFBUTs7QUF4REosWUFBWTtJQUR4QixVQUFVLEVBQUU7SUFvREosV0FBQSxRQUFRLEVBQUUsQ0FBQTtJQUNWLFdBQUEsUUFBUSxFQUFFLENBQUE7SUFDVixXQUFBLFFBQVEsRUFBRSxDQUFBO0lBR1YsV0FBQSxRQUFRLEVBQUUsQ0FBQTtxQ0FQTyxNQUFNO1FBQ1IsVUFBVTtRQUNMLFlBQVk7UUFDRyxpQkFBaUI7UUFDdkIsVUFBVTtRQUNuQixnQkFBZ0I7UUFDbkIsV0FBVztRQUNDLFdBQVc7R0F4RHBDLFlBQVksQ0F5dkV4QjtTQXp2RVksWUFBWSIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUsIE5nWm9uZSwgT3B0aW9uYWwsIE9uRGVzdHJveSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgSHR0cENsaWVudCwgSHR0cEhlYWRlcnMsIEh0dHBQYXJhbXMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBTdWJqZWN0LCBTdWJzY3JpcHRpb24sIG9mLCByYWNlLCBmcm9tIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgeyBmaWx0ZXIsIGRlbGF5LCBmaXJzdCwgdGFwLCBtYXAsIHN3aXRjaE1hcCwgZGVib3VuY2VUaW1lIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuXG5pbXBvcnQge1xuICAgIFZhbGlkYXRpb25IYW5kbGVyLFxuICAgIFZhbGlkYXRpb25QYXJhbXNcbn0gZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL3ZhbGlkYXRpb24taGFuZGxlcic7XG5pbXBvcnQgeyBVcmxIZWxwZXJTZXJ2aWNlIH0gZnJvbSAnLi91cmwtaGVscGVyLnNlcnZpY2UnO1xuaW1wb3J0IHtcbiAgICBPQXV0aEV2ZW50LFxuICAgIE9BdXRoSW5mb0V2ZW50LFxuICAgIE9BdXRoRXJyb3JFdmVudCxcbiAgICBPQXV0aFN1Y2Nlc3NFdmVudFxufSBmcm9tICcuL2V2ZW50cyc7XG5pbXBvcnQge1xuICAgIE9BdXRoTG9nZ2VyLFxuICAgIE9BdXRoU3RvcmFnZSxcbiAgICBMb2dpbk9wdGlvbnMsXG4gICAgUGFyc2VkSWRUb2tlbixcbiAgICBPaWRjRGlzY292ZXJ5RG9jLFxuICAgIFRva2VuUmVzcG9uc2UsXG4gICAgVXNlckluZm9cbn0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBiNjREZWNvZGVVbmljb2RlLCBiYXNlNjRVcmxFbmNvZGUgfSBmcm9tICcuL2Jhc2U2NC1oZWxwZXInO1xuaW1wb3J0IHsgQXV0aENvbmZpZyB9IGZyb20gJy4vYXV0aC5jb25maWcnO1xuaW1wb3J0IHsgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMgfSBmcm9tICcuL2VuY29kZXInO1xuaW1wb3J0IHsgSGFzaEhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyJztcblxuLyoqXG4gKiBTZXJ2aWNlIGZvciBsb2dnaW5nIGluIGFuZCBsb2dnaW5nIG91dCB3aXRoXG4gKiBPSURDIGFuZCBPQXV0aDIuIFN1cHBvcnRzIGltcGxpY2l0IGZsb3cgYW5kXG4gKiBwYXNzd29yZCBmbG93LlxuICovXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgT0F1dGhTZXJ2aWNlIGV4dGVuZHMgQXV0aENvbmZpZyBpbXBsZW1lbnRzIE9uRGVzdHJveSB7XG4gICAgLy8gRXh0ZW5kaW5nIEF1dGhDb25maWcgaXN0IGp1c3QgZm9yIExFR0FDWSByZWFzb25zXG4gICAgLy8gdG8gbm90IGJyZWFrIGV4aXN0aW5nIGNvZGUuXG5cbiAgICAvKipcbiAgICAgKiBUaGUgVmFsaWRhdGlvbkhhbmRsZXIgdXNlZCB0byB2YWxpZGF0ZSByZWNlaXZlZFxuICAgICAqIGlkX3Rva2Vucy5cbiAgICAgKi9cbiAgICBwdWJsaWMgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjogVmFsaWRhdGlvbkhhbmRsZXI7XG5cbiAgICAvKipcbiAgICAgKiBAaW50ZXJuYWxcbiAgICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXG4gICAgICovXG4gICAgcHVibGljIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkID0gZmFsc2U7XG5cbiAgICAvKipcbiAgICAgKiBAaW50ZXJuYWxcbiAgICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXG4gICAgICovXG4gICAgcHVibGljIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkJDogT2JzZXJ2YWJsZTxPaWRjRGlzY292ZXJ5RG9jPjtcblxuICAgIC8qKlxuICAgICAqIEluZm9ybXMgYWJvdXQgZXZlbnRzLCBsaWtlIHRva2VuX3JlY2VpdmVkIG9yIHRva2VuX2V4cGlyZXMuXG4gICAgICogU2VlIHRoZSBzdHJpbmcgZW51bSBFdmVudFR5cGUgZm9yIGEgZnVsbCBsaXN0IG9mIGV2ZW50IHR5cGVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBldmVudHM6IE9ic2VydmFibGU8T0F1dGhFdmVudD47XG5cbiAgICAvKipcbiAgICAgKiBUaGUgcmVjZWl2ZWQgKHBhc3NlZCBhcm91bmQpIHN0YXRlLCB3aGVuIGxvZ2dpbmdcbiAgICAgKiBpbiB3aXRoIGltcGxpY2l0IGZsb3cuXG4gICAgICovXG4gICAgcHVibGljIHN0YXRlPz0gJyc7XG5cbiAgICBwcm90ZWN0ZWQgZXZlbnRzU3ViamVjdDogU3ViamVjdDxPQXV0aEV2ZW50PiA9IG5ldyBTdWJqZWN0PE9BdXRoRXZlbnQ+KCk7XG4gICAgcHJvdGVjdGVkIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdDogU3ViamVjdDxPaWRjRGlzY292ZXJ5RG9jPiA9IG5ldyBTdWJqZWN0PE9pZGNEaXNjb3ZlcnlEb2M+KCk7XG4gICAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XG4gICAgcHJvdGVjdGVkIGdyYW50VHlwZXNTdXBwb3J0ZWQ6IEFycmF5PHN0cmluZz4gPSBbXTtcbiAgICBwcm90ZWN0ZWQgX3N0b3JhZ2U6IE9BdXRoU3RvcmFnZTtcbiAgICBwcm90ZWN0ZWQgYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gICAgcHJvdGVjdGVkIGlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gICAgcHJvdGVjdGVkIHRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcbiAgICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcjogRXZlbnRMaXN0ZW5lcjtcbiAgICBwcm90ZWN0ZWQgandrc1VyaTogc3RyaW5nO1xuICAgIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tUaW1lcjogYW55O1xuICAgIHByb3RlY3RlZCBzaWxlbnRSZWZyZXNoU3ViamVjdDogc3RyaW5nO1xuICAgIHByb3RlY3RlZCBpbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuXG4gICAgY29uc3RydWN0b3IoXG4gICAgICAgIHByb3RlY3RlZCBuZ1pvbmU6IE5nWm9uZSxcbiAgICAgICAgcHJvdGVjdGVkIGh0dHA6IEh0dHBDbGllbnQsXG4gICAgICAgIEBPcHRpb25hbCgpIHN0b3JhZ2U6IE9BdXRoU3RvcmFnZSxcbiAgICAgICAgQE9wdGlvbmFsKCkgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjogVmFsaWRhdGlvbkhhbmRsZXIsXG4gICAgICAgIEBPcHRpb25hbCgpIHByb3RlY3RlZCBjb25maWc6IEF1dGhDb25maWcsXG4gICAgICAgIHByb3RlY3RlZCB1cmxIZWxwZXI6IFVybEhlbHBlclNlcnZpY2UsXG4gICAgICAgIHByb3RlY3RlZCBsb2dnZXI6IE9BdXRoTG9nZ2VyLFxuICAgICAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY3J5cHRvOiBIYXNoSGFuZGxlcixcbiAgICApIHtcbiAgICAgICAgc3VwZXIoKTtcblxuICAgICAgICB0aGlzLmRlYnVnKCdhbmd1bGFyLW9hdXRoMi1vaWRjIHY4LWJldGEnKTtcblxuICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkJCA9IHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xuICAgICAgICB0aGlzLmV2ZW50cyA9IHRoaXMuZXZlbnRzU3ViamVjdC5hc09ic2VydmFibGUoKTtcblxuICAgICAgICBpZiAodG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xuICAgICAgICAgICAgdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyID0gdG9rZW5WYWxpZGF0aW9uSGFuZGxlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChjb25maWcpIHtcbiAgICAgICAgICAgIHRoaXMuY29uZmlndXJlKGNvbmZpZyk7XG4gICAgICAgIH1cblxuICAgICAgICB0cnkge1xuICAgICAgICAgICAgaWYgKHN0b3JhZ2UpIHtcbiAgICAgICAgICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc3RvcmFnZSk7XG4gICAgICAgICAgICB9IGVsc2UgaWYgKHR5cGVvZiBzZXNzaW9uU3RvcmFnZSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc2Vzc2lvblN0b3JhZ2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGNhdGNoIChlKSB7XG5cbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ05vIE9BdXRoU3RvcmFnZSBwcm92aWRlZCBhbmQgY2Fubm90IGFjY2VzcyBkZWZhdWx0IChzZXNzaW9uU3RvcmFnZSkuJ1xuICAgICAgICAgICAgICAgICsgJ0NvbnNpZGVyIHByb3ZpZGluZyBhIGN1c3RvbSBPQXV0aFN0b3JhZ2UgaW1wbGVtZW50YXRpb24gaW4geW91ciBtb2R1bGUuJyxcbiAgICAgICAgICAgICAgICBlXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5zZXR1cFJlZnJlc2hUaW1lcigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVzZSB0aGlzIG1ldGhvZCB0byBjb25maWd1cmUgdGhlIHNlcnZpY2VcbiAgICAgKiBAcGFyYW0gY29uZmlnIHRoZSBjb25maWd1cmF0aW9uXG4gICAgICovXG4gICAgcHVibGljIGNvbmZpZ3VyZShjb25maWc6IEF1dGhDb25maWcpOiB2b2lkIHtcbiAgICAgICAgLy8gRm9yIHRoZSBzYWtlIG9mIGRvd253YXJkIGNvbXBhdGliaWxpdHkgd2l0aFxuICAgICAgICAvLyBvcmlnaW5hbCBjb25maWd1cmF0aW9uIEFQSVxuICAgICAgICBPYmplY3QuYXNzaWduKHRoaXMsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XG5cbiAgICAgICAgdGhpcy5jb25maWcgPSBPYmplY3QuYXNzaWduKHt9IGFzIEF1dGhDb25maWcsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XG5cbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgICAgICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2soKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuY29uZmlnQ2hhbmdlZCgpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjb25maWdDaGFuZ2VkKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XG4gICAgfVxuXG4gICAgcHVibGljIHJlc3RhcnRTZXNzaW9uQ2hlY2tzSWZTdGlsbExvZ2dlZEluKCk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgcmVzdGFydFJlZnJlc2hUaW1lcklmU3RpbGxMb2dnZWRJbigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBTZXNzaW9uQ2hlY2soKTogdm9pZCB7XG4gICAgICAgIHRoaXMuZXZlbnRzLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSkuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFdpbGwgc2V0dXAgdXAgc2lsZW50IHJlZnJlc2hpbmcgZm9yIHdoZW4gdGhlIHRva2VuIGlzXG4gICAgICogYWJvdXQgdG8gZXhwaXJlLiBXaGVuIHRoZSB1c2VyIGlzIGxvZ2dlZCBvdXQgdmlhIHRoaXMubG9nT3V0IG1ldGhvZCwgdGhlXG4gICAgICogc2lsZW50IHJlZnJlc2hpbmcgd2lsbCBwYXVzZSBhbmQgbm90IHJlZnJlc2ggdGhlIHRva2VucyB1bnRpbCB0aGUgdXNlciBpc1xuICAgICAqIGxvZ2dlZCBiYWNrIGluIHZpYSByZWNlaXZpbmcgYSBuZXcgdG9rZW4uXG4gICAgICogQHBhcmFtIHBhcmFtcyBBZGRpdGlvbmFsIHBhcmFtZXRlciB0byBwYXNzXG4gICAgICogQHBhcmFtIGxpc3RlblRvIFNldHVwIGF1dG9tYXRpYyByZWZyZXNoIG9mIGEgc3BlY2lmaWMgdG9rZW4gdHlwZVxuICAgICAqL1xuICAgIHB1YmxpYyBzZXR1cEF1dG9tYXRpY1NpbGVudFJlZnJlc2gocGFyYW1zOiBvYmplY3QgPSB7fSwgbGlzdGVuVG8/OiAnYWNjZXNzX3Rva2VuJyB8ICdpZF90b2tlbicgfCAnYW55Jywgbm9Qcm9tcHQgPSB0cnVlKTogdm9pZCB7XG4gICAgICAgIGxldCBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gdHJ1ZTtcbiAgICAgICAgdGhpcy5ldmVudHMucGlwZShcbiAgICAgICAgICAgIHRhcCgoZSkgPT4ge1xuICAgICAgICAgICAgICAgIGlmIChlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpIHtcbiAgICAgICAgICAgICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IHRydWU7XG4gICAgICAgICAgICAgICAgfSBlbHNlIGlmIChlLnR5cGUgPT09ICdsb2dvdXQnKSB7XG4gICAgICAgICAgICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KSxcbiAgICAgICAgICAgIGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX2V4cGlyZXMnKSxcbiAgICAgICAgICAgIGRlYm91bmNlVGltZSgxMDAwKSxcbiAgICAgICAgKS5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgICBjb25zdCBldmVudCA9IGUgYXMgT0F1dGhJbmZvRXZlbnQ7XG4gICAgICAgICAgICBpZiAoKGxpc3RlblRvID09IG51bGwgfHwgbGlzdGVuVG8gPT09ICdhbnknIHx8IGV2ZW50LmluZm8gPT09IGxpc3RlblRvKSAmJiBzaG91bGRSdW5TaWxlbnRSZWZyZXNoKSB7XG4gICAgICAgICAgICAgICAgLy8gdGhpcy5zaWxlbnRSZWZyZXNoKHBhcmFtcywgbm9Qcm9tcHQpLmNhdGNoKF8gPT4ge1xuICAgICAgICAgICAgICAgIHRoaXMucmVmcmVzaEludGVybmFsKHBhcmFtcywgbm9Qcm9tcHQpLmNhdGNoKF8gPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdBdXRvbWF0aWMgc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrJyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuXG4gICAgICAgIHRoaXMucmVzdGFydFJlZnJlc2hUaW1lcklmU3RpbGxMb2dnZWRJbigpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCByZWZyZXNoSW50ZXJuYWwocGFyYW1zLCBub1Byb21wdCk6IFByb21pc2U8VG9rZW5SZXNwb25zZSB8IE9BdXRoRXZlbnQ+IHtcblxuICAgICAgICBpZiAoIXRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpICYmIHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hUb2tlbigpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuc2lsZW50UmVmcmVzaChwYXJhbXMsIG5vUHJvbXB0KTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoLi4uKWAgYW5kXG4gICAgICogZGlyZWN0bHkgY2hhaW5zIHVzaW5nIHRoZSBgdGhlbiguLi4pYCBwYXJ0IG9mIHRoZSBwcm9taXNlIHRvIGNhbGxcbiAgICAgKiB0aGUgYHRyeUxvZ2luKC4uLilgIG1ldGhvZC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBvcHRpb25zIExvZ2luT3B0aW9ucyB0byBwYXNzIHRocm91Z2ggdG8gYHRyeUxvZ2luKC4uLilgXG4gICAgICovXG4gICAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50KCkudGhlbihkb2MgPT4ge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW4ob3B0aW9ucyk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbiguLi4pYFxuICAgICAqIGFuZCBpZiB0aGVuIGNoYWlucyB0byBgaW5pdExvZ2luRmxvdygpYCwgYnV0IG9ubHkgaWYgdGhlcmUgaXMgbm8gdmFsaWRcbiAgICAgKiBJZFRva2VuIG9yIG5vIHZhbGlkIEFjY2Vzc1Rva2VuLlxuICAgICAqXG4gICAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kTG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zICYgeyBzdGF0ZT86IHN0cmluZyB9ID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICBpZiAoIW9wdGlvbnMpIHtcbiAgICAgICAgICAgIG9wdGlvbnMgPSB7IHN0YXRlOiAnJyB9O1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLmxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKG9wdGlvbnMpLnRoZW4oXyA9PiB7XG4gICAgICAgICAgICBpZiAoIXRoaXMuaGFzVmFsaWRJZFRva2VuKCkgfHwgIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgICAgICAgICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5pbml0Q29kZUZsb3coKTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3coKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGRlYnVnKC4uLmFyZ3MpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuc2hvd0RlYnVnSW5mb3JtYXRpb24pIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmRlYnVnLmFwcGx5KHRoaXMubG9nZ2VyLCBhcmdzKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudCh1cmw6IHN0cmluZyk6IHN0cmluZ1tdIHtcbiAgICAgICAgY29uc3QgZXJyb3JzOiBzdHJpbmdbXSA9IFtdO1xuICAgICAgICBjb25zdCBodHRwc0NoZWNrID0gdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHVybCk7XG4gICAgICAgIGNvbnN0IGlzc3VlckNoZWNrID0gdGhpcy52YWxpZGF0ZVVybEFnYWluc3RJc3N1ZXIodXJsKTtcblxuICAgICAgICBpZiAoIWh0dHBzQ2hlY2spIHtcbiAgICAgICAgICAgIGVycm9ycy5wdXNoKFxuICAgICAgICAgICAgICAgICdodHRwcyBmb3IgYWxsIHVybHMgcmVxdWlyZWQuIEFsc28gZm9yIHVybHMgcmVjZWl2ZWQgYnkgZGlzY292ZXJ5LidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWlzc3VlckNoZWNrKSB7XG4gICAgICAgICAgICBlcnJvcnMucHVzaChcbiAgICAgICAgICAgICAgICAnRXZlcnkgdXJsIGluIGRpc2NvdmVyeSBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyIHVybC4nICtcbiAgICAgICAgICAgICAgICAnQWxzbyBzZWUgcHJvcGVydHkgc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uLidcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gZXJyb3JzO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZvckh0dHBzKHVybDogc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICAgIGlmICghdXJsKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGxjVXJsID0gdXJsLnRvTG93ZXJDYXNlKCk7XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWlyZUh0dHBzID09PSBmYWxzZSkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoXG4gICAgICAgICAgICAobGNVcmwubWF0Y2goL15odHRwOlxcL1xcL2xvY2FsaG9zdCgkfFs6XFwvXSkvKSB8fFxuICAgICAgICAgICAgICAgIGxjVXJsLm1hdGNoKC9eaHR0cDpcXC9cXC9sb2NhbGhvc3QoJHxbOlxcL10pLykpICYmXG4gICAgICAgICAgICB0aGlzLnJlcXVpcmVIdHRwcyA9PT0gJ3JlbW90ZU9ubHknXG4gICAgICAgICkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbGNVcmwuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbCh1cmw6IHN0cmluZyB8IHVuZGVmaW5lZCwgZGVzY3JpcHRpb246IHN0cmluZykge1xuICAgICAgICBpZiAoIXVybCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGAnJHtkZXNjcmlwdGlvbn0nIHNob3VsZCBub3QgYmUgbnVsbGApO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHVybCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgJyR7ZGVzY3JpcHRpb259JyBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5gKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCB2YWxpZGF0ZVVybEFnYWluc3RJc3N1ZXIodXJsOiBzdHJpbmcpIHtcbiAgICAgICAgaWYgKCF0aGlzLnN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbikge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF1cmwpIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB1cmwudG9Mb3dlckNhc2UoKS5zdGFydHNXaXRoKHRoaXMuaXNzdWVyLnRvTG93ZXJDYXNlKCkpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzZXR1cFJlZnJlc2hUaW1lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHR5cGVvZiB3aW5kb3cgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCd0aW1lciBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdHRmb3JtJyk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSB8fCB0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xuICAgICAgICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICAgICAgICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcbiAgICAgICAgICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy50b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uKVxuICAgICAgICAgICAgdGhpcy50b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uLnVuc3Vic2NyaWJlKCk7XG5cbiAgICAgICAgdGhpcy50b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uID0gdGhpcy5ldmVudHMucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpKS5zdWJzY3JpYmUoXyA9PiB7XG4gICAgICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xuICAgICAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwRXhwaXJhdGlvblRpbWVycygpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgICAgICB0aGlzLnNldHVwQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICB9XG5cblxuICAgICAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgICAgICAgdGhpcy5zZXR1cElkVG9rZW5UaW1lcigpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwQWNjZXNzVG9rZW5UaW1lcigpOiB2b2lkIHtcblxuICAgICAgICBjb25zdCBleHBpcmF0aW9uID0gdGhpcy5nZXRBY2Nlc3NUb2tlbkV4cGlyYXRpb24oKTtcbiAgICAgICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTtcbiAgICAgICAgY29uc3QgdGltZW91dCA9IHRoaXMuY2FsY1RpbWVvdXQoc3RvcmVkQXQsIGV4cGlyYXRpb24pO1xuXG4gICAgICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uID0gb2YoXG4gICAgICAgICAgICAgICAgbmV3IE9BdXRoSW5mb0V2ZW50KCd0b2tlbl9leHBpcmVzJywgJ2FjY2Vzc190b2tlbicpXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwSWRUb2tlblRpbWVyKCk6IHZvaWQge1xuXG4gICAgICAgIGNvbnN0IGV4cGlyYXRpb24gPSB0aGlzLmdldElkVG9rZW5FeHBpcmF0aW9uKCk7XG4gICAgICAgIGNvbnN0IHN0b3JlZEF0ID0gdGhpcy5nZXRJZFRva2VuU3RvcmVkQXQoKTtcbiAgICAgICAgY29uc3QgdGltZW91dCA9IHRoaXMuY2FsY1RpbWVvdXQoc3RvcmVkQXQsIGV4cGlyYXRpb24pO1xuXG4gICAgICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24gPSBvZihcbiAgICAgICAgICAgICAgICBuZXcgT0F1dGhJbmZvRXZlbnQoJ3Rva2VuX2V4cGlyZXMnLCAnaWRfdG9rZW4nKVxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIC5waXBlKGRlbGF5KHRpbWVvdXQpKVxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBjbGVhckFjY2Vzc1Rva2VuVGltZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xuICAgICAgICAgICAgdGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBjbGVhcklkVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24pIHtcbiAgICAgICAgICAgIHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBjYWxjVGltZW91dChzdG9yZWRBdDogbnVtYmVyLCBleHBpcmF0aW9uOiBudW1iZXIpOiBudW1iZXIge1xuICAgICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBkZWx0YSA9IChleHBpcmF0aW9uIC0gc3RvcmVkQXQpICogdGhpcy50aW1lb3V0RmFjdG9yIC0gKG5vdyAtIHN0b3JlZEF0KTtcbiAgICAgICAgcmV0dXJuIE1hdGgubWF4KDAsIGRlbHRhKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBERVBSRUNBVEVELiBVc2UgYSBwcm92aWRlciBmb3IgT0F1dGhTdG9yYWdlIGluc3RlYWQ6XG4gICAgICpcbiAgICAgKiB7IHByb3ZpZGU6IE9BdXRoU3RvcmFnZSwgdXNlRmFjdG9yeTogb0F1dGhTdG9yYWdlRmFjdG9yeSB9XG4gICAgICogZXhwb3J0IGZ1bmN0aW9uIG9BdXRoU3RvcmFnZUZhY3RvcnkoKTogT0F1dGhTdG9yYWdlIHsgcmV0dXJuIGxvY2FsU3RvcmFnZTsgfVxuICAgICAqIFNldHMgYSBjdXN0b20gc3RvcmFnZSB1c2VkIHRvIHN0b3JlIHRoZSByZWNlaXZlZFxuICAgICAqIHRva2VucyBvbiBjbGllbnQgc2lkZS4gQnkgZGVmYXVsdCwgdGhlIGJyb3dzZXInc1xuICAgICAqIHNlc3Npb25TdG9yYWdlIGlzIHVzZWQuXG4gICAgICogQGlnbm9yZVxuICAgICAqXG4gICAgICogQHBhcmFtIHN0b3JhZ2VcbiAgICAgKi9cbiAgICBwdWJsaWMgc2V0U3RvcmFnZShzdG9yYWdlOiBPQXV0aFN0b3JhZ2UpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5fc3RvcmFnZSA9IHN0b3JhZ2U7XG4gICAgICAgIHRoaXMuY29uZmlnQ2hhbmdlZCgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExvYWRzIHRoZSBkaXNjb3ZlcnkgZG9jdW1lbnQgdG8gY29uZmlndXJlIG1vc3RcbiAgICAgKiBwcm9wZXJ0aWVzIG9mIHRoaXMgc2VydmljZS4gVGhlIHVybCBvZiB0aGUgZGlzY292ZXJ5XG4gICAgICogZG9jdW1lbnQgaXMgaW5mZXJlZCBmcm9tIHRoZSBpc3N1ZXIncyB1cmwgYWNjb3JkaW5nXG4gICAgICogdG8gdGhlIE9wZW5JZCBDb25uZWN0IHNwZWMuIFRvIHVzZSBhbm90aGVyIHVybCB5b3VcbiAgICAgKiBjYW4gcGFzcyBpdCB0byB0byBvcHRpb25hbCBwYXJhbWV0ZXIgZnVsbFVybC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBmdWxsVXJsXG4gICAgICovXG4gICAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudChmdWxsVXJsOiBzdHJpbmcgPSBudWxsKTogUHJvbWlzZTxPQXV0aFN1Y2Nlc3NFdmVudD4ge1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgaWYgKCFmdWxsVXJsKSB7XG4gICAgICAgICAgICAgICAgZnVsbFVybCA9IHRoaXMuaXNzdWVyIHx8ICcnO1xuICAgICAgICAgICAgICAgIGlmICghZnVsbFVybC5lbmRzV2l0aCgnLycpKSB7XG4gICAgICAgICAgICAgICAgICAgIGZ1bGxVcmwgKz0gJy8nO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBmdWxsVXJsICs9ICcud2VsbC1rbm93bi9vcGVuaWQtY29uZmlndXJhdGlvbic7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKGZ1bGxVcmwpKSB7XG4gICAgICAgICAgICAgICAgcmVqZWN0KCdpc3N1ZXIgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgXFwncmVxdWlyZUh0dHBzXFwnIG11c3QgYmUgc2V0IHRvIFxcJ2ZhbHNlXFwnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuJyk7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmh0dHAuZ2V0PE9pZGNEaXNjb3ZlcnlEb2M+KGZ1bGxVcmwpLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICBkb2MgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVEaXNjb3ZlcnlEb2N1bWVudChkb2MpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfdmFsaWRhdGlvbl9lcnJvcicsIG51bGwpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KCdkaXNjb3ZlcnlfZG9jdW1lbnRfdmFsaWRhdGlvbl9lcnJvcicpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dpblVybCA9IGRvYy5hdXRob3JpemF0aW9uX2VuZHBvaW50O1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ291dFVybCA9IGRvYy5lbmRfc2Vzc2lvbl9lbmRwb2ludCB8fCB0aGlzLmxvZ291dFVybDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ncmFudFR5cGVzU3VwcG9ydGVkID0gZG9jLmdyYW50X3R5cGVzX3N1cHBvcnRlZDtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5pc3N1ZXIgPSBkb2MuaXNzdWVyO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLnRva2VuRW5kcG9pbnQgPSBkb2MudG9rZW5fZW5kcG9pbnQ7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMudXNlcmluZm9FbmRwb2ludCA9IGRvYy51c2VyaW5mb19lbmRwb2ludCB8fCB0aGlzLnVzZXJpbmZvRW5kcG9pbnQ7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuandrc1VyaSA9IGRvYy5qd2tzX3VyaTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwgPSBkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUgfHwgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmw7XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0Lm5leHQoZG9jKTtcblxuICAgICAgICAgICAgICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5yZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2FkSndrcygpXG4gICAgICAgICAgICAgICAgICAgICAgICAudGhlbihqd2tzID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCByZXN1bHQ6IG9iamVjdCA9IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzY292ZXJ5RG9jdW1lbnQ6IGRvYyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgandrczogandrc1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXN1bHRcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKGV2ZW50KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgLmNhdGNoKGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyBkaXNjb3ZlcnkgZG9jdW1lbnQnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgbG9hZEp3a3MoKTogUHJvbWlzZTxvYmplY3Q+IHtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlPG9iamVjdD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgaWYgKHRoaXMuandrc1VyaSkge1xuICAgICAgICAgICAgICAgIHRoaXMuaHR0cC5nZXQodGhpcy5qd2tzVXJpKS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgICAgIGp3a3MgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5qd2tzID0gandrcztcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZShqd2tzKTtcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGp3a3MnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnandrc19sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgcmVzb2x2ZShudWxsKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jOiBPaWRjRGlzY292ZXJ5RG9jKTogYm9vbGVhbiB7XG4gICAgICAgIGxldCBlcnJvcnM6IHN0cmluZ1tdO1xuXG4gICAgICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgZG9jLmlzc3VlciAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICAgICdpbnZhbGlkIGlzc3VlciBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICAgICAgICAgICdleHBlY3RlZDogJyArIHRoaXMuaXNzdWVyLFxuICAgICAgICAgICAgICAgICdjdXJyZW50OiAnICsgZG9jLmlzc3VlclxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmF1dGhvcml6YXRpb25fZW5kcG9pbnQpO1xuICAgICAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGF1dGhvcml6YXRpb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5lbmRfc2Vzc2lvbl9lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgZW5kX3Nlc3Npb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy50b2tlbl9lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdG9rZW5fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy51c2VyaW5mb19lbmRwb2ludCk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdXNlcmluZm9fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgICAgICAgICBlcnJvcnNcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5qd2tzX3VyaSk7XG4gICAgICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIHZhbGlkYXRpbmcgandrc191cmkgaW4gZGlzY292ZXJ5IGRvY3VtZW50JywgZXJyb3JzKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgZGlzY292ZXJ5IGRvY3VtZW50JyArXG4gICAgICAgICAgICAgICAgJyBkb2VzIG5vdCBjb250YWluIGEgY2hlY2tfc2Vzc2lvbl9pZnJhbWUgZmllbGQnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW5cbiAgICAgKiBhY2Nlc3NfdG9rZW4uIEFmdGVyIHJlY2VpdmluZyB0aGUgYWNjZXNzX3Rva2VuLCB0aGlzIG1ldGhvZFxuICAgICAqIHVzZXMgaXQgdG8gcXVlcnkgdGhlIHVzZXJpbmZvIGVuZHBvaW50IGluIG9yZGVyIHRvIGdldCBpbmZvcm1hdGlvblxuICAgICAqIGFib3V0IHRoZSB1c2VyIGluIHF1ZXN0aW9uLlxuICAgICAqXG4gICAgICogV2hlbiB1c2luZyB0aGlzLCBtYWtlIHN1cmUgdGhhdCB0aGUgcHJvcGVydHkgb2lkYyBpcyBzZXQgdG8gZmFsc2UuXG4gICAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uXG4gICAgICogZmFpbC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB1c2VyTmFtZVxuICAgICAqIEBwYXJhbSBwYXNzd29yZFxuICAgICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxuICAgICAqL1xuICAgIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3dBbmRMb2FkVXNlclByb2ZpbGUoXG4gICAgICAgIHVzZXJOYW1lOiBzdHJpbmcsXG4gICAgICAgIHBhc3N3b3JkOiBzdHJpbmcsXG4gICAgICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcbiAgICApOiBQcm9taXNlPFVzZXJJbmZvPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvdyh1c2VyTmFtZSwgcGFzc3dvcmQsIGhlYWRlcnMpLnRoZW4oXG4gICAgICAgICAgICAoKSA9PiB0aGlzLmxvYWRVc2VyUHJvZmlsZSgpXG4gICAgICAgICk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTG9hZHMgdGhlIHVzZXIgcHJvZmlsZSBieSBhY2Nlc3NpbmcgdGhlIHVzZXIgaW5mbyBlbmRwb2ludCBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0LlxuICAgICAqXG4gICAgICogV2hlbiB1c2luZyB0aGlzIHdpdGggT0F1dGgyIHBhc3N3b3JkIGZsb3csIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cbiAgICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb24gZmFpbC5cbiAgICAgKi9cbiAgICBwdWJsaWMgbG9hZFVzZXJQcm9maWxlKCk6IFByb21pc2U8VXNlckluZm8+IHtcbiAgICAgICAgaWYgKCF0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdDYW4gbm90IGxvYWQgVXNlciBQcm9maWxlIHdpdGhvdXQgYWNjZXNzX3Rva2VuJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy51c2VyaW5mb0VuZHBvaW50KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCd1c2VyaW5mb0VuZHBvaW50IG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgXFwncmVxdWlyZUh0dHBzXFwnIG11c3QgYmUgc2V0IHRvIFxcJ2ZhbHNlXFwnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuJyk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgY29uc3QgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcbiAgICAgICAgICAgICAgICAnQXV0aG9yaXphdGlvbicsXG4gICAgICAgICAgICAgICAgJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmh0dHAuZ2V0PFVzZXJJbmZvPih0aGlzLnVzZXJpbmZvRW5kcG9pbnQsIHsgaGVhZGVycyB9KS5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgaW5mbyA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3VzZXJpbmZvIHJlY2VpdmVkJywgaW5mbyk7XG5cbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZXhpc3RpbmdDbGFpbXMgPSB0aGlzLmdldElkZW50aXR5Q2xhaW1zKCkgfHwge307XG5cbiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLnNraXBTdWJqZWN0Q2hlY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLm9pZGMgJiZcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAoIWV4aXN0aW5nQ2xhaW1zWydzdWInXSB8fCBpbmZvLnN1YiAhPT0gZXhpc3RpbmdDbGFpbXNbJ3N1YiddKVxuICAgICAgICAgICAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZXJyID1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2lmIHByb3BlcnR5IG9pZGMgaXMgdHJ1ZSwgdGhlIHJlY2VpdmVkIHVzZXItaWQgKHN1YikgaGFzIHRvIGJlIHRoZSB1c2VyLWlkICcgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnb2YgdGhlIHVzZXIgdGhhdCBoYXMgbG9nZ2VkIGluIHdpdGggb2lkYy5cXG4nICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2lmIHlvdSBhcmUgbm90IHVzaW5nIG9pZGMgYnV0IGp1c3Qgb2F1dGgyIHBhc3N3b3JkIGZsb3cgc2V0IG9pZGMgdG8gZmFsc2UnO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaW5mbyA9IE9iamVjdC5hc3NpZ24oe30sIGV4aXN0aW5nQ2xhaW1zLCBpbmZvKTtcblxuICAgICAgICAgICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonLCBKU09OLnN0cmluZ2lmeShpbmZvKSk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndXNlcl9wcm9maWxlX2xvYWRlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZShpbmZvKTtcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIHVzZXIgaW5mbycsIGVycik7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndXNlcl9wcm9maWxlX2xvYWRfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVzZXMgcGFzc3dvcmQgZmxvdyB0byBleGNoYW5nZSB1c2VyTmFtZSBhbmQgcGFzc3dvcmQgZm9yIGFuIGFjY2Vzc190b2tlbi5cbiAgICAgKiBAcGFyYW0gdXNlck5hbWVcbiAgICAgKiBAcGFyYW0gcGFzc3dvcmRcbiAgICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cbiAgICAgKi9cbiAgICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93KFxuICAgICAgICB1c2VyTmFtZTogc3RyaW5nLFxuICAgICAgICBwYXNzd29yZDogc3RyaW5nLFxuICAgICAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXG5cbiAgICApOiBQcm9taXNlPFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgdGhpcy5hc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKHRoaXMudG9rZW5FbmRwb2ludCwgJ3Rva2VuRW5kcG9pbnQnKTtcblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBBIGBIdHRwUGFyYW1ldGVyQ29kZWNgIHRoYXQgdXNlcyBgZW5jb2RlVVJJQ29tcG9uZW50YCBhbmQgYGRlY29kZVVSSUNvbXBvbmVudGAgdG9cbiAgICAgICAgICAgICAqIHNlcmlhbGl6ZSBhbmQgcGFyc2UgVVJMIHBhcmFtZXRlciBrZXlzIGFuZCB2YWx1ZXMuXG4gICAgICAgICAgICAgKlxuICAgICAgICAgICAgICogQHN0YWJsZVxuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoeyBlbmNvZGVyOiBuZXcgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMoKSB9KVxuICAgICAgICAgICAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAncGFzc3dvcmQnKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3Njb3BlJywgdGhpcy5zY29wZSlcbiAgICAgICAgICAgICAgICAuc2V0KCd1c2VybmFtZScsIHVzZXJOYW1lKVxuICAgICAgICAgICAgICAgIC5zZXQoJ3Bhc3N3b3JkJywgcGFzc3dvcmQpO1xuXG4gICAgICAgICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XG4gICAgICAgICAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KFxuICAgICAgICAgICAgICAgICAgICAnQXV0aG9yaXphdGlvbicsXG4gICAgICAgICAgICAgICAgICAgICdCYXNpYyAnICsgaGVhZGVyKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGggJiYgdGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgICAgICAgICAnQ29udGVudC1UeXBlJyxcbiAgICAgICAgICAgICAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgdGhpcy5odHRwXG4gICAgICAgICAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciBwZXJmb3JtaW5nIHBhc3N3b3JkIGZsb3cnLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCBlcnIpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVmcmVzaGVzIHRoZSB0b2tlbiB1c2luZyBhIHJlZnJlc2hfdG9rZW4uXG4gICAgICogVGhpcyBkb2VzIG5vdCB3b3JrIGZvciBpbXBsaWNpdCBmbG93LCBiL2NcbiAgICAgKiB0aGVyZSBpcyBubyByZWZyZXNoX3Rva2VuIGluIHRoaXMgZmxvdy5cbiAgICAgKiBBIHNvbHV0aW9uIGZvciB0aGlzIGlzIHByb3ZpZGVkIGJ5IHRoZVxuICAgICAqIG1ldGhvZCBzaWxlbnRSZWZyZXNoLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWZyZXNoVG9rZW4oKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbCh0aGlzLnRva2VuRW5kcG9pbnQsICd0b2tlbkVuZHBvaW50Jyk7XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXG4gICAgICAgICAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdyZWZyZXNoX3Rva2VuJylcbiAgICAgICAgICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXG4gICAgICAgICAgICAgICAgLnNldCgncmVmcmVzaF90b2tlbicsIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgncmVmcmVzaF90b2tlbicpKTtcblxuICAgICAgICAgICAgbGV0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXG4gICAgICAgICAgICAgICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgICAgICAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcbiAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcbiAgICAgICAgICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXG4gICAgICAgICAgICAgICAgICAgICdBdXRob3JpemF0aW9uJyxcbiAgICAgICAgICAgICAgICAgICAgJ0Jhc2ljICcgKyBoZWFkZXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICAgICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdGhpcy5odHRwXG4gICAgICAgICAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxuICAgICAgICAgICAgICAgIC5waXBlKHN3aXRjaE1hcCh0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmcm9tKHRoaXMucHJvY2Vzc0lkVG9rZW4odG9rZW5SZXNwb25zZS5pZF90b2tlbiwgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sIHRydWUpKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC5waXBlKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0YXAocmVzdWx0ID0+IHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCkpLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtYXAoXyA9PiB0b2tlblJlc3BvbnNlKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gb2YodG9rZW5SZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KSlcbiAgICAgICAgICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3JlZnJlc2ggdG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHJlZnJlc2hpbmcgdG9rZW4nLCBlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCByZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lcikge1xuICAgICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoXG4gICAgICAgICAgICAgICAgJ21lc3NhZ2UnLFxuICAgICAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lclxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IG51bGw7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc2V0dXBTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5yZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLnByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGUpO1xuXG4gICAgICAgICAgICB0aGlzLnRyeUxvZ2luKHtcbiAgICAgICAgICAgICAgICBjdXN0b21IYXNoRnJhZ21lbnQ6IG1lc3NhZ2UsXG4gICAgICAgICAgICAgICAgcHJldmVudENsZWFySGFzaEFmdGVyTG9naW46IHRydWUsXG4gICAgICAgICAgICAgICAgY3VzdG9tUmVkaXJlY3RVcmk6IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmlcbiAgICAgICAgICAgIH0pLmNhdGNoKGVyciA9PiB0aGlzLmRlYnVnKCd0cnlMb2dpbiBkdXJpbmcgc2lsZW50IHJlZnJlc2ggZmFpbGVkJywgZXJyKSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoXG4gICAgICAgICAgICAnbWVzc2FnZScsXG4gICAgICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcbiAgICAgICAgKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQZXJmb3JtcyBhIHNpbGVudCByZWZyZXNoIGZvciBpbXBsaWNpdCBmbG93LlxuICAgICAqIFVzZSB0aGlzIG1ldGhvZCB0byBnZXQgbmV3IHRva2VucyB3aGVuL2JlZm9yZVxuICAgICAqIHRoZSBleGlzdGluZyB0b2tlbnMgZXhwaXJlLlxuICAgICAqL1xuICAgIHB1YmxpYyBzaWxlbnRSZWZyZXNoKHBhcmFtczogb2JqZWN0ID0ge30sIG5vUHJvbXB0ID0gdHJ1ZSk6IFByb21pc2U8T0F1dGhFdmVudD4ge1xuICAgICAgICBjb25zdCBjbGFpbXM6IG9iamVjdCA9IHRoaXMuZ2V0SWRlbnRpdHlDbGFpbXMoKSB8fCB7fTtcblxuICAgICAgICBpZiAodGhpcy51c2VJZFRva2VuSGludEZvclNpbGVudFJlZnJlc2ggJiYgdGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgICAgICAgcGFyYW1zWydpZF90b2tlbl9oaW50J10gPSB0aGlzLmdldElkVG9rZW4oKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ2xvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5IFxcJ3JlcXVpcmVIdHRwc1xcJyBtdXN0IGJlIHNldCB0byBcXCdmYWxzZVxcJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLicpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHR5cGVvZiBkb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignc2lsZW50IHJlZnJlc2ggaXMgbm90IHN1cHBvcnRlZCBvbiB0aGlzIHBsYXRmb3JtJyk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBleGlzdGluZ0lmcmFtZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoSUZyYW1lTmFtZVxuICAgICAgICApO1xuXG4gICAgICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xuICAgICAgICAgICAgZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChleGlzdGluZ0lmcmFtZSk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gY2xhaW1zWydzdWInXTtcblxuICAgICAgICBjb25zdCBpZnJhbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcbiAgICAgICAgaWZyYW1lLmlkID0gdGhpcy5zaWxlbnRSZWZyZXNoSUZyYW1lTmFtZTtcblxuICAgICAgICB0aGlzLnNldHVwU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcblxuICAgICAgICBjb25zdCByZWRpcmVjdFVyaSA9IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmk7XG4gICAgICAgIHRoaXMuY3JlYXRlTG9naW5VcmwobnVsbCwgbnVsbCwgcmVkaXJlY3RVcmksIG5vUHJvbXB0LCBwYXJhbXMpLnRoZW4odXJsID0+IHtcbiAgICAgICAgICAgIGlmcmFtZS5zZXRBdHRyaWJ1dGUoJ3NyYycsIHVybCk7XG5cbiAgICAgICAgICAgIGlmICghdGhpcy5zaWxlbnRSZWZyZXNoU2hvd0lGcmFtZSkge1xuICAgICAgICAgICAgICAgIGlmcmFtZS5zdHlsZVsnZGlzcGxheSddID0gJ25vbmUnO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xuICAgICAgICB9KTtcblxuICAgICAgICBjb25zdCBlcnJvcnMgPSB0aGlzLmV2ZW50cy5waXBlKFxuICAgICAgICAgICAgZmlsdGVyKGUgPT4gZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCksXG4gICAgICAgICAgICBmaXJzdCgpXG4gICAgICAgICk7XG4gICAgICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLmV2ZW50cy5waXBlKFxuICAgICAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSxcbiAgICAgICAgICAgIGZpcnN0KClcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3QgdGltZW91dCA9IG9mKFxuICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfdGltZW91dCcsIG51bGwpXG4gICAgICAgICkucGlwZShkZWxheSh0aGlzLnNpbGVudFJlZnJlc2hUaW1lb3V0KSk7XG5cbiAgICAgICAgcmV0dXJuIHJhY2UoW2Vycm9ycywgc3VjY2VzcywgdGltZW91dF0pXG4gICAgICAgICAgICAucGlwZShcbiAgICAgICAgICAgICAgICBtYXAoZSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZSA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ3NpbGVudF9yZWZyZXNoX2Vycm9yJywgZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB0aHJvdyBlO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZSA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnc2lsZW50bHlfcmVmcmVzaGVkJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgLnRvUHJvbWlzZSgpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFRoaXMgbWV0aG9kIGV4aXN0cyBmb3IgYmFja3dhcmRzIGNvbXBhdGliaWxpdHkuXG4gICAgICoge0BsaW5rIE9BdXRoU2VydmljZSNpbml0TG9naW5GbG93SW5Qb3B1cH0gaGFuZGxlcyBib3RoIGNvZGVcbiAgICAgKiBhbmQgaW1wbGljaXQgZmxvd3MuXG4gICAgICovXG4gICAgcHVibGljIGluaXRJbXBsaWNpdEZsb3dJblBvcHVwKG9wdGlvbnM/OiB7IGhlaWdodD86IG51bWJlciwgd2lkdGg/OiBudW1iZXIgfSkge1xuICAgICAgICByZXR1cm4gdGhpcy5pbml0TG9naW5GbG93SW5Qb3B1cChvcHRpb25zKTtcbiAgICB9XG5cbiAgICBwdWJsaWMgaW5pdExvZ2luRmxvd0luUG9wdXAob3B0aW9ucz86IHsgaGVpZ2h0PzogbnVtYmVyLCB3aWR0aD86IG51bWJlciB9KSB7XG4gICAgICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuICAgICAgICByZXR1cm4gdGhpcy5jcmVhdGVMb2dpblVybChudWxsLCBudWxsLCB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSwgZmFsc2UsIHtcbiAgICAgICAgICAgIGRpc3BsYXk6ICdwb3B1cCdcbiAgICAgICAgfSkudGhlbih1cmwgPT4ge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAgICAgKiBFcnJvciBoYW5kbGluZyBzZWN0aW9uXG4gICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgY29uc3QgY2hlY2tGb3JQb3B1cENsb3NlZEludGVydmFsID0gNTAwO1xuICAgICAgICAgICAgICAgIGxldCB3aW5kb3dSZWYgPSB3aW5kb3cub3Blbih1cmwsICdfYmxhbmsnLCB0aGlzLmNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9ucykpO1xuICAgICAgICAgICAgICAgIGxldCBjaGVja0ZvclBvcHVwQ2xvc2VkVGltZXI6IGFueTtcbiAgICAgICAgICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkID0gKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIXdpbmRvd1JlZiB8fCB3aW5kb3dSZWYuY2xvc2VkKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjbGVhbnVwKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWplY3QobmV3IE9BdXRoRXJyb3JFdmVudCgncG9wdXBfY2xvc2VkJywge30pKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgaWYgKCF3aW5kb3dSZWYpIHtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3BvcHVwX2Jsb2NrZWQnLCB7fSkpO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGNoZWNrRm9yUG9wdXBDbG9zZWRUaW1lciA9IHdpbmRvdy5zZXRJbnRlcnZhbChjaGVja0ZvclBvcHVwQ2xvc2VkLCBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWwpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGNvbnN0IGNsZWFudXAgPSAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHdpbmRvdy5jbGVhckludGVydmFsKGNoZWNrRm9yUG9wdXBDbG9zZWRUaW1lcik7XG4gICAgICAgICAgICAgICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgICAgICBpZiAod2luZG93UmVmICE9PSBudWxsKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB3aW5kb3dSZWYuY2xvc2UoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB3aW5kb3dSZWYgPSBudWxsO1xuICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICBjb25zdCBsaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgbWVzc2FnZSA9IHRoaXMucHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYgKG1lc3NhZ2UgJiYgbWVzc2FnZSAhPT0gbnVsbCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy50cnlMb2dpbih7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY3VzdG9tSGFzaEZyYWdtZW50OiBtZXNzYWdlLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luOiB0cnVlLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN1c3RvbVJlZGlyZWN0VXJpOiB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSxcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pLnRoZW4oKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9LCBlcnIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ2ZhbHNlIGV2ZW50IGZpcmluZycpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBsaXN0ZW5lcik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9uczogeyBoZWlnaHQ/OiBudW1iZXIsIHdpZHRoPzogbnVtYmVyIH0pOiBzdHJpbmcge1xuICAgICAgICAvLyBTcGVjaWZ5IGFuIHN0YXRpYyBoZWlnaHQgYW5kIHdpZHRoIGFuZCBjYWxjdWxhdGUgY2VudGVyZWQgcG9zaXRpb25cblxuICAgICAgICBjb25zdCBoZWlnaHQgPSBvcHRpb25zLmhlaWdodCB8fCA0NzA7XG4gICAgICAgIGNvbnN0IHdpZHRoID0gb3B0aW9ucy53aWR0aCB8fCA1MDA7XG4gICAgICAgIGNvbnN0IGxlZnQgPSB3aW5kb3cuc2NyZWVuTGVmdCArICgod2luZG93Lm91dGVyV2lkdGggLSB3aWR0aCkgLyAyKTtcbiAgICAgICAgY29uc3QgdG9wID0gd2luZG93LnNjcmVlblRvcCArICgod2luZG93Lm91dGVySGVpZ2h0IC0gaGVpZ2h0KSAvIDIpO1xuICAgICAgICByZXR1cm4gYGxvY2F0aW9uPW5vLHRvb2xiYXI9bm8sd2lkdGg9JHt3aWR0aH0saGVpZ2h0PSR7aGVpZ2h0fSx0b3A9JHt0b3B9LGxlZnQ9JHtsZWZ0fWA7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGU6IE1lc3NhZ2VFdmVudCk6IHN0cmluZyB7XG4gICAgICAgIGxldCBleHBlY3RlZFByZWZpeCA9ICcjJztcblxuICAgICAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeCkge1xuICAgICAgICAgICAgZXhwZWN0ZWRQcmVmaXggKz0gdGhpcy5zaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeDtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghZSB8fCAhZS5kYXRhIHx8IHR5cGVvZiBlLmRhdGEgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBwcmVmaXhlZE1lc3NhZ2U6IHN0cmluZyA9IGUuZGF0YTtcblxuICAgICAgICBpZiAoIXByZWZpeGVkTWVzc2FnZS5zdGFydHNXaXRoKGV4cGVjdGVkUHJlZml4KSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuICcjJyArIHByZWZpeGVkTWVzc2FnZS5zdWJzdHIoZXhwZWN0ZWRQcmVmaXgubGVuZ3RoKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2FuUGVyZm9ybVNlc3Npb25DaGVjaygpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybCkge1xuICAgICAgICAgICAgY29uc29sZS53YXJuKFxuICAgICAgICAgICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25DaGVja0lGcmFtZVVybCdcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gdGhpcy5nZXRTZXNzaW9uU3RhdGUoKTtcbiAgICAgICAgaWYgKCFzZXNzaW9uU3RhdGUpIHtcbiAgICAgICAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCB0aGVyZSBpcyBubyBzZXNzaW9uX3N0YXRlJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHNldHVwU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XG5cbiAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgICAgICAgY29uc3Qgb3JpZ2luID0gZS5vcmlnaW4udG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIGNvbnN0IGlzc3VlciA9IHRoaXMuaXNzdWVyLnRvTG93ZXJDYXNlKCk7XG5cbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3Nlc3Npb25DaGVja0V2ZW50TGlzdGVuZXInKTtcblxuICAgICAgICAgICAgaWYgKCFpc3N1ZXIuc3RhcnRzV2l0aChvcmlnaW4pKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5kZWJ1ZyhcbiAgICAgICAgICAgICAgICAgICAgJ3Nlc3Npb25DaGVja0V2ZW50TGlzdGVuZXInLFxuICAgICAgICAgICAgICAgICAgICAnd3Jvbmcgb3JpZ2luJyxcbiAgICAgICAgICAgICAgICAgICAgb3JpZ2luLFxuICAgICAgICAgICAgICAgICAgICAnZXhwZWN0ZWQnLFxuICAgICAgICAgICAgICAgICAgICBpc3N1ZXJcbiAgICAgICAgICAgICAgICApO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBvbmx5IHJ1biBpbiBBbmd1bGFyIHpvbmUgaWYgaXQgaXMgJ2NoYW5nZWQnIG9yICdlcnJvcidcbiAgICAgICAgICAgIHN3aXRjaCAoZS5kYXRhKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAndW5jaGFuZ2VkJzpcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uVW5jaGFuZ2VkKCk7XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ2NoYW5nZWQnOlxuICAgICAgICAgICAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uQ2hhbmdlKCk7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdlcnJvcic6XG4gICAgICAgICAgICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25FcnJvcigpO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ2dvdCBpbmZvIGZyb20gc2Vzc2lvbiBjaGVjayBpbmZyYW1lJywgZSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgLy8gcHJldmVudCBBbmd1bGFyIGZyb20gcmVmcmVzaGluZyB0aGUgdmlldyBvbiBldmVyeSBtZXNzYWdlIChydW5zIGluIGludGVydmFscylcbiAgICAgICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpOiB2b2lkIHtcbiAgICAgICAgdGhpcy5kZWJ1Zygnc2Vzc2lvbiBjaGVjaycsICdzZXNzaW9uIHVuY2hhbmdlZCcpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uQ2hhbmdlKCk6IHZvaWQge1xuICAgICAgICAvKiBldmVudHM6IHNlc3Npb25fY2hhbmdlZCwgcmVsb2dpbiwgc3RvcFRpbWVyLCBsb2dnZWRfb3V0Ki9cbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX2NoYW5nZWQnKSk7XG4gICAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgICAgIGlmICh0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSkge1xuICAgICAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoKCkuY2F0Y2goXyA9PlxuICAgICAgICAgICAgICAgIHRoaXMuZGVidWcoJ3NpbGVudCByZWZyZXNoIGZhaWxlZCBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHRoaXMud2FpdEZvclNpbGVudFJlZnJlc2hBZnRlclNlc3Npb25DaGFuZ2UoKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl90ZXJtaW5hdGVkJykpO1xuICAgICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgd2FpdEZvclNpbGVudFJlZnJlc2hBZnRlclNlc3Npb25DaGFuZ2UoKTogdm9pZCB7XG4gICAgICAgIHRoaXMuZXZlbnRzXG4gICAgICAgICAgICAucGlwZShcbiAgICAgICAgICAgICAgICBmaWx0ZXIoXG4gICAgICAgICAgICAgICAgICAgIChlOiBPQXV0aEV2ZW50KSA9PlxuICAgICAgICAgICAgICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50bHlfcmVmcmVzaGVkJyB8fFxuICAgICAgICAgICAgICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcgfHxcbiAgICAgICAgICAgICAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX2Vycm9yJ1xuICAgICAgICAgICAgICAgICksXG4gICAgICAgICAgICAgICAgZmlyc3QoKVxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgICAgICAgICBpZiAoZS50eXBlICE9PSAnc2lsZW50bHlfcmVmcmVzaGVkJykge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJyk7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl90ZXJtaW5hdGVkJykpO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ091dCh0cnVlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkVycm9yKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fZXJyb3InKSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpIHtcbiAgICAgICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKTtcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IG51bGw7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgaW5pdFNlc3Npb25DaGVjaygpOiB2b2lkIHtcbiAgICAgICAgaWYgKCF0aGlzLmNhblBlcmZvcm1TZXNzaW9uQ2hlY2soKSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgZXhpc3RpbmdJZnJhbWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWUpO1xuICAgICAgICBpZiAoZXhpc3RpbmdJZnJhbWUpIHtcbiAgICAgICAgICAgIGRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoZXhpc3RpbmdJZnJhbWUpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgaWZyYW1lID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaWZyYW1lJyk7XG4gICAgICAgIGlmcmFtZS5pZCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZTtcblxuICAgICAgICB0aGlzLnNldHVwU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpO1xuXG4gICAgICAgIGNvbnN0IHVybCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xuICAgICAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xuICAgICAgICBpZnJhbWUuc3R5bGUuZGlzcGxheSA9ICdub25lJztcbiAgICAgICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xuXG4gICAgICAgIHRoaXMuc3RhcnRTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBzdGFydFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xuICAgICAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgICAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja1RpbWVyID0gc2V0SW50ZXJ2YWwoXG4gICAgICAgICAgICAgICAgdGhpcy5jaGVja1Nlc3Npb24uYmluZCh0aGlzKSxcbiAgICAgICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja0ludGVydmFsbFxuICAgICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIpIHtcbiAgICAgICAgICAgIGNsZWFySW50ZXJ2YWwodGhpcy5zZXNzaW9uQ2hlY2tUaW1lcik7XG4gICAgICAgICAgICB0aGlzLnNlc3Npb25DaGVja1RpbWVyID0gbnVsbDtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBjaGVja1Nlc3Npb24oKTogdm9pZCB7XG4gICAgICAgIGNvbnN0IGlmcmFtZTogYW55ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQodGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lKTtcblxuICAgICAgICBpZiAoIWlmcmFtZSkge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgICAgICAgICAnY2hlY2tTZXNzaW9uIGRpZCBub3QgZmluZCBpZnJhbWUnLFxuICAgICAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHRoaXMuZ2V0U2Vzc2lvblN0YXRlKCk7XG5cbiAgICAgICAgaWYgKCFzZXNzaW9uU3RhdGUpIHtcbiAgICAgICAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5jbGllbnRJZCArICcgJyArIHNlc3Npb25TdGF0ZTtcbiAgICAgICAgaWZyYW1lLmNvbnRlbnRXaW5kb3cucG9zdE1lc3NhZ2UobWVzc2FnZSwgdGhpcy5pc3N1ZXIpO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBhc3luYyBjcmVhdGVMb2dpblVybChcbiAgICAgICAgc3RhdGUgPSAnJyxcbiAgICAgICAgbG9naW5IaW50ID0gJycsXG4gICAgICAgIGN1c3RvbVJlZGlyZWN0VXJpID0gJycsXG4gICAgICAgIG5vUHJvbXB0ID0gZmFsc2UsXG4gICAgICAgIHBhcmFtczogb2JqZWN0ID0ge31cbiAgICApOiBQcm9taXNlPHN0cmluZz4ge1xuICAgICAgICBjb25zdCB0aGF0ID0gdGhpcztcblxuICAgICAgICBsZXQgcmVkaXJlY3RVcmk6IHN0cmluZztcblxuICAgICAgICBpZiAoY3VzdG9tUmVkaXJlY3RVcmkpIHtcbiAgICAgICAgICAgIHJlZGlyZWN0VXJpID0gY3VzdG9tUmVkaXJlY3RVcmk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICByZWRpcmVjdFVyaSA9IHRoaXMucmVkaXJlY3RVcmk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBub25jZSA9IGF3YWl0IHRoaXMuY3JlYXRlQW5kU2F2ZU5vbmNlKCk7XG5cbiAgICAgICAgaWYgKHN0YXRlKSB7XG4gICAgICAgICAgICBzdGF0ZSA9IG5vbmNlICsgdGhpcy5jb25maWcubm9uY2VTdGF0ZVNlcGFyYXRvciArIHN0YXRlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgc3RhdGUgPSBub25jZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIXRoaXMub2lkYykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICdFaXRoZXIgcmVxdWVzdEFjY2Vzc1Rva2VuIG9yIG9pZGMgb3IgYm90aCBtdXN0IGJlIHRydWUnXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSkge1xuICAgICAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSB0aGlzLmNvbmZpZy5yZXNwb25zZVR5cGU7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpZiAodGhpcy5vaWRjICYmIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSAnaWRfdG9rZW4gdG9rZW4nO1xuICAgICAgICAgICAgfSBlbHNlIGlmICh0aGlzLm9pZGMgJiYgIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSAnaWRfdG9rZW4nO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICd0b2tlbic7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBzZXBlcmF0aW9uQ2hhciA9IHRoYXQubG9naW5VcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPyc7XG5cbiAgICAgICAgbGV0IHNjb3BlID0gdGhhdC5zY29wZTtcblxuICAgICAgICBpZiAodGhpcy5vaWRjICYmICFzY29wZS5tYXRjaCgvKF58XFxzKW9wZW5pZCgkfFxccykvKSkge1xuICAgICAgICAgICAgc2NvcGUgPSAnb3BlbmlkICcgKyBzY29wZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCB1cmwgPVxuICAgICAgICAgICAgdGhhdC5sb2dpblVybCArXG4gICAgICAgICAgICBzZXBlcmF0aW9uQ2hhciArXG4gICAgICAgICAgICAncmVzcG9uc2VfdHlwZT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LnJlc3BvbnNlVHlwZSkgK1xuICAgICAgICAgICAgJyZjbGllbnRfaWQ9JyArXG4gICAgICAgICAgICBlbmNvZGVVUklDb21wb25lbnQodGhhdC5jbGllbnRJZCkgK1xuICAgICAgICAgICAgJyZzdGF0ZT0nICtcbiAgICAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzdGF0ZSkgK1xuICAgICAgICAgICAgJyZyZWRpcmVjdF91cmk9JyArXG4gICAgICAgICAgICBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpICtcbiAgICAgICAgICAgICcmc2NvcGU9JyArXG4gICAgICAgICAgICBlbmNvZGVVUklDb21wb25lbnQoc2NvcGUpO1xuXG4gICAgICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnICYmICF0aGlzLmRpc2FibGVQS0NFKSB7XG4gICAgICAgICAgICBjb25zdCBbY2hhbGxlbmdlLCB2ZXJpZmllcl0gPSBhd2FpdCB0aGlzLmNyZWF0ZUNoYWxsYW5nZVZlcmlmaWVyUGFpckZvclBLQ0UoKTtcbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnUEtDSV92ZXJpZmllcicsIHZlcmlmaWVyKTtcbiAgICAgICAgICAgIHVybCArPSAnJmNvZGVfY2hhbGxlbmdlPScgKyBjaGFsbGVuZ2U7XG4gICAgICAgICAgICB1cmwgKz0gJyZjb2RlX2NoYWxsZW5nZV9tZXRob2Q9UzI1Nic7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAobG9naW5IaW50KSB7XG4gICAgICAgICAgICB1cmwgKz0gJyZsb2dpbl9oaW50PScgKyBlbmNvZGVVUklDb21wb25lbnQobG9naW5IaW50KTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGF0LnJlc291cmNlKSB7XG4gICAgICAgICAgICB1cmwgKz0gJyZyZXNvdXJjZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzb3VyY2UpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoYXQub2lkYykge1xuICAgICAgICAgICAgdXJsICs9ICcmbm9uY2U9JyArIGVuY29kZVVSSUNvbXBvbmVudChub25jZSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAobm9Qcm9tcHQpIHtcbiAgICAgICAgICAgIHVybCArPSAnJnByb21wdD1ub25lJztcbiAgICAgICAgfVxuXG4gICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKHBhcmFtcykpIHtcbiAgICAgICAgICAgIHVybCArPVxuICAgICAgICAgICAgICAgICcmJyArIGVuY29kZVVSSUNvbXBvbmVudChrZXkpICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHBhcmFtc1trZXldKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgICAgICAgIHVybCArPVxuICAgICAgICAgICAgICAgICAgICAnJicgKyBrZXkgKyAnPScgKyBlbmNvZGVVUklDb21wb25lbnQodGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB1cmw7XG5cbiAgICB9XG5cbiAgICBpbml0SW1wbGljaXRGbG93SW50ZXJuYWwoXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXG4gICAgKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmluSW1wbGljaXRGbG93KSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gdHJ1ZTtcblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAgICAgICAgICdsb2dpblVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSBcXCdyZXF1aXJlSHR0cHNcXCcgbXVzdCBiZSBzZXQgdG8gXFwnZmFsc2VcXCcgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS4nXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGFkZFBhcmFtczogb2JqZWN0ID0ge307XG4gICAgICAgIGxldCBsb2dpbkhpbnQ6IHN0cmluZyA9IG51bGw7XG5cbiAgICAgICAgaWYgKHR5cGVvZiBwYXJhbXMgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICBsb2dpbkhpbnQgPSBwYXJhbXM7XG4gICAgICAgIH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ29iamVjdCcpIHtcbiAgICAgICAgICAgIGFkZFBhcmFtcyA9IHBhcmFtcztcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCBsb2dpbkhpbnQsIG51bGwsIGZhbHNlLCBhZGRQYXJhbXMpXG4gICAgICAgICAgICAudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKVxuICAgICAgICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0SW1wbGljaXRGbG93JywgZXJyb3IpO1xuICAgICAgICAgICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICAgICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFN0YXJ0cyB0aGUgaW1wbGljaXQgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cbiAgICAgKiB0aGUgYXV0aCBzZXJ2ZXJzJyBsb2dpbiB1cmwuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gYWRkaXRpb25hbFN0YXRlIE9wdGlvbmFsIHN0YXRlIHRoYXQgaXMgcGFzc2VkIGFyb3VuZC5cbiAgICAgKiAgWW91J2xsIGZpbmQgdGhpcyBzdGF0ZSBpbiB0aGUgcHJvcGVydHkgYHN0YXRlYCBhZnRlciBgdHJ5TG9naW5gIGxvZ2dlZCBpbiB0aGUgdXNlci5cbiAgICAgKiBAcGFyYW0gcGFyYW1zIEhhc2ggd2l0aCBhZGRpdGlvbmFsIHBhcmFtZXRlci4gSWYgaXQgaXMgYSBzdHJpbmcsIGl0IGlzIHVzZWQgZm9yIHRoZVxuICAgICAqICAgICAgICAgICAgICAgcGFyYW1ldGVyIGxvZ2luSGludCAoZm9yIHRoZSBzYWtlIG9mIGNvbXBhdGliaWxpdHkgd2l0aCBmb3JtZXIgdmVyc2lvbnMpXG4gICAgICovXG4gICAgcHVibGljIGluaXRJbXBsaWNpdEZsb3coXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXG4gICAgKTogdm9pZCB7XG4gICAgICAgIGlmICh0aGlzLmxvZ2luVXJsICE9PSAnJykge1xuICAgICAgICAgICAgdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5ldmVudHNcbiAgICAgICAgICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXG4gICAgICAgICAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXNldCBjdXJyZW50IGltcGxpY2l0IGZsb3dcbiAgICAgKlxuICAgICAqIEBkZXNjcmlwdGlvbiBUaGlzIG1ldGhvZCBhbGxvd3MgcmVzZXR0aW5nIHRoZSBjdXJyZW50IGltcGxpY3QgZmxvdyBpbiBvcmRlciB0byBiZSBpbml0aWFsaXplZCBhZ2Fpbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVzZXRJbXBsaWNpdEZsb3coKTogdm9pZCB7XG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnM6IExvZ2luT3B0aW9ucyk6IHZvaWQge1xuICAgICAgICBjb25zdCB0aGF0ID0gdGhpcztcbiAgICAgICAgaWYgKG9wdGlvbnMub25Ub2tlblJlY2VpdmVkKSB7XG4gICAgICAgICAgICBjb25zdCB0b2tlblBhcmFtcyA9IHtcbiAgICAgICAgICAgICAgICBpZENsYWltczogdGhhdC5nZXRJZGVudGl0eUNsYWltcygpLFxuICAgICAgICAgICAgICAgIGlkVG9rZW46IHRoYXQuZ2V0SWRUb2tlbigpLFxuICAgICAgICAgICAgICAgIGFjY2Vzc1Rva2VuOiB0aGF0LmdldEFjY2Vzc1Rva2VuKCksXG4gICAgICAgICAgICAgICAgc3RhdGU6IHRoYXQuc3RhdGVcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBvcHRpb25zLm9uVG9rZW5SZWNlaXZlZCh0b2tlblBhcmFtcyk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxuICAgICAgICByZWZyZXNoVG9rZW46IHN0cmluZyxcbiAgICAgICAgZXhwaXJlc0luOiBudW1iZXIsXG4gICAgICAgIGdyYW50ZWRTY29wZXM6IFN0cmluZyxcbiAgICAgICAgY3VzdG9tUGFyYW1ldGVycz86IGFueVxuICAgICk6IHZvaWQge1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbicsIGFjY2Vzc1Rva2VuKTtcbiAgICAgICAgaWYgKGdyYW50ZWRTY29wZXMpIHtcbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnLCBKU09OLnN0cmluZ2lmeShncmFudGVkU2NvcGVzLnNwbGl0KCcrJykpKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xuICAgICAgICBpZiAoZXhwaXJlc0luKSB7XG4gICAgICAgICAgICBjb25zdCBleHBpcmVzSW5NaWxsaVNlY29uZHMgPSBleHBpcmVzSW4gKiAxMDAwO1xuICAgICAgICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXNBdCA9IG5vdy5nZXRUaW1lKCkgKyBleHBpcmVzSW5NaWxsaVNlY29uZHM7XG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2V4cGlyZXNfYXQnLCAnJyArIGV4cGlyZXNBdCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAocmVmcmVzaFRva2VuKSB7XG4gICAgICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nLCByZWZyZXNoVG9rZW4pO1xuICAgICAgICB9XG4gICAgICAgIGlmIChjdXN0b21QYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgICBPYmplY3Qua2V5cyhjdXN0b21QYXJhbWV0ZXJzKS5mb3JFYWNoKGtleSA9PiB7XG4gICAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbShrZXksIGN1c3RvbVBhcmFtZXRlcnNba2V5XSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlbGVnYXRlcyB0byB0cnlMb2dpbkltcGxpY2l0RmxvdyBmb3IgdGhlIHNha2Ugb2YgY29tcGV0YWJpbGl0eVxuICAgICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXG4gICAgICovXG4gICAgcHVibGljIHRyeUxvZ2luKG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy50cnlMb2dpbkNvZGVGbG93KG9wdGlvbnMpLnRoZW4oXyA9PiB0cnVlKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luSW1wbGljaXRGbG93KG9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgfVxuXG5cblxuICAgIHByaXZhdGUgcGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcbiAgICAgICAgaWYgKCFxdWVyeVN0cmluZyB8fCBxdWVyeVN0cmluZy5sZW5ndGggPT09IDApIHtcbiAgICAgICAgICAgIHJldHVybiB7fTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChxdWVyeVN0cmluZy5jaGFyQXQoMCkgPT09ICc/Jykge1xuICAgICAgICAgICAgcXVlcnlTdHJpbmcgPSBxdWVyeVN0cmluZy5zdWJzdHIoMSk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy51cmxIZWxwZXIucGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZyk7XG5cblxuICAgIH1cblxuICAgIHB1YmxpYyB0cnlMb2dpbkNvZGVGbG93KG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAgICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgICAgICAgY29uc3QgcXVlcnlTb3VyY2UgPSBvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCA/XG4gICAgICAgICAgICBvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudC5zdWJzdHJpbmcoMSkgOlxuICAgICAgICAgICAgd2luZG93LmxvY2F0aW9uLnNlYXJjaDtcblxuICAgICAgICBjb25zdCBwYXJ0cyA9IHRoaXMuZ2V0Q29kZVBhcnRzRnJvbVVybCh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcblxuICAgICAgICBjb25zdCBjb2RlID0gcGFydHNbJ2NvZGUnXTtcbiAgICAgICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgICAgICBpZiAoIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgICAgICAgIGNvbnN0IGhyZWYgPSBsb2NhdGlvbi5ocmVmXG4gICAgICAgICAgICAgICAgLnJlcGxhY2UoL1smXFw/XWNvZGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvWyZcXD9dc2NvcGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvWyZcXD9dc3RhdGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvWyZcXD9dc2Vzc2lvbl9zdGF0ZT1bXiZcXCRdKi8sICcnKTtcblxuICAgICAgICAgICAgaGlzdG9yeS5yZXBsYWNlU3RhdGUobnVsbCwgd2luZG93Lm5hbWUsIGhyZWYpO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IFtub25jZUluU3RhdGUsIHVzZXJTdGF0ZV0gPSB0aGlzLnBhcnNlU3RhdGUoc3RhdGUpO1xuICAgICAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xuXG4gICAgICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygnZXJyb3IgdHJ5aW5nIHRvIGxvZ2luJyk7XG4gICAgICAgICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Ioe30sIHBhcnRzKTtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2NvZGVfZXJyb3InLCB7fSwgcGFydHMpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFub25jZUluU3RhdGUpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLnZhbGlkYXRlTm9uY2Uobm9uY2VJblN0YXRlKTtcbiAgICAgICAgaWYgKCFzdWNjZXNzKSB7XG4gICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChldmVudCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoY29kZSkge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgICAgICAgICAgICB0aGlzLmdldFRva2VuRnJvbUNvZGUoY29kZSwgb3B0aW9ucykudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICAgICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgICAgICAgICAgfSkuY2F0Y2goZXJyID0+IHtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICogUmV0cmlldmUgdGhlIHJldHVybmVkIGF1dGggY29kZSBmcm9tIHRoZSByZWRpcmVjdCB1cmkgdGhhdCBoYXMgYmVlbiBjYWxsZWQuXG4gICAgKiBJZiByZXF1aXJlZCBhbHNvIGNoZWNrIGhhc2gsIGFzIHdlIGNvdWxkIHVzZSBoYXNoIGxvY2F0aW9uIHN0cmF0ZWd5LlxuICAgICovXG4gICAgcHJpdmF0ZSBnZXRDb2RlUGFydHNGcm9tVXJsKHF1ZXJ5U3RyaW5nOiBzdHJpbmcpOiBvYmplY3Qge1xuICAgICAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcygpO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gbm9ybWFsaXplIHF1ZXJ5IHN0cmluZ1xuICAgICAgICBpZiAocXVlcnlTdHJpbmcuY2hhckF0KDApID09PSAnPycpIHtcbiAgICAgICAgICAgIHF1ZXJ5U3RyaW5nID0gcXVlcnlTdHJpbmcuc3Vic3RyKDEpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLnBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmcpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEdldCB0b2tlbiB1c2luZyBhbiBpbnRlcm1lZGlhdGUgY29kZS4gV29ya3MgZm9yIHRoZSBBdXRob3JpemF0aW9uIENvZGUgZmxvdy5cbiAgICAgKi9cbiAgICBwcml2YXRlIGdldFRva2VuRnJvbUNvZGUoY29kZTogc3RyaW5nLCBvcHRpb25zOiBMb2dpbk9wdGlvbnMpOiBQcm9taXNlPG9iamVjdD4ge1xuICAgICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKVxuICAgICAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdhdXRob3JpemF0aW9uX2NvZGUnKVxuICAgICAgICAgICAgLnNldCgnY29kZScsIGNvZGUpXG4gICAgICAgICAgICAuc2V0KCdyZWRpcmVjdF91cmknLCBvcHRpb25zLmN1c3RvbVJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmkpO1xuXG4gICAgICAgIGlmICghdGhpcy5kaXNhYmxlUEtDRSkge1xuICAgICAgICAgICAgY29uc3QgcGtjaVZlcmlmaWVyID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdQS0NJX3ZlcmlmaWVyJyk7XG5cbiAgICAgICAgICAgIGlmICghcGtjaVZlcmlmaWVyKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS53YXJuKCdObyBQS0NJIHZlcmlmaWVyIGZvdW5kIGluIG9hdXRoIHN0b3JhZ2UhJyk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NvZGVfdmVyaWZpZXInLCBwa2NpVmVyaWZpZXIpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRoaXMuZmV0Y2hBbmRQcm9jZXNzVG9rZW4ocGFyYW1zKTtcbiAgICB9XG5cbiAgICBwcml2YXRlIGZldGNoQW5kUHJvY2Vzc1Rva2VuKHBhcmFtczogSHR0cFBhcmFtcyk6IFByb21pc2U8VG9rZW5SZXNwb25zZT4ge1xuXG4gICAgICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbCh0aGlzLnRva2VuRW5kcG9pbnQsICd0b2tlbkVuZHBvaW50Jyk7XG4gICAgICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcbiAgICAgICAgICAgIC5zZXQoJ0NvbnRlbnQtVHlwZScsICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnKTtcblxuICAgICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcbiAgICAgICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgICAgICAgICAnQXV0aG9yaXphdGlvbicsXG4gICAgICAgICAgICAgICAgJ0Jhc2ljICcgKyBoZWFkZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGggJiYgdGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xuICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcblxuICAgICAgICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0aGlzLmh0dHAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pLnN1YnNjcmliZShcbiAgICAgICAgICAgICAgICAodG9rZW5SZXNwb25zZSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UucmVmcmVzaF90b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbixcbiAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyh0b2tlblJlc3BvbnNlKSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYgKHRoaXMub2lkYyAmJiB0b2tlblJlc3BvbnNlLmlkX3Rva2VuKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnByb2Nlc3NJZFRva2VuKHRva2VuUmVzcG9uc2UuaWRfdG9rZW4sIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuKS5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIHZhbGlkYXRpbmcgdG9rZW5zJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IocmVhc29uKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWplY3QocmVhc29uKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgKGVycikgPT4ge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBnZXR0aW5nIHRva2VuJywgZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycikpO1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICApO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDaGVja3Mgd2hldGhlciB0aGVyZSBhcmUgdG9rZW5zIGluIHRoZSBoYXNoIGZyYWdtZW50XG4gICAgICogYXMgYSByZXN1bHQgb2YgdGhlIGltcGxpY2l0IGZsb3cuIFRoZXNlIHRva2VucyBhcmVcbiAgICAgKiBwYXJzZWQsIHZhbGlkYXRlZCBhbmQgdXNlZCB0byBzaWduIHRoZSB1c2VyIGluIHRvIHRoZVxuICAgICAqIGN1cnJlbnQgY2xpZW50LlxuICAgICAqXG4gICAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cbiAgICAgKi9cbiAgICBwdWJsaWMgdHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgICAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcblxuICAgICAgICBsZXQgcGFydHM6IG9iamVjdDtcblxuICAgICAgICBpZiAob3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnQpIHtcbiAgICAgICAgICAgIHBhcnRzID0gdGhpcy51cmxIZWxwZXIuZ2V0SGFzaEZyYWdtZW50UGFyYW1zKG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHBhcnRzID0gdGhpcy51cmxIZWxwZXIuZ2V0SGFzaEZyYWdtZW50UGFyYW1zKCk7XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLmRlYnVnKCdwYXJzZWQgdXJsJywgcGFydHMpO1xuXG4gICAgICAgIGNvbnN0IHN0YXRlID0gcGFydHNbJ3N0YXRlJ107XG5cbiAgICAgICAgbGV0IFtub25jZUluU3RhdGUsIHVzZXJTdGF0ZV0gPSB0aGlzLnBhcnNlU3RhdGUoc3RhdGUpO1xuICAgICAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xuXG4gICAgICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygnZXJyb3IgdHJ5aW5nIHRvIGxvZ2luJyk7XG4gICAgICAgICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Iob3B0aW9ucywgcGFydHMpO1xuICAgICAgICAgICAgY29uc3QgZXJyID0gbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCB7fSwgcGFydHMpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgYWNjZXNzVG9rZW4gPSBwYXJ0c1snYWNjZXNzX3Rva2VuJ107XG4gICAgICAgIGNvbnN0IGlkVG9rZW4gPSBwYXJ0c1snaWRfdG9rZW4nXTtcbiAgICAgICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gcGFydHNbJ3Nlc3Npb25fc3RhdGUnXTtcbiAgICAgICAgY29uc3QgZ3JhbnRlZFNjb3BlcyA9IHBhcnRzWydzY29wZSddO1xuXG4gICAgICAgIGlmICghdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIXRoaXMub2lkYykge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KFxuICAgICAgICAgICAgICAgICdFaXRoZXIgcmVxdWVzdEFjY2Vzc1Rva2VuIG9yIG9pZGMgKG9yIGJvdGgpIG11c3QgYmUgdHJ1ZS4nXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFhY2Nlc3NUb2tlbikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFvcHRpb25zLmRpc2FibGVPQXV0aDJTdGF0ZUNoZWNrICYmICFzdGF0ZSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMub2lkYyAmJiAhaWRUb2tlbikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJiAhc2Vzc2lvblN0YXRlKSB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKFxuICAgICAgICAgICAgICAgICdzZXNzaW9uIGNoZWNrcyAoU2Vzc2lvbiBTdGF0dXMgQ2hhbmdlIE5vdGlmaWNhdGlvbikgJyArXG4gICAgICAgICAgICAgICAgJ3dlcmUgYWN0aXZhdGVkIGluIHRoZSBjb25maWd1cmF0aW9uIGJ1dCB0aGUgaWRfdG9rZW4gJyArXG4gICAgICAgICAgICAgICAgJ2RvZXMgbm90IGNvbnRhaW4gYSBzZXNzaW9uX3N0YXRlIGNsYWltJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjaykge1xuICAgICAgICAgICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMudmFsaWRhdGVOb25jZShub25jZUluU3RhdGUpO1xuXG4gICAgICAgICAgICBpZiAoIXN1Y2Nlc3MpIHtcbiAgICAgICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgICAgYWNjZXNzVG9rZW4sXG4gICAgICAgICAgICAgICAgbnVsbCxcbiAgICAgICAgICAgICAgICBwYXJ0c1snZXhwaXJlc19pbiddIHx8IHRoaXMuZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWMsXG4gICAgICAgICAgICAgICAgZ3JhbnRlZFNjb3Blc1xuICAgICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghdGhpcy5vaWRjKSB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgICAgICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdGhpcy5jYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9ucyk7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRydWUpO1xuXG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzSWRUb2tlbihpZFRva2VuLCBhY2Nlc3NUb2tlbilcbiAgICAgICAgICAgIC50aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMudmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG9wdGlvbnNcbiAgICAgICAgICAgICAgICAgICAgICAgIC52YWxpZGF0aW9uSGFuZGxlcih7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkQ2xhaW1zOiByZXN1bHQuaWRUb2tlbkNsYWltcyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZFRva2VuOiByZXN1bHQuaWRUb2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGF0ZTogc3RhdGVcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICAudGhlbihfID0+IHJlc3VsdCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpO1xuICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlKTtcbiAgICAgICAgICAgICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICAgICAgICAgICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcbiAgICAgICAgICAgICAgICB0aGlzLmNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zKTtcbiAgICAgICAgICAgICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLmNhdGNoKHJlYXNvbiA9PiB7XG4gICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InLCByZWFzb24pXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgdmFsaWRhdGluZyB0b2tlbnMnKTtcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcihyZWFzb24pO1xuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChyZWFzb24pO1xuICAgICAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgcHJpdmF0ZSBwYXJzZVN0YXRlKHN0YXRlOiBzdHJpbmcpOiBbc3RyaW5nLCBzdHJpbmddIHtcbiAgICAgICAgbGV0IG5vbmNlID0gc3RhdGU7XG4gICAgICAgIGxldCB1c2VyU3RhdGUgPSAnJztcblxuICAgICAgICBpZiAoc3RhdGUpIHtcbiAgICAgICAgICAgIGNvbnN0IGlkeCA9IHN0YXRlLmluZGV4T2YodGhpcy5jb25maWcubm9uY2VTdGF0ZVNlcGFyYXRvcik7XG4gICAgICAgICAgICBpZiAoaWR4ID4gLTEpIHtcbiAgICAgICAgICAgICAgICBub25jZSA9IHN0YXRlLnN1YnN0cigwLCBpZHgpO1xuICAgICAgICAgICAgICAgIHVzZXJTdGF0ZSA9IHN0YXRlLnN1YnN0cihpZHggKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yLmxlbmd0aCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIFtub25jZSwgdXNlclN0YXRlXTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgdmFsaWRhdGVOb25jZShcbiAgICAgICAgbm9uY2VJblN0YXRlOiBzdHJpbmdcbiAgICApOiBib29sZWFuIHtcbiAgICAgICAgY29uc3Qgc2F2ZWROb25jZSA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcbiAgICAgICAgaWYgKHNhdmVkTm9uY2UgIT09IG5vbmNlSW5TdGF0ZSkge1xuXG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnVmFsaWRhdGluZyBhY2Nlc3NfdG9rZW4gZmFpbGVkLCB3cm9uZyBzdGF0ZS9ub25jZS4nO1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihlcnIsIHNhdmVkTm9uY2UsIG5vbmNlSW5TdGF0ZSk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0b3JlSWRUb2tlbihpZFRva2VuOiBQYXJzZWRJZFRva2VuKTogdm9pZCB7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW4nLCBpZFRva2VuLmlkVG9rZW4pO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonLCBpZFRva2VuLmlkVG9rZW5DbGFpbXNKc29uKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JywgJycgKyBpZFRva2VuLmlkVG9rZW5FeHBpcmVzQXQpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcsICcnICsgRGF0ZS5ub3coKSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIHN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZTogc3RyaW5nKTogdm9pZCB7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnc2Vzc2lvbl9zdGF0ZScsIHNlc3Npb25TdGF0ZSk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGdldFNlc3Npb25TdGF0ZSgpOiBzdHJpbmcge1xuICAgICAgICByZXR1cm4gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XG4gICAgfVxuXG4gICAgcHJvdGVjdGVkIGhhbmRsZUxvZ2luRXJyb3Iob3B0aW9uczogTG9naW5PcHRpb25zLCBwYXJ0czogb2JqZWN0KTogdm9pZCB7XG4gICAgICAgIGlmIChvcHRpb25zLm9uTG9naW5FcnJvcikge1xuICAgICAgICAgICAgb3B0aW9ucy5vbkxvZ2luRXJyb3IocGFydHMpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4gJiYgIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcbiAgICAgICAgfVxuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEBpZ25vcmVcbiAgICAgKi9cbiAgICBwdWJsaWMgcHJvY2Vzc0lkVG9rZW4oXG4gICAgICAgIGlkVG9rZW46IHN0cmluZyxcbiAgICAgICAgYWNjZXNzVG9rZW46IHN0cmluZyxcbiAgICAgICAgc2tpcE5vbmNlQ2hlY2sgPSBmYWxzZVxuICAgICk6IFByb21pc2U8UGFyc2VkSWRUb2tlbj4ge1xuICAgICAgICBjb25zdCB0b2tlblBhcnRzID0gaWRUb2tlbi5zcGxpdCgnLicpO1xuICAgICAgICBjb25zdCBoZWFkZXJCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzBdKTtcbiAgICAgICAgY29uc3QgaGVhZGVySnNvbiA9IGI2NERlY29kZVVuaWNvZGUoaGVhZGVyQmFzZTY0KTtcbiAgICAgICAgY29uc3QgaGVhZGVyID0gSlNPTi5wYXJzZShoZWFkZXJKc29uKTtcbiAgICAgICAgY29uc3QgY2xhaW1zQmFzZTY0ID0gdGhpcy5wYWRCYXNlNjQodG9rZW5QYXJ0c1sxXSk7XG4gICAgICAgIGNvbnN0IGNsYWltc0pzb24gPSBiNjREZWNvZGVVbmljb2RlKGNsYWltc0Jhc2U2NCk7XG4gICAgICAgIGNvbnN0IGNsYWltcyA9IEpTT04ucGFyc2UoY2xhaW1zSnNvbik7XG4gICAgICAgIGNvbnN0IHNhdmVkTm9uY2UgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XG5cbiAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoY2xhaW1zLmF1ZCkpIHtcbiAgICAgICAgICAgIGlmIChjbGFpbXMuYXVkLmV2ZXJ5KHYgPT4gdiAhPT0gdGhpcy5jbGllbnRJZCkpIHtcbiAgICAgICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXVkaWVuY2U6ICcgKyBjbGFpbXMuYXVkLmpvaW4oJywnKTtcbiAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpZiAoY2xhaW1zLmF1ZCAhPT0gdGhpcy5jbGllbnRJZCkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQ7XG4gICAgICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFjbGFpbXMuc3ViKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnTm8gc3ViIGNsYWltIGluIGlkX3Rva2VuJztcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgLyogRm9yIG5vdywgd2Ugb25seSBjaGVjayB3aGV0aGVyIHRoZSBzdWIgYWdhaW5zdFxuICAgICAgICAgKiBzaWxlbnRSZWZyZXNoU3ViamVjdCB3aGVuIHNlc3Npb25DaGVja3NFbmFibGVkIGlzIG9uXG4gICAgICAgICAqIFdlIHdpbGwgcmVjb25zaWRlciBpbiBhIGxhdGVyIHZlcnNpb24gdG8gZG8gdGhpc1xuICAgICAgICAgKiBpbiBldmVyeSBvdGhlciBjYXNlIHRvby5cbiAgICAgICAgICovXG4gICAgICAgIGlmIChcbiAgICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQgJiZcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgJiZcbiAgICAgICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgIT09IGNsYWltc1snc3ViJ11cbiAgICAgICAgKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPVxuICAgICAgICAgICAgICAgICdBZnRlciByZWZyZXNoaW5nLCB3ZSBnb3QgYW4gaWRfdG9rZW4gZm9yIGFub3RoZXIgdXNlciAoc3ViKS4gJyArXG4gICAgICAgICAgICAgICAgYEV4cGVjdGVkIHN1YjogJHt0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0fSwgcmVjZWl2ZWQgc3ViOiAke1xuICAgICAgICAgICAgICAgIGNsYWltc1snc3ViJ11cbiAgICAgICAgICAgICAgICB9YDtcblxuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWNsYWltcy5pYXQpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdObyBpYXQgY2xhaW0gaW4gaWRfdG9rZW4nO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIXRoaXMuc2tpcElzc3VlckNoZWNrICYmIGNsYWltcy5pc3MgIT09IHRoaXMuaXNzdWVyKSB7XG4gICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgaXNzdWVyOiAnICsgY2xhaW1zLmlzcztcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKCFza2lwTm9uY2VDaGVjayAmJiBjbGFpbXMubm9uY2UgIT09IHNhdmVkTm9uY2UpIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBub25jZTogJyArIGNsYWltcy5ub25jZTtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG4gICAgICAgIC8vIGF0X2hhc2ggaXMgbm90IGFwcGxpY2FibGUgdG8gYXV0aG9yaXphdGlvbiBjb2RlIGZsb3dcbiAgICAgICAgLy8gYWRkcmVzc2luZyBodHRwczovL2dpdGh1Yi5jb20vbWFuZnJlZHN0ZXllci9hbmd1bGFyLW9hdXRoMi1vaWRjL2lzc3Vlcy82NjFcbiAgICAgICAgLy8gaS5lLiBCYXNlZCBvbiBzcGVjIHRoZSBhdF9oYXNoIGNoZWNrIGlzIG9ubHkgdHJ1ZSBmb3IgaW1wbGljaXQgY29kZSBmbG93IG9uIFBpbmcgRmVkZXJhdGVcbiAgICAgICAgLy8gaHR0cHM6Ly93d3cucGluZ2lkZW50aXR5LmNvbS9kZXZlbG9wZXIvZW4vcmVzb3VyY2VzL29wZW5pZC1jb25uZWN0LWRldmVsb3BlcnMtZ3VpZGUuaHRtbFxuICAgICAgICBpZiAodGhpcy5oYXNPd25Qcm9wZXJ0eSgncmVzcG9uc2VUeXBlJykgJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgICAgICAgdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgPSB0cnVlO1xuICAgICAgICB9XG4gICAgICAgIGlmIChcbiAgICAgICAgICAgICF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJlxuICAgICAgICAgICAgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiZcbiAgICAgICAgICAgICFjbGFpbXNbJ2F0X2hhc2gnXVxuICAgICAgICApIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdBbiBhdF9oYXNoIGlzIG5lZWRlZCEnO1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBpc3N1ZWRBdE1TZWMgPSBjbGFpbXMuaWF0ICogMTAwMDtcbiAgICAgICAgY29uc3QgZXhwaXJlc0F0TVNlYyA9IGNsYWltcy5leHAgKiAxMDAwO1xuICAgICAgICBjb25zdCBjbG9ja1NrZXdJbk1TZWMgPSAodGhpcy5jbG9ja1NrZXdJblNlYyB8fCA2MDApICogMTAwMDtcblxuICAgICAgICBpZiAoXG4gICAgICAgICAgICBpc3N1ZWRBdE1TZWMgLSBjbG9ja1NrZXdJbk1TZWMgPj0gbm93IHx8XG4gICAgICAgICAgICBleHBpcmVzQXRNU2VjICsgY2xvY2tTa2V3SW5NU2VjIDw9IG5vd1xuICAgICAgICApIHtcbiAgICAgICAgICAgIGNvbnN0IGVyciA9ICdUb2tlbiBoYXMgZXhwaXJlZCc7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKGVycik7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKHtcbiAgICAgICAgICAgICAgICBub3c6IG5vdyxcbiAgICAgICAgICAgICAgICBpc3N1ZWRBdE1TZWM6IGlzc3VlZEF0TVNlYyxcbiAgICAgICAgICAgICAgICBleHBpcmVzQXRNU2VjOiBleHBpcmVzQXRNU2VjXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgdmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyA9IHtcbiAgICAgICAgICAgIGFjY2Vzc1Rva2VuOiBhY2Nlc3NUb2tlbixcbiAgICAgICAgICAgIGlkVG9rZW46IGlkVG9rZW4sXG4gICAgICAgICAgICBqd2tzOiB0aGlzLmp3a3MsXG4gICAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXG4gICAgICAgICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXG4gICAgICAgICAgICBsb2FkS2V5czogKCkgPT4gdGhpcy5sb2FkSndrcygpXG4gICAgICAgIH07XG5cbiAgICAgICAgaWYgKHRoaXMuZGlzYWJsZUF0SGFzaENoZWNrKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xuICAgICAgICAgICAgICAgIGNvbnN0IHJlc3VsdDogUGFyc2VkSWRUb2tlbiA9IHtcbiAgICAgICAgICAgICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgICAgICAgICAgICAgICAgaWRUb2tlbkNsYWltczogY2xhaW1zLFxuICAgICAgICAgICAgICAgICAgICBpZFRva2VuQ2xhaW1zSnNvbjogY2xhaW1zSnNvbixcbiAgICAgICAgICAgICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxuICAgICAgICAgICAgICAgICAgICBpZFRva2VuSGVhZGVySnNvbjogaGVhZGVySnNvbixcbiAgICAgICAgICAgICAgICAgICAgaWRUb2tlbkV4cGlyZXNBdDogZXhwaXJlc0F0TVNlY1xuICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHRoaXMuY2hlY2tBdEhhc2godmFsaWRhdGlvblBhcmFtcylcbiAgICAgICAgICAgIC50aGVuKGF0SGFzaFZhbGlkID0+IHtcbiAgICAgICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICAgICAgICF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJlxuICAgICAgICAgICAgICAgICAgICB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJlxuICAgICAgICAgICAgICAgICAgICAhYXRIYXNoVmFsaWRcbiAgICAgICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmNoZWNrU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oXyA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IGF0SGFzaENoZWNrRW5hYmxlZCA9ICF0aGlzLmRpc2FibGVBdEhhc2hDaGVjaztcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgcmVzdWx0OiBQYXJzZWRJZFRva2VuID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcbiAgICAgICAgICAgICAgICAgICAgICAgIGlkVG9rZW5DbGFpbXNKc29uOiBjbGFpbXNKc29uLFxuICAgICAgICAgICAgICAgICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxuICAgICAgICAgICAgICAgICAgICAgICAgaWRUb2tlbkhlYWRlckpzb246IGhlYWRlckpzb24sXG4gICAgICAgICAgICAgICAgICAgICAgICBpZFRva2VuRXhwaXJlc0F0OiBleHBpcmVzQXRNU2VjXG4gICAgICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgICAgIGlmIChhdEhhc2hDaGVja0VuYWJsZWQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmNoZWNrQXRIYXNoKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oYXRIYXNoVmFsaWQgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYXRIYXNoVmFsaWQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSByZWNlaXZlZCBjbGFpbXMgYWJvdXQgdGhlIHVzZXIuXG4gICAgICovXG4gICAgcHVibGljIGdldElkZW50aXR5Q2xhaW1zKCk6IG9iamVjdCB7XG4gICAgICAgIGNvbnN0IGNsYWltcyA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicpO1xuICAgICAgICBpZiAoIWNsYWltcykge1xuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIEpTT04ucGFyc2UoY2xhaW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBncmFudGVkIHNjb3BlcyBmcm9tIHRoZSBzZXJ2ZXIuXG4gICAgICovXG4gICAgcHVibGljIGdldEdyYW50ZWRTY29wZXMoKTogb2JqZWN0IHtcbiAgICAgICAgY29uc3Qgc2NvcGVzID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdncmFudGVkX3Njb3BlcycpO1xuICAgICAgICBpZiAoIXNjb3Blcykge1xuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIEpTT04ucGFyc2Uoc2NvcGVzKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGlkX3Rva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBnZXRJZFRva2VuKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiB0aGlzLl9zdG9yYWdlXG4gICAgICAgICAgICA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW4nKVxuICAgICAgICAgICAgOiBudWxsO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBwYWRCYXNlNjQoYmFzZTY0ZGF0YSk6IHN0cmluZyB7XG4gICAgICAgIHdoaWxlIChiYXNlNjRkYXRhLmxlbmd0aCAlIDQgIT09IDApIHtcbiAgICAgICAgICAgIGJhc2U2NGRhdGEgKz0gJz0nO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBiYXNlNjRkYXRhO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGN1cnJlbnQgYWNjZXNzX3Rva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBnZXRBY2Nlc3NUb2tlbigpOiBzdHJpbmcge1xuICAgICAgICByZXR1cm4gdGhpcy5fc3RvcmFnZVxuICAgICAgICAgICAgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2FjY2Vzc190b2tlbicpXG4gICAgICAgICAgICA6IG51bGw7XG4gICAgfVxuXG4gICAgcHVibGljIGdldFJlZnJlc2hUb2tlbigpOiBzdHJpbmcge1xuICAgICAgICByZXR1cm4gdGhpcy5fc3RvcmFnZVxuICAgICAgICAgICAgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nKVxuICAgICAgICAgICAgOiBudWxsO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgYWNjZXNzX3Rva2VuXG4gICAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXG4gICAgICovXG4gICAgcHVibGljIGdldEFjY2Vzc1Rva2VuRXhwaXJhdGlvbigpOiBudW1iZXIge1xuICAgICAgICBpZiAoIXRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZXhwaXJlc19hdCcpKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0JyksIDEwKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgZ2V0QWNjZXNzVG9rZW5TdG9yZWRBdCgpOiBudW1iZXIge1xuICAgICAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgZ2V0SWRUb2tlblN0b3JlZEF0KCk6IG51bWJlciB7XG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcpLCAxMCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgZXhwaXJhdGlvbiBkYXRlIG9mIHRoZSBpZF90b2tlblxuICAgICAqIGFzIG1pbGxpc2Vjb25kcyBzaW5jZSAxOTcwLlxuICAgICAqL1xuICAgIHB1YmxpYyBnZXRJZFRva2VuRXhwaXJhdGlvbigpOiBudW1iZXIge1xuICAgICAgICBpZiAoIXRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpKSB7XG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKSwgMTApO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoZWNrZXMsIHdoZXRoZXIgdGhlcmUgaXMgYSB2YWxpZCBhY2Nlc3NfdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGhhc1ZhbGlkQWNjZXNzVG9rZW4oKTogYm9vbGVhbiB7XG4gICAgICAgIGlmICh0aGlzLmdldEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgICAgICAgIGNvbnN0IGV4cGlyZXNBdCA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZXhwaXJlc19hdCcpO1xuICAgICAgICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgIGlmIChleHBpcmVzQXQgJiYgcGFyc2VJbnQoZXhwaXJlc0F0LCAxMCkgPCBub3cuZ2V0VGltZSgpKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDaGVja3Mgd2hldGhlciB0aGVyZSBpcyBhIHZhbGlkIGlkX3Rva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBoYXNWYWxpZElkVG9rZW4oKTogYm9vbGVhbiB7XG4gICAgICAgIGlmICh0aGlzLmdldElkVG9rZW4oKSkge1xuICAgICAgICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0Jyk7XG4gICAgICAgICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIGF1dGgtaGVhZGVyIHRoYXQgY2FuIGJlIHVzZWRcbiAgICAgKiB0byB0cmFuc21pdCB0aGUgYWNjZXNzX3Rva2VuIHRvIGEgc2VydmljZVxuICAgICAqL1xuICAgIHB1YmxpYyBhdXRob3JpemF0aW9uSGVhZGVyKCk6IHN0cmluZyB7XG4gICAgICAgIHJldHVybiAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlcyBhbGwgdG9rZW5zIGFuZCBsb2dzIHRoZSB1c2VyIG91dC5cbiAgICAgKiBJZiBhIGxvZ291dCB1cmwgaXMgY29uZmlndXJlZCwgdGhlIHVzZXIgaXNcbiAgICAgKiByZWRpcmVjdGVkIHRvIGl0LlxuICAgICAqIEBwYXJhbSBub1JlZGlyZWN0VG9Mb2dvdXRVcmxcbiAgICAgKi9cbiAgICBwdWJsaWMgbG9nT3V0KG5vUmVkaXJlY3RUb0xvZ291dFVybCA9IGZhbHNlKTogdm9pZCB7XG4gICAgICAgIGNvbnN0IGlkX3Rva2VuID0gdGhpcy5nZXRJZFRva2VuKCk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnYWNjZXNzX3Rva2VuJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW4nKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdyZWZyZXNoX3Rva2VuJyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnbm9uY2UnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdleHBpcmVzX2F0Jyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicpO1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0Jyk7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnZ3JhbnRlZF9zY29wZXMnKTtcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XG5cbiAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IG51bGw7XG5cbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdsb2dvdXQnKSk7XG5cbiAgICAgICAgaWYgKCF0aGlzLmxvZ291dFVybCkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIGlmIChub1JlZGlyZWN0VG9Mb2dvdXRVcmwpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghaWRfdG9rZW4gJiYgIXRoaXMucG9zdExvZ291dFJlZGlyZWN0VXJpKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBsZXQgbG9nb3V0VXJsOiBzdHJpbmc7XG5cbiAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dvdXRVcmwpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICAgJ2xvZ291dFVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSBcXCdyZXF1aXJlSHR0cHNcXCcgbXVzdCBiZSBzZXQgdG8gXFwnZmFsc2VcXCcgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS4nXG4gICAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRm9yIGJhY2t3YXJkIGNvbXBhdGliaWxpdHlcbiAgICAgICAgaWYgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJ3t7JykgPiAtMSkge1xuICAgICAgICAgICAgbG9nb3V0VXJsID0gdGhpcy5sb2dvdXRVcmxcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvXFx7XFx7aWRfdG9rZW5cXH1cXH0vLCBpZF90b2tlbilcbiAgICAgICAgICAgICAgICAucmVwbGFjZSgvXFx7XFx7Y2xpZW50X2lkXFx9XFx9LywgdGhpcy5jbGllbnRJZCk7XG4gICAgICAgIH0gZWxzZSB7XG5cbiAgICAgICAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpO1xuXG4gICAgICAgICAgICBpZiAoaWRfdG9rZW4pIHtcbiAgICAgICAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdpZF90b2tlbl9oaW50JywgaWRfdG9rZW4pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBjb25zdCBwb3N0TG9nb3V0VXJsID0gdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcbiAgICAgICAgICAgIGlmIChwb3N0TG9nb3V0VXJsKSB7XG4gICAgICAgICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgncG9zdF9sb2dvdXRfcmVkaXJlY3RfdXJpJywgcG9zdExvZ291dFVybCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGxvZ291dFVybCA9XG4gICAgICAgICAgICAgICAgdGhpcy5sb2dvdXRVcmwgK1xuICAgICAgICAgICAgICAgICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JykgK1xuICAgICAgICAgICAgICAgIHBhcmFtcy50b1N0cmluZygpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuY29uZmlnLm9wZW5VcmkobG9nb3V0VXJsKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBAaWdub3JlXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUFuZFNhdmVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgICAgICBjb25zdCB0aGF0ID0gdGhpcztcbiAgICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlTm9uY2UoKS50aGVuKGZ1bmN0aW9uIChub25jZTogYW55KSB7XG4gICAgICAgICAgICB0aGF0Ll9zdG9yYWdlLnNldEl0ZW0oJ25vbmNlJywgbm9uY2UpO1xuICAgICAgICAgICAgcmV0dXJuIG5vbmNlO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBAaWdub3JlXG4gICAgICovXG4gICAgcHVibGljIG5nT25EZXN0cm95KCk6IHZvaWQge1xuICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xuICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG5cbiAgICAgICAgdGhpcy5yZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xuICAgICAgICBjb25zdCBzaWxlbnRSZWZyZXNoRnJhbWUgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCh0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lKTtcbiAgICAgICAgaWYgKHNpbGVudFJlZnJlc2hGcmFtZSkge1xuICAgICAgICAgICAgc2lsZW50UmVmcmVzaEZyYW1lLnJlbW92ZSgpO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICAgICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XG4gICAgICAgIGNvbnN0IHNlc3Npb25DaGVja0ZyYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQodGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lKTtcbiAgICAgICAgaWYgKHNlc3Npb25DaGVja0ZyYW1lKSB7XG4gICAgICAgICAgICBzZXNzaW9uQ2hlY2tGcmFtZS5yZW1vdmUoKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHByb3RlY3RlZCBjcmVhdGVOb25jZSgpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUpID0+IHtcbiAgICAgICAgICAgIGlmICh0aGlzLnJuZ1VybCkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgICAgICAgJ2NyZWF0ZU5vbmNlIHdpdGggcm5nLXdlYi1hcGkgaGFzIG5vdCBiZWVuIGltcGxlbWVudGVkIHNvIGZhcidcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvKlxuICAgICAgICAgICAgICogVGhpcyBhbHBoYWJldCBpcyBmcm9tOlxuICAgICAgICAgICAgICogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzc2MzYjc2VjdGlvbi00LjFcbiAgICAgICAgICAgICAqXG4gICAgICAgICAgICAgKiBbQS1aXSAvIFthLXpdIC8gWzAtOV0gLyBcIi1cIiAvIFwiLlwiIC8gXCJfXCIgLyBcIn5cIlxuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBjb25zdCB1bnJlc2VydmVkID0gJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5LS5ffic7XG4gICAgICAgICAgICBsZXQgc2l6ZSA9IDQ1O1xuICAgICAgICAgICAgbGV0IGlkID0gJyc7XG5cbiAgICAgICAgICAgIGNvbnN0IGNyeXB0byA9IHR5cGVvZiBzZWxmID09PSAndW5kZWZpbmVkJyA/IG51bGwgOiAoc2VsZi5jcnlwdG8gfHwgc2VsZlsnbXNDcnlwdG8nXSk7XG4gICAgICAgICAgICBpZiAoY3J5cHRvKSB7XG4gICAgICAgICAgICAgICAgbGV0IGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoc2l6ZSk7XG4gICAgICAgICAgICAgICAgY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhieXRlcyk7XG4gICAgICAgICAgICAgICAgYnl0ZXMgPSBieXRlcy5tYXAoeCA9PiB1bnJlc2VydmVkLmNoYXJDb2RlQXQoeCAlIHVucmVzZXJ2ZWQubGVuZ3RoKSk7XG4gICAgICAgICAgICAgICAgaWQgPSBTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIGJ5dGVzKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgd2hpbGUgKDAgPCBzaXplLS0pIHtcbiAgICAgICAgICAgICAgICAgICAgaWQgKz0gdW5yZXNlcnZlZFtNYXRoLnJhbmRvbSgpICogdW5yZXNlcnZlZC5sZW5ndGggfCAwXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJlc29sdmUoYmFzZTY0VXJsRW5jb2RlKGlkKSk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBhc3luYyBjaGVja0F0SGFzaChwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICAgICAgaWYgKCF0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ05vIHRva2VuVmFsaWRhdGlvbkhhbmRsZXIgY29uZmlndXJlZC4gQ2Fubm90IGNoZWNrIGF0X2hhc2guJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIudmFsaWRhdGVBdEhhc2gocGFyYW1zKTtcbiAgICB9XG5cbiAgICBwcm90ZWN0ZWQgY2hlY2tTaWduYXR1cmUocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxhbnk+IHtcbiAgICAgICAgaWYgKCF0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICAgICAgICAgJ05vIHRva2VuVmFsaWRhdGlvbkhhbmRsZXIgY29uZmlndXJlZC4gQ2Fubm90IGNoZWNrIHNpZ25hdHVyZS4nXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShudWxsKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyLnZhbGlkYXRlU2lnbmF0dXJlKHBhcmFtcyk7XG4gICAgfVxuXG5cbiAgICAvKipcbiAgICAgKiBTdGFydCB0aGUgaW1wbGljaXQgZmxvdyBvciB0aGUgY29kZSBmbG93LFxuICAgICAqIGRlcGVuZGluZyBvbiB5b3VyIGNvbmZpZ3VyYXRpb24uXG4gICAgICovXG4gICAgcHVibGljIGluaXRMb2dpbkZsb3coXG4gICAgICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgICAgICBwYXJhbXMgPSB7fVxuICAgICk6IHZvaWQge1xuICAgICAgICBpZiAodGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuaW5pdENvZGVGbG93KGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmluaXRJbXBsaWNpdEZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU3RhcnRzIHRoZSBhdXRob3JpemF0aW9uIGNvZGUgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cbiAgICAgKiB0aGUgYXV0aCBzZXJ2ZXJzIGxvZ2luIHVybC5cbiAgICAgKi9cbiAgICBwdWJsaWMgaW5pdENvZGVGbG93KFxuICAgICAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICAgICAgcGFyYW1zID0ge31cbiAgICApOiB2b2lkIHtcbiAgICAgICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XG4gICAgICAgICAgICB0aGlzLmluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcpKVxuICAgICAgICAgICAgICAgIC5zdWJzY3JpYmUoXyA9PiB0aGlzLmluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBwcml2YXRlIGluaXRDb2RlRmxvd0ludGVybmFsKFxuICAgICAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICAgICAgcGFyYW1zID0ge31cbiAgICApOiB2b2lkIHtcblxuICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdsb2dpblVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSBcXCdyZXF1aXJlSHR0cHNcXCcgbXVzdCBiZSBzZXQgdG8gXFwnZmFsc2VcXCcgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS4nKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCAnJywgbnVsbCwgZmFsc2UsIHBhcmFtcylcbiAgICAgICAgICAgIC50aGVuKHRoaXMuY29uZmlnLm9wZW5VcmkpXG4gICAgICAgICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGluIGluaXRBdXRob3JpemF0aW9uQ29kZUZsb3cnKTtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICAgICAgICAgIH0pO1xuICAgIH1cblxuICAgIHByb3RlY3RlZCBhc3luYyBjcmVhdGVDaGFsbGFuZ2VWZXJpZmllclBhaXJGb3JQS0NFKCk6IFByb21pc2U8W3N0cmluZywgc3RyaW5nXT4ge1xuXG4gICAgICAgIGlmICghdGhpcy5jcnlwdG8pIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignUEtDSSBzdXBwb3J0IGZvciBjb2RlIGZsb3cgbmVlZHMgYSBDcnlwdG9IYW5kZXIuIERpZCB5b3UgaW1wb3J0IHRoZSBPQXV0aE1vZHVsZSB1c2luZyBmb3JSb290KCkgPycpO1xuICAgICAgICB9XG5cblxuICAgICAgICBjb25zdCB2ZXJpZmllciA9IGF3YWl0IHRoaXMuY3JlYXRlTm9uY2UoKTtcbiAgICAgICAgY29uc3QgY2hhbGxlbmdlUmF3ID0gYXdhaXQgdGhpcy5jcnlwdG8uY2FsY0hhc2godmVyaWZpZXIsICdzaGEtMjU2Jyk7XG4gICAgICAgIGNvbnN0IGNoYWxsYW5nZSA9IGJhc2U2NFVybEVuY29kZShjaGFsbGVuZ2VSYXcpO1xuXG4gICAgICAgIHJldHVybiBbY2hhbGxhbmdlLCB2ZXJpZmllcl07XG4gICAgfVxuXG4gICAgcHJpdmF0ZSBleHRyYWN0UmVjb2duaXplZEN1c3RvbVBhcmFtZXRlcnModG9rZW5SZXNwb25zZTogVG9rZW5SZXNwb25zZSk6IGFueSB7XG4gICAgICBpZiAoIXRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycykge1xuICAgICAgICAgIHJldHVybiB7fTtcbiAgICAgIH1cbiAgICAgIGxldCBmb3VuZFBhcmFtZXRlcnM6IGFueSA9IHt9O1xuICAgICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzLmZvckVhY2gocmVjb2duaXplZFBhcmFtZXRlciA9PiB7XG4gICAgICAgICAgaWYgKHRva2VuUmVzcG9uc2VbcmVjb2duaXplZFBhcmFtZXRlcl0pIHtcbiAgICAgICAgICAgIGZvdW5kUGFyYW1ldGVyc1tyZWNvZ25pemVkUGFyYW1ldGVyXSA9IHRva2VuUmVzcG9uc2VbcmVjb2duaXplZFBhcmFtZXRlcl07XG4gICAgICAgICAgfVxuICAgICAgfSk7XG4gICAgICByZXR1cm4gZm91bmRQYXJhbWV0ZXJzO1xuICAgIH1cbn1cbiJdfQ==