export class AuthConfig {
    constructor(json) {
        /**
         * The client's id as registered with the auth server
         */
        this.clientId = '';
        /**
         * The client's redirectUri as registered with the auth server
         */
        this.redirectUri = '';
        /**
         * An optional second redirectUri where the auth server
         * redirects the user to after logging out.
         */
        this.postLogoutRedirectUri = '';
        /**
         * The auth server's endpoint that allows to log
         * the user in when using implicit flow.
         */
        this.loginUrl = '';
        /**
         * The requested scopes
         */
        this.scope = 'openid profile';
        this.resource = '';
        this.rngUrl = '';
        /**
         * Defines whether to use OpenId Connect during
         * implicit flow.
         */
        this.oidc = true;
        /**
         * Defines whether to request an access token during
         * implicit flow.
         */
        this.requestAccessToken = true;
        this.options = null;
        /**
         * The issuer's uri.
         */
        this.issuer = '';
        /**
         * The logout url.
         */
        this.logoutUrl = '';
        /**
         * Defines whether to clear the hash fragment after logging in.
         */
        this.clearHashAfterLogin = true;
        /**
         * Url of the token endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.tokenEndpoint = null;
        /**
         * Names of known parameters sent out in the TokenResponse. https://tools.ietf.org/html/rfc6749#section-5.1
         */
        this.customTokenParameters = [];
        /**
         * Url of the userinfo endpoint as defined by OpenId Connect.
         */
        this.userinfoEndpoint = null;
        this.responseType = '';
        /**
         * Defines whether additional debug information should
         * be shown at the console. Note that in certain browsers
         * the verbosity of the console needs to be explicitly set
         * to include Debug level messages.
         */
        this.showDebugInformation = false;
        /**
         * The redirect uri used when doing silent refresh.
         */
        this.silentRefreshRedirectUri = '';
        this.silentRefreshMessagePrefix = '';
        /**
         * Set this to true to display the iframe used for
         * silent refresh for debugging.
         */
        this.silentRefreshShowIFrame = false;
        /**
         * Timeout for silent refresh.
         * @internal
         * depreacted b/c of typo, see silentRefreshTimeout
         */
        this.siletRefreshTimeout = 1000 * 20;
        /**
         * Timeout for silent refresh.
         */
        this.silentRefreshTimeout = 1000 * 20;
        /**
         * Some auth servers don't allow using password flow
         * w/o a client secret while the standards do not
         * demand for it. In this case, you can set a password
         * here. As this password is exposed to the public
         * it does not bring additional security and is therefore
         * as good as using no password.
         */
        this.dummyClientSecret = null;
        /**
         * Defines whether https is required.
         * The default value is remoteOnly which only allows
         * http for localhost, while every other domains need
         * to be used with https.
         */
        this.requireHttps = 'remoteOnly';
        /**
         * Defines whether every url provided by the discovery
         * document has to start with the issuer's url.
         */
        this.strictDiscoveryDocumentValidation = true;
        /**
         * JSON Web Key Set (https://tools.ietf.org/html/rfc7517)
         * with keys used to validate received id_tokens.
         * This is taken out of the disovery document. Can be set manually too.
         */
        this.jwks = null;
        /**
         * Map with additional query parameter that are appended to
         * the request when initializing implicit flow.
         */
        this.customQueryParams = null;
        this.silentRefreshIFrameName = 'angular-oauth-oidc-silent-refresh-iframe';
        /**
         * Defines when the token_timeout event should be raised.
         * If you set this to the default value 0.75, the event
         * is triggered after 75% of the token's life time.
         */
        this.timeoutFactor = 0.75;
        /**
         * If true, the lib will try to check whether the user
         * is still logged in on a regular basis as described
         * in http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionChecksEnabled = false;
        /**
         * Interval in msec for checking the session
         * according to http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionCheckIntervall = 3 * 1000;
        /**
         * Url for the iframe used for session checks
         */
        this.sessionCheckIFrameUrl = null;
        /**
         * Name of the iframe to use for session checks
         */
        this.sessionCheckIFrameName = 'angular-oauth-oidc-check-session-iframe';
        /**
         * This property has been introduced to disable at_hash checks
         * and is indented for Identity Provider that does not deliver
         * an at_hash EVEN THOUGH its recommended by the OIDC specs.
         * Of course, when disabling these checks the we are bypassing
         * a security check which means we are more vulnerable.
         */
        this.disableAtHashCheck = false;
        /**
         * Defines wether to check the subject of a refreshed token after silent refresh.
         * Normally, it should be the same as before.
         */
        this.skipSubjectCheck = false;
        this.useIdTokenHintForSilentRefresh = false;
        /**
         * Defined whether to skip the validation of the issuer in the discovery document.
         * Normally, the discovey document's url starts with the url of the issuer.
         */
        this.skipIssuerCheck = false;
        /**
         * final state sent to issuer is built as follows:
         * state = nonce + nonceStateSeparator + additional state
         * Default separator is ';' (encoded %3B).
         * In rare cases, this character might be forbidden or inconvenient to use by the issuer so it can be customized.
         */
        this.nonceStateSeparator = ';';
        /**
         * Set this to true to use HTTP BASIC auth for password flow
         */
        this.useHttpBasicAuth = false;
        /**
         * The interceptors waits this time span if there is no token
        */
        this.waitForTokenInMsec = 0;
        /**
         * Code Flow is by defauld used together with PKCI which is also higly recommented.
         * You can disbale it here by setting this flag to true.
         * https://tools.ietf.org/html/rfc7636#section-1.1
         */
        this.disablePKCE = false;
        /**
         * This property allows you to override the method that is used to open the login url,
         * allowing a way for implementations to specify their own method of routing to new
         * urls.
         */
        this.openUri = uri => {
            location.href = uri;
        };
        if (json) {
            Object.assign(this, json);
        }
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5jb25maWcuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsiYXV0aC5jb25maWcudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsTUFBTSxPQUFPLFVBQVU7SUFnUHJCLFlBQVksSUFBMEI7UUEvT3RDOztXQUVHO1FBQ0ksYUFBUSxHQUFJLEVBQUUsQ0FBQztRQUV0Qjs7V0FFRztRQUNJLGdCQUFXLEdBQUksRUFBRSxDQUFDO1FBRXpCOzs7V0FHRztRQUNJLDBCQUFxQixHQUFJLEVBQUUsQ0FBQztRQUVuQzs7O1dBR0c7UUFDSSxhQUFRLEdBQUksRUFBRSxDQUFDO1FBRXRCOztXQUVHO1FBQ0ksVUFBSyxHQUFJLGdCQUFnQixDQUFDO1FBRTFCLGFBQVEsR0FBSSxFQUFFLENBQUM7UUFFZixXQUFNLEdBQUksRUFBRSxDQUFDO1FBRXBCOzs7V0FHRztRQUNJLFNBQUksR0FBSSxJQUFJLENBQUM7UUFFcEI7OztXQUdHO1FBQ0ksdUJBQWtCLEdBQUksSUFBSSxDQUFDO1FBRTNCLFlBQU8sR0FBUyxJQUFJLENBQUM7UUFFNUI7O1dBRUc7UUFDSSxXQUFNLEdBQUksRUFBRSxDQUFDO1FBRXBCOztXQUVHO1FBQ0ksY0FBUyxHQUFJLEVBQUUsQ0FBQztRQUV2Qjs7V0FFRztRQUNJLHdCQUFtQixHQUFJLElBQUksQ0FBQztRQUVuQzs7V0FFRztRQUNJLGtCQUFhLEdBQVksSUFBSSxDQUFDO1FBRXJDOztXQUVHO1FBQ0ksMEJBQXFCLEdBQWMsRUFBRSxDQUFDO1FBRTdDOztXQUVHO1FBQ0kscUJBQWdCLEdBQVksSUFBSSxDQUFDO1FBRWpDLGlCQUFZLEdBQUksRUFBRSxDQUFDO1FBRTFCOzs7OztXQUtHO1FBQ0sseUJBQW9CLEdBQUksS0FBSyxDQUFDO1FBRXRDOztXQUVHO1FBQ0ksNkJBQXdCLEdBQUksRUFBRSxDQUFDO1FBRS9CLCtCQUEwQixHQUFJLEVBQUUsQ0FBQztRQUV4Qzs7O1dBR0c7UUFDSSw0QkFBdUIsR0FBSSxLQUFLLENBQUM7UUFFeEM7Ozs7V0FJRztRQUNJLHdCQUFtQixHQUFZLElBQUksR0FBRyxFQUFFLENBQUM7UUFFaEQ7O1dBRUc7UUFDSSx5QkFBb0IsR0FBWSxJQUFJLEdBQUcsRUFBRSxDQUFDO1FBRWpEOzs7Ozs7O1dBT0c7UUFDSSxzQkFBaUIsR0FBWSxJQUFJLENBQUM7UUFFekM7Ozs7O1dBS0c7UUFDSSxpQkFBWSxHQUE0QixZQUFZLENBQUM7UUFFNUQ7OztXQUdHO1FBQ0ksc0NBQWlDLEdBQUksSUFBSSxDQUFDO1FBRWpEOzs7O1dBSUc7UUFDSSxTQUFJLEdBQVksSUFBSSxDQUFDO1FBRTVCOzs7V0FHRztRQUNJLHNCQUFpQixHQUFZLElBQUksQ0FBQztRQUVsQyw0QkFBdUIsR0FBSSwwQ0FBMEMsQ0FBQztRQUU3RTs7OztXQUlHO1FBQ0ksa0JBQWEsR0FBSSxJQUFJLENBQUM7UUFFN0I7Ozs7V0FJRztRQUNJLHlCQUFvQixHQUFJLEtBQUssQ0FBQztRQUVyQzs7O1dBR0c7UUFDSSwwQkFBcUIsR0FBSSxDQUFDLEdBQUcsSUFBSSxDQUFDO1FBRXpDOztXQUVHO1FBQ0ksMEJBQXFCLEdBQVksSUFBSSxDQUFDO1FBRTdDOztXQUVHO1FBQ0ksMkJBQXNCLEdBQUkseUNBQXlDLENBQUM7UUFFM0U7Ozs7OztXQU1HO1FBQ0ksdUJBQWtCLEdBQUksS0FBSyxDQUFDO1FBRW5DOzs7V0FHRztRQUNJLHFCQUFnQixHQUFJLEtBQUssQ0FBQztRQUUxQixtQ0FBOEIsR0FBSSxLQUFLLENBQUM7UUFFL0M7OztXQUdHO1FBQ0ksb0JBQWUsR0FBSSxLQUFLLENBQUM7UUFTaEM7Ozs7O1dBS0c7UUFDSSx3QkFBbUIsR0FBSSxHQUFHLENBQUM7UUFFbEM7O1dBRUc7UUFDSSxxQkFBZ0IsR0FBSSxLQUFLLENBQUM7UUFPakM7O1VBRUU7UUFDSyx1QkFBa0IsR0FBSSxDQUFDLENBQUM7UUFFL0I7Ozs7V0FJRztRQUNJLGdCQUFXLEdBQUksS0FBSyxDQUFDO1FBUTVCOzs7O1dBSUc7UUFDSSxZQUFPLEdBQTZCLEdBQUcsQ0FBQyxFQUFFO1lBQy9DLFFBQVEsQ0FBQyxJQUFJLEdBQUcsR0FBRyxDQUFDO1FBQ3RCLENBQUMsQ0FBQTtRQVpDLElBQUksSUFBSSxFQUFFO1lBQ1IsTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUM7U0FDM0I7SUFDSCxDQUFDO0NBVUYiLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgY2xhc3MgQXV0aENvbmZpZyB7XG4gIC8qKlxuICAgKiBUaGUgY2xpZW50J3MgaWQgYXMgcmVnaXN0ZXJlZCB3aXRoIHRoZSBhdXRoIHNlcnZlclxuICAgKi9cbiAgcHVibGljIGNsaWVudElkPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBUaGUgY2xpZW50J3MgcmVkaXJlY3RVcmkgYXMgcmVnaXN0ZXJlZCB3aXRoIHRoZSBhdXRoIHNlcnZlclxuICAgKi9cbiAgcHVibGljIHJlZGlyZWN0VXJpPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBBbiBvcHRpb25hbCBzZWNvbmQgcmVkaXJlY3RVcmkgd2hlcmUgdGhlIGF1dGggc2VydmVyXG4gICAqIHJlZGlyZWN0cyB0aGUgdXNlciB0byBhZnRlciBsb2dnaW5nIG91dC5cbiAgICovXG4gIHB1YmxpYyBwb3N0TG9nb3V0UmVkaXJlY3RVcmk/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFRoZSBhdXRoIHNlcnZlcidzIGVuZHBvaW50IHRoYXQgYWxsb3dzIHRvIGxvZ1xuICAgKiB0aGUgdXNlciBpbiB3aGVuIHVzaW5nIGltcGxpY2l0IGZsb3cuXG4gICAqL1xuICBwdWJsaWMgbG9naW5Vcmw/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFRoZSByZXF1ZXN0ZWQgc2NvcGVzXG4gICAqL1xuICBwdWJsaWMgc2NvcGU/ID0gJ29wZW5pZCBwcm9maWxlJztcblxuICBwdWJsaWMgcmVzb3VyY2U/ID0gJyc7XG5cbiAgcHVibGljIHJuZ1VybD8gPSAnJztcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIHRvIHVzZSBPcGVuSWQgQ29ubmVjdCBkdXJpbmdcbiAgICogaW1wbGljaXQgZmxvdy5cbiAgICovXG4gIHB1YmxpYyBvaWRjPyA9IHRydWU7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciB0byByZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiBkdXJpbmdcbiAgICogaW1wbGljaXQgZmxvdy5cbiAgICovXG4gIHB1YmxpYyByZXF1ZXN0QWNjZXNzVG9rZW4/ID0gdHJ1ZTtcblxuICBwdWJsaWMgb3B0aW9ucz86IGFueSA9IG51bGw7XG5cbiAgLyoqXG4gICAqIFRoZSBpc3N1ZXIncyB1cmkuXG4gICAqL1xuICBwdWJsaWMgaXNzdWVyPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBUaGUgbG9nb3V0IHVybC5cbiAgICovXG4gIHB1YmxpYyBsb2dvdXRVcmw/ID0gJyc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciB0byBjbGVhciB0aGUgaGFzaCBmcmFnbWVudCBhZnRlciBsb2dnaW5nIGluLlxuICAgKi9cbiAgcHVibGljIGNsZWFySGFzaEFmdGVyTG9naW4/ID0gdHJ1ZTtcblxuICAvKipcbiAgICogVXJsIG9mIHRoZSB0b2tlbiBlbmRwb2ludCBhcyBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0IGFuZCBPQXV0aCAyLlxuICAgKi9cbiAgcHVibGljIHRva2VuRW5kcG9pbnQ/OiBzdHJpbmcgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBOYW1lcyBvZiBrbm93biBwYXJhbWV0ZXJzIHNlbnQgb3V0IGluIHRoZSBUb2tlblJlc3BvbnNlLiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTUuMVxuICAgKi9cbiAgcHVibGljIGN1c3RvbVRva2VuUGFyYW1ldGVycz86IHN0cmluZ1tdID0gW107XG5cbiAgLyoqXG4gICAqIFVybCBvZiB0aGUgdXNlcmluZm8gZW5kcG9pbnQgYXMgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cbiAgICovXG4gIHB1YmxpYyB1c2VyaW5mb0VuZHBvaW50Pzogc3RyaW5nID0gbnVsbDtcblxuICBwdWJsaWMgcmVzcG9uc2VUeXBlPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgYWRkaXRpb25hbCBkZWJ1ZyBpbmZvcm1hdGlvbiBzaG91bGRcbiAgICogYmUgc2hvd24gYXQgdGhlIGNvbnNvbGUuIE5vdGUgdGhhdCBpbiBjZXJ0YWluIGJyb3dzZXJzXG4gICAqIHRoZSB2ZXJib3NpdHkgb2YgdGhlIGNvbnNvbGUgbmVlZHMgdG8gYmUgZXhwbGljaXRseSBzZXRcbiAgICogdG8gaW5jbHVkZSBEZWJ1ZyBsZXZlbCBtZXNzYWdlcy5cbiAgICovXG4gICBwdWJsaWMgc2hvd0RlYnVnSW5mb3JtYXRpb24/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIFRoZSByZWRpcmVjdCB1cmkgdXNlZCB3aGVuIGRvaW5nIHNpbGVudCByZWZyZXNoLlxuICAgKi9cbiAgcHVibGljIHNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaT8gPSAnJztcblxuICBwdWJsaWMgc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXg/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFNldCB0aGlzIHRvIHRydWUgdG8gZGlzcGxheSB0aGUgaWZyYW1lIHVzZWQgZm9yXG4gICAqIHNpbGVudCByZWZyZXNoIGZvciBkZWJ1Z2dpbmcuXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaFNob3dJRnJhbWU/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIFRpbWVvdXQgZm9yIHNpbGVudCByZWZyZXNoLlxuICAgKiBAaW50ZXJuYWxcbiAgICogZGVwcmVhY3RlZCBiL2Mgb2YgdHlwbywgc2VlIHNpbGVudFJlZnJlc2hUaW1lb3V0XG4gICAqL1xuICBwdWJsaWMgc2lsZXRSZWZyZXNoVGltZW91dD86IG51bWJlciA9IDEwMDAgKiAyMDtcblxuICAvKipcbiAgICogVGltZW91dCBmb3Igc2lsZW50IHJlZnJlc2guXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaFRpbWVvdXQ/OiBudW1iZXIgPSAxMDAwICogMjA7XG5cbiAgLyoqXG4gICAqIFNvbWUgYXV0aCBzZXJ2ZXJzIGRvbid0IGFsbG93IHVzaW5nIHBhc3N3b3JkIGZsb3dcbiAgICogdy9vIGEgY2xpZW50IHNlY3JldCB3aGlsZSB0aGUgc3RhbmRhcmRzIGRvIG5vdFxuICAgKiBkZW1hbmQgZm9yIGl0LiBJbiB0aGlzIGNhc2UsIHlvdSBjYW4gc2V0IGEgcGFzc3dvcmRcbiAgICogaGVyZS4gQXMgdGhpcyBwYXNzd29yZCBpcyBleHBvc2VkIHRvIHRoZSBwdWJsaWNcbiAgICogaXQgZG9lcyBub3QgYnJpbmcgYWRkaXRpb25hbCBzZWN1cml0eSBhbmQgaXMgdGhlcmVmb3JlXG4gICAqIGFzIGdvb2QgYXMgdXNpbmcgbm8gcGFzc3dvcmQuXG4gICAqL1xuICBwdWJsaWMgZHVtbXlDbGllbnRTZWNyZXQ/OiBzdHJpbmcgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgaHR0cHMgaXMgcmVxdWlyZWQuXG4gICAqIFRoZSBkZWZhdWx0IHZhbHVlIGlzIHJlbW90ZU9ubHkgd2hpY2ggb25seSBhbGxvd3NcbiAgICogaHR0cCBmb3IgbG9jYWxob3N0LCB3aGlsZSBldmVyeSBvdGhlciBkb21haW5zIG5lZWRcbiAgICogdG8gYmUgdXNlZCB3aXRoIGh0dHBzLlxuICAgKi9cbiAgcHVibGljIHJlcXVpcmVIdHRwcz86IGJvb2xlYW4gfCAncmVtb3RlT25seScgPSAncmVtb3RlT25seSc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciBldmVyeSB1cmwgcHJvdmlkZWQgYnkgdGhlIGRpc2NvdmVyeVxuICAgKiBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyJ3MgdXJsLlxuICAgKi9cbiAgcHVibGljIHN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbj8gPSB0cnVlO1xuXG4gIC8qKlxuICAgKiBKU09OIFdlYiBLZXkgU2V0IChodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzUxNylcbiAgICogd2l0aCBrZXlzIHVzZWQgdG8gdmFsaWRhdGUgcmVjZWl2ZWQgaWRfdG9rZW5zLlxuICAgKiBUaGlzIGlzIHRha2VuIG91dCBvZiB0aGUgZGlzb3ZlcnkgZG9jdW1lbnQuIENhbiBiZSBzZXQgbWFudWFsbHkgdG9vLlxuICAgKi9cbiAgcHVibGljIGp3a3M/OiBvYmplY3QgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBNYXAgd2l0aCBhZGRpdGlvbmFsIHF1ZXJ5IHBhcmFtZXRlciB0aGF0IGFyZSBhcHBlbmRlZCB0b1xuICAgKiB0aGUgcmVxdWVzdCB3aGVuIGluaXRpYWxpemluZyBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIGN1c3RvbVF1ZXJ5UGFyYW1zPzogb2JqZWN0ID0gbnVsbDtcblxuICBwdWJsaWMgc2lsZW50UmVmcmVzaElGcmFtZU5hbWU/ID0gJ2FuZ3VsYXItb2F1dGgtb2lkYy1zaWxlbnQtcmVmcmVzaC1pZnJhbWUnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZW4gdGhlIHRva2VuX3RpbWVvdXQgZXZlbnQgc2hvdWxkIGJlIHJhaXNlZC5cbiAgICogSWYgeW91IHNldCB0aGlzIHRvIHRoZSBkZWZhdWx0IHZhbHVlIDAuNzUsIHRoZSBldmVudFxuICAgKiBpcyB0cmlnZ2VyZWQgYWZ0ZXIgNzUlIG9mIHRoZSB0b2tlbidzIGxpZmUgdGltZS5cbiAgICovXG4gIHB1YmxpYyB0aW1lb3V0RmFjdG9yPyA9IDAuNzU7XG5cbiAgLyoqXG4gICAqIElmIHRydWUsIHRoZSBsaWIgd2lsbCB0cnkgdG8gY2hlY2sgd2hldGhlciB0aGUgdXNlclxuICAgKiBpcyBzdGlsbCBsb2dnZWQgaW4gb24gYSByZWd1bGFyIGJhc2lzIGFzIGRlc2NyaWJlZFxuICAgKiBpbiBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1zZXNzaW9uLTFfMC5odG1sI0NoYW5nZU5vdGlmaWNhdGlvblxuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja3NFbmFibGVkPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBJbnRlcnZhbCBpbiBtc2VjIGZvciBjaGVja2luZyB0aGUgc2Vzc2lvblxuICAgKiBhY2NvcmRpbmcgdG8gaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3Qtc2Vzc2lvbi0xXzAuaHRtbCNDaGFuZ2VOb3RpZmljYXRpb25cbiAgICovXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tJbnRlcnZhbGw/ID0gMyAqIDEwMDA7XG5cbiAgLyoqXG4gICAqIFVybCBmb3IgdGhlIGlmcmFtZSB1c2VkIGZvciBzZXNzaW9uIGNoZWNrc1xuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja0lGcmFtZVVybD86IHN0cmluZyA9IG51bGw7XG5cbiAgLyoqXG4gICAqIE5hbWUgb2YgdGhlIGlmcmFtZSB0byB1c2UgZm9yIHNlc3Npb24gY2hlY2tzXG4gICAqL1xuICBwdWJsaWMgc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZT8gPSAnYW5ndWxhci1vYXV0aC1vaWRjLWNoZWNrLXNlc3Npb24taWZyYW1lJztcblxuICAvKipcbiAgICogVGhpcyBwcm9wZXJ0eSBoYXMgYmVlbiBpbnRyb2R1Y2VkIHRvIGRpc2FibGUgYXRfaGFzaCBjaGVja3NcbiAgICogYW5kIGlzIGluZGVudGVkIGZvciBJZGVudGl0eSBQcm92aWRlciB0aGF0IGRvZXMgbm90IGRlbGl2ZXJcbiAgICogYW4gYXRfaGFzaCBFVkVOIFRIT1VHSCBpdHMgcmVjb21tZW5kZWQgYnkgdGhlIE9JREMgc3BlY3MuXG4gICAqIE9mIGNvdXJzZSwgd2hlbiBkaXNhYmxpbmcgdGhlc2UgY2hlY2tzIHRoZSB3ZSBhcmUgYnlwYXNzaW5nXG4gICAqIGEgc2VjdXJpdHkgY2hlY2sgd2hpY2ggbWVhbnMgd2UgYXJlIG1vcmUgdnVsbmVyYWJsZS5cbiAgICovXG4gIHB1YmxpYyBkaXNhYmxlQXRIYXNoQ2hlY2s/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2V0aGVyIHRvIGNoZWNrIHRoZSBzdWJqZWN0IG9mIGEgcmVmcmVzaGVkIHRva2VuIGFmdGVyIHNpbGVudCByZWZyZXNoLlxuICAgKiBOb3JtYWxseSwgaXQgc2hvdWxkIGJlIHRoZSBzYW1lIGFzIGJlZm9yZS5cbiAgICovXG4gIHB1YmxpYyBza2lwU3ViamVjdENoZWNrPyA9IGZhbHNlO1xuXG4gIHB1YmxpYyB1c2VJZFRva2VuSGludEZvclNpbGVudFJlZnJlc2g/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIERlZmluZWQgd2hldGhlciB0byBza2lwIHRoZSB2YWxpZGF0aW9uIG9mIHRoZSBpc3N1ZXIgaW4gdGhlIGRpc2NvdmVyeSBkb2N1bWVudC5cbiAgICogTm9ybWFsbHksIHRoZSBkaXNjb3ZleSBkb2N1bWVudCdzIHVybCBzdGFydHMgd2l0aCB0aGUgdXJsIG9mIHRoZSBpc3N1ZXIuXG4gICAqL1xuICBwdWJsaWMgc2tpcElzc3VlckNoZWNrPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBBY2NvcmRpbmcgdG8gcmZjNjc0OSBpdCBpcyByZWNvbW1lbmRlZCAoYnV0IG5vdCByZXF1aXJlZCkgdGhhdCB0aGUgYXV0aFxuICAgKiBzZXJ2ZXIgZXhwb3NlcyB0aGUgYWNjZXNzX3Rva2VuJ3MgbGlmZSB0aW1lIGluIHNlY29uZHMuXG4gICAqIFRoaXMgaXMgYSBmYWxsYmFjayB2YWx1ZSBmb3IgdGhlIGNhc2UgdGhpcyB2YWx1ZSBpcyBub3QgZXhwb3NlZC5cbiAgICovXG4gIHB1YmxpYyBmYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYz86IG51bWJlcjtcblxuICAvKipcbiAgICogZmluYWwgc3RhdGUgc2VudCB0byBpc3N1ZXIgaXMgYnVpbHQgYXMgZm9sbG93czpcbiAgICogc3RhdGUgPSBub25jZSArIG5vbmNlU3RhdGVTZXBhcmF0b3IgKyBhZGRpdGlvbmFsIHN0YXRlXG4gICAqIERlZmF1bHQgc2VwYXJhdG9yIGlzICc7JyAoZW5jb2RlZCAlM0IpLlxuICAgKiBJbiByYXJlIGNhc2VzLCB0aGlzIGNoYXJhY3RlciBtaWdodCBiZSBmb3JiaWRkZW4gb3IgaW5jb252ZW5pZW50IHRvIHVzZSBieSB0aGUgaXNzdWVyIHNvIGl0IGNhbiBiZSBjdXN0b21pemVkLlxuICAgKi9cbiAgcHVibGljIG5vbmNlU3RhdGVTZXBhcmF0b3I/ID0gJzsnO1xuXG4gIC8qKlxuICAgKiBTZXQgdGhpcyB0byB0cnVlIHRvIHVzZSBIVFRQIEJBU0lDIGF1dGggZm9yIHBhc3N3b3JkIGZsb3dcbiAgICovXG4gIHB1YmxpYyB1c2VIdHRwQmFzaWNBdXRoPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBUaGUgd2luZG93IG9mIHRpbWUgKGluIHNlY29uZHMpIHRvIGFsbG93IHRoZSBjdXJyZW50IHRpbWUgdG8gZGV2aWF0ZSB3aGVuIHZhbGlkYXRpbmcgaWRfdG9rZW4ncyBpYXQgYW5kIGV4cCB2YWx1ZXMuXG4gICAqL1xuICBwdWJsaWMgY2xvY2tTa2V3SW5TZWM/OiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIFRoZSBpbnRlcmNlcHRvcnMgd2FpdHMgdGhpcyB0aW1lIHNwYW4gaWYgdGhlcmUgaXMgbm8gdG9rZW5cbiAgKi9cbiAgcHVibGljIHdhaXRGb3JUb2tlbkluTXNlYz8gPSAwO1xuXG4gIC8qKlxuICAgKiBDb2RlIEZsb3cgaXMgYnkgZGVmYXVsZCB1c2VkIHRvZ2V0aGVyIHdpdGggUEtDSSB3aGljaCBpcyBhbHNvIGhpZ2x5IHJlY29tbWVudGVkLlxuICAgKiBZb3UgY2FuIGRpc2JhbGUgaXQgaGVyZSBieSBzZXR0aW5nIHRoaXMgZmxhZyB0byB0cnVlLlxuICAgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzYzNiNzZWN0aW9uLTEuMVxuICAgKi9cbiAgcHVibGljIGRpc2FibGVQS0NFPyA9IGZhbHNlO1xuXG4gIGNvbnN0cnVjdG9yKGpzb24/OiBQYXJ0aWFsPEF1dGhDb25maWc+KSB7XG4gICAgaWYgKGpzb24pIHtcbiAgICAgIE9iamVjdC5hc3NpZ24odGhpcywganNvbik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgcHJvcGVydHkgYWxsb3dzIHlvdSB0byBvdmVycmlkZSB0aGUgbWV0aG9kIHRoYXQgaXMgdXNlZCB0byBvcGVuIHRoZSBsb2dpbiB1cmwsXG4gICAqIGFsbG93aW5nIGEgd2F5IGZvciBpbXBsZW1lbnRhdGlvbnMgdG8gc3BlY2lmeSB0aGVpciBvd24gbWV0aG9kIG9mIHJvdXRpbmcgdG8gbmV3XG4gICAqIHVybHMuXG4gICAqL1xuICBwdWJsaWMgb3BlblVyaT86ICgodXJpOiBzdHJpbmcpID0+IHZvaWQpID0gdXJpID0+IHtcbiAgICBsb2NhdGlvbi5ocmVmID0gdXJpO1xuICB9XG59XG4iXX0=