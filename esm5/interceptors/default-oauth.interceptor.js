import { __decorate, __metadata, __param } from "tslib";
import { Injectable, Optional } from '@angular/core';
import { of, merge } from 'rxjs';
import { catchError, filter, map, take, mergeMap, timeout } from 'rxjs/operators';
import { OAuthResourceServerErrorHandler } from './resource-server-error-handler';
import { OAuthModuleConfig } from '../oauth-module.config';
import { OAuthStorage } from '../types';
import { OAuthService } from '../oauth-service';
var DefaultOAuthInterceptor = /** @class */ (function () {
    function DefaultOAuthInterceptor(authStorage, oAuthService, errorHandler, moduleConfig) {
        this.authStorage = authStorage;
        this.oAuthService = oAuthService;
        this.errorHandler = errorHandler;
        this.moduleConfig = moduleConfig;
    }
    DefaultOAuthInterceptor.prototype.checkUrl = function (url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find(function (u) { return url.startsWith(u); });
        }
        return true;
    };
    DefaultOAuthInterceptor.prototype.intercept = function (req, next) {
        var _this = this;
        var url = req.url.toLowerCase();
        if (!this.moduleConfig || !this.moduleConfig.resourceServer || !this.checkUrl(url)) {
            return next.handle(req);
        }
        var sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError(function (err) { return _this.errorHandler.handleError(err); }));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter(function (token) { return token ? true : false; })), this.oAuthService.events.pipe(filter(function (e) { return e.type === 'token_received'; }), timeout(this.oAuthService.waitForTokenInMsec || 0), catchError(function (_) { return of(null); }), // timeout is not an error
        map(function (_) { return _this.oAuthService.getAccessToken(); }))).pipe(take(1), mergeMap(function (token) {
            if (token) {
                var header = 'Bearer ' + token;
                var headers = req.headers.set('Authorization', header);
                req = req.clone({ headers: headers });
            }
            return next
                .handle(req)
                .pipe(catchError(function (err) { return _this.errorHandler.handleError(err); }));
        }));
    };
    DefaultOAuthInterceptor.ctorParameters = function () { return [
        { type: OAuthStorage },
        { type: OAuthService },
        { type: OAuthResourceServerErrorHandler },
        { type: OAuthModuleConfig, decorators: [{ type: Optional }] }
    ]; };
    DefaultOAuthInterceptor = __decorate([
        Injectable(),
        __param(3, Optional()),
        __metadata("design:paramtypes", [OAuthStorage,
            OAuthService,
            OAuthResourceServerErrorHandler,
            OAuthModuleConfig])
    ], DefaultOAuthInterceptor);
    return DefaultOAuthInterceptor;
}());
export { DefaultOAuthInterceptor };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJpbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFRckQsT0FBTyxFQUFjLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDN0MsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLElBQUksRUFBRSxRQUFRLEVBQUUsT0FBTyxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFDbEYsT0FBTyxFQUFFLCtCQUErQixFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFDbEYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sd0JBQXdCLENBQUM7QUFDM0QsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLFVBQVUsQ0FBQztBQUN4QyxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFHaEQ7SUFFSSxpQ0FDWSxXQUF5QixFQUN6QixZQUEwQixFQUMxQixZQUE2QyxFQUNqQyxZQUErQjtRQUgzQyxnQkFBVyxHQUFYLFdBQVcsQ0FBYztRQUN6QixpQkFBWSxHQUFaLFlBQVksQ0FBYztRQUMxQixpQkFBWSxHQUFaLFlBQVksQ0FBaUM7UUFDakMsaUJBQVksR0FBWixZQUFZLENBQW1CO0lBQ25ELENBQUM7SUFFRywwQ0FBUSxHQUFoQixVQUFpQixHQUFXO1FBQ3hCLElBQUksSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLENBQUMsbUJBQW1CLEVBQUU7WUFDdEQsT0FBTyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLENBQUMsQ0FBQztTQUNwRTtRQUVELElBQUksSUFBSSxDQUFDLFlBQVks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QyxVQUFVLEVBQUU7UUFPSixXQUFBLFFBQVEsRUFBRSxDQUFBO3lDQUhVLFlBQVk7WUFDWCxZQUFZO1lBQ1osK0JBQStCO1lBQ25CLGlCQUFpQjtPQU45Qyx1QkFBdUIsQ0FpRW5DO0lBQUQsOEJBQUM7Q0FBQSxBQWpFRCxJQWlFQztTQWpFWSx1QkFBdUIiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBPcHRpb25hbCB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuXG5pbXBvcnQge1xuICBIdHRwRXZlbnQsXG4gIEh0dHBIYW5kbGVyLFxuICBIdHRwSW50ZXJjZXB0b3IsXG4gIEh0dHBSZXF1ZXN0LFxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBvZiwgbWVyZ2UgfSBmcm9tICdyeGpzJztcbmltcG9ydCB7IGNhdGNoRXJyb3IsIGZpbHRlciwgbWFwLCB0YWtlLCBtZXJnZU1hcCwgdGltZW91dCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIgfSBmcm9tICcuL3Jlc291cmNlLXNlcnZlci1lcnJvci1oYW5kbGVyJztcbmltcG9ydCB7IE9BdXRoTW9kdWxlQ29uZmlnIH0gZnJvbSAnLi4vb2F1dGgtbW9kdWxlLmNvbmZpZyc7XG5pbXBvcnQgeyBPQXV0aFN0b3JhZ2UgfSBmcm9tICcuLi90eXBlcyc7XG5pbXBvcnQgeyBPQXV0aFNlcnZpY2UgfSBmcm9tICcuLi9vYXV0aC1zZXJ2aWNlJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIERlZmF1bHRPQXV0aEludGVyY2VwdG9yIGltcGxlbWVudHMgSHR0cEludGVyY2VwdG9yIHtcblxuICAgIGNvbnN0cnVjdG9yKFxuICAgICAgICBwcml2YXRlIGF1dGhTdG9yYWdlOiBPQXV0aFN0b3JhZ2UsXG4gICAgICAgIHByaXZhdGUgb0F1dGhTZXJ2aWNlOiBPQXV0aFNlcnZpY2UsXG4gICAgICAgIHByaXZhdGUgZXJyb3JIYW5kbGVyOiBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxuICAgICAgICBAT3B0aW9uYWwoKSBwcml2YXRlIG1vZHVsZUNvbmZpZzogT0F1dGhNb2R1bGVDb25maWdcbiAgICApIHsgfVxuXG4gICAgcHJpdmF0ZSBjaGVja1VybCh1cmw6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgICAgICBpZiAodGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuY3VzdG9tVXJsVmFsaWRhdGlvbikge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmN1c3RvbVVybFZhbGlkYXRpb24odXJsKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5hbGxvd2VkVXJscykge1xuICAgICAgICAgICAgcmV0dXJuICEhdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuYWxsb3dlZFVybHMuZmluZCh1ID0+IHVybC5zdGFydHNXaXRoKHUpKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICBwdWJsaWMgaW50ZXJjZXB0KFxuICAgIHJlcTogSHR0cFJlcXVlc3Q8YW55PixcbiAgICBuZXh0OiBIdHRwSGFuZGxlclxuICApOiBPYnNlcnZhYmxlPEh0dHBFdmVudDxhbnk+PiB7XG4gICAgY29uc3QgdXJsID0gcmVxLnVybC50b0xvd2VyQ2FzZSgpO1xuXG5cbiAgICBpZiAoIXRoaXMubW9kdWxlQ29uZmlnIHx8ICF0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlciB8fCAhdGhpcy5jaGVja1VybCh1cmwpKSB7XG4gICAgICByZXR1cm4gbmV4dC5oYW5kbGUocmVxKTtcbiAgICB9XG5cbiAgICBjb25zdCBzZW5kQWNjZXNzVG9rZW4gPSB0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5zZW5kQWNjZXNzVG9rZW47XG5cbiAgICBpZiAoIXNlbmRBY2Nlc3NUb2tlbikge1xuICAgICAgcmV0dXJuIG5leHRcbiAgICAgICAgLmhhbmRsZShyZXEpXG4gICAgICAgIC5waXBlKGNhdGNoRXJyb3IoZXJyID0+IHRoaXMuZXJyb3JIYW5kbGVyLmhhbmRsZUVycm9yKGVycikpKTtcbiAgICB9XG5cbiAgICByZXR1cm4gbWVyZ2UoXG4gICAgICBvZih0aGlzLm9BdXRoU2VydmljZS5nZXRBY2Nlc3NUb2tlbigpKS5waXBlKFxuICAgICAgICBmaWx0ZXIodG9rZW4gPT4gdG9rZW4gPyB0cnVlIDogZmFsc2UpLFxuICAgICAgKSxcbiAgICAgIHRoaXMub0F1dGhTZXJ2aWNlLmV2ZW50cy5waXBlKFxuICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpLFxuICAgICAgICB0aW1lb3V0KHRoaXMub0F1dGhTZXJ2aWNlLndhaXRGb3JUb2tlbkluTXNlYyB8fCAwKSxcbiAgICAgICAgY2F0Y2hFcnJvcihfID0+IG9mKG51bGwpKSwgLy8gdGltZW91dCBpcyBub3QgYW4gZXJyb3JcbiAgICAgICAgbWFwKF8gPT4gdGhpcy5vQXV0aFNlcnZpY2UuZ2V0QWNjZXNzVG9rZW4oKSksXG4gICAgICApLFxuICAgICkucGlwZShcbiAgICAgIHRha2UoMSksXG4gICAgICBtZXJnZU1hcCh0b2tlbiA9PiB7XG4gICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgIGNvbnN0IGhlYWRlciA9ICdCZWFyZXIgJyArIHRva2VuO1xuICAgICAgICAgIGNvbnN0IGhlYWRlcnMgPSByZXEuaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCBoZWFkZXIpO1xuICAgICAgICAgIHJlcSA9IHJlcS5jbG9uZSh7IGhlYWRlcnMgfSk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbmV4dFxuICAgICAgICAgIC5oYW5kbGUocmVxKVxuICAgICAgICAgIC5waXBlKGNhdGNoRXJyb3IoZXJyID0+IHRoaXMuZXJyb3JIYW5kbGVyLmhhbmRsZUVycm9yKGVycikpKTtcbiAgICAgIH0pLFxuICAgICk7XG4gIH1cbn1cbiJdfQ==