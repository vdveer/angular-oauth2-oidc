var OAuthModule_1;
import { __decorate } from "tslib";
import { OAuthStorage, OAuthLogger } from './types';
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { OAuthService } from './oauth-service';
import { UrlHelperService } from './url-helper.service';
import { OAuthModuleConfig } from './oauth-module.config';
import { OAuthResourceServerErrorHandler, OAuthNoopResourceServerErrorHandler } from './interceptors/resource-server-error-handler';
import { DefaultOAuthInterceptor } from './interceptors/default-oauth.interceptor';
import { ValidationHandler } from './token-validation/validation-handler';
import { NullValidationHandler } from './token-validation/null-validation-handler';
import { createDefaultLogger, createDefaultStorage } from './factories';
import { HashHandler, DefaultHashHandler } from './token-validation/hash-handler';
let OAuthModule = OAuthModule_1 = class OAuthModule {
    static forRoot(config = null, validationHandlerClass = NullValidationHandler) {
        return {
            ngModule: OAuthModule_1,
            providers: [
                OAuthService,
                UrlHelperService,
                { provide: OAuthLogger, useFactory: createDefaultLogger },
                { provide: OAuthStorage, useFactory: createDefaultStorage },
                { provide: ValidationHandler, useClass: validationHandlerClass },
                { provide: HashHandler, useClass: DefaultHashHandler },
                {
                    provide: OAuthResourceServerErrorHandler,
                    useClass: OAuthNoopResourceServerErrorHandler
                },
                { provide: OAuthModuleConfig, useValue: config },
                {
                    provide: HTTP_INTERCEPTORS,
                    useClass: DefaultOAuthInterceptor,
                    multi: true
                }
            ]
        };
    }
};
OAuthModule = OAuthModule_1 = __decorate([
    NgModule({
        imports: [CommonModule],
        declarations: [],
        exports: []
    })
], OAuthModule);
export { OAuthModule };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJhbmd1bGFyLW9hdXRoLW9pZGMubW9kdWxlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBQUEsT0FBTyxFQUFFLFlBQVksRUFBRSxXQUFXLEVBQUUsTUFBTSxTQUFTLENBQUM7QUFDcEQsT0FBTyxFQUFFLFFBQVEsRUFBdUIsTUFBTSxlQUFlLENBQUM7QUFDOUQsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQy9DLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBRXpELE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUV4RCxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQztBQUMxRCxPQUFPLEVBQ0wsK0JBQStCLEVBQy9CLG1DQUFtQyxFQUNwQyxNQUFNLDhDQUE4QyxDQUFDO0FBQ3RELE9BQU8sRUFBRSx1QkFBdUIsRUFBRSxNQUFNLDBDQUEwQyxDQUFDO0FBQ25GLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHVDQUF1QyxDQUFDO0FBQzFFLE9BQU8sRUFBRSxxQkFBcUIsRUFBRSxNQUFNLDRDQUE0QyxDQUFDO0FBQ25GLE9BQU8sRUFBRSxtQkFBbUIsRUFBRSxvQkFBb0IsRUFBRSxNQUFNLGFBQWEsQ0FBQztBQUN4RSxPQUFPLEVBQUUsV0FBVyxFQUFFLGtCQUFrQixFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFPbEYsSUFBYSxXQUFXLG1CQUF4QixNQUFhLFdBQVc7SUFDdEIsTUFBTSxDQUFDLE9BQU8sQ0FDWixTQUE0QixJQUFJLEVBQ2hDLHNCQUFzQixHQUFHLHFCQUFxQjtRQUU5QyxPQUFPO1lBQ0wsUUFBUSxFQUFFLGFBQVc7WUFDckIsU0FBUyxFQUFFO2dCQUNULFlBQVk7Z0JBQ1osZ0JBQWdCO2dCQUNoQixFQUFFLE9BQU8sRUFBRSxXQUFXLEVBQUUsVUFBVSxFQUFFLG1CQUFtQixFQUFFO2dCQUN6RCxFQUFFLE9BQU8sRUFBRSxZQUFZLEVBQUUsVUFBVSxFQUFFLG9CQUFvQixFQUFFO2dCQUMzRCxFQUFFLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxRQUFRLEVBQUUsc0JBQXNCLEVBQUM7Z0JBQy9ELEVBQUUsT0FBTyxFQUFFLFdBQVcsRUFBRSxRQUFRLEVBQUUsa0JBQWtCLEVBQUU7Z0JBQ3REO29CQUNFLE9BQU8sRUFBRSwrQkFBK0I7b0JBQ3hDLFFBQVEsRUFBRSxtQ0FBbUM7aUJBQzlDO2dCQUNELEVBQUUsT0FBTyxFQUFFLGlCQUFpQixFQUFFLFFBQVEsRUFBRSxNQUFNLEVBQUU7Z0JBQ2hEO29CQUNFLE9BQU8sRUFBRSxpQkFBaUI7b0JBQzFCLFFBQVEsRUFBRSx1QkFBdUI7b0JBQ2pDLEtBQUssRUFBRSxJQUFJO2lCQUNaO2FBQ0Y7U0FDRixDQUFDO0lBQ0osQ0FBQztDQUNGLENBQUE7QUEzQlksV0FBVztJQUx2QixRQUFRLENBQUM7UUFDUixPQUFPLEVBQUUsQ0FBQyxZQUFZLENBQUM7UUFDdkIsWUFBWSxFQUFFLEVBQUU7UUFDaEIsT0FBTyxFQUFFLEVBQUU7S0FDWixDQUFDO0dBQ1csV0FBVyxDQTJCdkI7U0EzQlksV0FBVyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IE9BdXRoU3RvcmFnZSwgT0F1dGhMb2dnZXIgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IE5nTW9kdWxlLCBNb2R1bGVXaXRoUHJvdmlkZXJzIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBDb21tb25Nb2R1bGUgfSBmcm9tICdAYW5ndWxhci9jb21tb24nO1xuaW1wb3J0IHsgSFRUUF9JTlRFUkNFUFRPUlMgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5cbmltcG9ydCB7IE9BdXRoU2VydmljZSB9IGZyb20gJy4vb2F1dGgtc2VydmljZSc7XG5pbXBvcnQgeyBVcmxIZWxwZXJTZXJ2aWNlIH0gZnJvbSAnLi91cmwtaGVscGVyLnNlcnZpY2UnO1xuXG5pbXBvcnQgeyBPQXV0aE1vZHVsZUNvbmZpZyB9IGZyb20gJy4vb2F1dGgtbW9kdWxlLmNvbmZpZyc7XG5pbXBvcnQge1xuICBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxuICBPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlclxufSBmcm9tICcuL2ludGVyY2VwdG9ycy9yZXNvdXJjZS1zZXJ2ZXItZXJyb3ItaGFuZGxlcic7XG5pbXBvcnQgeyBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3JzL2RlZmF1bHQtb2F1dGguaW50ZXJjZXB0b3InO1xuaW1wb3J0IHsgVmFsaWRhdGlvbkhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyJztcbmltcG9ydCB7IE51bGxWYWxpZGF0aW9uSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9udWxsLXZhbGlkYXRpb24taGFuZGxlcic7XG5pbXBvcnQgeyBjcmVhdGVEZWZhdWx0TG9nZ2VyLCBjcmVhdGVEZWZhdWx0U3RvcmFnZSB9IGZyb20gJy4vZmFjdG9yaWVzJztcbmltcG9ydCB7IEhhc2hIYW5kbGVyLCBEZWZhdWx0SGFzaEhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyJztcblxuQE5nTW9kdWxlKHtcbiAgaW1wb3J0czogW0NvbW1vbk1vZHVsZV0sXG4gIGRlY2xhcmF0aW9uczogW10sXG4gIGV4cG9ydHM6IFtdXG59KVxuZXhwb3J0IGNsYXNzIE9BdXRoTW9kdWxlIHtcbiAgc3RhdGljIGZvclJvb3QoXG4gICAgY29uZmlnOiBPQXV0aE1vZHVsZUNvbmZpZyA9IG51bGwsXG4gICAgdmFsaWRhdGlvbkhhbmRsZXJDbGFzcyA9IE51bGxWYWxpZGF0aW9uSGFuZGxlclxuICApOiBNb2R1bGVXaXRoUHJvdmlkZXJzPE9BdXRoTW9kdWxlPiB7XG4gICAgcmV0dXJuIHtcbiAgICAgIG5nTW9kdWxlOiBPQXV0aE1vZHVsZSxcbiAgICAgIHByb3ZpZGVyczogW1xuICAgICAgICBPQXV0aFNlcnZpY2UsXG4gICAgICAgIFVybEhlbHBlclNlcnZpY2UsXG4gICAgICAgIHsgcHJvdmlkZTogT0F1dGhMb2dnZXIsIHVzZUZhY3Rvcnk6IGNyZWF0ZURlZmF1bHRMb2dnZXIgfSxcbiAgICAgICAgeyBwcm92aWRlOiBPQXV0aFN0b3JhZ2UsIHVzZUZhY3Rvcnk6IGNyZWF0ZURlZmF1bHRTdG9yYWdlIH0sXG4gICAgICAgIHsgcHJvdmlkZTogVmFsaWRhdGlvbkhhbmRsZXIsIHVzZUNsYXNzOiB2YWxpZGF0aW9uSGFuZGxlckNsYXNzfSxcbiAgICAgICAgeyBwcm92aWRlOiBIYXNoSGFuZGxlciwgdXNlQ2xhc3M6IERlZmF1bHRIYXNoSGFuZGxlciB9LFxuICAgICAgICB7XG4gICAgICAgICAgcHJvdmlkZTogT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlcixcbiAgICAgICAgICB1c2VDbGFzczogT0F1dGhOb29wUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXJcbiAgICAgICAgfSxcbiAgICAgICAgeyBwcm92aWRlOiBPQXV0aE1vZHVsZUNvbmZpZywgdXNlVmFsdWU6IGNvbmZpZyB9LFxuICAgICAgICB7XG4gICAgICAgICAgcHJvdmlkZTogSFRUUF9JTlRFUkNFUFRPUlMsXG4gICAgICAgICAgdXNlQ2xhc3M6IERlZmF1bHRPQXV0aEludGVyY2VwdG9yLFxuICAgICAgICAgIG11bHRpOiB0cnVlXG4gICAgICAgIH1cbiAgICAgIF1cbiAgICB9O1xuICB9XG59XG4iXX0=