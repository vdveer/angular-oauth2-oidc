import { __extends } from "tslib";
import { NullValidationHandler } from './null-validation-handler';
var err = "PLEASE READ THIS CAREFULLY:\n\nBeginning with angular-oauth2-oidc version 9, the JwksValidationHandler\nhas been moved to an library of its own. If you need it for implementing\nOAuth2/OIDC **implicit flow**, please install it using npm:\n\n  npm i angular-oauth2-oidc-jwks --save\n\nAfter that, you can import it into your application:\n\n  import { JwksValidationHandler } from 'angular-oauth2-oidc-jwks';\n\nPlease note, that this dependency is not needed for the **code flow**,\nwhich is nowadays the **recommented** one for single page applications.\nThis also results in smaller bundle sizes.\n";
/**
 * This is just a dummy of the JwksValidationHandler
 * telling the users that the real one has been moved
 * to an library of its own, namely angular-oauth2-oidc-utils
 */
var JwksValidationHandler = /** @class */ (function (_super) {
    __extends(JwksValidationHandler, _super);
    function JwksValidationHandler() {
        var _this = _super.call(this) || this;
        console.error(err);
        return _this;
    }
    return JwksValidationHandler;
}(NullValidationHandler));
export { JwksValidationHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiandrcy12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidG9rZW4tdmFsaWRhdGlvbi9qd2tzLXZhbGlkYXRpb24taGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsT0FBTyxFQUFFLHFCQUFxQixFQUFFLE1BQU0sMkJBQTJCLENBQUM7QUFFbEUsSUFBTSxHQUFHLEdBQUcsMGxCQWVYLENBQUM7QUFFRjs7OztHQUlHO0FBQ0g7SUFBMkMseUNBQXFCO0lBRTlEO1FBQUEsWUFDRSxpQkFBTyxTQUVSO1FBREMsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQzs7SUFDckIsQ0FBQztJQUVILDRCQUFDO0FBQUQsQ0FBQyxBQVBELENBQTJDLHFCQUFxQixHQU8vRCIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IE51bGxWYWxpZGF0aW9uSGFuZGxlciB9IGZyb20gJy4vbnVsbC12YWxpZGF0aW9uLWhhbmRsZXInO1xuXG5jb25zdCBlcnIgPSBgUExFQVNFIFJFQUQgVEhJUyBDQVJFRlVMTFk6XG5cbkJlZ2lubmluZyB3aXRoIGFuZ3VsYXItb2F1dGgyLW9pZGMgdmVyc2lvbiA5LCB0aGUgSndrc1ZhbGlkYXRpb25IYW5kbGVyXG5oYXMgYmVlbiBtb3ZlZCB0byBhbiBsaWJyYXJ5IG9mIGl0cyBvd24uIElmIHlvdSBuZWVkIGl0IGZvciBpbXBsZW1lbnRpbmdcbk9BdXRoMi9PSURDICoqaW1wbGljaXQgZmxvdyoqLCBwbGVhc2UgaW5zdGFsbCBpdCB1c2luZyBucG06XG5cbiAgbnBtIGkgYW5ndWxhci1vYXV0aDItb2lkYy1qd2tzIC0tc2F2ZVxuXG5BZnRlciB0aGF0LCB5b3UgY2FuIGltcG9ydCBpdCBpbnRvIHlvdXIgYXBwbGljYXRpb246XG5cbiAgaW1wb3J0IHsgSndrc1ZhbGlkYXRpb25IYW5kbGVyIH0gZnJvbSAnYW5ndWxhci1vYXV0aDItb2lkYy1qd2tzJztcblxuUGxlYXNlIG5vdGUsIHRoYXQgdGhpcyBkZXBlbmRlbmN5IGlzIG5vdCBuZWVkZWQgZm9yIHRoZSAqKmNvZGUgZmxvdyoqLFxud2hpY2ggaXMgbm93YWRheXMgdGhlICoqcmVjb21tZW50ZWQqKiBvbmUgZm9yIHNpbmdsZSBwYWdlIGFwcGxpY2F0aW9ucy5cblRoaXMgYWxzbyByZXN1bHRzIGluIHNtYWxsZXIgYnVuZGxlIHNpemVzLlxuYDtcblxuLyoqXG4gKiBUaGlzIGlzIGp1c3QgYSBkdW1teSBvZiB0aGUgSndrc1ZhbGlkYXRpb25IYW5kbGVyXG4gKiB0ZWxsaW5nIHRoZSB1c2VycyB0aGF0IHRoZSByZWFsIG9uZSBoYXMgYmVlbiBtb3ZlZFxuICogdG8gYW4gbGlicmFyeSBvZiBpdHMgb3duLCBuYW1lbHkgYW5ndWxhci1vYXV0aDItb2lkYy11dGlsc1xuICovXG5leHBvcnQgY2xhc3MgSndrc1ZhbGlkYXRpb25IYW5kbGVyIGV4dGVuZHMgTnVsbFZhbGlkYXRpb25IYW5kbGVyIHtcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICBzdXBlcigpO1xuICAgIGNvbnNvbGUuZXJyb3IoZXJyKTtcbiAgfVxuXG59Il19