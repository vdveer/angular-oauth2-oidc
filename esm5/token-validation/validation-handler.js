import { __awaiter, __generator } from "tslib";
import { base64UrlEncode } from '../base64-helper';
/**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 */
var ValidationHandler = /** @class */ (function () {
    function ValidationHandler() {
    }
    return ValidationHandler;
}());
export { ValidationHandler };
/**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 */
var AbstractValidationHandler = /** @class */ (function () {
    function AbstractValidationHandler() {
    }
    /**
     * Validates the at_hash in an id_token against the received access_token.
     */
    AbstractValidationHandler.prototype.validateAtHash = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var hashAlg, tokenHash, leftMostHalf, atHash, claimsAtHash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        hashAlg = this.inferHashAlgorithm(params.idTokenHeader);
                        return [4 /*yield*/, this.calcHash(params.accessToken, hashAlg)];
                    case 1:
                        tokenHash = _a.sent();
                        leftMostHalf = tokenHash.substr(0, tokenHash.length / 2);
                        atHash = base64UrlEncode(leftMostHalf);
                        claimsAtHash = params.idTokenClaims['at_hash'].replace(/=/g, '');
                        if (atHash !== claimsAtHash) {
                            console.error('exptected at_hash: ' + atHash);
                            console.error('actual at_hash: ' + claimsAtHash);
                        }
                        return [2 /*return*/, atHash === claimsAtHash];
                }
            });
        });
    };
    /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @param jwtHeader the id_token's parsed header
     */
    AbstractValidationHandler.prototype.inferHashAlgorithm = function (jwtHeader) {
        var alg = jwtHeader['alg'];
        if (!alg.match(/^.S[0-9]{3}$/)) {
            throw new Error('Algorithm not supported: ' + alg);
        }
        return 'sha-' + alg.substr(2);
    };
    return AbstractValidationHandler;
}());
export { AbstractValidationHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmFsaWRhdGlvbi1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsZUFBZSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFXbkQ7OztHQUdHO0FBQ0g7SUFBQTtJQVlBLENBQUM7SUFBRCx3QkFBQztBQUFELENBQUMsQUFaRCxJQVlDOztBQUVEOzs7O0dBSUc7QUFDSDtJQUFBO0lBb0RBLENBQUM7SUE5Q0M7O09BRUc7SUFDRyxrREFBYyxHQUFwQixVQUFxQixNQUF3Qjs7Ozs7O3dCQUN2QyxPQUFPLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUMsQ0FBQzt3QkFFNUMscUJBQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsV0FBVyxFQUFFLE9BQU8sQ0FBQyxFQUFBOzt3QkFBNUQsU0FBUyxHQUFHLFNBQWdEO3dCQUU1RCxZQUFZLEdBQUcsU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBQzt3QkFFekQsTUFBTSxHQUFHLGVBQWUsQ0FBQyxZQUFZLENBQUMsQ0FBQzt3QkFFdkMsWUFBWSxHQUFHLE1BQU0sQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQzt3QkFFckUsSUFBSSxNQUFNLEtBQUssWUFBWSxFQUFFOzRCQUMzQixPQUFPLENBQUMsS0FBSyxDQUFDLHFCQUFxQixHQUFHLE1BQU0sQ0FBQyxDQUFDOzRCQUM5QyxPQUFPLENBQUMsS0FBSyxDQUFDLGtCQUFrQixHQUFHLFlBQVksQ0FBQyxDQUFDO3lCQUNsRDt3QkFFRCxzQkFBTyxNQUFNLEtBQUssWUFBWSxFQUFDOzs7O0tBQ2hDO0lBRUQ7Ozs7O09BS0c7SUFDTyxzREFBa0IsR0FBNUIsVUFBNkIsU0FBaUI7UUFDNUMsSUFBSSxHQUFHLEdBQVcsU0FBUyxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBRW5DLElBQUksQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLGNBQWMsQ0FBQyxFQUFFO1lBQzlCLE1BQU0sSUFBSSxLQUFLLENBQUMsMkJBQTJCLEdBQUcsR0FBRyxDQUFDLENBQUM7U0FDcEQ7UUFFRCxPQUFPLE1BQU0sR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2hDLENBQUM7SUFVSCxnQ0FBQztBQUFELENBQUMsQUFwREQsSUFvREMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBiYXNlNjRVcmxFbmNvZGUgfSBmcm9tICcuLi9iYXNlNjQtaGVscGVyJztcblxuZXhwb3J0IGludGVyZmFjZSBWYWxpZGF0aW9uUGFyYW1zIHtcbiAgaWRUb2tlbjogc3RyaW5nO1xuICBhY2Nlc3NUb2tlbjogc3RyaW5nO1xuICBpZFRva2VuSGVhZGVyOiBvYmplY3Q7XG4gIGlkVG9rZW5DbGFpbXM6IG9iamVjdDtcbiAgandrczogb2JqZWN0O1xuICBsb2FkS2V5czogKCkgPT4gUHJvbWlzZTxvYmplY3Q+O1xufVxuXG4vKipcbiAqIEludGVyZmFjZSBmb3IgSGFuZGxlcnMgdGhhdCBhcmUgaG9va2VkIGluIHRvXG4gKiB2YWxpZGF0ZSB0b2tlbnMuXG4gKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBWYWxpZGF0aW9uSGFuZGxlciB7XG4gIC8qKlxuICAgKiBWYWxpZGF0ZXMgdGhlIHNpZ25hdHVyZSBvZiBhbiBpZF90b2tlbi5cbiAgICovXG4gIHB1YmxpYyBhYnN0cmFjdCB2YWxpZGF0ZVNpZ25hdHVyZShcbiAgICB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zXG4gICk6IFByb21pc2U8YW55PjtcblxuICAvKipcbiAgICogVmFsaWRhdGVzIHRoZSBhdF9oYXNoIGluIGFuIGlkX3Rva2VuIGFnYWluc3QgdGhlIHJlY2VpdmVkIGFjY2Vzc190b2tlbi5cbiAgICovXG4gIHB1YmxpYyBhYnN0cmFjdCB2YWxpZGF0ZUF0SGFzaCh2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxib29sZWFuPjtcbn1cblxuLyoqXG4gKiBUaGlzIGFic3RyYWN0IGltcGxlbWVudGF0aW9uIG9mIFZhbGlkYXRpb25IYW5kbGVyIGFscmVhZHkgaW1wbGVtZW50c1xuICogdGhlIG1ldGhvZCB2YWxpZGF0ZUF0SGFzaC4gSG93ZXZlciwgdG8gbWFrZSB1c2Ugb2YgaXQsXG4gKiB5b3UgaGF2ZSB0byBvdmVycmlkZSB0aGUgbWV0aG9kIGNhbGNIYXNoLlxuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgQWJzdHJhY3RWYWxpZGF0aW9uSGFuZGxlciBpbXBsZW1lbnRzIFZhbGlkYXRpb25IYW5kbGVyIHtcbiAgLyoqXG4gICAqIFZhbGlkYXRlcyB0aGUgc2lnbmF0dXJlIG9mIGFuIGlkX3Rva2VuLlxuICAgKi9cbiAgYWJzdHJhY3QgdmFsaWRhdGVTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8YW55PjtcblxuICAvKipcbiAgICogVmFsaWRhdGVzIHRoZSBhdF9oYXNoIGluIGFuIGlkX3Rva2VuIGFnYWluc3QgdGhlIHJlY2VpdmVkIGFjY2Vzc190b2tlbi5cbiAgICovXG4gIGFzeW5jIHZhbGlkYXRlQXRIYXNoKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGxldCBoYXNoQWxnID0gdGhpcy5pbmZlckhhc2hBbGdvcml0aG0ocGFyYW1zLmlkVG9rZW5IZWFkZXIpO1xuXG4gICAgbGV0IHRva2VuSGFzaCA9IGF3YWl0IHRoaXMuY2FsY0hhc2gocGFyYW1zLmFjY2Vzc1Rva2VuLCBoYXNoQWxnKTsgLy8gc2hhMjU2KGFjY2Vzc1Rva2VuLCB7IGFzU3RyaW5nOiB0cnVlIH0pO1xuXG4gICAgbGV0IGxlZnRNb3N0SGFsZiA9IHRva2VuSGFzaC5zdWJzdHIoMCwgdG9rZW5IYXNoLmxlbmd0aCAvIDIpO1xuXG4gICAgbGV0IGF0SGFzaCA9IGJhc2U2NFVybEVuY29kZShsZWZ0TW9zdEhhbGYpO1xuXG4gICAgbGV0IGNsYWltc0F0SGFzaCA9IHBhcmFtcy5pZFRva2VuQ2xhaW1zWydhdF9oYXNoJ10ucmVwbGFjZSgvPS9nLCAnJyk7XG5cbiAgICBpZiAoYXRIYXNoICE9PSBjbGFpbXNBdEhhc2gpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ2V4cHRlY3RlZCBhdF9oYXNoOiAnICsgYXRIYXNoKTtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ2FjdHVhbCBhdF9oYXNoOiAnICsgY2xhaW1zQXRIYXNoKTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXRIYXNoID09PSBjbGFpbXNBdEhhc2g7XG4gIH1cblxuICAvKipcbiAgICogSW5mZXJzIHRoZSBuYW1lIG9mIHRoZSBoYXNoIGFsZ29yaXRobSB0byB1c2VcbiAgICogZnJvbSB0aGUgYWxnIGZpZWxkIG9mIGFuIGlkX3Rva2VuLlxuICAgKlxuICAgKiBAcGFyYW0gand0SGVhZGVyIHRoZSBpZF90b2tlbidzIHBhcnNlZCBoZWFkZXJcbiAgICovXG4gIHByb3RlY3RlZCBpbmZlckhhc2hBbGdvcml0aG0oand0SGVhZGVyOiBvYmplY3QpOiBzdHJpbmcge1xuICAgIGxldCBhbGc6IHN0cmluZyA9IGp3dEhlYWRlclsnYWxnJ107XG5cbiAgICBpZiAoIWFsZy5tYXRjaCgvXi5TWzAtOV17M30kLykpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQWxnb3JpdGhtIG5vdCBzdXBwb3J0ZWQ6ICcgKyBhbGcpO1xuICAgIH1cblxuICAgIHJldHVybiAnc2hhLScgKyBhbGcuc3Vic3RyKDIpO1xuICB9XG5cbiAgLyoqXG4gICAqIENhbGN1bGF0ZXMgdGhlIGhhc2ggZm9yIHRoZSBwYXNzZWQgdmFsdWUgYnkgdXNpbmdcbiAgICogdGhlIHBhc3NlZCBoYXNoIGFsZ29yaXRobS5cbiAgICpcbiAgICogQHBhcmFtIHZhbHVlVG9IYXNoXG4gICAqIEBwYXJhbSBhbGdvcml0aG1cbiAgICovXG4gIHByb3RlY3RlZCBhYnN0cmFjdCBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPjtcbn1cbiJdfQ==