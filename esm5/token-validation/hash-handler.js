import { __awaiter, __decorate, __generator, __values } from "tslib";
import { Injectable } from '@angular/core';
/**
 * Abstraction for crypto algorithms
*/
var HashHandler = /** @class */ (function () {
    function HashHandler() {
    }
    return HashHandler;
}());
export { HashHandler };
var DefaultHashHandler = /** @class */ (function () {
    function DefaultHashHandler() {
    }
    DefaultHashHandler.prototype.calcHash = function (valueToHash, algorithm) {
        return __awaiter(this, void 0, void 0, function () {
            var encoder, data, hashArray;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        encoder = new TextEncoder();
                        data = encoder.encode(valueToHash);
                        return [4 /*yield*/, window.crypto.subtle.digest(algorithm, data)];
                    case 1:
                        hashArray = _a.sent();
                        return [2 /*return*/, this.toHashString(hashArray)];
                }
            });
        });
    };
    DefaultHashHandler.prototype.toHashString = function (buffer) {
        var e_1, _a;
        var byteArray = new Uint8Array(buffer);
        var result = '';
        try {
            for (var byteArray_1 = __values(byteArray), byteArray_1_1 = byteArray_1.next(); !byteArray_1_1.done; byteArray_1_1 = byteArray_1.next()) {
                var e = byteArray_1_1.value;
                result += String.fromCharCode(e);
            }
        }
        catch (e_1_1) { e_1 = { error: e_1_1 }; }
        finally {
            try {
                if (byteArray_1_1 && !byteArray_1_1.done && (_a = byteArray_1.return)) _a.call(byteArray_1);
            }
            finally { if (e_1) throw e_1.error; }
        }
        return result;
    };
    DefaultHashHandler = __decorate([
        Injectable()
    ], DefaultHashHandler);
    return DefaultHashHandler;
}());
export { DefaultHashHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaGFzaC1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBRTNDOztFQUVFO0FBQ0Y7SUFBQTtJQUVBLENBQUM7SUFBRCxrQkFBQztBQUFELENBQUMsQUFGRCxJQUVDOztBQUdEO0lBQUE7SUF1Q0EsQ0FBQztJQXJDUyxxQ0FBUSxHQUFkLFVBQWUsV0FBbUIsRUFBRSxTQUFpQjs7Ozs7O3dCQUMzQyxPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUUsQ0FBQzt3QkFDNUIsSUFBSSxHQUFHLE9BQU8sQ0FBQyxNQUFNLENBQUMsV0FBVyxDQUFDLENBQUM7d0JBQ3ZCLHFCQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsSUFBSSxDQUFDLEVBQUE7O3dCQUE5RCxTQUFTLEdBQUcsU0FBa0Q7d0JBQ3BFLHNCQUFPLElBQUksQ0FBQyxZQUFZLENBQUMsU0FBUyxDQUFDLEVBQUM7Ozs7S0FDdkM7SUFFRCx5Q0FBWSxHQUFaLFVBQWEsTUFBbUI7O1FBQzlCLElBQU0sU0FBUyxHQUFHLElBQUksVUFBVSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQ3pDLElBQUksTUFBTSxHQUFHLEVBQUUsQ0FBQzs7WUFDaEIsS0FBYyxJQUFBLGNBQUEsU0FBQSxTQUFTLENBQUEsb0NBQUEsMkRBQUU7Z0JBQXBCLElBQUksQ0FBQyxzQkFBQTtnQkFDUixNQUFNLElBQUksTUFBTSxDQUFDLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FBQzthQUNsQzs7Ozs7Ozs7O1FBQ0QsT0FBTyxNQUFNLENBQUM7SUFDaEIsQ0FBQztJQWhCUSxrQkFBa0I7UUFEOUIsVUFBVSxFQUFFO09BQ0Esa0JBQWtCLENBdUM5QjtJQUFELHlCQUFDO0NBQUEsQUF2Q0QsSUF1Q0M7U0F2Q1ksa0JBQWtCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuXG4vKipcbiAqIEFic3RyYWN0aW9uIGZvciBjcnlwdG8gYWxnb3JpdGhtc1xuKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBIYXNoSGFuZGxlciB7XG4gICAgYWJzdHJhY3QgY2FsY0hhc2godmFsdWVUb0hhc2g6IHN0cmluZywgYWxnb3JpdGhtOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz47XG59XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBEZWZhdWx0SGFzaEhhbmRsZXIgaW1wbGVtZW50cyBIYXNoSGFuZGxlciB7XG5cbiAgICBhc3luYyBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgICAgIGNvbnN0IGVuY29kZXIgPSBuZXcgVGV4dEVuY29kZXIoKTtcbiAgICAgICAgY29uc3QgZGF0YSA9IGVuY29kZXIuZW5jb2RlKHZhbHVlVG9IYXNoKTtcbiAgICAgICAgY29uc3QgaGFzaEFycmF5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZGlnZXN0KGFsZ29yaXRobSwgZGF0YSk7XG4gICAgICAgIHJldHVybiB0aGlzLnRvSGFzaFN0cmluZyhoYXNoQXJyYXkpO1xuICAgIH1cblxuICAgIHRvSGFzaFN0cmluZyhidWZmZXI6IEFycmF5QnVmZmVyKSB7XG4gICAgICBjb25zdCBieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheShidWZmZXIpO1xuICAgICAgbGV0IHJlc3VsdCA9ICcnO1xuICAgICAgZm9yIChsZXQgZSBvZiBieXRlQXJyYXkpIHtcbiAgICAgICAgcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoZSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gcmVzdWx0O1xuICAgIH1cblxuICAgIC8vIGhleFN0cmluZyhidWZmZXIpIHtcbiAgICAvLyAgICAgY29uc3QgYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYnVmZmVyKTtcbiAgICAvLyAgICAgY29uc3QgaGV4Q29kZXMgPSBbLi4uYnl0ZUFycmF5XS5tYXAodmFsdWUgPT4ge1xuICAgIC8vICAgICAgIGNvbnN0IGhleENvZGUgPSB2YWx1ZS50b1N0cmluZygxNik7XG4gICAgLy8gICAgICAgY29uc3QgcGFkZGVkSGV4Q29kZSA9IGhleENvZGUucGFkU3RhcnQoMiwgJzAnKTtcbiAgICAvLyAgICAgICByZXR1cm4gcGFkZGVkSGV4Q29kZTtcbiAgICAvLyAgICAgfSk7XG4gICAgICBcbiAgICAvLyAgICAgcmV0dXJuIGhleENvZGVzLmpvaW4oJycpO1xuICAgIC8vICAgfVxuICAgIFxuICAgICAgLy8gdG9IYXNoU3RyaW5nKGhleFN0cmluZzogc3RyaW5nKSB7XG4gICAgICAvLyAgIGxldCByZXN1bHQgPSAnJztcbiAgICAgIC8vICAgZm9yIChsZXQgaSA9IDA7IGkgPCBoZXhTdHJpbmcubGVuZ3RoOyBpICs9IDIpIHtcbiAgICAgIC8vICAgICBsZXQgaGV4RGlnaXQgPSBoZXhTdHJpbmcuY2hhckF0KGkpICsgaGV4U3RyaW5nLmNoYXJBdChpICsgMSk7XG4gICAgICAvLyAgICAgbGV0IG51bSA9IHBhcnNlSW50KGhleERpZ2l0LCAxNik7XG4gICAgICAvLyAgICAgcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUobnVtKTtcbiAgICAgIC8vICAgfVxuICAgICAgLy8gICByZXR1cm4gcmVzdWx0O1xuICAgICAgLy8gfVxuXG59Il19