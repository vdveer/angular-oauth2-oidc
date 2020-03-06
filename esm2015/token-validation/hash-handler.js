import { __awaiter, __decorate } from "tslib";
import { Injectable } from '@angular/core';
/**
 * Abstraction for crypto algorithms
*/
export class HashHandler {
}
let DefaultHashHandler = class DefaultHashHandler {
    calcHash(valueToHash, algorithm) {
        return __awaiter(this, void 0, void 0, function* () {
            const encoder = new TextEncoder();
            const data = encoder.encode(valueToHash);
            const hashArray = yield window.crypto.subtle.digest(algorithm, data);
            return this.toHashString(hashArray);
        });
    }
    toHashString(buffer) {
        const byteArray = new Uint8Array(buffer);
        let result = '';
        for (let e of byteArray) {
            result += String.fromCharCode(e);
        }
        return result;
    }
};
DefaultHashHandler = __decorate([
    Injectable()
], DefaultHashHandler);
export { DefaultHashHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaGFzaC1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBRTNDOztFQUVFO0FBQ0YsTUFBTSxPQUFnQixXQUFXO0NBRWhDO0FBR0QsSUFBYSxrQkFBa0IsR0FBL0IsTUFBYSxrQkFBa0I7SUFFckIsUUFBUSxDQUFDLFdBQW1CLEVBQUUsU0FBaUI7O1lBQ2pELE1BQU0sT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFLENBQUM7WUFDbEMsTUFBTSxJQUFJLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQztZQUN6QyxNQUFNLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsSUFBSSxDQUFDLENBQUM7WUFDckUsT0FBTyxJQUFJLENBQUMsWUFBWSxDQUFDLFNBQVMsQ0FBQyxDQUFDO1FBQ3hDLENBQUM7S0FBQTtJQUVELFlBQVksQ0FBQyxNQUFtQjtRQUM5QixNQUFNLFNBQVMsR0FBRyxJQUFJLFVBQVUsQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUN6QyxJQUFJLE1BQU0sR0FBRyxFQUFFLENBQUM7UUFDaEIsS0FBSyxJQUFJLENBQUMsSUFBSSxTQUFTLEVBQUU7WUFDdkIsTUFBTSxJQUFJLE1BQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDLENBQUM7U0FDbEM7UUFDRCxPQUFPLE1BQU0sQ0FBQztJQUNoQixDQUFDO0NBdUJKLENBQUE7QUF2Q1ksa0JBQWtCO0lBRDlCLFVBQVUsRUFBRTtHQUNBLGtCQUFrQixDQXVDOUI7U0F2Q1ksa0JBQWtCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuXG4vKipcbiAqIEFic3RyYWN0aW9uIGZvciBjcnlwdG8gYWxnb3JpdGhtc1xuKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBIYXNoSGFuZGxlciB7XG4gICAgYWJzdHJhY3QgY2FsY0hhc2godmFsdWVUb0hhc2g6IHN0cmluZywgYWxnb3JpdGhtOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz47XG59XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBEZWZhdWx0SGFzaEhhbmRsZXIgaW1wbGVtZW50cyBIYXNoSGFuZGxlciB7XG5cbiAgICBhc3luYyBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgICAgIGNvbnN0IGVuY29kZXIgPSBuZXcgVGV4dEVuY29kZXIoKTtcbiAgICAgICAgY29uc3QgZGF0YSA9IGVuY29kZXIuZW5jb2RlKHZhbHVlVG9IYXNoKTtcbiAgICAgICAgY29uc3QgaGFzaEFycmF5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZGlnZXN0KGFsZ29yaXRobSwgZGF0YSk7XG4gICAgICAgIHJldHVybiB0aGlzLnRvSGFzaFN0cmluZyhoYXNoQXJyYXkpO1xuICAgIH1cblxuICAgIHRvSGFzaFN0cmluZyhidWZmZXI6IEFycmF5QnVmZmVyKSB7XG4gICAgICBjb25zdCBieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheShidWZmZXIpO1xuICAgICAgbGV0IHJlc3VsdCA9ICcnO1xuICAgICAgZm9yIChsZXQgZSBvZiBieXRlQXJyYXkpIHtcbiAgICAgICAgcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoZSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gcmVzdWx0O1xuICAgIH1cblxuICAgIC8vIGhleFN0cmluZyhidWZmZXIpIHtcbiAgICAvLyAgICAgY29uc3QgYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYnVmZmVyKTtcbiAgICAvLyAgICAgY29uc3QgaGV4Q29kZXMgPSBbLi4uYnl0ZUFycmF5XS5tYXAodmFsdWUgPT4ge1xuICAgIC8vICAgICAgIGNvbnN0IGhleENvZGUgPSB2YWx1ZS50b1N0cmluZygxNik7XG4gICAgLy8gICAgICAgY29uc3QgcGFkZGVkSGV4Q29kZSA9IGhleENvZGUucGFkU3RhcnQoMiwgJzAnKTtcbiAgICAvLyAgICAgICByZXR1cm4gcGFkZGVkSGV4Q29kZTtcbiAgICAvLyAgICAgfSk7XG4gICAgICBcbiAgICAvLyAgICAgcmV0dXJuIGhleENvZGVzLmpvaW4oJycpO1xuICAgIC8vICAgfVxuICAgIFxuICAgICAgLy8gdG9IYXNoU3RyaW5nKGhleFN0cmluZzogc3RyaW5nKSB7XG4gICAgICAvLyAgIGxldCByZXN1bHQgPSAnJztcbiAgICAgIC8vICAgZm9yIChsZXQgaSA9IDA7IGkgPCBoZXhTdHJpbmcubGVuZ3RoOyBpICs9IDIpIHtcbiAgICAgIC8vICAgICBsZXQgaGV4RGlnaXQgPSBoZXhTdHJpbmcuY2hhckF0KGkpICsgaGV4U3RyaW5nLmNoYXJBdChpICsgMSk7XG4gICAgICAvLyAgICAgbGV0IG51bSA9IHBhcnNlSW50KGhleERpZ2l0LCAxNik7XG4gICAgICAvLyAgICAgcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUobnVtKTtcbiAgICAgIC8vICAgfVxuICAgICAgLy8gICByZXR1cm4gcmVzdWx0O1xuICAgICAgLy8gfVxuXG59Il19