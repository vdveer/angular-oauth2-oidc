import { __extends } from "tslib";
var OAuthEvent = /** @class */ (function () {
    function OAuthEvent(type) {
        this.type = type;
    }
    return OAuthEvent;
}());
export { OAuthEvent };
var OAuthSuccessEvent = /** @class */ (function (_super) {
    __extends(OAuthSuccessEvent, _super);
    function OAuthSuccessEvent(type, info) {
        if (info === void 0) { info = null; }
        var _this = _super.call(this, type) || this;
        _this.info = info;
        return _this;
    }
    return OAuthSuccessEvent;
}(OAuthEvent));
export { OAuthSuccessEvent };
var OAuthInfoEvent = /** @class */ (function (_super) {
    __extends(OAuthInfoEvent, _super);
    function OAuthInfoEvent(type, info) {
        if (info === void 0) { info = null; }
        var _this = _super.call(this, type) || this;
        _this.info = info;
        return _this;
    }
    return OAuthInfoEvent;
}(OAuthEvent));
export { OAuthInfoEvent };
var OAuthErrorEvent = /** @class */ (function (_super) {
    __extends(OAuthErrorEvent, _super);
    function OAuthErrorEvent(type, reason, params) {
        if (params === void 0) { params = null; }
        var _this = _super.call(this, type) || this;
        _this.reason = reason;
        _this.params = params;
        return _this;
    }
    return OAuthErrorEvent;
}(OAuthEvent));
export { OAuthErrorEvent };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXZlbnRzLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbImV2ZW50cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBeUJBO0lBQ0Usb0JBQXFCLElBQWU7UUFBZixTQUFJLEdBQUosSUFBSSxDQUFXO0lBQUcsQ0FBQztJQUMxQyxpQkFBQztBQUFELENBQUMsQUFGRCxJQUVDOztBQUVEO0lBQXVDLHFDQUFVO0lBQy9DLDJCQUFZLElBQWUsRUFBVyxJQUFnQjtRQUFoQixxQkFBQSxFQUFBLFdBQWdCO1FBQXRELFlBQ0Usa0JBQU0sSUFBSSxDQUFDLFNBQ1o7UUFGcUMsVUFBSSxHQUFKLElBQUksQ0FBWTs7SUFFdEQsQ0FBQztJQUNILHdCQUFDO0FBQUQsQ0FBQyxBQUpELENBQXVDLFVBQVUsR0FJaEQ7O0FBRUQ7SUFBb0Msa0NBQVU7SUFDNUMsd0JBQVksSUFBZSxFQUFXLElBQWdCO1FBQWhCLHFCQUFBLEVBQUEsV0FBZ0I7UUFBdEQsWUFDRSxrQkFBTSxJQUFJLENBQUMsU0FDWjtRQUZxQyxVQUFJLEdBQUosSUFBSSxDQUFZOztJQUV0RCxDQUFDO0lBQ0gscUJBQUM7QUFBRCxDQUFDLEFBSkQsQ0FBb0MsVUFBVSxHQUk3Qzs7QUFFRDtJQUFxQyxtQ0FBVTtJQUM3Qyx5QkFDRSxJQUFlLEVBQ04sTUFBYyxFQUNkLE1BQXFCO1FBQXJCLHVCQUFBLEVBQUEsYUFBcUI7UUFIaEMsWUFLRSxrQkFBTSxJQUFJLENBQUMsU0FDWjtRQUpVLFlBQU0sR0FBTixNQUFNLENBQVE7UUFDZCxZQUFNLEdBQU4sTUFBTSxDQUFlOztJQUdoQyxDQUFDO0lBQ0gsc0JBQUM7QUFBRCxDQUFDLEFBUkQsQ0FBcUMsVUFBVSxHQVE5QyIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCB0eXBlIEV2ZW50VHlwZSA9XG4gIHwgJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnXG4gIHwgJ2p3a3NfbG9hZF9lcnJvcidcbiAgfCAnaW52YWxpZF9ub25jZV9pbl9zdGF0ZSdcbiAgfCAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InXG4gIHwgJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJ1xuICB8ICd1c2VyX3Byb2ZpbGVfbG9hZGVkJ1xuICB8ICd1c2VyX3Byb2ZpbGVfbG9hZF9lcnJvcidcbiAgfCAndG9rZW5fcmVjZWl2ZWQnXG4gIHwgJ3Rva2VuX2Vycm9yJ1xuICB8ICdjb2RlX2Vycm9yJ1xuICB8ICd0b2tlbl9yZWZyZXNoZWQnXG4gIHwgJ3Rva2VuX3JlZnJlc2hfZXJyb3InXG4gIHwgJ3NpbGVudF9yZWZyZXNoX2Vycm9yJ1xuICB8ICdzaWxlbnRseV9yZWZyZXNoZWQnXG4gIHwgJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnXG4gIHwgJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InXG4gIHwgJ3Rva2VuX2V4cGlyZXMnXG4gIHwgJ3Nlc3Npb25fY2hhbmdlZCdcbiAgfCAnc2Vzc2lvbl9lcnJvcidcbiAgfCAnc2Vzc2lvbl90ZXJtaW5hdGVkJ1xuICB8ICdsb2dvdXQnXG4gIHwgJ3BvcHVwX2Nsb3NlZCdcbiAgfCAncG9wdXBfYmxvY2tlZCc7XG5cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBPQXV0aEV2ZW50IHtcbiAgY29uc3RydWN0b3IocmVhZG9ubHkgdHlwZTogRXZlbnRUeXBlKSB7fVxufVxuXG5leHBvcnQgY2xhc3MgT0F1dGhTdWNjZXNzRXZlbnQgZXh0ZW5kcyBPQXV0aEV2ZW50IHtcbiAgY29uc3RydWN0b3IodHlwZTogRXZlbnRUeXBlLCByZWFkb25seSBpbmZvOiBhbnkgPSBudWxsKSB7XG4gICAgc3VwZXIodHlwZSk7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIE9BdXRoSW5mb0V2ZW50IGV4dGVuZHMgT0F1dGhFdmVudCB7XG4gIGNvbnN0cnVjdG9yKHR5cGU6IEV2ZW50VHlwZSwgcmVhZG9ubHkgaW5mbzogYW55ID0gbnVsbCkge1xuICAgIHN1cGVyKHR5cGUpO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBPQXV0aEVycm9yRXZlbnQgZXh0ZW5kcyBPQXV0aEV2ZW50IHtcbiAgY29uc3RydWN0b3IoXG4gICAgdHlwZTogRXZlbnRUeXBlLFxuICAgIHJlYWRvbmx5IHJlYXNvbjogb2JqZWN0LFxuICAgIHJlYWRvbmx5IHBhcmFtczogb2JqZWN0ID0gbnVsbFxuICApIHtcbiAgICBzdXBlcih0eXBlKTtcbiAgfVxufVxuIl19