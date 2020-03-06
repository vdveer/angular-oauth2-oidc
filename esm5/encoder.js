/**
 * This custom encoder allows charactes like +, % and / to be used in passwords
 */
var WebHttpUrlEncodingCodec = /** @class */ (function () {
    function WebHttpUrlEncodingCodec() {
    }
    WebHttpUrlEncodingCodec.prototype.encodeKey = function (k) {
        return encodeURIComponent(k);
    };
    WebHttpUrlEncodingCodec.prototype.encodeValue = function (v) {
        return encodeURIComponent(v);
    };
    WebHttpUrlEncodingCodec.prototype.decodeKey = function (k) {
        return decodeURIComponent(k);
    };
    WebHttpUrlEncodingCodec.prototype.decodeValue = function (v) {
        return decodeURIComponent(v);
    };
    return WebHttpUrlEncodingCodec;
}());
export { WebHttpUrlEncodingCodec };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZW5jb2Rlci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJlbmNvZGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUNBOztHQUVHO0FBQ0g7SUFBQTtJQWdCQSxDQUFDO0lBZkMsMkNBQVMsR0FBVCxVQUFVLENBQVM7UUFDakIsT0FBTyxrQkFBa0IsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUMvQixDQUFDO0lBRUQsNkNBQVcsR0FBWCxVQUFZLENBQVM7UUFDbkIsT0FBTyxrQkFBa0IsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUMvQixDQUFDO0lBRUQsMkNBQVMsR0FBVCxVQUFVLENBQVM7UUFDakIsT0FBTyxrQkFBa0IsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUMvQixDQUFDO0lBRUQsNkNBQVcsR0FBWCxVQUFZLENBQVM7UUFDbkIsT0FBTyxrQkFBa0IsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUMvQixDQUFDO0lBQ0gsOEJBQUM7QUFBRCxDQUFDLEFBaEJELElBZ0JDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSHR0cFBhcmFtZXRlckNvZGVjIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuLyoqXG4gKiBUaGlzIGN1c3RvbSBlbmNvZGVyIGFsbG93cyBjaGFyYWN0ZXMgbGlrZSArLCAlIGFuZCAvIHRvIGJlIHVzZWQgaW4gcGFzc3dvcmRzXG4gKi9cbmV4cG9ydCBjbGFzcyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYyBpbXBsZW1lbnRzIEh0dHBQYXJhbWV0ZXJDb2RlYyB7XG4gIGVuY29kZUtleShrOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQoayk7XG4gIH1cblxuICBlbmNvZGVWYWx1ZSh2OiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQodik7XG4gIH1cblxuICBkZWNvZGVLZXkoazogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KGspO1xuICB9XG5cbiAgZGVjb2RlVmFsdWUodjogc3RyaW5nKSB7XG4gICAgcmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudCh2KTtcbiAgfVxufVxuIl19