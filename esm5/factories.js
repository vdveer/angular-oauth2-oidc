import { MemoryStorage } from './types';
export function createDefaultLogger() {
    return console;
}
export function createDefaultStorage() {
    return typeof sessionStorage !== 'undefined' ? sessionStorage : new MemoryStorage();
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZmFjdG9yaWVzLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbImZhY3Rvcmllcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0sU0FBUyxDQUFDO0FBRXhDLE1BQU0sVUFBVSxtQkFBbUI7SUFDL0IsT0FBTyxPQUFPLENBQUM7QUFDbkIsQ0FBQztBQUVELE1BQU0sVUFBVSxvQkFBb0I7SUFDaEMsT0FBTyxPQUFPLGNBQWMsS0FBSyxXQUFXLENBQUMsQ0FBQyxDQUFDLGNBQWMsQ0FBQyxDQUFDLENBQUMsSUFBSSxhQUFhLEVBQUUsQ0FBQztBQUN4RixDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgTWVtb3J5U3RvcmFnZSB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlRGVmYXVsdExvZ2dlcigpIHtcbiAgICByZXR1cm4gY29uc29sZTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGNyZWF0ZURlZmF1bHRTdG9yYWdlKCkge1xuICAgIHJldHVybiB0eXBlb2Ygc2Vzc2lvblN0b3JhZ2UgIT09ICd1bmRlZmluZWQnID8gc2Vzc2lvblN0b3JhZ2UgOiBuZXcgTWVtb3J5U3RvcmFnZSgpO1xufSJdfQ==