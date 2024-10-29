Java.perform(function() {
    var surface_view = Java.use('android.view.SurfaceView');

    var set_secure = surface_view.setSecure.overload('boolean');

    set_secure.implementation = function(flag){
        console.log("setSecure() 함수가 다음 인수로 호출되었습니다: " + flag); 
        set_secure.call(false);
    };

    var window = Java.use('android.view.Window');
    var set_flags = window.setFlags.overload('int', 'int');

    var window_manager = Java.use('android.view.WindowManager');
    var layout_params = Java.use('android.view.WindowManager$LayoutParams');

    set_flags.implementation = function(flags, mask){
        //console.log(Object.getOwnPropertyNames(window.__proto__).join('\n'));
        console.log("보안 플래그: " + layout_params.FLAG_SECURE.value);

        console.log("setFlags 호출 전 플래그: " + flags);
        flags = (flags.value & ~layout_params.FLAG_SECURE.value);
        console.log("setFlags 호출 후 플래그: " + flags);

        set_flags.call(this, flags, mask);
    };
});
