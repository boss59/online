<?php

namespace App\Http\Controllers\ssl;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;

class SllController extends Controller
{
    // 登陆
    public function login(Request $request)
    {
        echo '这是 login 接口';
        echo "<br />";
        var_dump( $request->post('user_name') );
    }
    // 注册
    public function register(Request $request)
    {
        echo '这是 register 接口';
        echo "<br />";
        var_dump( $request->post('user_name') );
    }
}
