<?php

namespace App\Http\Controllers\ssl;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;

class SllController extends Controller
{
    public function login(Request $request)
    {
        var_dump( $request->post('user_name') );
    }
}
