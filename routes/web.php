<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});
// ================   接口 验签   ==============
Route::any('/ssl/login','ssl\SllController@login')->middleware('apiCheck');
Route::any('/ssl/register','ssl\SllController@register')->middleware('apiCheck');
