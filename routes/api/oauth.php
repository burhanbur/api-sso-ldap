<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\Api\OAuthController;

Route::group(['prefix' => 'oauth'], function () {
    Route::get('authorize', [OAuthController::class, 'authorize']);
    Route::post('token', [OAuthController::class, 'token']);;
    Route::get('userinfo ', [OAuthController::class, 'userinfo ']);

});