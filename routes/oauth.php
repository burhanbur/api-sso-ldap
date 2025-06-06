<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\Auth\OAuthController;

Route::group(['prefix' => 'oauth'], function () {
    Route::group(['middleware' => ['oauth.auth']], function () {
        Route::get('userinfo', [OAuthController::class, 'userinfo']);
    });

    Route::get('login', [OAuthController::class, 'loginForm'])->name('oauth.login');
    Route::post('login', [OAuthController::class, 'login']);
    Route::get('authorize', [OAuthController::class, 'authorize'])->name('oauth.authorize');
    Route::post('token', [OAuthController::class, 'token'])->name('oauth.token');
    
    Route::get('error', function(Request $request) {
        return view('oauth.error', [
            'client_id' => $request->client_id,
            'error' => $request->error,
            'error_description' => $request->error_description
        ]);
    })->name('oauth.error');
});