<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\UserController;

Route::group(['prefix' => 'auth'], function () {
    Route::post('login', [AuthController::class, 'login']);
    Route::get('ldap', [UserController::class, 'userLdap']);

    Route::group(['prefix' => 'password'], function () {
        Route::post('forgot', [AuthController::class, 'forgotPassword']);
        Route::post('reset', [AuthController::class, 'resetPassword']);  
        
        Route::group(['middleware' => ['jwt.auth']], function () {
            Route::post('change', [AuthController::class, 'changeUserPassword']);  
        });
    });

    Route::group(['prefix' => 'me', 'middleware' => ['jwt.auth']], function () {
        Route::get('/', [AuthController::class, 'me']);
        Route::post('password/change', [AuthController::class, 'changeMyPassword']);
    });
});

Route::group(['middleware' => ['jwt.auth']], function () {
    Route::group(['prefix' => 'users'], function () {
        Route::get('/', [UserController::class, 'index']);
        Route::get('/{uuid}', [UserController::class, 'show']);
        Route::post('/', [UserController::class, 'store']);
        Route::put('/{uuid}', [UserController::class, 'update']);
        Route::put('/{uuid}/status', [UserController::class, 'updateStatus']);
    });
});