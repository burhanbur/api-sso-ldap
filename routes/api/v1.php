<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\Api\V1\ApplicationController;
use App\Http\Controllers\Api\V1\AuthController;
use App\Http\Controllers\Api\V1\EntityTypeController;
use App\Http\Controllers\Api\V1\RoleController;
use App\Http\Controllers\Api\V1\RoleTypeController;
use App\Http\Controllers\Api\V1\ScopeController;
use App\Http\Controllers\Api\V1\UserController;
use App\Http\Controllers\Api\V1\UserRoleController;


Route::group(['prefix' => 'v1'], function () {
    Route::group(['prefix' => 'auth'], function () {
        Route::post('login', [AuthController::class, 'login']);
        Route::post('logout', [AuthController::class, 'logout']);
        Route::get('ldap', [UserController::class, 'userLdap']);

        Route::post('session', [AuthController::class, 'checkToken']);

        Route::group(['prefix' => 'password'], function () {
            Route::post('forgot', [AuthController::class, 'forgotPassword']);
            Route::post('reset', [AuthController::class, 'resetPassword']);
            
            Route::group(['middleware' => ['jwt.auth']], function () {
                Route::post('change', [AuthController::class, 'changeUserPassword']);
            });
        });

        Route::group(['middleware' => ['jwt.refresh']], function () {
            Route::post('refresh', [AuthController::class, 'refreshToken']);
        });

        Route::group(['middleware' => ['jwt.auth']], function () {
            // TODO: cek apakah role admin SSO yang impersonate atau bukan
            Route::group(['prefix' => 'impersonate'], function () {
                Route::post('start/{uuid}', [AuthController::class, 'startImpersonate']);
                Route::post('leave', [AuthController::class, 'leaveImpersonate']);
            });

            Route::group(['prefix' => 'devices'], function () {
                Route::get('active', [AuthController::class, 'getUserActiveDevices']);
                Route::get('active/impersonate', [AuthController::class, 'getActiveImpersonations']);
                Route::post('logout', [AuthController::class, 'logoutUserAllDevices']);
            });
        });

        Route::group(['prefix' => 'me', 'middleware' => ['jwt.auth']], function () {
            Route::get('/', [AuthController::class, 'me']);
            Route::get('applications', [ApplicationController::class, 'myApplication']);
            Route::post('password/change', [AuthController::class, 'changeMyPassword']);
        });
    });

    // TODO: cek apakah role admin SSO yang impersonate atau bukan
    Route::group(['middleware' => ['jwt.auth']], function () {
        Route::group(['prefix' => 'users'], function () {
            Route::get('/', [UserController::class, 'index']);
            Route::get('/{uuid}', [UserController::class, 'show']);
            Route::post('/', [UserController::class, 'store']);
            Route::put('/{uuid}', [UserController::class, 'update']);
            Route::put('/{uuid}/status', [UserController::class, 'updateStatus']);

            Route::post('profile', [UserController::class, 'updateMyProfile']);
            Route::post('generate-username', [UserController::class, 'generateUsername']);
            Route::post('import', [UserController::class, 'import']);
        });
        
        Route::get('scopes', [ScopeController::class, 'index']);
        Route::get('entity-types', [EntityTypeController::class, 'index']);
        Route::get('role-types', [RoleTypeController::class, 'index']);
        
        Route::group(['prefix' => 'user-roles'], function () {
            Route::get('/', [UserRoleController::class, 'index']);
            Route::post('/', [UserRoleController::class, 'store']);
            Route::delete('/{uuid}', [UserRoleController::class, 'destroy']);
        });

        Route::group(['prefix' => 'roles'], function () {
            Route::get('/', [RoleController::class, 'index']);
            Route::get('/{uuid}', [RoleController::class, 'show']);
            Route::post('/', [RoleController::class, 'store']);
            Route::put('/{uuid}', [RoleController::class, 'update']);
            Route::delete('/{uuid}', [RoleController::class, 'destroy']);
        });
        
        Route::group(['prefix' => 'applications'], function () {
            Route::get('/', [ApplicationController::class, 'index']);
            Route::get('/{uuid}/users', [ApplicationController::class, 'showUserApplication']);
            Route::get('/{uuid}', [ApplicationController::class, 'show']);
            Route::post('/', [ApplicationController::class, 'store']);
            Route::put('/{uuid}', [ApplicationController::class, 'update']);
            Route::put('/{uuid}/status', [ApplicationController::class, 'updateStatus']);
            Route::delete('/{uuid}', [ApplicationController::class, 'destroy']);
        });
    });
});