<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\Api\V1\ApplicationController;
use App\Http\Controllers\Api\V1\AuthController;
use App\Http\Controllers\Api\V1\ClientController;
use App\Http\Controllers\Api\V1\EntityTypeController;
use App\Http\Controllers\Api\V1\RoleController;
use App\Http\Controllers\Api\V1\RoleTypeController;
use App\Http\Controllers\Api\V1\ScopeController;
use App\Http\Controllers\Api\V1\UserController;
use App\Http\Controllers\Api\V1\UserRoleController;

Route::group(['prefix' => 'v1'], function () {
    // Public routes (no auth required)
    Route::group(['prefix' => 'auth'], function () {
        Route::post('login', [AuthController::class, 'login']);
        Route::post('logout', [AuthController::class, 'logout']);
        Route::post('session', [AuthController::class, 'checkSession']);
        Route::post('password/forgot', [AuthController::class, 'forgotPassword']);
        Route::post('password/reset', [AuthController::class, 'resetPassword']);
    });

    // JWT refresh token routes
    Route::group(['middleware' => ['jwt.refresh']], function () {
        Route::post('auth/refresh', [AuthController::class, 'refreshToken']);
    });

    // Authenticated user routes
    Route::group(['middleware' => ['jwt.auth']], function () {
        // Client routes
        Route::group(['prefix' => 'client', 'middleware' => ['client.authorize']], function () {
            Route::get('users', [ClientController::class, 'getUserByCode']);
            Route::post('users', [ClientController::class, 'insertOrUpdateUser']);
        });

        // User profile and personal routes
        Route::group(['prefix' => 'auth/me'], function () {
            Route::get('/', [AuthController::class, 'me']);
            Route::get('applications', [ApplicationController::class, 'myApplication']);
            Route::post('profiles', [UserController::class, 'updateMyProfile']);
            Route::post('password/change', [AuthController::class, 'changeMyPassword']);
        });

        Route::post('auth/impersonate/leave', [AuthController::class, 'leaveImpersonate']);

        // SSO Admin only routes
        Route::group(['middleware' => ['sso.admin']], function () {
            // Authentication user and impersonation
            Route::group(['prefix' => 'auth'], function () {
                Route::get('ldap', [UserController::class, 'userLdap']);
                Route::post('password/change', [AuthController::class, 'changeUserPassword']);
                Route::post('impersonate/start/{uuid}', [AuthController::class, 'startImpersonate']);
            });
            
            // User Management
            Route::prefix('users')->group(function () {
                Route::get('/', [UserController::class, 'index']);
                Route::get('/{uuid}', [UserController::class, 'show']);
                Route::post('/', [UserController::class, 'store']);
                Route::put('/{uuid}', [UserController::class, 'update']);
                Route::put('/{uuid}/status', [UserController::class, 'updateStatus']);
                Route::post('generate-username', [UserController::class, 'generateUsername']);
                Route::post('import', [UserController::class, 'import']);
            });

            // Device Management
            Route::prefix('auth/devices')->group(function () {
                Route::get('active', [AuthController::class, 'getUserActiveDevices']);
                Route::get('active/impersonate', [AuthController::class, 'getActiveImpersonations']);
                Route::post('logout', [AuthController::class, 'logoutUserAllDevices']);
            });

            // System Configuration Routes
            Route::get('scopes', [ScopeController::class, 'index']);
            Route::get('entity-types', [EntityTypeController::class, 'index']);
            Route::get('role-types', [RoleTypeController::class, 'index']);

            // Role Management
            Route::prefix('roles')->group(function () {
                Route::get('/', [RoleController::class, 'index']);
                Route::get('/{uuid}', [RoleController::class, 'show']);
                Route::post('/', [RoleController::class, 'store']);
                Route::put('/{uuid}', [RoleController::class, 'update']);
                Route::delete('/{uuid}', [RoleController::class, 'destroy']);
            });

            // User Role Management
            Route::prefix('user-roles')->group(function () {
                Route::get('/', [UserRoleController::class, 'index']);
                Route::post('/', [UserRoleController::class, 'store']);
                Route::delete('/{uuid}', [UserRoleController::class, 'destroy']);
            });

            // Application Management
            Route::prefix('applications')->group(function () {
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
});